# Filtros para PowerDNS Recursor

La pestaña **DNS privado** tiene dos subpestañas: **Zonas / Dominios** conserva la administración autoritativa y **Filtros** administra una política independiente para cuatro PowerDNS Recursor.

## Listas y aplicación

Se admiten entradas `0.0.0.0 dominio.com`, un dominio por línea y comentarios `#`. Los nombres se normalizan a minúsculas y se eliminan duplicados. Se aceptan las etiquetas DNS con `_` de los ejemplos de analítica.

El selector **StevenBlacklist** usa la [variante gambling-porn de StevenBlack](https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-porn/hosts). Al aplicar, la política se calcula así:

```text
(StevenBlack, si está seleccionado ∪ lista negra) − lista blanca
```

La comparación es de **nombre exacto**: permitir `example.org` no permite automáticamente `www.example.org`. Del mismo modo, bloquear un dominio no crea una regla comodín para sus subdominios. Añade explícitamente los nombres que necesites.

**Guardar listas** solo conserva la edición. **Aplicar filtros** guarda las listas, descarga Steven si corresponde, genera una lista `hosts` y una política RPZ de respuesta **NXDOMAIN**, comprueba los cuatro destinos y luego aplica y reinicia cada recursivo de forma secuencial. La ejecución continúa en segundo plano y el panel muestra el resultado individual.

Si Steven no se puede descargar o falla una comprobación previa, no se envían políticas. Los errores posteriores se muestran por servidor: no hay una transacción global entre los cuatro. Si el reinicio de un recursivo falla, su helper restaura la política anterior e intenta recuperar el servicio. Un timeout SSH deja un resultado incierto que debe revisarse en ese servidor.

Con Steven desmarcado y una lista negra vacía, aplicar genera una política sin bloqueos. El contenido de la lista blanca no crea registros DNS ni cambia las respuestas de otros filtros que ya existan en Recursor.

Solo los administradores pueden guardar, aplicar y consultar el seguimiento de operaciones. Los usuarios de consulta pueden ver las listas.

## Configurar el servidor de la aplicación

El instalador de esta rama instala el cliente SSH y prepara `/var/lib/pdnsadmin/filters` y `/var/lib/pdnsadmin/.ssh` para el usuario `pdnsadmin`. En una instalación manual, crea esos directorios con permisos de escritura para el usuario del servicio.

Completa las nuevas secciones de `config.example.ini` en tu INI existente; una reinstalación conserva el INI y no añade automáticamente opciones.

```ini
[filters]
state_dir = /var/lib/pdnsadmin/filters
targets = recursor1, recursor2, recursor3, recursor4

[recursor:recursor1]
host = 192.0.2.11
user = pdnsadmin-deploy
port = 22
identity_file = /var/lib/pdnsadmin/.ssh/id_ed25519
known_hosts_file = /var/lib/pdnsadmin/.ssh/known_hosts
```

Repite la sección de destino para los otros tres servidores con direcciones distintas. Son destinos recursivos: no se utilizan las URLs ni las claves de `[pdns]`.

Genera una clave dedicada en el servidor de la aplicación:

```sh
sudo runuser -u pdnsadmin -- ssh-keygen -t ed25519 -N '' -f /var/lib/pdnsadmin/.ssh/id_ed25519
```

Instala la clave **pública** en la cuenta SSH elegida de cada recursivo. Añade sus claves de host verificadas a `known_hosts` y deja ambos archivos legibles por `pdnsadmin`. El cliente usa `BatchMode`, identidades explícitas y comprobación estricta del host: no acepta hosts desconocidos automáticamente ni solicita contraseñas desde la web.

## Preparar cada recursivo una vez

Este desarrollo utiliza RPZ cargada desde un archivo Lua y un helper limitado a actualizar esa política. La [documentación de RPZ de PowerDNS](https://doc.powerdns.com/recursor/lua-config/rpz.html) describe `rpzFile` y las acciones de política.

1. Instala Python 3, SSH y sudo en el recursivo si no están disponibles.
2. Crea la cuenta SSH de despliegue, por ejemplo `pdnsadmin-deploy`, con shell para ejecutar comandos remotos e instala la clave pública dedicada.
3. Copia `scripts/pdnsadmin-rpz` desde esta rama y déjalo en `/usr/local/sbin/pdnsadmin-rpz`, propietario `root:root`, modo `0755`. La cuenta de despliegue no debe poder modificar el helper ni su configuración.
4. Configura la política y su activación en Recursor como se indica debajo.

Ejemplo de instalación del helper, una vez copiado al recursivo:

```sh
sudo install -o root -g root -m 0755 pdnsadmin-rpz /usr/local/sbin/pdnsadmin-rpz
sudoedit /etc/pdnsadmin-rpz.json
```

Contenido de `/etc/pdnsadmin-rpz.json`:

```json
{
  "policy_file": "/etc/powerdns/pdnsadmin.rpz",
  "lua_file": "/etc/powerdns/recursor.lua",
  "service": "pdns-recursor",
  "init_system": "auto",
  "control_args": []
}
```

Adapta rutas y nombre de servicio a cada máquina. `init_system` acepta `auto`, `systemd` o `sysv`. `control_args` permite seleccionar el socket o directorio de configuración de esa instancia al ejecutar `rec_control`, por ejemplo `['--config-dir=/etc/powerdns']` (en JSON usa comillas dobles).

```sh
sudo chown root:root /etc/pdnsadmin-rpz.json
sudo chmod 0644 /etc/pdnsadmin-rpz.json
```

Crea la política inicial **vacía**, sin sustituir un archivo ya existente:

```text
$ORIGIN pdnsadmin.rpz.
$TTL 60
@ IN SOA localhost. hostmaster.localhost. 1 60 60 604800 60
@ IN NS localhost.
```

Guárdala en la ruta configurada, con permisos para que el usuario de PowerDNS pueda leerla. Añade esta declaración al Lua de configuración existente, conservando las demás instrucciones:

```lua
rpzFile("/etc/powerdns/pdnsadmin.rpz")
```

Si no se utiliza todavía un Lua de configuración, actívalo en `recursor.conf`:

```ini
lua-config-file=/etc/powerdns/recursor.lua
```

O en una configuración YAML que todavía no defina las opciones equivalentes directamente en YAML:

```yaml
recursor:
  lua_config_file: /etc/powerdns/recursor.lua
```

Conserva las claves existentes del bloque `recursor`. No mezcles opciones RPZ nativas de YAML con su equivalente Lua; PowerDNS exige elegir una modalidad para esas opciones. Consulta la [configuración YAML de Recursor](https://doc.powerdns.com/recursor/yamlsettings.html) para tu versión. Si ya tienes RPZ nativas de YAML, adapta la integración antes de utilizar este helper.

Reinicia Recursor para cargar esta preparación inicial. El helper comprueba tanto la declaración `rpzFile` como el parámetro del Lua activo mediante `rec_control get-parameter` antes de cambiar la política; un servicio activo por sí solo no basta.

## Permisos para aplicar desde la aplicación

Con `sudo visudo -f /etc/sudoers.d/pdnsadmin-rpz`, permite únicamente los dos comandos del helper a la cuenta SSH elegida:

```sudoers
pdnsadmin-deploy ALL=(root) NOPASSWD: /usr/local/sbin/pdnsadmin-rpz --check, /usr/local/sbin/pdnsadmin-rpz --apply
```

Puedes restringir también la clave en `authorized_keys` con la opción `restrict` y una restricción de origen apropiada para tu red. No concedas sudo general a esa cuenta.

Comprueba desde el servidor de la aplicación, con las mismas opciones SSH del INI:

```sh
sudo runuser -u pdnsadmin -- ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o IdentitiesOnly=yes -o UserKnownHostsFile=/var/lib/pdnsadmin/.ssh/known_hosts \
  -i /var/lib/pdnsadmin/.ssh/id_ed25519 pdnsadmin-deploy@192.0.2.11 \
  sudo -n /usr/local/sbin/pdnsadmin-rpz --check
```

Repite esa comprobación para los cuatro destinos antes de pulsar **Aplicar filtros**.

## Archivos y seguimiento

Las listas se guardan en `lists.json` dentro de `state_dir`. Cada aplicación conserva un identificador, su política `.rpz`, su lista `.hosts`, conteos y resultados individuales en `jobs/`. Se almacenan con permisos privados y no hay una base de datos intermedia. Los accesos y aplicaciones se registran con el logger `pdnsadmin`.

Solo se permite una aplicación simultánea. Si se reinicia el proceso de la aplicación durante un trabajo, el panel lo marca como interrumpido; revisa los cuatro recursivos antes de reintentar. El helper mantiene una copia `.previous` junto a la política en cada servidor.

Los archivos históricos no se purgan automáticamente en esta primera versión. Planifica la retención de `jobs/` según el uso.
