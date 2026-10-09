# Configuración de recursivos

La pestaña **Configuración de recursivos** permite editar filtros y forwarders. El formulario valida los dominios y genera un archivo hosts con:

```text
(StevenBlack, si está seleccionado ∪ lista negra) − lista blanca
```

Se admiten `0.0.0.0 dominio.com`, un dominio por línea y comentarios `#`. La lista blanca tiene prioridad por nombre exacto; los subdominios deben añadirse explícitamente. StevenBlacklist usa la variante gambling-porn.

**Guardar listas** conserva la edición. **Aplicar filtros** genera el archivo y llama a un único script local para cada recursivo. El script hace dos cosas: copiar `/etc/powerdns/hosts` por SCP y reiniciar `pdns-recursor` por SSH. La aplicación muestra éxito o error para cada servidor y continúa con los otros destinos si uno falla.

## Instalación del script

En el servidor de la aplicación:

```sh
sudo install -o root -g root -m 0755 scripts/pdnsadmin-update-recursors /usr/local/sbin/pdnsadmin-update-recursors
```

Configura los alias `recursor1`, `recursor2`, `recursor3` y `recursor4` en `/root/.ssh/config`. Las claves y `known_hosts` quedan administradas por el sistema, fuera de la aplicación. Ejemplo para un destino; repite para los otros tres:

```sshconfig
Host recursor1
    HostName 192.0.2.11
    User root
    IdentityFile /root/.ssh/id_ed25519
    IdentitiesOnly yes
```

La cuenta SSH debe poder sobrescribir `/etc/powerdns/hosts` y reiniciar el servicio. El ejemplo usa root; si utilizas otra cuenta, ajusta sus permisos y el comando de reinicio del script. Comprueba las claves de host y añade cada equipo al `known_hosts` de root.

Autoriza únicamente los ocho comandos mediante `sudo visudo -f /etc/sudoers.d/pdnsadmin-filters`:

```sudoers
pdnsadmin ALL=(root) NOPASSWD: /usr/local/sbin/pdnsadmin-update-recursors recursor1 hosts, /usr/local/sbin/pdnsadmin-update-recursors recursor1 forward-zones, /usr/local/sbin/pdnsadmin-update-recursors recursor2 hosts, /usr/local/sbin/pdnsadmin-update-recursors recursor2 forward-zones, /usr/local/sbin/pdnsadmin-update-recursors recursor3 hosts, /usr/local/sbin/pdnsadmin-update-recursors recursor3 forward-zones, /usr/local/sbin/pdnsadmin-update-recursors recursor4 hosts, /usr/local/sbin/pdnsadmin-update-recursors recursor4 forward-zones
```

No hace falta instalar scripts ni archivos de configuración adicionales en los recursivos. Mantén:

```ini
etc-hosts-file=/etc/powerdns/hosts
export-etc-hosts=on
forward-zones-file=/etc/powerdns/forward-zones
```

El script detecta systemd o SysV init en el destino para reiniciar. Si tu servicio tiene otro nombre, cambia `pdns-recursor` en el script del sistema.

## Configuración del panel

```ini
[filters]
state_dir = /var/lib/pdnsadmin/filters
targets = recursor1, recursor2, recursor3, recursor4

[recursor:recursor1]
host = 192.0.2.11

[recursor:recursor2]
host = 192.0.2.12

[recursor:recursor3]
host = 192.0.2.13

[recursor:recursor4]
host = 192.0.2.14
```

Los hosts del INI identifican los equipos en pantalla; los destinos efectivos son los alias SSH del sistema y deben corresponderse. No se usan credenciales del INI ni de la API autoritativa.

El instalador incluye el script, SSH/SCP y sudo, pero los alias y el permiso sudo se configuran una vez a mano. Una reinstalación conserva tu INI.

El archivo hosts se reemplaza completo, incluso si la lista queda vacía. No hay comprobaciones previas, copias de respaldo ni restauración automática. Si falla SCP no se reinicia ese servidor; si falla el reinicio, el archivo nuevo queda copiado y el panel informa del error. Un timeout requiere comprobar el estado del servidor.

Las listas e historial se guardan en archivos privados en `state_dir`, sin base de datos. Solo los administradores pueden guardar o aplicar filtros.

## Forwarders

Pega el contenido de tu archivo actual en **Forwarders** y guarda. El panel conserva esa edición localmente; no lee automáticamente el archivo de los recursivos.

```text
# Destinos autoritativos
example.org=192.0.2.10,192.0.2.11:5300
# Destino recursivo
+example.net=192.0.2.20
# IPv6 con puerto
ipv6.example=[2001:db8::10]:5353
```

La aplicación comprueba zonas, IP y puertos, y rechaza zonas duplicadas. Admite comentarios, IPv4/IPv6, varias IP separadas por coma o punto y coma y los prefijos `+` y `^`. Genera una zona por línea. `+` pide recursión al destino; `^` permite NOTIFY en versiones compatibles. Consulta la [sintaxis de PowerDNS](https://doc.powerdns.com/recursor/settings.html#forward-zones-file).

**Aplicar forwarders** copia exclusivamente `/etc/powerdns/forward-zones` y reinicia. **Aplicar filtros** copia exclusivamente `/etc/powerdns/hosts` y reinicia. El script recibe dos argumentos fijos: el alias del destino y `hosts` o `forward-zones`. Cada botón guarda todo el formulario pero aplica solamente su sección.

Una lista de forwarders vacía reemplaza el archivo con uno vacío y elimina sus reenvíos. Las reglas de bloqueo permanecen independientes: la lista blanca de filtros no modifica los forwarders.
