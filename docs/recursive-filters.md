# Configuración de recursivos

La pestaña **Configuración de recursivos** permite editar filtros y forwarders. El formulario valida los dominios y genera un archivo hosts con:

```text
(StevenBlack, si está seleccionado ∪ lista negra) − lista blanca
```

Se admiten `0.0.0.0 dominio.com`, un dominio por línea y comentarios `#`. La lista blanca tiene prioridad por nombre exacto; los subdominios deben añadirse explícitamente. StevenBlacklist descarga la URL indicada en `[recursor] steven_url`; el ejemplo usa la variante gambling-porn.

**Guardar listas** conserva la edición. **Aplicar filtros** genera el archivo y llama a un único script local para cada recursivo. El script envía una transacción por SSH: prepara el archivo, comprueba la configuración, reemplaza `/etc/powerdns/hosts` de forma atómica y reinicia `pdns-recursor`. La aplicación muestra el resultado de cada servidor y detiene la distribución ante el primer fallo. Los destinos restantes aparecen como **No modificado**; los que ya se aplicaron correctamente conservan la versión nueva.

## Instalación del script

En el servidor de la aplicación:

```sh
sudo install -o root -g root -m 0755 scripts/pdnsadmin-update-recursors /usr/local/sbin/pdnsadmin-update-recursors
sudo install -o root -g root -m 0755 scripts/pdnsadmin-start-recursor-job /usr/local/sbin/pdnsadmin-start-recursor-job
```

Configura los alias `recursor1`, `recursor2`, `recursor3` y `recursor4` en `/root/.ssh/config`. Las claves y `known_hosts` quedan administradas por el sistema, fuera de la aplicación. Ejemplo para un destino; repite para los otros tres:

```sshconfig
Host recursor1
    HostName 192.0.2.11
    User root
    IdentityFile /root/.ssh/id_ed25519
    IdentitiesOnly yes
```

La cuenta SSH debe poder crear archivos en `/etc/powerdns`, conservar sus propietarios y permisos, ejecutar las comprobaciones de PowerDNS y reiniciar el servicio. El ejemplo usa root; si utilizas otra cuenta, ajusta sus permisos y el comando de reinicio del script. Comprueba las claves de host y añade cada equipo al `known_hosts` de root.

Autoriza los ocho comandos de distribución y el lanzador restringido mediante `sudo visudo -f /etc/sudoers.d/pdnsadmin-filters`:

```sudoers
pdnsadmin ALL=(root) NOPASSWD: /usr/local/sbin/pdnsadmin-update-recursors recursor1 hosts, /usr/local/sbin/pdnsadmin-update-recursors recursor1 forward-zones, /usr/local/sbin/pdnsadmin-update-recursors recursor2 hosts, /usr/local/sbin/pdnsadmin-update-recursors recursor2 forward-zones, /usr/local/sbin/pdnsadmin-update-recursors recursor3 hosts, /usr/local/sbin/pdnsadmin-update-recursors recursor3 forward-zones, /usr/local/sbin/pdnsadmin-update-recursors recursor4 hosts, /usr/local/sbin/pdnsadmin-update-recursors recursor4 forward-zones
pdnsadmin ALL=(root) NOPASSWD: /usr/local/sbin/pdnsadmin-start-recursor-job *
```

El lanzador acepta exactamente un identificador hexadecimal de 32 caracteres y un directorio absoluto. Las rutas del intérprete y del ejecutor están fijas; el directorio se abre después de cambiar al usuario sin privilegios. No concedas permiso sudo genérico a `systemd-run`, Python, `runuser` o una shell. El ejemplo usa la cuenta `pdnsadmin` del instalador; si ejecutas el panel como `www-data`, adapta `RUN_AS` del lanzador y ambas reglas sudo a esa cuenta. El código instalado, el entorno virtual y los lanzadores deben seguir siendo propiedad de root y no ser escribibles por el usuario del panel.

No hace falta instalar scripts ni archivos de configuración adicionales en los recursivos. Mantén:

```ini
etc-hosts-file=/etc/powerdns/hosts
export-etc-hosts=on
forward-zones-file=/etc/powerdns/forward-zones
```

El script detecta systemd o SysV init en el destino para reiniciar. Si tu servicio tiene otro nombre, cambia `pdns-recursor` en el script del sistema. Requiere en cada destino `pdns_recursor` con soporte para `--config=check` (4.8 o posterior), `rec_control`, `flock`, `timeout`, `base64`, `sha256sum`, `awk` y las utilidades habituales de shell. Usa `/etc/powerdns` para el archivo de configuración y el socket de control según esa configuración. Está preparado para la disposición clásica de hosts y forward-zones descrita aquí; si tu servicio usa otra instancia, rutas o argumentos, adapta las comprobaciones y el reinicio juntos. Si falta una dependencia o falla una comprobación previa, no reemplaza el archivo ni reinicia.

Después de actualizar el repositorio, vuelve a instalar el script local con el comando anterior: la aplicación ejecuta `/usr/local/sbin/pdnsadmin-update-recursors`, no la copia del repositorio.

## Configuración del panel

```ini
[recursor]
steven_url = https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-porn/hosts
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

`steven_url` permite cambiar la lista de StevenBlack sin modificar el código. También puede proporcionarse con `PDNSADMIN_STEVEN_URL` si la opción no está en el INI.

Los hosts del INI identifican los equipos en pantalla; los destinos efectivos son los alias SSH del sistema y deben corresponderse. No se usan credenciales del INI ni de la API autoritativa.

El instalador incluye el ejecutor y ambos scripts, instala el lanzador en `/usr/local/sbin` y añade SSH/SCP y sudo como dependencias. Los alias, el script de distribución en `/usr/local/sbin` y las reglas sudo se configuran con los pasos anteriores. Una reinstalación conserva tu INI.

Los archivos se reemplazan completos, incluso si la lista queda vacía. Cada destino se procesa bajo un bloqueo exclusivo:

1. La transacción se recibe completa en un temporal privado y se verifica con SHA-256 antes de ejecutarla. El archivo recibido también se verifica y se comprueba su formato normalizado. Una transferencia incompleta no modifica el archivo activo.
2. Se ejecuta `pdns_recursor --config=check` con la ruta del candidato y se comprueba que el servicio actual responde mediante `rec_control ping`. La comprobación nativa valida la configuración y sus opciones; no garantiza que todas las versiones carguen los archivos auxiliares en esta fase. La carga efectiva se comprueba después del reinicio. Véanse la [comprobación de configuración](https://doc.powerdns.com/recursor/manpages/pdns_recursor.1.html) y el [control del recursor](https://doc.powerdns.com/recursor/manpages/rec_control.1.html).
3. Se conserva el archivo anterior y se reemplaza el destino mediante renombrado dentro del mismo sistema de archivos. Se conservan propietario y permisos existentes; un archivo nuevo se crea con permisos `0644`.
4. Se reinicia el servicio con un tiempo máximo de 45 segundos y se espera su respuesta de control. Si falla, se restaura el archivo anterior —o se elimina el nuevo si antes no existía— y se intenta reiniciar y comprobar el servicio de nuevo. Una recuperación fallida se informa explícitamente.
5. Tras un despliegue correcto, la última versión anterior queda en `/etc/powerdns/.pdnsadmin-backups/hosts.previous` o `forward-zones.previous`, dentro de un directorio privado. Se conserva un solo respaldo por tipo.

Los errores y señales normales activan la restauración si ya se reemplazó el archivo. Un corte de energía, SIGKILL o timeout de la conexión puede dejar un estado incierto; verifica el servidor antes de reintentar. No hay restauración global de los servidores que ya finalizaron correctamente. La comprobación de salud usa el socket de control y no sustituye una consulta DNS de extremo a extremo.

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

## Ejecutor temporal de despliegues

Cada aplicación guarda un trabajo, una copia de las listas, la URL de origen y los cuatro destinos en `state_dir/jobs`. El panel lanza un proceso temporal con entrada estándar desconectada y salida privada en `<id>.log`. El ejecutor procesa exclusivamente esa copia y termina al completar el trabajo. No se instala un servicio permanente ni se crea una cola de trabajos.

En systemd, el lanzador crea un scope de sistema `pdnsadmin-recursor-<id>.scope` mediante `systemd-run --scope` y ejecuta el trabajo como la cuenta del panel. Ese scope es independiente de `pdnsadmin.service`: una vez iniciado el ejecutor, una recarga o reinicio de Gunicorn no lo termina. En SysV el proceso se inicia en una sesión separada y no depende del PID del servidor web. La [documentación de systemd-run](https://www.freedesktop.org/software/systemd/man/258/systemd-run.html) describe los scopes temporales.

Durante el arranque se reserva el trabajo durante 30 segundos; después el ejecutor mantiene `apply.lock` hasta terminar. Se rechazan nuevas aplicaciones y guardados mientras haya una reserva o un despliegue activo. Si falla el lanzador o no consigue iniciar a tiempo, la consulta de estado marca el trabajo como error e incluye la salida del lanzador. Si muere el ejecutor o se reinicia el equipo, el trabajo se marca como interrumpido al consultarlo. Nunca se reejecuta automáticamente: verifica los servidores antes de crear otro trabajo. Las interrupciones anteriores al arranque efectivo del ejecutor pueden impedir que el trabajo llegue a comenzar.

Para actualizar una instalación existente, copia también `recursor_job.py` y la versión nueva de `recursor_config.py` al directorio de la aplicación, reinstala ambos scripts locales y añade la regla sudo del lanzador. No es necesario cambiar `KillMode=mixed` ni habilitar otro servicio.

## Retención del historial

Se conservan como máximo los **20 trabajos más recientes**, y los trabajos finalizados caducan al cumplir **15 días desde su creación**. Se aplica el límite que elimine antes cada trabajo. La limpieza elimina juntos el resultado JSON, la copia de la solicitud, el log, el archivo hosts o forward-zones generado y sus temporales reconocidos. No modifica las listas guardadas, los bloqueos ni los archivos desplegados en los recursivos.

El trabajo activo y su reserva de arranque están protegidos; cuentan dentro del límite de 20. El último resultado también caduca a los 15 días: la referencia a la última operación se actualiza o se elimina para no apuntar a un trabajo borrado. Los archivos huérfanos reconocidos también se someten a retención.

La limpieza se ejecuta al consultar la última operación, guardar listas e iniciar o terminar un despliegue, bajo el mismo bloqueo que coordina la distribución. Si hay un ejecutor activo, la limpieza del panel se pospone. No requiere cron ni otro servicio: si el panel permanece sin actividad, los archivos vencidos se retiran en la siguiente limpieza.
