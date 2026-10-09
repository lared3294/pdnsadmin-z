# pdnsadmin-z

Interfaz web en Python y Flask para administrar zonas y registros de PowerDNS, con servidores internos y externos y autenticación OIDC.

## Instalación

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install cachelib gunicorn
cp config.example.ini config.ini
```

Editar `config.ini` con las URLs, claves de PowerDNS y configuración OIDC del entorno. Definir una clave de sesión persistente para Flask. La configuración del archivo tiene prioridad sobre las variables de entorno; `DNSADMIN_CONFIG` permite elegir otra ruta.

## Ejecución

```sh
gunicorn --bind 127.0.0.1:5000 wsgi:app
```

Usar HTTPS para las cookies seguras. Los scripts `dnsadmin.init` e `init/dnsadmin` son ejemplos de servicio: adaptar rutas, usuario y certificados al despliegue.

La configuración local, certificados, claves privadas y archivos ZIP se excluyen mediante `.gitignore`.
