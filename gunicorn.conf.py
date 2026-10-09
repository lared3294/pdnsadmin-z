"""Gunicorn settings shared by manual, SysV and systemd startup."""

import configparser
import os
from pathlib import Path
import ssl


_config_path = Path(os.environ.get("DNSADMIN_CONFIG", "config.ini")).resolve()
_config = configparser.ConfigParser()
try:
    with _config_path.open() as _file:
        _config.read_file(_file)
except (OSError, configparser.Error) as _error:
    raise RuntimeError(f"No se pudo leer la configuración: {_config_path}") from _error

# Ensure the application reads exactly the same file as Gunicorn.
os.environ["DNSADMIN_CONFIG"] = str(_config_path)


def _option(section, key, envvar, default):
    if _config.has_option(section, key):
        return _config.get(section, key)
    return os.environ.get(envvar, default)


def _boolean(section, key, envvar, default):
    value = _option(section, key, envvar, default).strip().lower()
    if value not in configparser.ConfigParser.BOOLEAN_STATES:
        raise RuntimeError(f"[{section}] {key} debe ser True o False")
    return configparser.ConfigParser.BOOLEAN_STATES[value]


bind = _option("server", "bind", "PDNSADMIN_BIND", "127.0.0.1:5000")
try:
    workers = int(_option("server", "workers", "PDNSADMIN_WORKERS", "3"))
except ValueError as _error:
    raise RuntimeError("[server] workers debe ser un entero positivo") from _error
if workers < 1:
    raise RuntimeError("[server] workers debe ser un entero positivo")

proc_name = "pdnsadmin"
accesslog = "-"
errorlog = "-"
capture_output = True

certfile = None
keyfile = None
if _boolean("tls", "enabled", "PDNSADMIN_TLS_ENABLED", "False"):
    def _tls_path(key, envvar):
        value = _option("tls", key, envvar, "").strip()
        if not value:
            raise RuntimeError(f"TLS habilitado: falta [tls] {key}")
        path = Path(value)
        if not path.is_absolute():
            path = _config_path.parent / path
        path = path.resolve()
        try:
            with path.open("rb"):
                pass
        except OSError as error:
            raise RuntimeError(f"TLS: archivo {key} inexistente o ilegible: {path}") from error
        return str(path)

    certfile = _tls_path("certfile", "PDNSADMIN_TLS_CERTFILE")
    keyfile = _tls_path("keyfile", "PDNSADMIN_TLS_KEYFILE")
    try:
        _context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Encrypted private keys are unsupported: never prompt during service startup.
        _context.load_cert_chain(certfile, keyfile, password=lambda: "")
    except (OSError, ssl.SSLError) as _error:
        raise RuntimeError(
            "TLS: certificado o clave inválidos, clave cifrada o par incompatible"
        ) from _error
