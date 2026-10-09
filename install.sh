#!/usr/bin/env bash
# Install pdnsadmin without starting it before configuration.
set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
APP_DIR=/opt/pdnsadmin-z
CONFIG_DIR=/etc/pdnsadmin
STATE_DIR=/var/lib/pdnsadmin
SERVICE_USER=pdnsadmin
INIT_MODE=auto
SYSTEMD_DIR=/etc/systemd/system
SYSV_DIR=/etc/init.d
DRY_RUN=0
INSTALL_PACKAGES=1

usage() {
    cat <<'EOF'
Uso: sudo ./install.sh [opciones]
  --init auto|systemd|sysv  Gestor de servicios (por defecto: detección automática)
  --no-packages           Omitir paquetes del sistema; comprobar dependencias
  --dry-run               Mostrar acciones sin modificar el sistema (no requiere sudo)
  -h, --help             Mostrar esta ayuda

Instala en /opt/pdnsadmin-z; configuración: /etc/pdnsadmin/config.ini.
Crea el usuario de sistema pdnsadmin. Conserva el INI existente.
El servicio NO se inicia ni se habilita: editar la configuración primero.
EOF
}

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
run() {
    if (( DRY_RUN )); then printf '  '; printf '%q ' "$@"; printf '\n'; else "$@"; fi
}

parse_args() {
    while (($#)); do
        case "$1" in
            --init) (($# >= 2)) || fail 'Falta el valor de --init'; INIT_MODE=$2; shift 2 ;;
            --no-packages) INSTALL_PACKAGES=0; shift ;;
            --dry-run) DRY_RUN=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) fail "Opción desconocida: $1" ;;
        esac
    done
    case "$INIT_MODE" in auto|systemd|sysv) ;; *) fail '--init debe ser auto, systemd o sysv' ;; esac
}

systemd_running() {
    [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null
}

detect_init() {
    if [[ "$INIT_MODE" != auto ]]; then printf '%s\n' "$INIT_MODE"; return; fi
    if systemd_running; then printf 'systemd\n'
    elif [[ -d /etc/init.d ]] && { command -v update-rc.d >/dev/null || command -v chkconfig >/dev/null; }; then
        printf 'sysv\n'
    else fail 'No se detectó systemd ni SysV. Usa --init para preparar una instalación explícita.'; fi
}

detect_packages() {
    if command -v apt-get >/dev/null; then printf 'apt\n'
    elif command -v dnf >/dev/null; then printf 'dnf\n'
    elif command -v yum >/dev/null; then printf 'yum\n'
    elif command -v zypper >/dev/null; then printf 'zypper\n'
    else fail 'Gestor de paquetes no compatible; instala las dependencias y usa --no-packages.'; fi
}

install_packages() {
    case "$PACKAGE_MANAGER" in
        apt)
            run apt-get update
            run apt-get install -y python3 python3-venv python3-pip ca-certificates util-linux passwd
            if [[ "$SELECTED_INIT" == sysv ]]; then run apt-get install -y dpkg init-system-helpers; fi
            ;;
        dnf|yum) run "$PACKAGE_MANAGER" install -y python3 python3-pip ca-certificates util-linux shadow-utils ;;
        zypper) run zypper --non-interactive install python3 python3-pip ca-certificates util-linux shadow ;;
    esac
}

check_dependencies() {
    local cmd
    for cmd in python3 install getent useradd groupadd runuser; do
        command -v "$cmd" >/dev/null || fail "Falta $cmd. Instala las dependencias del sistema.";
    done
    python3 -c 'import venv, ensurepip' || fail 'Python requiere venv y ensurepip (en Debian/Ubuntu: python3-venv).'
    if [[ "$SELECTED_INIT" == systemd ]]; then
        command -v systemctl >/dev/null || fail 'Falta systemctl.'
    else
        command -v start-stop-daemon >/dev/null || fail 'SysV requiere start-stop-daemon (paquete dpkg en Debian/Ubuntu).'
        { command -v update-rc.d >/dev/null || command -v chkconfig >/dev/null; } || fail 'SysV requiere update-rc.d o chkconfig.'
    fi
}

check_running_services() {
    # Do not replace a running application or migrate an active legacy service.
    local name pidfile pid
    for name in pdnsadmin dnsadmin; do
        if systemd_running && systemctl is-active --quiet "$name"; then
            fail "El servicio $name está activo. Deténlo antes de instalar: sudo systemctl stop $name";
        fi
        for pidfile in "/run/$name/$name.pid" "$APP_DIR/$name.pid"; do
            if [[ -r "$pidfile" ]]; then
                pid=$(cat "$pidfile")
                if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null; then
                    fail "El servicio $name está activo. Deténlo antes de instalar: sudo service $name stop";
                fi
            fi
        done
    done
}

create_account() {
    local shell account uid
    if getent passwd "$SERVICE_USER" >/dev/null; then
        account=$(getent passwd "$SERVICE_USER"); IFS=: read -r _ _ uid _ _ _ shell <<< "$account"
        [[ "$uid" != 0 ]] || fail 'El usuario pdnsadmin no puede ser root.'
        case "$shell" in */nologin|*/false) ;; *) fail 'El usuario pdnsadmin existente tiene login interactivo; revisa la cuenta antes de instalar.' ;; esac
    else
        shell=$(command -v nologin || printf '/bin/false')
        if ! getent group "$SERVICE_USER" >/dev/null; then run groupadd --system "$SERVICE_USER"; fi
        run useradd --system --gid "$SERVICE_USER" --home-dir "$STATE_DIR" --no-create-home --shell "$shell" "$SERVICE_USER"
    fi
    getent group "$SERVICE_USER" >/dev/null || (( DRY_RUN )) || fail 'Falta el grupo pdnsadmin.'
}

copy_application() {
    local name
    run install -d -o root -g root -m 0755 "$APP_DIR" "$APP_DIR/template" "$APP_DIR/init" "$APP_DIR/systemd"
    # Explicit list: never copy config.ini, certificates, ZIPs, .git or local environments.
    for name in pdnsadmin-z.py wsgi.py gunicorn.conf.py requirements.txt config.example.ini README.md; do
        if [[ "$SOURCE_DIR/$name" != "$APP_DIR/$name" ]]; then
            run install -o root -g root -m 0644 "$SOURCE_DIR/$name" "$APP_DIR/$name"
        fi
    done
    for name in dashboard.html login.html review.html; do
        if [[ "$SOURCE_DIR/template/$name" != "$APP_DIR/template/$name" ]]; then
            run install -o root -g root -m 0644 "$SOURCE_DIR/template/$name" "$APP_DIR/template/$name"
        fi
    done
    if [[ "$SOURCE_DIR" != "$APP_DIR" ]]; then
        run install -o root -g root -m 0755 "$SOURCE_DIR/init/pdnsadmin" "$APP_DIR/init/pdnsadmin"
        run install -o root -g root -m 0644 "$SOURCE_DIR/systemd/pdnsadmin.service" "$APP_DIR/systemd/pdnsadmin.service"
        run install -o root -g root -m 0755 "$SOURCE_DIR/install.sh" "$APP_DIR/install.sh"
    fi
    run python3 -m venv "$APP_DIR/.venv"
    run "$APP_DIR/.venv/bin/python" -m pip install --upgrade pip
    run "$APP_DIR/.venv/bin/python" -m pip install -r "$APP_DIR/requirements.txt"
    run "$APP_DIR/.venv/bin/python" -m pip check
}

prepare_config() {
    umask 077
    run install -d -o root -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR" "$CONFIG_DIR/certs"
    run install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$STATE_DIR" "$STATE_DIR/sessions"
    if [[ -e "$CONFIG_DIR/config.ini" || -L "$CONFIG_DIR/config.ini" ]]; then
        [[ ! -L "$CONFIG_DIR/config.ini" && -f "$CONFIG_DIR/config.ini" ]] || fail 'config.ini debe ser un archivo normal, no un enlace.'
        printf 'Se conserva la configuración existente: %s/config.ini\n' "$CONFIG_DIR"
    else
        if (( DRY_RUN )); then
            printf '  Crear INI desde el ejemplo, generar secret_key y configurar sesiones persistentes.\n'
        else
            "$APP_DIR/.venv/bin/python" - "$APP_DIR/config.example.ini" "$CONFIG_DIR/config.ini" "$STATE_DIR" <<'PY'
import configparser
from pathlib import Path
import secrets
import sys
cfg = configparser.ConfigParser()
cfg.read(sys.argv[1])
cfg['flask']['secret_key'] = secrets.token_hex(32)
cfg['flask']['session_file_dir'] = str(Path(sys.argv[3]) / 'sessions')
cfg['pdns']['url_internal'] = 'http://127.0.0.1:8081/api/v1/servers/localhost'
cfg['pdns']['url_external'] = 'http://127.0.0.1:8082/api/v1/servers/localhost'
# Create with restrictive permissions from the first byte; do not display secrets.
with Path(sys.argv[2]).open('x') as file:
    cfg.write(file)
PY
        fi
    fi
    run chown "root:$SERVICE_USER" "$CONFIG_DIR/config.ini"
    run chmod 0640 "$CONFIG_DIR/config.ini"
    umask 022
}

install_service() {
    local source target
    if [[ "$SELECTED_INIT" == systemd ]]; then
        source="$SOURCE_DIR/systemd/pdnsadmin.service"; target="$SYSTEMD_DIR/pdnsadmin.service"
        run install -d -m 0755 "$SYSTEMD_DIR"
    else
        source="$SOURCE_DIR/init/pdnsadmin"; target="$SYSV_DIR/pdnsadmin"
        run install -d -m 0755 "$SYSV_DIR"
    fi
    [[ ! -L "$target" ]] || fail "El servicio existente es un enlace: $target; revísalo antes de instalar."
    if [[ -f "$target" ]]; then run cp -p -- "$target" "$target.bak.$(date +%Y%m%d%H%M%S).$$"; fi
    if (( DRY_RUN )); then
        printf '  Instalar %s como %s, usando el usuario y grupo pdnsadmin.\n' "$source" "$target"
    else
        python3 - "$source" "$target" "$SELECTED_INIT" <<'PY'
from pathlib import Path
import sys
source, target, mode = sys.argv[1:]
text = Path(source).read_text()
if mode == 'systemd':
    text = text.replace('User=www-data', 'User=pdnsadmin').replace('Group=www-data', 'Group=pdnsadmin')
else:
    text = text.replace('RUN_AS="www-data"', 'RUN_AS="pdnsadmin"').replace('RUN_GROUP="www-data"', 'RUN_GROUP="pdnsadmin"')
Path(target).write_text(text)
Path(target).chmod(0o644 if mode == 'systemd' else 0o755)
PY
    fi
    if [[ "$SELECTED_INIT" == systemd ]]; then run systemctl daemon-reload
    elif command -v update-rc.d >/dev/null; then
        run update-rc.d pdnsadmin defaults
        run update-rc.d pdnsadmin disable
    else
        run chkconfig --add pdnsadmin
        run chkconfig pdnsadmin off
    fi
}

main() {
    parse_args "$@"
    (( DRY_RUN )) || [[ "$EUID" == 0 ]] || fail 'Ejecuta con sudo, o usa --dry-run para previsualizar.'
    [[ "$(uname -s)" == Linux ]] || fail 'El instalador requiere Linux.'
    local name
    for name in pdnsadmin-z.py wsgi.py gunicorn.conf.py requirements.txt config.example.ini README.md init/pdnsadmin systemd/pdnsadmin.service; do
        [[ -f "$SOURCE_DIR/$name" ]] || fail "Falta el archivo $name en el proyecto.";
    done
    SELECTED_INIT=$(detect_init)
    if (( INSTALL_PACKAGES )); then PACKAGE_MANAGER=$(detect_packages); fi
    printf 'Instalación de pdnsadmin: %s; aplicación: %s\n' "$SELECTED_INIT" "$APP_DIR"
    if (( DRY_RUN )); then printf 'Simulación: ninguna acción se ejecutará.\n'; fi
    check_running_services
    if (( INSTALL_PACKAGES )); then install_packages; fi
    if (( ! DRY_RUN )); then check_dependencies; fi
    umask 022
    create_account
    copy_application
    prepare_config
    install_service
    printf '\nPreparado. Edita PowerDNS, OIDC y TLS:\n  sudoedit %s/config.ini\n' "$CONFIG_DIR"
    printf 'Comprueba la configuración después de editarla:\n  sudo runuser -u pdnsadmin -- sh -c '\''cd /opt/pdnsadmin-z && DNSADMIN_CONFIG=/etc/pdnsadmin/config.ini .venv/bin/gunicorn --config gunicorn.conf.py --check-config wsgi:app'\''\n'
    printf 'Usuario del servicio: %s. Certificados: %s/certs (legibles por ese grupo).\n' "$SERVICE_USER" "$CONFIG_DIR"
    if [[ "$SELECTED_INIT" == systemd ]]; then
        printf 'Después de configurar:\n  sudo systemctl enable --now pdnsadmin\n  sudo systemctl status pdnsadmin\n  sudo journalctl -u pdnsadmin -f\n'
    else
        printf 'Después de configurar:\n  sudo update-rc.d pdnsadmin enable  # o chkconfig pdnsadmin on\n  sudo service pdnsadmin start\n  sudo service pdnsadmin status\n'
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
