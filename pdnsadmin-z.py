import os
import re
import ipaddress
import time
import logging
from logging.handlers import SysLogHandler
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from datetime import timedelta
import requests
import json
import configparser
from urllib.parse import quote
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import MismatchingStateError
from werkzeug.middleware.proxy_fix import ProxyFix
from flask.sessions import SessionInterface, SessionMixin
from cachelib.file import FileSystemCache
from collections import UserDict
import uuid
from recursor_config import FilterError, FilterStore, read_targets

# --- configuración desde archivo/env -------------------------------------
# para evitar tocar el script se lee un fichero INI (por defecto `config.ini`)
# con secciones opcionales: [pdns], [auth], [flask], etc. Cada opción puede
# también ser suministrada mediante la correspondiente variable de entorno; en
# caso de conflicto la configuración del fichero tiene prioridad.
#
# ejemplo de config.ini incluido en el repositorio.
#
# la ruta del fichero se toma de DNSADMIN_CONFIG si está definida.
CONFIG_FILE = os.environ.get('DNSADMIN_CONFIG', 'config.ini')


def load_config(path=CONFIG_FILE):
    cfg = configparser.ConfigParser()
    # no fallar si no existe; ConfigParser devuelve un conjunto vacío
    cfg.read(path)
    return cfg

cfg = load_config()


def cfg_get(section: str, key: str, envvar: str, default: str) -> str:
    """Obtener valor de config file, env var o valor por defecto.

    La prioridad es: fichero de config > variable de entorno > default.
    """
    if cfg.has_section(section) and cfg.has_option(section, key):
        return cfg.get(section, key)
    return os.environ.get(envvar, default)

# -------------------------------------------------------------------------

# configurar logger hacia syslog
logger = logging.getLogger('pdnsadmin')
logger.setLevel(logging.INFO)
try:
    handler = SysLogHandler(address='/dev/log')
except Exception:
    handler = SysLogHandler(address=('localhost', 514))
formatter = logging.Formatter('%(name)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def log_event(user, action, zone=None, record=None, level=logging.INFO, details=None):
    """Escribe una entrada en syslog en el formato deseado.

    Salida mínima:
        <user> <ip> <action>
    Si se proporciona una zona:
        <user> <ip> <action> <zone>
    Si además se especifica `record` se incluye entre comillas:
        <user> <ip> <action> <zone> "<record>"

    `level` puede ser un valor de logging (INFO, ERROR, etc.).
    """
    ip = request.remote_addr or 'unknown'
    if zone and record:
        message = f'{user} {ip} {action} {zone} "{record}"'
    elif zone:
        message = f'{user} {ip} {action} {zone}'
    else:
        message = f'{user} {ip} {action}'

    if details:
        message += f' [{details}]'

    if level == logging.ERROR:
        logger.error(message)
    else:
        logger.info(message)

# expresiones y constantes para validación básica
# Permite alfanuméricos, subguiones (_) para SRV/TXT, y comodines (*)
DOMAIN_RE = re.compile(r'^[\w\*](?:[\w\-\*]{0,61}[\w\*])?(?:\.[\w\*](?:[\w\-\*]{0,61}[\w\*])?)*\.?$')
ALLOWED_TYPES = {'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA'}
# límites de longitud para evitar DoS o envíos abusivos
MAX_DOMAIN_LENGTH = 255
MAX_RECORD_CONTENT = 1024  # por ejemplo, texto de registros TXT etc.
MAX_TTL_LENGTH = 7  # dígitos
MAX_RECORDS_PER_RRSET = 20
MAX_PENDING_CHANGES = 10

# búsqueda global de registros en todas las zonas (endpoint /search-data de PowerDNS)
# 'max' es obligatorio en la API; configurable en [pdns] search_max o env PDNS_SEARCH_MAX
try:
    SEARCH_MAX = max(1, int(cfg_get('pdns', 'search_max', 'PDNS_SEARCH_MAX', '500')))
except ValueError:
    SEARCH_MAX = 500
MIN_SEARCH_LENGTH = 2
MAX_SEARCH_LENGTH = 100

app = Flask(__name__, template_folder='template')
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024
# clave de sesión: valor explícito en config.ini ([flask] secret_key) o
# env FLASK_SECRET_KEY, o se genera uno aleatorio cada arranque.
#app.secret_key = cfg_get('flask', 'secret_key', 'FLASK_SECRET_KEY', '') or os.urandom(24)
app.secret_key = cfg_get('flask', 'secret_key', 'FLASK_SECRET_KEY', '') or os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Middleware para manejar cabeceras reenviadas solo cuando hay proxy confiable
TRUST_PROXY = cfg_get('flask', 'trust_proxy', 'TRUST_PROXY', 'False').lower() in ('1', 'true', 'yes')
try:
    PROXY_HOPS = max(1, int(cfg_get('flask', 'proxy_hops', 'PROXY_HOPS', '1')))
except ValueError:
    PROXY_HOPS = 1
if TRUST_PROXY:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=PROXY_HOPS,
        x_proto=PROXY_HOPS,
        x_host=PROXY_HOPS,
        x_prefix=PROXY_HOPS,
    )

# --- SESIONES EN SERVIDOR (cachelib) ---
# Evita el límite de 4KB del navegador y previene que datos sensibles
# (id_token, pending_changes) vayan en la cookie.
SESSION_DIR = cfg_get('flask', 'session_file_dir', 'SESSION_FILE_DIR', '/tmp/flask_sessions')
os.makedirs(SESSION_DIR, exist_ok=True)

class ServerSideSession(UserDict, SessionMixin):
    def __init__(self, sid, initial=None):
        super().__init__(initial or {})
        self.sid = sid
        self.modified = False

class FileSystemSessionInterface(SessionInterface):
    def __init__(self, cache_dir, threshold=500, mode=0o600):
        self.cache = FileSystemCache(cache_dir, threshold=threshold, mode=mode)

    def _get_sid(self, app, request):
        return request.cookies.get(app.config.get('SESSION_COOKIE_NAME', 'session'))

    def open_session(self, app, request):
        sid = self._get_sid(app, request)
        if not sid:
            sid = secrets.token_urlsafe(32)
            return ServerSideSession(sid)
        data = self.cache.get(sid)
        if data is not None:
            return ServerSideSession(sid, data)
        return ServerSideSession(sid)

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        expires = self.get_expiration_time(app, session)

        if not session:
            self.cache.delete(session.sid)
            response.delete_cookie(app.config.get('SESSION_COOKIE_NAME', 'session'),
                                   domain=domain, path=path)
            return

        self.cache.set(session.sid, dict(session),
                       timeout=int(app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()))
        response.set_cookie(
            app.config.get('SESSION_COOKIE_NAME', 'session'),
            session.sid,
            expires=expires,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite
        )

app.session_interface = FileSystemSessionInterface(SESSION_DIR)

@app.before_request
def make_session_permanent():
    session.permanent = True
    # Solo inicializamos pending_changes para usuarios autenticados
    # para evitar crear archivos de sesión innecesarios para visitas anónimas
    if 'user' in session and 'pending_changes' not in session:
        session['pending_changes'] = []

# --- CONFIGURACION DE SEGURIDAD SSL ---
# Forzar que las cookies de sesión solo se envían por HTTPS
app.config['SESSION_COOKIE_SECURE'] = cfg_get('flask', 'session_secure', 'SESSION_SECURE', 'True').lower() in ('1', 'true', 'yes')
# Opcional: Evitar que Javascript acceda a las cookies (seguridad extra)
app.config['SESSION_COOKIE_HTTPONLY'] = True
# Recomendado: Evitar envíos en contextos cross-site
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configuración PowerDNS API (sección [pdns] en config.ini opcional)
# admitimos dos servidores separados: internal y external
PDNS_API_URL_INTERNAL = cfg_get('pdns', 'url_internal', 'PDNS_API_URL_INTERNAL',
                               'http://127.0.0.1:8081/api/v1/servers/internal')
PDNS_API_KEY_INTERNAL = cfg_get('pdns', 'key_internal', 'PDNS_API_KEY_INTERNAL',
                               'tu-api-key-internal')
PDNS_API_URL_EXTERNAL = cfg_get('pdns', 'url_external', 'PDNS_API_URL_EXTERNAL',
                               'http://127.0.0.1:8081/api/v1/servers/external')
PDNS_API_KEY_EXTERNAL = cfg_get('pdns', 'key_external', 'PDNS_API_KEY_EXTERNAL',
                               'tu-api-key-external')
# valores por defecto para nuevas zonas
DEFAULT_ZONE_KIND = cfg_get('pdns', 'default_zone_kind', 'DEFAULT_ZONE_KIND', 'Master')
ns = cfg_get('pdns', 'default_nameservers', 'DEFAULT_ZONE_NAMESERVERS', '')
DEFAULT_ZONE_NAMESERVERS = [n.strip() for n in ns.split(',') if n.strip()]

# utilidad para leer la configuración de acuerdo al servidor actualmente seleccionado

def get_pdns_server():
    """Devuelve 'internal' o 'external'; usa 'internal' por defecto."""
    return session.get('pdns_server', 'internal')

def set_pdns_server(server: str):
    """Guarda la preferencia del usuario en la sesión."""
    if server in ('internal', 'external'):
        session['pdns_server'] = server

def get_pdns_url(server=None):
    s = server or get_pdns_server()
    return PDNS_API_URL_EXTERNAL if s == 'external' else PDNS_API_URL_INTERNAL

def get_pdns_key(server=None):
    s = server or get_pdns_server()
    return PDNS_API_KEY_EXTERNAL if s == 'external' else PDNS_API_KEY_INTERNAL


# Configuración OIDC / Keycloak
OIDC_ENABLED = cfg_get('oidc', 'enabled', 'OIDC_ENABLED', 'False').lower() in ('1', 'true', 'yes')
OIDC_ISSUER = cfg_get('oidc', 'issuer', 'OIDC_ISSUER', '')
OIDC_CLIENT_ID = cfg_get('oidc', 'client_id', 'OIDC_CLIENT_ID', '')
OIDC_CLIENT_SECRET = cfg_get('oidc', 'client_secret', 'OIDC_CLIENT_SECRET', '')
OIDC_ADMIN_ROLE = cfg_get('oidc', 'admin_role', 'OIDC_ADMIN_ROLE', 'AdminDNSUsers')
OIDC_USER_ROLE = cfg_get('oidc', 'user_role', 'OIDC_USER_ROLE', 'DNSUsers')
OIDC_GROUPS_CLAIM = cfg_get('oidc', 'groups_claim', 'OIDC_GROUPS_CLAIM', 'Grupos').strip() or 'Grupos'
OIDC_VERIFY_SSL = cfg_get('oidc', 'verify_ssl', 'OIDC_VERIFY_SSL', 'True').lower() in ('1', 'true', 'yes')
OIDC_REDIRECT_URI = cfg_get('oidc', 'redirect_uri', 'OIDC_REDIRECT_URI', '').strip()

oauth = OAuth(app)
if OIDC_ENABLED:
    # Asegurar que el issuer no tenga barra al final para evitar // en la metadata url
    issuer_clean = OIDC_ISSUER.rstrip('/')
    oauth.register(
        name='keycloak',
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        server_metadata_url=f"{issuer_clean}/.well-known/openid-configuration",
        client_kwargs={
            'scope': 'openid email profile',
            'verify': OIDC_VERIFY_SSL
        },
    )


# --- HELPERS ---

def get_pdns_headers(server=None):
    return {'X-API-Key': get_pdns_key(server), 'Content-Type': 'application/json'}





def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session.get('role') != 'admin':
            flash('Acceso solo para administradores', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def is_valid_domain(name: str) -> bool:
    """Chequeo muy básico de un nombre de dominio o etiqueta.
    La expresión permite etiquetas separadas por puntos y opcional punto final.
    También verifica que no exceda la longitud máxima.
    """
    if not name:
        return False
    # El símbolo de origen puro '@' siempre es válido
    if name == '@':
        return True
    if len(name) > MAX_DOMAIN_LENGTH:
        return False
    #return bool(DOMAIN_RE.match(name))
    if name.endswith('.'):
        name = name[:-1]  # Quitar punto final para validación
    return bool(DOMAIN_RE.match(name)) and not any(c in name for c in ['..', '.-', '-.'])


def validate_ttl(ttl) -> bool:
    # revisa que la longitud sea razonable antes de convertir
    if not isinstance(ttl, str) or len(ttl) > MAX_TTL_LENGTH:
        return False
    try:
        t = int(ttl)
        # Límites razonables: 120 segundos (2min) a 604800 (7 días)
        return 120 <= t <= 604800
    except Exception:
        return False


def validate_soa_content(content: str) -> bool:
    """Valida formato básico de SOA: 7 campos DNS."""
    parts = (content or "").split()
    if len(parts) != 7:
        return False

    mname, rname, serial, refresh, retry, expire, minimum = parts
    if not is_valid_domain(mname):
        return False
    if not is_valid_domain(rname):
        return False

    try:
        serial_i = int(serial)
        refresh_i = int(refresh)
        retry_i = int(retry)
        expire_i = int(expire)
        minimum_i = int(minimum)
    except Exception:
        return False

    if not (1 <= serial_i <= 4294967295):
        return False
    if not (1 <= refresh_i <= 2147483647):
        return False
    if not (1 <= retry_i <= 2147483647):
        return False
    if not (1 <= expire_i <= 2147483647):
        return False
    if not (0 <= minimum_i <= 2147483647):
        return False

    return True


def validate_content(content: str, rtype: str) -> bool:
    content = (content or "").strip()
    if not content:
        return False
    if rtype == 'A':
        try:
            ipaddress.IPv4Address(content)
            return True
        except Exception:
            return False
    if rtype == 'AAAA':
        try:
            ipaddress.IPv6Address(content)
            return True
        except Exception:
            return False
    if rtype == 'MX':
        # formato: "<prioridad> <servidor>" donde servidor es un FQDN
        parts = content.split()
        if len(parts) != 2:
            return False
        pr, host = parts
        try:
            if int(pr) < 0:
                return False
        except Exception:
            return False
        # host puede terminar con punto o no, pero debe ser dominio válido
        return is_valid_domain(host)
    if rtype in ('CNAME', 'NS', 'PTR'):
        return is_valid_domain(content)
    if rtype == 'SOA':
        return validate_soa_content(content)
    # otros tipos se permiten como cualquier cadena no vacía
    return True


def normalize_fqdn(name: str, zone: str) -> str:
    """
    Acepta:
      - name relativo: 'www' o '@'
      - FQDN: 'www.example.com.' o 'www.example.com'
    Devuelve siempre FQDN con punto final y consistente con zone.
    """
    name = (name or "").strip()
    zone = (zone or "").strip()

    # Asegurar que zone sea FQDN con punto final
    if not zone.endswith("."):
        zone = zone + "."

    # Caso '@' o vacío => la zona
    if name in ("@", ""):
        return zone

    # Quitar punto final si existe para comparar
    name_nodot = name[:-1] if name.endswith(".") else name
    zone_nodot = zone[:-1]  # zone siempre termina en '.'

    # Si ya es FQDN dentro de la zona, devolverlo con punto final
    if name_nodot == zone_nodot or name_nodot.endswith("." + zone_nodot):
        return name_nodot + "."

    # Si no, tratarlo como relativo y concatenar
    return f"{name_nodot}.{zone}"


def normalize_target_fqdn(target: str, zone: str) -> str:
    """
    Normaliza el contenido (lado derecho) de registros como CNAME, MX, NS, PTR.
    A diferencia del nombre del registro, estos pueden apuntar fuera de la zona.
    - target: "mail" -> "mail.zone."
    - target: "smtp.google.com" -> "smtp.google.com."
    """
    target = (target or "").strip()
    zone = (zone or "").strip()

    if not zone.endswith("."):
        zone += "."

    if target == "@":
        return zone
    if target.endswith("."):
        return target

    # Si contiene al menos un punto, se asume externo/absoluto sin punto final
    if "." in target:
        return target + "."

    # Relativo interno
    return f"{target}.{zone}"





def extract_preferred_ttl(zone_data: dict) -> int:
    """Calcula el TTL más común en memoria a partir del payload JSON de una zona descargada."""
    default = zone_data.get('default_ttl') or zone_data.get('ttl') or 300
    if 'rrsets' in zone_data:
        from collections import Counter
        ttl_counts = Counter()
        for rr in zone_data['rrsets']:
            t = rr.get('ttl')
            if isinstance(t, int):
                ttl_counts[t] += 1
        if ttl_counts:
            most_common, _ = ttl_counts.most_common(1)[0]
            return most_common
    return default





def fetch_rrset(zone: str, fqdn: str, rtype: str):
    """Devuelve el rrset completo de un registro específico.

    Retorna el objeto JSON del rrset (con "records", "ttl", etc.) o None si
    no se encuentra o hay error.
    """
    try:
        r = requests.get(f"{get_pdns_url()}/zones/{zone}", headers=get_pdns_headers(), timeout=5)
        if r.status_code == 200:
            data = r.json()
            for rr in data.get('rrsets', []):
                # comparar nombre y tipo tal como devuelve PowerDNS (FQDN con punto)
                if rr.get('name') == fqdn and rr.get('type') == rtype:
                    return rr
    except Exception:
        pass
    return None


def build_rrset_change_details(old_rrset: dict, new_contents=None, new_ttl=None, action='REPLACE') -> str:
    """Construye details homogéneo para syslog con old/new de un RRset."""
    old_ttl = old_rrset.get('ttl') if old_rrset else '-'
    old_vals = ''
    if old_rrset and old_rrset.get('records'):
        old_vals = ', '.join(rec.get('content', '') for rec in old_rrset.get('records', []))

    if action == 'DELETE':
        new_vals = ''
        new_ttl_str = '-'
    else:
        vals = new_contents or []
        new_vals = ', '.join(vals)
        new_ttl_str = str(new_ttl) if new_ttl is not None else '-'

    return f'old="{old_vals}" new="{new_vals}" old_ttl={old_ttl} new_ttl={new_ttl_str}'


# --- RUTAS ---


import secrets


def handle_api_error(r):
    try:
        return r.json().get('error', r.text)
    except json.JSONDecodeError:
        return r.text


def rotate_session_id():
    """Regenera el identificador de sesión para evitar session fixation."""
    if hasattr(session, 'sid'):
        try:
            app.session_interface.cache.delete(session.sid)
        except Exception:
            pass
        session.sid = secrets.token_urlsafe(32)
    session.modified = True


# --- CSRF PROTECTION --------------------------------------------------

# función para generar token y guardarlo en sesión
# está disponible en templates como csrf_token()

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(16)
    return session['_csrf_token']

@app.before_request
def csrf_protect():
    # Only check state-changing requests
    if request.method == "POST":
        token = session.get('_csrf_token', None)
        form_token = request.form.get('csrf_token')
        if not token or token != form_token:
            user = session.get('user')
            log_event(user, 'csrf_failure', details=f'path={request.path}', level=logging.ERROR)
            flash('CSRF token missing o inválido', 'danger')
            return redirect(url_for('index'))

# hace disponible la función en los templates como csrf_token()
app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si venimos de un error de grupos en Keycloak, no re-redirigir automáticamente
    # para evitar un bucle infinito de redirecciones.
    force_login_page = request.args.get('error') == 'unauthorized'

    if OIDC_ENABLED and not force_login_page:
        redirect_uri = OIDC_REDIRECT_URI or url_for('callback', _external=True)
        return oauth.keycloak.authorize_redirect(redirect_uri)

    return render_template('login.html', oidc_enabled=OIDC_ENABLED)

@app.route('/callback')
def callback():
    if not OIDC_ENABLED:
        return redirect(url_for('index'))

    try:
        token = oauth.keycloak.authorize_access_token()
    except MismatchingStateError:
        # Esto ocurre si el usuario refresca la página o vuelve atrás en el navegador
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'Error en la validación del token: {e}', 'danger')
        return redirect(url_for('login'))

    user_info = token.get('userinfo')
    if user_info:
        username = user_info.get('preferred_username') or user_info.get('email')

        # Determinar rol usando claim de grupos configurable (por defecto: "Grupos")
        raw_groups = user_info.get(OIDC_GROUPS_CLAIM, user_info.get('groups', []))
        if isinstance(raw_groups, str):
            grupos = [raw_groups]
        elif isinstance(raw_groups, (list, tuple, set)):
            grupos = [str(g) for g in raw_groups]
        else:
            grupos = []
        is_admin = (OIDC_ADMIN_ROLE in grupos) or (f"/{OIDC_ADMIN_ROLE}" in grupos)
        is_user = (OIDC_USER_ROLE in grupos) or (f"/{OIDC_USER_ROLE}" in grupos)

        if not is_admin and not is_user:
            # LIMPIAR SESIÓN: Es fundamental para borrar cualquier rastro de login previo
            session.clear()
            flash('No tienes permiso para acceder a esta aplicación', 'danger')
            log_event(username, 'login_failed_unauthorized_group', details=f"Grupos: {grupos}")
            # Redirigir con bandera de error para romper el bucle en /login
            return redirect(url_for('login', error='unauthorized'))

        # Si pasó los filtros, guardamos en sesión
        session.clear()
        rotate_session_id()
        session['user'] = username
        session['role'] = 'admin' if is_admin else 'consulta'
        if is_admin:
            session['admin_mode'] = 'seguro'

        # Guardamos el id_token para poder cerrar sesión sin confirmación en Keycloak
        session['id_token'] = token.get('id_token')

        log_event(username, 'login_success_oidc')
        return redirect(url_for('index'))

    flash('Error en la autenticación OIDC', 'danger')
    return redirect(url_for('login'))

@app.route('/logout', methods=['POST'])
def logout():
    user = session.get('user')
    id_token = session.get('id_token') # Extraer antes de limpiar
    # Borrar el archivo de sesión del disco inmediatamente
    if hasattr(session, 'sid'):
        app.session_interface.cache.delete(session.sid)
    session.clear()
    if user:
        log_event(user, 'logout')

    if OIDC_ENABLED:
        # Para un cierre de sesión voluntario, enviamos al login sin el error 'unauthorized'.
        # Esto disparará la redirección automática a Keycloak de nuevo (que ahora pedirá credenciales).
        # El error 'unauthorized' se queda solo para cuando el callback rechaza por grupos.
        target_url = url_for('login', _external=True)
        logout_url = f"{OIDC_ISSUER.rstrip('/')}/protocol/openid-connect/logout"

        params = f"?post_logout_redirect_uri={quote(target_url)}"
        if id_token:
            params += f"&id_token_hint={id_token}"
        else:
            params += f"&client_id={OIDC_CLIENT_ID}"

        return redirect(f"{logout_url}{params}")

    return redirect(url_for('login'))


@app.route('/admin_mode', methods=['POST'])
@admin_required
def set_admin_mode():
    mode = request.form.get('mode', 'seguro')
    if mode in ('seguro', 'kamikaze'):
        session['admin_mode'] = mode
        if mode == 'kamikaze':
            flash('Aviso: Estás en Modo Kamikaze. Tienes habilitada la creación y borrado de zonas.', 'warning')
        else:
            flash('Modo Seguro activado.', 'success')
    return redirect(url_for('index'))


@app.route('/')
@login_required
def index():
    # cambiar servidor si se indica en la query string
    server = request.args.get('server')
    if server:
        set_pdns_server(server)
    current = get_pdns_server()

    # Listar zonas
    try:
        r = requests.get(f"{get_pdns_url()}/zones", headers=get_pdns_headers(), timeout=5)
        if r.status_code == 200:
            zones = sorted(r.json(), key=lambda z: z.get('name', ''))
        else:
            zones = []
            flash(f"Error conectando a PowerDNS ({current}): {handle_api_error(r)}", 'danger')
    except requests.exceptions.ConnectionError:
        zones = []
        flash('Error de conexión al servidor DNS.', 'danger')
    except requests.exceptions.Timeout:
        zones = []
        flash('Timeout al conectar con el servidor DNS.', 'danger')
    except Exception as e:
        zones = []
        log_event(session.get('user'), 'index_exception', level=logging.ERROR, details=str(e))
        flash('Error inesperado al conectar con el servidor DNS.', 'danger')

    # pasar servidor actual para la vista
    return render_template('dashboard.html', zones=zones, current_server=current)


@app.route('/search')
@login_required
def search_records():
    """Búsqueda global de registros usando el endpoint search-data de PowerDNS.

    Delega la búsqueda al servidor DNS, que la hace sobre todas las zonas a la
    vez. La API admite los comodines '*' (varios caracteres) y '?' (un carácter).
    """
    query = (request.args.get('q') or '').strip()
    user = session.get('user')
    current = get_pdns_server()

    if not (MIN_SEARCH_LENGTH <= len(query) <= MAX_SEARCH_LENGTH):
        flash(f'El término de búsqueda debe tener entre {MIN_SEARCH_LENGTH} y {MAX_SEARCH_LENGTH} caracteres.', 'warning')
        return redirect(url_for('index'))

    results = []
    try:
        r = requests.get(
            f"{get_pdns_url()}/search-data",
            headers=get_pdns_headers(),
            params={'q': query, 'max': SEARCH_MAX, 'object_type': 'record'},
            timeout=5
        )
        if r.status_code == 200:
            for item in r.json():
                # la API puede devolver también zonas y comentarios; solo mostramos registros
                if item.get('object_type') != 'record':
                    continue
                results.append({
                    'zone': item.get('zone', ''),
                    'zone_id': item.get('zone_id', ''),
                    'name': item.get('name', ''),
                    'type': item.get('type', ''),
                    'ttl': item.get('ttl', ''),
                    'content': item.get('content', ''),
                    'disabled': bool(item.get('disabled', False)),
                })
            results.sort(key=lambda x: (x['zone'], x['name'], x['type'], x['content']))
#            log_event(user, 'search_records', details=f'q="{query}" server={current} results={len(results)}')
            if len(results) >= SEARCH_MAX:
                flash(f'Se alcanzó el máximo de {SEARCH_MAX} resultados; puede haber más coincidencias. Refiná el término de búsqueda.', 'warning')
        else:
            # algunos backends de PowerDNS no soportan la búsqueda
            flash(f'Error en la búsqueda: {handle_api_error(r)}', 'danger')
            log_event(user, 'search_records', level=logging.ERROR,
                      details=f'status={r.status_code} server={current}')
    except requests.exceptions.ConnectionError:
        flash('Error de conexión al servidor DNS.', 'danger')
    except requests.exceptions.Timeout:
        flash('Timeout al conectar con el servidor DNS.', 'danger')
    except Exception as e:
        log_event(user, 'search_exception', level=logging.ERROR, details=str(e))
        flash('Error inesperado durante la búsqueda.', 'danger')

    return render_template('dashboard.html', search_results=results, query=query, current_server=current)


@app.route('/zone/add', methods=['POST'])
@admin_required
def add_zone():
    if session.get('admin_mode') != 'kamikaze':
        flash('Debes estar en Modo Kamikaze para crear zonas', 'danger')
        return redirect(url_for('index'))

    name = request.form['name']
    user = session.get('user')
    current = get_pdns_server()
    # validación básica antes de enviar a PowerDNS
    if not is_valid_domain(name):
        flash('Nombre de zona inválido o demasiado largo', 'danger')
        return redirect(url_for('index'))

    # PowerDNS requiere el punto final (FQDN) para algunas versiones,
    # pero la API suele manejarlo. Enviamos el nombre tal cual o normalizado.
    if not name.endswith('.'):
        name += '.'

    payload = {
        "name": name,
        "kind": DEFAULT_ZONE_KIND,  # puede sobreescribirse desde config
        "nameservers": DEFAULT_ZONE_NAMESERVERS or []  # especificar en config
    }

    try:
        r = requests.post(f"{get_pdns_url()}/zones", headers=get_pdns_headers(), json=payload, timeout=5)
        if r.status_code in [201, 204]:
            flash('Zona creada exitosamente', 'success')
            log_event(user, 'add_zone', zone=name)
            return redirect(url_for('view_zone', zone_id=name))
        else:
            err = handle_api_error(r)
            flash(f'Error al crear zona: {err}', 'danger')
            log_event(user, 'add_zone', zone=name, level=logging.ERROR)
    except requests.exceptions.Timeout:
        flash('Timeout al crear zona.', 'danger')
        log_event(user, 'add_zone', zone=name, level=logging.ERROR)
    except Exception as e:
        log_event(user, 'add_zone', zone=name, level=logging.ERROR, details=str(e))
        flash('Error inesperado al crear la zona.', 'danger')

    return redirect(url_for('index'))

@app.route('/zone/delete/<zone_id>', methods=['POST'])
@admin_required
def delete_zone(zone_id):
    if session.get('admin_mode') != 'kamikaze':
        flash('Debes estar en Modo Kamikaze para eliminar zonas', 'danger')
        return redirect(url_for('index'))

    user = session.get('user')
    # asegurarse de que la id recibida es razonablemente válida
    if not is_valid_domain(zone_id):
        flash('Zona inválida', 'danger')
        return redirect(url_for('index'))

    confirm_name = request.form.get("confirm_name")

    # comparar sin importar punto final
    if (confirm_name or "").rstrip('.') != zone_id.rstrip('.'):
        flash("Confirmación incorrecta. La zona no fue eliminada.", "danger")
        return redirect(url_for("index"))

    # zone_id usualmente es el canonical name (ej: example.com.)
    try:
        r = requests.delete(f"{get_pdns_url()}/zones/{zone_id}", headers=get_pdns_headers(), timeout=5)
        if r.status_code in [200, 204]:
            flash('Zona eliminada', 'success')
            log_event(user, 'delete_zone', zone=zone_id)
        else:
            flash(f'Error al eliminar zona: {handle_api_error(r)}', 'danger')
            log_event(user, 'delete_zone', zone=zone_id, level=logging.ERROR)
    except requests.exceptions.Timeout:
        flash('Timeout al eliminar zona.', 'danger')
        log_event(user, 'delete_zone', zone=zone_id, level=logging.ERROR)
    except Exception as e:
        log_event(user, 'delete_zone', zone=zone_id, level=logging.ERROR, details=str(e))
        flash('Error inesperado al eliminar la zona.', 'danger')

    return redirect(url_for('index'))

@app.route('/zone/<zone_id>', methods=['GET'])
@login_required
def view_zone(zone_id):
    # Validar zone_id antes de enviarlo a la API
    if not is_valid_domain(zone_id):
        flash('Zona inválida.', 'danger')
        return redirect(url_for('index'))
    user = session.get('user')
    try:
        r = requests.get(f"{get_pdns_url()}/zones/{zone_id}", headers=get_pdns_headers(), timeout=5)
        if r.status_code == 200:
            zone_data = r.json()

            # Ordenar los registros (rrsets)
            if 'rrsets' in zone_data:
                order = {'SOA': 0, 'NS': 1, 'MX': 2, 'TXT': 3}
                # Ordena por el tipo de registro y luego por el nombre
                zone_data['rrsets'] = sorted(
                    zone_data['rrsets'],
                    key=lambda r: (order.get(r['type'], 99), r['name'])
                )

            # Como ya tenemos descargado todo el JSON p/ mostrar la zona en frontend,
            # reciclamos los datos y extraemos en memoria el TTL preferido para sugerirlo en la UI:
            default_ttl = extract_preferred_ttl(zone_data)

            # Calcular qué registros (name, type) tienen cambios pendientes para el servidor actual
            current = get_pdns_server()
            pending_keys = set(
                (c['name'], c['type']) for c in session.get('pending_changes', [])
                if c['zone'] == zone_id and c.get('server', 'internal') == current
            )

            return render_template('dashboard.html', zone_detail=zone_data, zones=[], default_ttl=default_ttl, current_server=current, pending_keys=pending_keys)
        else:
            flash(f'No se pudo cargar la zona: {handle_api_error(r)}', 'danger')
    except requests.exceptions.Timeout as e:
        flash(f'Timeout al obtener zona: {e}', 'danger')
    except Exception as e:
        flash(f'Excepción: {e}', 'danger')

    return redirect(url_for('index'))

@app.route('/record/add', methods=['POST'])
@admin_required
def add_record():
    zone = request.form['zone']
    name = request.form['name']
    rtype = request.form['type']
    ttl = request.form.get('ttl', '').strip()
    user = session.get('user')

    # validación básica de zona (primero, para evitar llamadas a la API con basura)
    if not is_valid_domain(zone):
        flash('Zona inválida o demasiado larga', 'danger')
        return redirect(url_for('index'))

    # limit name length
    if len(name) > MAX_DOMAIN_LENGTH:
        flash('Nombre de registro demasiado largo', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))
    if not is_valid_domain(name):
        flash('Nombre de registro inválido', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))

    # si el usuario dejó el TTL vacío, calcular el valor más común de la zona
    if not ttl:
        ttl = request.form.get('default_ttl', '300')


    # validaciones básicas
    if rtype not in ALLOWED_TYPES:
        flash('Tipo de registro no permitido', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))
    if rtype == 'SOA' and session.get('admin_mode') != 'kamikaze':
        flash('Para modificar SOA debes activar Modo Kamikaze', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))
    if not validate_ttl(ttl):
        flash('TTL inválido', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))

    # 1) Soportar múltiples valores:
    contents = request.form.getlist('content[]')
    if not contents:
        # fallback para el form simple (un solo content)
        single = request.form.get('content', '').strip()
        contents = [single] if single else []

    # limpiar vacíos
    contents = [c.strip() for c in contents if c and c.strip()]
    if not contents:
        flash('El campo contenido es obligatorio', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))

    if len(contents) > MAX_RECORDS_PER_RRSET:
        flash(f'Máximo {MAX_RECORDS_PER_RRSET} valores por registro', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))

    if rtype == 'SOA' and len(contents) != 1:
        flash('SOA debe tener exactamente un valor', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))

    normalized_contents = []
    # validar cada valor según el tipo y longitud
    for c in contents:
        if len(c) > MAX_RECORD_CONTENT:
            flash(f'Contenido demasiado largo para tipo {rtype}', 'danger')
            return redirect(url_for('view_zone', zone_id=zone))
        if not validate_content(c, rtype):
            msg = f'Contenido "{c}" inválido para tipo {rtype}'
            if rtype == 'MX':
                msg += ' (debe ser "prioridad servidor.example.com.")'
            flash(msg, 'danger')
            return redirect(url_for('view_zone', zone_id=zone))

        # Normalizar a FQDN los tipos que lo requieren, usando logica de TARGET
        if rtype in ('CNAME', 'NS', 'PTR'):
            c = normalize_target_fqdn(c, zone)
        elif rtype == 'MX':
            parts = c.split()
            c = f"{parts[0]} {normalize_target_fqdn(parts[1], zone)}"

        normalized_contents.append(c)

    contents = normalized_contents
    fqdn = normalize_fqdn(name, zone)
    zone_fqdn = normalize_fqdn('@', zone)
    if rtype == 'SOA' and fqdn != zone_fqdn:
        flash('El registro SOA solo puede existir en el apex de la zona', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))

    # REVISAR LÍMITE
    if len(session.get('pending_changes', [])) >= MAX_PENDING_CHANGES:
        flash(f'Límite de {MAX_PENDING_CHANGES} cambios pendientes alcanzado. Aplica o descarta los actuales.', 'warning')
        return redirect(url_for('view_zone', zone_id=zone))

    # EN LUGAR DE HACER EL PATCH, GUARDAMOS EN SESIÓN
    change = {
        'id': str(uuid.uuid4()),
        'action': 'REPLACE',
        'server': get_pdns_server(),
        'zone': zone,
        'name': fqdn,
        'type': rtype,
        'ttl': int(ttl),
        'records': [{"content": c, "disabled": False} for c in contents],
        'readable_records': ', '.join(contents),
        'timestamp': time.time()
    }

    pending = session.get('pending_changes', [])

    # Prevenir duplicados/conflictos: si ya hay un cambio para este registro, lo reemplazamos
    pending = [c for c in pending if not (
        c.get('server', get_pdns_server()) == change['server'] and
        c['zone'] == zone and
        c['name'] == fqdn and
        c['type'] == rtype
    )]

    pending.append(change)
    session['pending_changes'] = pending

    flash(f'Cambio para {fqdn} ({rtype}) añadido a la lista de espera.', 'info')
    current_rr = fetch_rrset(zone, fqdn, rtype)
    details = build_rrset_change_details(current_rr, new_contents=contents, new_ttl=int(ttl), action='REPLACE')
    action_name = 'stage_update_soa' if rtype == 'SOA' else 'stage_replace_record'
    log_event(user, action_name, zone=zone, record=f"{fqdn} {rtype}", details=details)

    return redirect(url_for('view_zone', zone_id=zone))


@app.route('/record/delete', methods=['POST'])
@admin_required
def delete_record():
    zone = request.form['zone']       # ej: "example.com."
    name = request.form['name']       # ej: "www" o "@"
    rtype = request.form['type']      # ej: "A"
    user = session.get('user')

    # validar
    if not is_valid_domain(zone):
        flash('Zona inválida', 'danger')
        return redirect(url_for('index'))
    if rtype not in ALLOWED_TYPES:
        flash('Tipo de registro no permitido', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))
    if rtype == 'SOA':
        flash('No está permitido borrar el registro SOA', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))
    if not is_valid_domain(name):
        flash('Nombre de registro inválido', 'danger')
        return redirect(url_for('view_zone', zone_id=zone))


    fqdn = normalize_fqdn(name, zone)

    # REVISAR LÍMITE
    if len(session.get('pending_changes', [])) >= MAX_PENDING_CHANGES:
        flash(f'Límite de {MAX_PENDING_CHANGES} cambios pendientes alcanzado.', 'warning')
        return redirect(url_for('view_zone', zone_id=zone))

    # Obtener valores actuales para mostrar en el resumen y para auditoría
    readable_vals = ""
    rr = fetch_rrset(zone, fqdn, rtype)
    if rr and 'records' in rr:
        readable_vals = ', '.join([rec.get('content', '') for rec in rr['records']])

    change = {
        'id': str(uuid.uuid4()),
        'action': 'DELETE',
        'server': get_pdns_server(),
        'zone': zone,
        'name': fqdn,
        'type': rtype,
        'readable_records': readable_vals,
        'timestamp': time.time()
    }

    pending = session.get('pending_changes', [])

    # Prevenir duplicados/conflictos: si ya hay un cambio para este registro, lo reemplazamos
    pending = [c for c in pending if not (
        c.get('server', get_pdns_server()) == change['server'] and
        c['zone'] == zone and
        c['name'] == fqdn and
        c['type'] == rtype
    )]

    pending.append(change)
    session['pending_changes'] = pending

    flash(f'Eliminación de {fqdn} ({rtype}) añadida a la lista de espera.', 'info')
    details = build_rrset_change_details(rr, action='DELETE')
    log_event(user, 'stage_delete_record', zone=zone, record=f"{fqdn} {rtype}", details=details)

    return redirect(url_for('view_zone', zone_id=zone))


@app.route('/review')
@login_required
def review_changes():
    pending = session.get('pending_changes', [])
    return render_template('review.html', changes=pending)


@app.route('/change/remove/<change_id>', methods=['POST'])
@admin_required
def remove_change(change_id):
    pending = session.get('pending_changes', [])
    new_pending = [c for c in pending if c['id'] != change_id]
    session['pending_changes'] = new_pending
    flash('Cambio descartado de la lista.', 'info')
    return redirect(url_for('review_changes'))


@app.route('/change/discard', methods=['POST'])
@admin_required
def discard_all():
    session['pending_changes'] = []
    flash('Todos los cambios pendientes han sido descartados.', 'warning')
    return redirect(url_for('index'))


@app.route('/commit', methods=['POST'])
@admin_required
def commit_changes():
    pending = session.get('pending_changes', [])
    if not pending:
        flash('No hay cambios pendientes para aplicar.', 'warning')
        return redirect(url_for('index'))

    # Agrupar por servidor y zona: almacenamos (rrsets, ids)
    by_server_zone = {}
    for c in pending:
        s = c.get('server', get_pdns_server()) # Fallback para pendientes viejos
        z = c['zone']

        key = (s, z)
        if key not in by_server_zone:
            by_server_zone[key] = ([], [])

        rrset = {
            "name": c['name'],
            "type": c['type'],
            "changetype": c['action']
        }
        if c['action'] == 'REPLACE':
            rrset['ttl'] = c['ttl']
            rrset['records'] = c['records']

        by_server_zone[key][0].append(rrset)
        by_server_zone[key][1].append(c['id'])

    user = session.get('user')
    success_count = 0
    error_count = 0
    failed_ids = set()  # IDs de cambios que fallaron

    for (pdns_server, zone), (rrsets, change_ids) in by_server_zone.items():
        payload = {"rrsets": rrsets}
        try:
            url = f"{get_pdns_url(pdns_server)}/zones/{zone}"
            headers = get_pdns_headers(pdns_server)
            r = requests.patch(url, headers=headers, json=payload, timeout=10)
            if r.status_code in [200, 204]:
                success_count += len(rrsets)
                log_event(user, 'commit_zone_success', zone=zone,
                          details=f"changes={len(rrsets)} server={pdns_server}")
            else:
                error_count += len(rrsets)
                failed_ids.update(change_ids)
                flash(f"Error en zona {zone}: {handle_api_error(r)}", 'danger')
                log_event(user, 'commit_zone_error', zone=zone,
                          level=logging.ERROR, details=f"server={pdns_server}")
        except Exception as e:
            error_count += len(rrsets)
            failed_ids.update(change_ids)
            log_event(user, 'commit_zone_exception', zone=zone,
                      level=logging.ERROR, details=str(e))
            flash(f'Error de conexión al aplicar cambios en zona {zone}.', 'danger')

    if success_count > 0:
        flash(f'Se aplicaron {success_count} cambios exitosamente.', 'success')
    if error_count > 0:
        flash(f'Hubo errores en {error_count} cambios. Se mantienen en la lista de pendientes.', 'danger')

    # Solo conservar los cambios que fallaron
    if failed_ids:
        session['pending_changes'] = [c for c in pending if c['id'] in failed_ids]
    else:
        session['pending_changes'] = []

    return redirect(url_for('index'))



# Recursive filter policies are independent from the authoritative PowerDNS API.
filter_store = FilterStore(cfg_get('filters', 'state_dir', 'PDNSADMIN_FILTERS_DIR', '/tmp/pdnsadmin-filters'))


@app.route('/filters', methods=['GET', 'POST'])
@login_required
def filters():
    set_pdns_server('internal')
    targets, config_error, state, job = [], '', None, None
    try:
        targets = read_targets(cfg)
    except FilterError as error:
        config_error = str(error)
    try:
        state = filter_store.read()
        if request.method == 'POST':
            if session.get('role') != 'admin':
                flash('Acceso solo para administradores', 'danger')
                return redirect(url_for('filters'))
            state = {'steven_enabled': request.form.get('steven_enabled') == 'on',
                     'blacklist': request.form.get('blacklist', ''),
                     'whitelist': request.form.get('whitelist', ''),
                     'forwarders': request.form.get('forwarders', '')}
            action = request.form.get('action', 'save')
            if action in ('apply', 'apply_forwarders'):
                if config_error:
                    raise FilterError(config_error)
                job_id = filter_store.start(state, targets, session['user'], 'forward-zones' if action == 'apply_forwarders' else 'hosts')
                log_event(session['user'], 'filters_apply_started', details=f'job={job_id}')
                flash('Generación y distribución iniciadas. El resultado se muestra debajo.', 'info')
                return redirect(url_for('filters'))
            if action != 'save':
                raise FilterError('Acción inválida.')
            filter_store.save(state)
            log_event(session['user'], 'filters_lists_saved')
            flash('Listas guardadas. Todavía no se aplicaron a los recursivos.', 'success')
            return redirect(url_for('filters'))
        job = filter_store.latest_job()
    except (FilterError, OSError, ValueError) as error:
        flash(f'Filtros: {error}', 'danger')
    return render_template('dashboard.html', filter_view=True, current_server='internal',
                           filter_state=state or {'steven_enabled': False, 'blacklist': '', 'whitelist': ''},
                           filter_targets=targets, filter_config_error=config_error, filter_job=job)


@app.route('/filters/status/<job_id>')
@admin_required
def filters_status(job_id):
    try:
        return jsonify(filter_store.job(job_id))
    except (FilterError, OSError, ValueError):
        return jsonify(error='La operación no está disponible.'), 404


# --- INICIO DE LA APLICACIÓN CON HTTPS ---
if __name__ == '__main__':
    # Rutas a los archivos del certificado
    cert_file = 'cert.pem'
    key_file = 'privkey.pem'

    # Verificar si existen los archivos antes de iniciar
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("ERROR: No se encuentran los archivos cert.pem y privkey.pem.")
        print("Por favor, genera el certificado con el comando OpenSSL indicado.")
    else:
        print("Iniciando servidor HTTPS en https://0.0.0.0:5000")
        # ssl_context acepta una tupla (certificado, llave)
        app.run(host='0.0.0.0', port=5002, debug=False, ssl_context=(cert_file, key_file))
