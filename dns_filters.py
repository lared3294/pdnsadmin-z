"""Hosts-list editing and RPZ deployment to recursive servers only."""
from dataclasses import dataclass
import fcntl
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import uuid

import requests

STEVEN_URL = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-porn/hosts'
ORIGIN = 'pdnsadmin.rpz.'
MAX_EDIT_BYTES = 1024 * 1024
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024
DEFAULT_STATE = {'steven_enabled': False, 'blacklist': '', 'whitelist': ''}


class FilterError(ValueError):
    pass


def parse_hosts(text, source=False):
    domains = set()
    ignored = {'localhost', 'localhost.localdomain', 'broadcasthost', 'ip6-localhost', 'ip6-loopback'}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.replace('\\.', '.').rstrip().rstrip('\\').split('#', 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        try:
            address = ipaddress.ip_address(parts[0])
        except ValueError:
            address = None
        if address is not None:
            if address not in (ipaddress.ip_address('0.0.0.0'), ipaddress.ip_address('127.0.0.1'), ipaddress.ip_address('::1')):
                if source:
                    continue
                raise FilterError(f'Línea {number}: usa 0.0.0.0 seguido del dominio.')
            parts = parts[1:]
        elif len(parts) != 1:
            raise FilterError(f'Línea {number}: formato hosts o un dominio por línea.')
        if not parts:
            if source:
                continue
            raise FilterError(f'Línea {number}: falta el dominio.')
        for name in parts:
            name = name.rstrip('.').lower()
            if source and (name in ignored or '.' not in name):
                continue
            try:
                name = name.encode('idna').decode('ascii')
                ipaddress.ip_address(name)
            except UnicodeError:
                raise FilterError(f'Línea {number}: dominio inválido.') from None
            except ValueError:
                pass
            else:
                if source:
                    continue
                raise FilterError(f'Línea {number}: se esperaba un dominio, no una IP.')
            labels = name.split('.')
            if (len(labels) < 2 or len(name + '.' + ORIGIN.rstrip('.')) > 253
                    or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', label) for label in labels)):
                raise FilterError(f'Línea {number}: dominio inválido o demasiado largo.')
            domains.add(name)
    return domains


def validate_state(state):
    cleaned = {'steven_enabled': bool(state.get('steven_enabled'))}
    for key in ('blacklist', 'whitelist'):
        text = state.get(key, '')
        if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_EDIT_BYTES:
            raise FilterError('Cada lista admite hasta 1 MiB de texto.')
        parse_hosts(text)
        cleaned[key] = text
    return cleaned


def generate_policy(state, steven_text=''):
    black = parse_hosts(state['blacklist'])
    white = parse_hosts(state['whitelist'])
    upstream = parse_hosts(steven_text, source=True) if state['steven_enabled'] else set()
    if state['steven_enabled'] and not upstream:
        raise FilterError('StevenBlacklist no devolvió dominios válidos; no se despliega.')
    combined = upstream | black
    final = sorted(combined - white)
    serial = int(time.time())
    header = f'$ORIGIN {ORIGIN}\n$TTL 60\n@ IN SOA localhost. hostmaster.localhost. {serial} 60 60 604800 60\n@ IN NS localhost.\n'
    rpz = header + ''.join(f'{domain} CNAME .\n' for domain in final)
    hosts = ''.join(f'0.0.0.0 {domain}\n' for domain in final)
    stats = {'steven': len(upstream), 'blacklist': len(black), 'whitelist': len(white),
             'excluded': len(combined & white), 'total': len(final)}
    return rpz, hosts, stats


def download_steven():
    chunks, size = [], 0
    started = time.monotonic()
    with requests.get(STEVEN_URL, stream=True, timeout=(5, 20), allow_redirects=False) as response:
        if response.status_code != 200:
            raise FilterError(f'No se pudo descargar StevenBlacklist (HTTP {response.status_code}).')
        for chunk in response.iter_content(65536):
            size += len(chunk)
            if size > MAX_DOWNLOAD_BYTES or time.monotonic() - started > 90:
                raise FilterError('La descarga de StevenBlacklist excedió el límite de tamaño o tiempo.')
            chunks.append(chunk)
    return b''.join(chunks).decode('utf-8-sig')


@dataclass(frozen=True)
class Target:
    name: str
    host: str
    user: str
    port: int
    identity_file: str
    known_hosts_file: str

    def ssh_command(self, operation):
        return ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15',
                '-o', 'ServerAliveCountMax=2', '-o', 'IdentitiesOnly=yes',
                '-o', 'LogLevel=ERROR', '-o', 'UserKnownHostsFile=' + self.known_hosts_file,
                '-i', self.identity_file, '-p', str(self.port), '-l', self.user,
                '--', self.host, 'sudo -n /usr/local/sbin/pdnsadmin-rpz ' + operation]


def read_targets(cfg):
    names = [name.strip() for name in cfg.get('filters', 'targets', fallback='').split(',') if name.strip()]
    if len(names) != 4 or len(set(names)) != 4:
        raise FilterError('Configura exactamente cuatro destinos distintos en [filters] targets.')
    targets = []
    for name in names:
        if not re.fullmatch(r'[a-zA-Z0-9_-]+', name):
            raise FilterError('Nombre de destino inválido.')
        section = 'recursor:' + name
        host = cfg.get(section, 'host', fallback='').strip()
        user = cfg.get(section, 'user', fallback='').strip()
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.:-]*', host) or not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_-]*', user):
            raise FilterError(f'{name}: configura host y usuario SSH válidos.')
        try:
            port = cfg.getint(section, 'port', fallback=22)
        except ValueError:
            raise FilterError(f'{name}: puerto inválido.') from None
        if not 1 <= port <= 65535:
            raise FilterError(f'{name}: puerto inválido.')
        paths = [cfg.get(section, key, fallback='').strip() for key in ('identity_file', 'known_hosts_file')]
        if any(not value or not Path(value).is_absolute() for value in paths):
            raise FilterError(f'{name}: usa rutas absolutas para la clave SSH y known_hosts.')
        targets.append(Target(name, host, user, port, *paths))
    if len({(t.host, t.port) for t in targets}) != 4:
        raise FilterError('Los cuatro destinos deben identificar servidores distintos.')
    return targets


def ssh_operation(target, operation, payload=None):
    try:
        result = subprocess.run(target.ssh_command(operation), input=payload if payload is not None else '',
                                capture_output=True, text=True, timeout=150, check=False)
    except subprocess.TimeoutExpired:
        return False, 'Tiempo de espera agotado; el estado remoto es incierto. Verifica el servidor.'
    except OSError:
        return False, 'No se pudo ejecutar SSH. Comprueba openssh-client y los permisos.'
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-1500:]
        return False, detail or 'Falló la operación remota.'
    return True, result.stdout.strip()[-1500:] or 'Correcto.'


class FilterStore:
    def __init__(self, directory):
        self.directory = Path(directory)

    def _prepare(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.directory / 'jobs').mkdir(exist_ok=True, mode=0o700)

    def _write(self, path, value):
        self._prepare()
        temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False)
        os.replace(temp, path)

    def read(self):
        self._prepare()
        path = self.directory / 'lists.json'
        return json.loads(path.read_text()) if path.exists() else dict(DEFAULT_STATE)

    def _lock(self):
        self._prepare()
        fd = os.open(self.directory / 'apply.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise FilterError('Ya hay una aplicación de filtros en curso.') from None
        return fd

    def save(self, state):
        cleaned = validate_state(state)
        fd = self._lock()
        try:
            self._write(self.directory / 'lists.json', cleaned)
        finally:
            os.close(fd)

    def job(self, job_id):
        if not re.fullmatch(r'[a-f0-9]{32}', job_id):
            raise FilterError('Identificador inválido.')
        path = self.directory / 'jobs' / (job_id + '.json')
        if not path.exists():
            raise FilterError('La operación no existe.')
        data = json.loads(path.read_text())
        if data['status'] == 'running':
            try:
                fd = self._lock()
            except FilterError:
                pass
            else:
                os.close(fd)
                data.update(status='error', message='La aplicación se interrumpió. Verifica los servidores antes de reintentar.')
        return data

    def latest_job(self):
        path = self.directory / 'latest.json'
        return self.job(json.loads(path.read_text())['id']) if path.exists() else None

    def start(self, state, targets, user):
        cleaned = validate_state(state)
        fd = self._lock()
        job_id = uuid.uuid4().hex
        data = {'id': job_id, 'status': 'running', 'message': 'Generando la política…',
                'user': user, 'created': int(time.time()), 'results': [], 'stats': None}
        path = self.directory / 'jobs' / (job_id + '.json')
        try:
            self._write(self.directory / 'lists.json', cleaned)
            self._write(path, data)
            self._write(self.directory / 'latest.json', {'id': job_id})
            def worker():
                try:
                    self._apply(cleaned, targets, data, path)
                except Exception as error:
                    data.update(status='error', message=f'No se completó la operación: {str(error)[:500]}')
                    self._write(path, data)
                finally:
                    logging.getLogger('pdnsadmin').info('filters_complete user=%s job=%s status=%s', user, job_id, data['status'])
                    os.close(fd)
            threading.Thread(target=worker, name='pdnsadmin-filters', daemon=True).start()
        except Exception:
            os.close(fd)
            raise
        return job_id

    def _apply(self, state, targets, data, path):
        source = download_steven() if state['steven_enabled'] else ''
        rpz, hosts, stats = generate_policy(state, source)
        data['stats'] = stats
        for suffix, content in [('rpz', rpz), ('hosts', hosts)]:
            output = self.directory / 'jobs' / (data['id'] + '.' + suffix)
            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(content)
        data['message'] = 'Comprobando los cuatro recursivos…'
        self._write(path, data)
        # Check every server before modifying any of them.
        for target in targets:
            success, detail = ssh_operation(target, '--check')
            data['results'].append({'name': target.name, 'host': target.host,
                                    'status': 'ready' if success else 'error', 'detail': detail})
            self._write(path, data)
        if any(result['status'] == 'error' for result in data['results']):
            data.update(status='error', message='Falló la comprobación previa. Ninguna política fue enviada.')
            self._write(path, data)
            return
        payload = json.dumps({'rpz': rpz})
        for target, result in zip(targets, data['results']):
            data['message'] = f'Aplicando y reiniciando {target.name}…'
            result['status'] = 'applying'
            self._write(path, data)
            success, detail = ssh_operation(target, '--apply', payload)
            result.update(status='success' if success else 'error', detail=detail)
            self._write(path, data)
        success = all(result['status'] == 'success' for result in data['results'])
        data.update(status='success' if success else 'error',
                    message='Filtros aplicados y servicios reiniciados en los cuatro recursivos.' if success
                    else 'Aplicación incompleta. Revisa el resultado de cada servidor antes de reintentar.')
        self._write(path, data)
