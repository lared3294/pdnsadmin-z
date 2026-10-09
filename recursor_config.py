"""Hosts and forward-zones editing and deployment to recursive servers."""
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
MAX_EDIT_BYTES = 1024 * 1024
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024
DEFAULT_STATE = {'steven_enabled': False, 'blacklist': '', 'whitelist': '', 'forwarders': ''}


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
            if (len(labels) < 2 or len(name) > 253
                    or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', label) for label in labels)):
                raise FilterError(f'Línea {number}: dominio inválido o demasiado largo.')
            domains.add(name)
    return domains


def parse_forwarders(text):
    """Validate classic forward-zones-file and return normalized file content."""
    lines, seen = [], set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        try:
            zone, destinations = line.split('=', 1)
            zone = zone.strip()
            flags = ''
            while zone and zone[0] in '+^':
                if zone[0] in flags:
                    raise ValueError()
                flags += zone[0]
                zone = zone[1:]
            zone = zone.lower().rstrip('.') if zone != '.' else '.'
            if zone != '.':
                zone = zone.encode('idna').decode('ascii')
            if zone != '.' and (not zone or len(zone) > 253 or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', label) for label in zone.split('.'))):
                raise ValueError()
            if zone in seen:
                raise ValueError()
            servers = []
            for endpoint in re.split(r'[,;]', destinations):
                endpoint = endpoint.strip()
                port = None
                if endpoint.startswith('['):
                    match = re.fullmatch(r'\[([^]]+)\](?::([0-9]+))?', endpoint)
                    if not match:
                        raise ValueError()
                    address, port = match.groups()
                    ip = ipaddress.IPv6Address(address)
                else:
                    try:
                        ip = ipaddress.ip_address(endpoint)
                    except ValueError:
                        address, port = endpoint.rsplit(':', 1)
                        ip = ipaddress.IPv4Address(address)
                if '%' in str(ip) or (port is not None and (not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535)):
                    raise ValueError()
                server = str(ip) if port is None else (f'[{ip}]:{int(port)}' if ip.version == 6 else f'{ip}:{int(port)}')
                servers.append(server)
            seen.add(zone)
            lines.append(flags + zone + '=' + ','.join(servers))
        except (ValueError, UnicodeError):
            raise FilterError(f'Forwarders, línea {number}: usa zona=IP[,IP:puerto], sin zonas duplicadas.') from None
    return ''.join(line + '\n' for line in lines)


def validate_state(state):
    cleaned = {'steven_enabled': bool(state.get('steven_enabled'))}
    for key in ('blacklist', 'whitelist', 'forwarders'):
        text = state.get(key, '')
        if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_EDIT_BYTES:
            raise FilterError('Cada lista admite hasta 1 MiB de texto.')
        (parse_forwarders if key == 'forwarders' else parse_hosts)(text)
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
    hosts = ''.join(f'0.0.0.0 {domain}\n' for domain in final)
    stats = {'steven': len(upstream), 'blacklist': len(black), 'whitelist': len(white),
             'excluded': len(combined & white), 'total': len(final)}
    return hosts, stats


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


DEPLOY_SCRIPT = '/usr/local/sbin/pdnsadmin-update-recursors'


@dataclass(frozen=True)
class Target:
    name: str
    host: str


def read_targets(cfg):
    names = [name.strip() for name in cfg.get('filters', 'targets', fallback='').split(',') if name.strip()]
    if len(names) != 4 or len(set(names)) != 4:
        raise FilterError('Configura exactamente cuatro destinos distintos en [filters] targets.')
    targets = []
    for name in names:
        if not re.fullmatch(r'[a-zA-Z0-9_-]+', name):
            raise FilterError('Nombre de destino inválido.')
        host = cfg.get('recursor:' + name, 'host', fallback='').strip()
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.:-]*', host):
            raise FilterError(f'{name}: configura el host para identificar el destino.')
        targets.append(Target(name, host))
    if len({t.host for t in targets}) != 4:
        raise FilterError('Los cuatro destinos deben identificar servidores distintos.')
    return targets


def deploy_operation(target, payload, kind='hosts'):
    if kind not in ('hosts', 'forward-zones'):
        raise FilterError('Tipo de archivo inválido.')
    # Host names and credentials are resolved by the root-owned system script.
    try:
        result = subprocess.run(['/usr/bin/sudo', '-n', DEPLOY_SCRIPT, target.name, kind],
                                input=payload,
                                capture_output=True, text=True, timeout=180, check=False)
    except subprocess.TimeoutExpired:
        return False, 'Tiempo de espera agotado; el estado remoto es incierto. Verifica el servidor.'
    except OSError:
        return False, 'No se pudo ejecutar el script del sistema. Comprueba su instalación y permisos.'
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-1500:]
        return False, detail or 'Falló la distribución.'
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
        return dict(DEFAULT_STATE, **json.loads(path.read_text())) if path.exists() else dict(DEFAULT_STATE)

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

    def start(self, state, targets, user, kind='hosts'):
        if kind not in ('hosts', 'forward-zones'):
            raise FilterError('Tipo de archivo inválido.')
        cleaned = validate_state(state)
        fd = self._lock()
        job_id = uuid.uuid4().hex
        data = {'id': job_id, 'status': 'running', 'message': 'Generando el archivo…', 'kind': kind,
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
        kind = data.get('kind', 'hosts')
        if kind == 'forward-zones':
            content = parse_forwarders(state.get('forwarders', ''))
            data['stats'] = {'zones': len(content.splitlines())}
        else:
            source = download_steven() if state['steven_enabled'] else ''
            content, data['stats'] = generate_policy(state, source)
        output = self.directory / 'jobs' / (data['id'] + '.' + kind)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
        for target in targets:
            result = {'name': target.name, 'host': target.host, 'status': 'applying', 'detail': ''}
            data['results'].append(result)
            data['message'] = f'Aplicando y reiniciando {target.name}…'
            result['status'] = 'applying'
            self._write(path, data)
            success, detail = deploy_operation(target, content, kind)
            result.update(status='success' if success else 'error', detail=detail)
            self._write(path, data)
        success = all(result['status'] == 'success' for result in data['results'])
        data.update(status='success' if success else 'error',
                    message=f'{kind} aplicado y servicios reiniciados en los cuatro recursivos.' if success
                    else 'Aplicación incompleta. Revisa el resultado de cada servidor antes de reintentar.')
        self._write(path, data)
