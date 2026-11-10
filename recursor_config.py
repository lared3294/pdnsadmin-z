"""Hosts and forward-zones editing and deployment to recursive servers."""
from dataclasses import dataclass, asdict
import fcntl
import configparser
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

import requests

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


def download_steven(url):
    if not url.strip():
        raise FilterError('Configura [recursor] steven_url antes de activar StevenBlacklist.')
    chunks, size = [], 0
    started = time.monotonic()
    with requests.get(url, stream=True, timeout=(5, 20), allow_redirects=False) as response:
        if response.status_code != 200:
            raise FilterError(f'No se pudo descargar StevenBlacklist (HTTP {response.status_code}).')
        for chunk in response.iter_content(65536):
            size += len(chunk)
            if size > MAX_DOWNLOAD_BYTES or time.monotonic() - started > 90:
                raise FilterError('La descarga de StevenBlacklist excedió el límite de tamaño o tiempo.')
            chunks.append(chunk)
    return b''.join(chunks).decode('utf-8-sig')


DEPLOY_SCRIPT = '/usr/local/sbin/pdnsadmin-update-recursors'
JOB_LAUNCHER = '/usr/local/sbin/pdnsadmin-start-recursor-job'
STARTUP_GRACE = 30
MAX_RETAINED_JOBS = 20
JOB_RETENTION_SECONDS = 15 * 24 * 60 * 60


@dataclass(frozen=True)
class Target:
    name: str
    host: str


def read_targets(cfg):
    names = [name.strip() for name in cfg.get('recursor', 'targets', fallback='').split(',') if name.strip()]
    if len(names) != 4 or len(set(names)) != 4:
        raise FilterError('Configura exactamente cuatro destinos distintos en [recursor] targets.')
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
                                capture_output=True, text=True, timeout=300, check=False)
    except subprocess.TimeoutExpired:
        return False, 'Tiempo de espera agotado; el estado remoto es incierto. Verifica el servidor.'
    except OSError:
        return False, 'No se pudo ejecutar el script del sistema. Comprueba su instalación y permisos.'
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-1500:]
        return False, detail or 'Falló la distribución.'
    return True, result.stdout.strip()[-1500:] or 'Correcto.'


class FilterStore:
    def __init__(self, directory, steven_url=''):
        self.directory = Path(directory)
        self.steven_url = steven_url

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

    def cleanup(self):
        """Opportunistic retention; never compete with a running deployment."""
        try:
            fd = self._lock()
        except FilterError:
            return
        try:
            self._prune_safely_locked()
        finally:
            os.close(fd)

    def _prune_safely_locked(self, active_job_id=None):
        try:
            self._prune_locked(active_job_id=active_job_id)
        except OSError:
            # Maintenance must not turn a completed deployment into a failure or
            # prevent the panel from displaying the last result.
            logging.getLogger('pdnsadmin').warning('No se pudo completar la limpieza del historial.', exc_info=True)

    def _prune_locked(self, active_job_id=None):
        """Caller owns apply.lock. Retain at most 20 jobs, for at most 15 days."""
        now = time.time()
        jobs_dir = self.directory / 'jobs'
        groups = {}
        pattern = re.compile(r'([a-f0-9]{32})\.(?:json|request\.json|log|hosts|forward-zones|'
                             r'(?:json|request\.json)\.[a-f0-9]{32}\.tmp)$')
        for entry in jobs_dir.iterdir():
            match = pattern.fullmatch(entry.name)
            if match and not entry.is_dir():
                groups.setdefault(match[1], []).append(entry)
        latest_path = self.directory / 'latest.json'
        try:
            latest_id = json.loads(latest_path.read_text())['id']
        except (OSError, ValueError, KeyError, TypeError):
            latest_id = None
        records, protected = [], set()
        for job_id, files in groups.items():
            path = jobs_dir / (job_id + '.json')
            try:
                # Never follow a symlink while inspecting a job's metadata.
                data = {} if path.is_symlink() else json.loads(path.read_text())
                if not isinstance(data, dict):
                    data = {}
            except (OSError, ValueError):
                data = {}
            created = data.get('created')
            if not isinstance(created, (int, float)) or not math.isfinite(created):
                created = min(file.lstat().st_mtime for file in files)
            created = min(created, now)
            if job_id == active_job_id:
                protected.add(job_id)
            elif data.get('status') == 'running':
                if job_id == latest_id and not data.get('runner_started') and now < data.get('startup_deadline', 0):
                    protected.add(job_id)
                else:
                    data['id'] = job_id
                    self._interrupted(data, path)
            records.append((created, job_id, data, files))
        records.sort(key=lambda record: (record[0], record[1] == latest_id, record[1]), reverse=True)
        eligible = [record for record in records
                    if record[1] not in protected and record[0] > now - JOB_RETENTION_SECONDS]
        keep = protected | {record[1] for record in eligible[:max(0, MAX_RETAINED_JOBS - len(protected))]}
        # Update the pointer before removing its old target, including an expired latest result.
        valid_ids = {record[1] for record in records
                     if record[2].get('status') in ('running', 'success', 'error')}
        if latest_id not in keep or latest_id not in valid_ids:
            newest = next((record[1] for record in records if record[1] in keep
                           and record[2].get('status') in ('running', 'success', 'error')), None)
            if newest is None:
                latest_path.unlink(missing_ok=True)
            else:
                self._write(latest_path, {'id': newest})
        for _, job_id, _, files in records:
            if job_id not in keep:
                # Exact recognized basenames only; no recursive deletion or shared state removal.
                for file in sorted(files, key=lambda file: file.name == job_id + '.json'):
                    file.unlink(missing_ok=True)

    def _check_starting(self):
        """Caller owns apply.lock; reserve the gap before the executor acquires it."""
        latest = self.directory / 'latest.json'
        if latest.exists():
            job_id = json.loads(latest.read_text())['id']
            data = self._read_job(job_id)
            if data['status'] == 'running':
                if not data.get('runner_started') and time.time() < data.get('startup_deadline', 0):
                    raise FilterError('Ya hay un despliegue iniciándose.')
                self._interrupted(data, self.directory / 'jobs' / (job_id + '.json'))

    def _interrupted(self, data, path):
        detail = 'El ejecutor se interrumpió o no pudo iniciarse. Verifica los servidores antes de reintentar.'
        log = self.directory / 'jobs' / (data['id'] + '.log')
        if not data.get('runner_started') and log.exists():
            with log.open('rb') as stream:
                stream.seek(0, 2)
                stream.seek(max(0, stream.tell() - 1500))
                output = stream.read().decode('utf-8', errors='replace').strip()
            if output:
                detail += ' ' + output
        for result in data.get('results', []):
            if result['status'] == 'applying':
                result.update(status='error', detail='Estado remoto incierto; verifica este servidor.')
        data.update(status='error', message=detail)
        self._write(path, data)

    def _read_job(self, job_id):
        if not isinstance(job_id, str) or not re.fullmatch(r'[a-f0-9]{32}', job_id):
            raise FilterError('Identificador inválido.')
        path = self.directory / 'jobs' / (job_id + '.json')
        if not path.exists():
            raise FilterError('La operación no existe.')
        data = json.loads(path.read_text())
        data['id'] = job_id
        return data

    def save(self, state):
        cleaned = validate_state(state)
        fd = self._lock()
        try:
            self._check_starting()
            self._write(self.directory / 'lists.json', cleaned)
            self._prune_safely_locked()
        finally:
            os.close(fd)

    def job(self, job_id):
        data = self._read_job(job_id)
        path = self.directory / 'jobs' / (job_id + '.json')
        if data['status'] == 'running':
            try:
                fd = self._lock()
            except FilterError:
                pass
            else:
                try:
                    data = self._read_job(job_id)
                    if data['status'] == 'running':
                        if data.get('runner_started') or time.time() >= data.get('startup_deadline', 0):
                            self._interrupted(data, path)
                finally:
                    os.close(fd)
        return data

    def latest_job(self):
        self.cleanup()
        path = self.directory / 'latest.json'
        return self.job(json.loads(path.read_text())['id']) if path.exists() else None

    def start(self, state, targets, user, kind='hosts'):
        if kind not in ('hosts', 'forward-zones'):
            raise FilterError('Tipo de archivo inválido.')
        cleaned = validate_state(state)
        fd = self._lock()
        job_id = uuid.uuid4().hex
        data = {'id': job_id, 'status': 'running', 'message': 'Iniciando el ejecutor…', 'kind': kind,
                'user': user, 'created': int(time.time()), 'results': [], 'stats': None,
                'runner_started': False, 'startup_deadline': time.time() + STARTUP_GRACE}
        path = self.directory / 'jobs' / (job_id + '.json')
        try:
            self._check_starting()
            self._write(self.directory / 'lists.json', cleaned)
            self._write(self.directory / 'jobs' / (job_id + '.request.json'), {
                'state': cleaned, 'targets': [asdict(target) for target in targets],
                'steven_url': self.steven_url})
            self._write(path, data)
            self._write(self.directory / 'latest.json', {'id': job_id})
            self._prune_safely_locked(active_job_id=job_id)
            try:
                log_fd = os.open(self.directory / 'jobs' / (job_id + '.log'),
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(log_fd, 'wb') as log:
                    process = subprocess.Popen(['/usr/bin/sudo', '-n', JOB_LAUNCHER, job_id, str(self.directory.resolve())],
                                               stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                               start_new_session=True, close_fds=True)
                if process.poll() not in (None, 0):
                    raise OSError('El lanzador rechazó el trabajo; revisa su log y el permiso sudo.')
            except OSError as error:
                data.update(status='error', message=f'No se pudo iniciar el ejecutor: {error}')
                self._write(path, data)
                raise FilterError(data['message']) from error
        finally:
            os.close(fd)
        return job_id

    def run_job(self, job_id):
        """One-shot executor entry point; never resume an interrupted job."""
        self._read_job(job_id)  # Validate the identifier before constructing paths.
        deadline = time.monotonic() + STARTUP_GRACE
        while True:
            try:
                fd = self._lock()
                break
            except FilterError:
                if time.monotonic() >= deadline:
                    raise FilterError('No se pudo obtener el bloqueo del despliegue.') from None
                time.sleep(0.05)
        path = self.directory / 'jobs' / (job_id + '.json')
        data = None
        try:
            data = self._read_job(job_id)
            if (data['status'] != 'running' or data.get('runner_started')
                    or time.time() >= data.get('startup_deadline', 0)):
                raise FilterError('El trabajo ya terminó, se interrumpió o expiró; no se reejecuta.')
            if data.get('kind') not in ('hosts', 'forward-zones'):
                raise FilterError('Tipo de despliegue inválido.')
            data.update(runner_started=True, message='Generando el archivo…')
            self._write(path, data)
            try:
                snapshot = json.loads((self.directory / 'jobs' / (job_id + '.request.json')).read_text())
                state = validate_state(snapshot['state'])
                target_cfg = configparser.ConfigParser()
                target_cfg['recursor'] = {'targets': ','.join(target['name'] for target in snapshot['targets'])}
                for target in snapshot['targets']:
                    target_cfg['recursor:' + target['name']] = {'host': target['host']}
                targets = read_targets(target_cfg)
                self.steven_url = snapshot['steven_url']
                self._apply(state, targets, data, path)
            except Exception as error:
                data.update(status='error', message=f'No se completó la operación: {str(error)[:500]}')
                self._write(path, data)
            logging.getLogger('pdnsadmin').info('filters_complete user=%s job=%s status=%s',
                                               data['user'], job_id, data['status'])
            self._prune_safely_locked(active_job_id=job_id)
            return data['status'] == 'success'
        finally:
            os.close(fd)

    def _apply(self, state, targets, data, path):
        kind = data.get('kind', 'hosts')
        if kind == 'forward-zones':
            content = parse_forwarders(state.get('forwarders', ''))
            data['stats'] = {'zones': len(content.splitlines())}
        else:
            source = download_steven(self.steven_url) if state['steven_enabled'] else ''
            content, data['stats'] = generate_policy(state, source)
        output = self.directory / 'jobs' / (data['id'] + '.' + kind)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
        for index, target in enumerate(targets):
            result = {'name': target.name, 'host': target.host, 'status': 'applying', 'detail': ''}
            data['results'].append(result)
            data['message'] = f'Aplicando y reiniciando {target.name}…'
            result['status'] = 'applying'
            self._write(path, data)
            success, detail = deploy_operation(target, content, kind)
            result.update(status='success' if success else 'error', detail=detail)
            self._write(path, data)
            if not success:
                for skipped in targets[index + 1:]:
                    data['results'].append({'name': skipped.name, 'host': skipped.host,
                                            'status': 'skipped',
                                            'detail': 'No modificado: distribución detenida tras el primer error.'})
                break
        success = all(result['status'] == 'success' for result in data['results'])
        data.update(status='success' if success else 'error',
                    message=f'{kind} aplicado y servicios reiniciados en los cuatro recursivos.' if success
                    else 'Distribución detenida tras un error. Los destinos restantes no se modificaron. Revisa el servidor afectado antes de reintentar.')
        self._write(path, data)
