"""Serialize session read/modify/save across Gunicorn processes on one host."""
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import time

from werkzeug.wrappers import Request, Response

SESSION_SID_ENV = 'pdnsadmin.session_sid'
SID_PATTERN = re.compile(r'[A-Za-z0-9_-]{43}')


class SessionLockTimeout(TimeoutError):
    pass


class SessionLockMiddleware:
    def __init__(self, application, directory, cookie_name='session', timeout=5):
        self.application = application
        self.directory = Path(directory)
        self.cookie_name = cookie_name
        self.timeout = float(timeout)
        if not 0 < self.timeout <= 60:
            raise ValueError('session_lock_timeout debe estar entre 0 y 60 segundos.')
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    @contextmanager
    def acquire(self, sid):
        # Bounded lock striping: never delete lock files (unlink breaks exclusion).
        # At most 4096 files, independently of anonymous traffic or expired sessions.
        bucket = hashlib.sha256(sid.encode('ascii')).hexdigest()[:3]
        fd = os.open(self.directory / (bucket + '.lock'),
                     os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SessionLockTimeout() from None
                    time.sleep(min(0.025, remaining))
            yield
        finally:
            # Closing also releases the lock on exceptions or worker termination.
            os.close(fd)

    def __call__(self, environ, start_response):
        sid = Request(environ).cookies.get(self.cookie_name, '')
        if not SID_PATTERN.fullmatch(sid):
            sid = secrets.token_urlsafe(32)
        environ[SESSION_SID_ENV] = sid
        # Acquisition precedes Flask's open_session; release follows save_session
        # and request teardown. Streaming response bodies must not modify sessions.
        try:
            with self.acquire(sid):
                return self.application(environ, start_response)
        except SessionLockTimeout:
            response = Response(
                'Hay otra petición de esta sesión en curso. Espera y vuelve a intentar. '
                'Esta petición no se ejecutó.', status=503, content_type='text/plain; charset=utf-8',
                headers={'Retry-After': '1', 'Cache-Control': 'no-store'})
            return response(environ, start_response)
