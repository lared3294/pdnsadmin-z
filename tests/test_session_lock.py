"""Concurrency regression tests using real flock and server-side sessions."""
import importlib.util
import hashlib
import multiprocessing
import os
from pathlib import Path
import secrets
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from session_lock import SessionLockMiddleware, SessionLockTimeout


def hold_process_lock(directory, sid, ready):
    middleware = SessionLockMiddleware(None, directory, timeout=2)
    with middleware.acquire(sid):
        ready.send('locked')
        ready.close()
        time.sleep(30)


class SessionLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        ini = root / 'config.ini'
        ini.write_text(f'[flask]\nsecret_key=test\nsession_secure=False\nsession_file_dir={root}/sessions\nsession_lock_timeout=1\n[oidc]\nenabled=False\n')
        with patch.dict(os.environ, DNSADMIN_CONFIG=str(ini)):
            spec = importlib.util.spec_from_file_location('locked_session_app', Path(__file__).resolve().parents[1] / 'pdnsadmin-z.py')
            cls.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.module)
        cls.module.logger.disabled = True
        cls.module.app.config['TESTING'] = True

        @cls.module.app.route('/test/exception')
        def raise_error():
            raise RuntimeError('test failure')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.client = self.module.app.test_client()
        with self.client.session_transaction() as state:
            state.update(user='admin', role='admin', _csrf_token='csrf', pending_changes=[
                dict(id='one', action='DELETE', server='external', zone='example.org.',
                     name='www.example.org.', type='A', readable_records='192.0.2.1')])
        self.sid = self.client.get_cookie('session').value
        self.middleware = self.module.app.wsgi_app

    def another_client(self):
        client = self.module.app.test_client()
        client.set_cookie('session', self.sid)
        return client

    def test_concurrent_review_waits_until_commit_saves_and_does_not_resurrect_pending(self):
        entered = threading.Event()
        release = threading.Event()
        reader_started = threading.Event()
        reader_loaded = threading.Event()
        results, errors = {}, []
        def send(*args, **kwargs):
            entered.set()
            if not release.wait(3):
                raise RuntimeError('test timed out')
            return Mock(status_code=204)
        original_open = self.module.app.session_interface.open_session
        def open_session(*args, **kwargs):
            if threading.current_thread().name == 'review-reader':
                reader_loaded.set()
            return original_open(*args, **kwargs)
        def commit():
            try:
                results['commit'] = self.client.post('/commit', data={'csrf_token': 'csrf'})
            except Exception as error:
                errors.append(error)
        def read():
            try:
                reader_started.set()
                results['review'] = self.another_client().get('/review')
            except Exception as error:
                errors.append(error)
        with patch.object(self.module.requests, 'patch', side_effect=send), patch.object(self.module.app.session_interface, 'open_session', side_effect=open_session):
            writer = threading.Thread(target=commit)
            reader = threading.Thread(target=read, name='review-reader')
            writer.start()
            try:
                self.assertTrue(entered.wait(2))
                reader.start()
                self.assertTrue(reader_started.wait(1))
                self.assertFalse(reader_loaded.wait(.1), 'Reader must not load the stale session')
            finally:
                release.set()
                writer.join(3)
                if reader.ident is not None:
                    reader.join(3)
            self.assertFalse(writer.is_alive())
            self.assertFalse(reader.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results['commit'].status_code, 302)
        self.assertEqual(results['review'].status_code, 200)
        self.assertIn('No hay cambios pendientes', results['review'].text)
        self.assertEqual(self.module.app.session_interface.cache.get(self.sid)['pending_changes'], [])

    def test_timeout_rejects_before_reading_session_or_executing_mutation(self):
        with patch.object(self.middleware, 'timeout', .05):
            with self.middleware.acquire(self.sid), patch.object(self.module.requests, 'patch') as send, patch.object(self.module.app.session_interface, 'open_session') as open_session:
                response = self.client.post('/commit', data={'csrf_token': 'csrf'})
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.headers['Retry-After'], '1')
                self.assertNotIn('Set-Cookie', response.headers)
                send.assert_not_called()
                open_session.assert_not_called()
        self.assertEqual(len(self.module.app.session_interface.cache.get(self.sid)['pending_changes']), 1)
        self.assertEqual(self.client.get('/review').status_code, 200)

    def test_distinct_sessions_can_run_concurrently(self):
        other = self.module.app.test_client()
        bucket = hashlib.sha256(self.sid.encode('ascii')).hexdigest()[:3]
        other_sid = secrets.token_urlsafe(32)
        while hashlib.sha256(other_sid.encode('ascii')).hexdigest()[:3] == bucket:
            other_sid = secrets.token_urlsafe(32)
        other.set_cookie('session', other_sid)
        with self.middleware.acquire(self.sid):
            self.assertEqual(other.get('/login').status_code, 200)

    def test_exception_releases_lock(self):
        with self.assertRaisesRegex(RuntimeError, 'test failure'):
            self.client.get('/test/exception')
        with self.middleware.acquire(self.sid):
            pass

    def test_cache_save_failure_releases_lock(self):
        with patch.object(self.module.app.session_interface.cache, 'set', side_effect=OSError('disk error')):
            with self.assertRaisesRegex(OSError, 'disk error'):
                self.client.get('/review')
        with self.middleware.acquire(self.sid):
            pass

    def test_invalid_cookie_is_replaced_with_new_safe_identifier(self):
        self.client.set_cookie('session', '../../invalid')
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        sid = self.client.get_cookie('session').value
        self.assertRegex(sid, r'^[A-Za-z0-9_-]{43}$')

    def test_lock_is_shared_between_processes_and_released_on_worker_death(self):
        context = multiprocessing.get_context('spawn')
        ready, child_ready = context.Pipe(duplex=False)
        process = context.Process(target=hold_process_lock,
                                  args=(str(self.middleware.directory), self.sid, child_ready))
        process.start()
        try:
            self.assertTrue(ready.poll(3))
            self.assertEqual(ready.recv(), 'locked')
            with patch.object(self.middleware, 'timeout', .05), self.assertRaises(SessionLockTimeout):
                with self.middleware.acquire(self.sid):
                    pass
            process.terminate()
            process.join(3)
            self.assertFalse(process.is_alive())
            with self.middleware.acquire(self.sid):
                pass
        finally:
            ready.close()
            child_ready.close()
            if process.is_alive():
                process.terminate()
            process.join(3)

    def test_lock_file_is_stable_after_release(self):
        with tempfile.TemporaryDirectory() as directory:
            middleware = SessionLockMiddleware(None, directory)
            sid = secrets.token_urlsafe(32)
            with middleware.acquire(sid):
                lock = next(Path(directory).glob('*.lock'))
                inode = lock.stat().st_ino
            with middleware.acquire(sid):
                self.assertEqual(lock.stat().st_ino, inode)
                self.assertEqual(lock.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
