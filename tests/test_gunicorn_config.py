"""TLS startup checks without contacting PowerDNS or the identity provider."""
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

CONFIG = Path(__file__).resolve().parents[1] / 'gunicorn.conf.py'


class GunicornConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        for stem in ['server', 'other']:
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(cls.root / (stem + '.key')),
                '-out', str(cls.root / (stem + '.pem')),
                '-days', '1', '-subj', '/CN=localhost',
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def load(self, contents, **env):
        ini = self.root / 'config.ini'
        ini.write_text(contents)
        with patch.dict(os.environ, {'DNSADMIN_CONFIG': str(ini), **env}, clear=True):
            return runpy.run_path(str(CONFIG))

    def test_disabled_tls_ignores_unused_paths(self):
        settings = self.load('[tls]\nenabled=False\ncertfile=missing.pem\nkeyfile=missing.key\n')
        self.assertIsNone(settings['certfile'])
        self.assertIsNone(settings['keyfile'])

    def test_missing_tls_section_defaults_to_http(self):
        self.assertIsNone(self.load('[flask]\n')['certfile'])

    def test_relative_paths_use_ini_directory(self):
        settings = self.load('[tls]\nenabled=True\ncertfile=server.pem\nkeyfile=server.key\n')
        self.assertEqual(settings['certfile'], str(self.root / 'server.pem'))
        self.assertEqual(settings['keyfile'], str(self.root / 'server.key'))

    def test_absolute_paths(self):
        settings = self.load(f'[tls]\nenabled=True\ncertfile={self.root}/server.pem\nkeyfile={self.root}/server.key\n')
        self.assertEqual(settings['keyfile'], str(self.root / 'server.key'))

    def test_missing_key_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'falta.*keyfile'):
            self.load('[tls]\nenabled=True\ncertfile=server.pem\n')

    def test_missing_file_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'inexistente o ilegible'):
            self.load('[tls]\nenabled=True\ncertfile=missing.pem\nkeyfile=server.key\n')

    def test_mismatched_key_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'par incompatible'):
            self.load('[tls]\nenabled=True\ncertfile=server.pem\nkeyfile=other.key\n')

    def test_invalid_certificate_fails(self):
        (self.root / 'invalid.pem').write_text('not a certificate')
        with self.assertRaisesRegex(RuntimeError, 'certificado o clave inválidos'):
            self.load('[tls]\nenabled=True\ncertfile=invalid.pem\nkeyfile=server.key\n')

    def test_encrypted_key_fails_without_prompt(self):
        subprocess.run([
            'openssl', 'pkey', '-in', str(self.root / 'server.key'),
            '-aes-256-cbc', '-passout', 'pass:test-only',
            '-out', str(self.root / 'encrypted.key'),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self.assertRaisesRegex(RuntimeError, 'clave cifrada'):
            self.load('[tls]\nenabled=True\ncertfile=server.pem\nkeyfile=encrypted.key\n')

    def test_unreadable_certificate_fails(self):
        original_open = Path.open

        def open_with_denied_certificate(path, *args, **kwargs):
            if path.name == 'server.pem':
                raise PermissionError('test-only access denial')
            return original_open(path, *args, **kwargs)

        with patch.object(Path, 'open', open_with_denied_certificate):
            with self.assertRaisesRegex(RuntimeError, 'inexistente o ilegible'):
                self.load('[tls]\nenabled=True\ncertfile=server.pem\nkeyfile=server.key\n')

    def test_environment_fallback(self):
        settings = self.load('[flask]\n', PDNSADMIN_TLS_ENABLED='True',
                             PDNSADMIN_TLS_CERTFILE='server.pem',
                             PDNSADMIN_TLS_KEYFILE='server.key',
                             PDNSADMIN_BIND='127.0.0.1:8443', PDNSADMIN_WORKERS='2')
        self.assertIsNotNone(settings['certfile'])
        self.assertEqual(settings['bind'], '127.0.0.1:8443')
        self.assertEqual(settings['workers'], 2)

    def test_ini_overrides_environment_including_empty_values(self):
        settings = self.load('[tls]\nenabled=False\n', PDNSADMIN_TLS_ENABLED='True')
        self.assertIsNone(settings['certfile'])
        with self.assertRaisesRegex(RuntimeError, 'falta.*keyfile'):
            self.load('[tls]\nenabled=True\ncertfile=server.pem\nkeyfile=\n',
                      PDNSADMIN_TLS_KEYFILE='server.key')

    def test_invalid_boolean_and_workers_fail(self):
        for contents in ['[tls]\nenabled=maybe\n', '[server]\nworkers=zero\n', '[server]\nworkers=0\n']:
            with self.subTest(contents=contents), self.assertRaises(RuntimeError):
                self.load(contents)

    def test_explicit_missing_config_fails(self):
        with patch.dict(os.environ, {'DNSADMIN_CONFIG': str(self.root / 'missing.ini')}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'No se pudo leer'):
                runpy.run_path(str(CONFIG))


if __name__ == '__main__':
    unittest.main()
