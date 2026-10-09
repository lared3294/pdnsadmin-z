import configparser
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recursor_config import FilterStore


class FilterRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        ini = root / 'config.ini'
        ini.write_text(f'[flask]\nsecret_key=test-only\nsession_secure=False\nsession_file_dir={root}/sessions\n[oidc]\nenabled=False\n')
        with patch.dict(os.environ, {'DNSADMIN_CONFIG': str(ini)}):
            spec = importlib.util.spec_from_file_location('filter_route_app', Path(__file__).resolve().parents[1] / 'pdnsadmin-z.py')
            cls.module = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.module)
        cls.module.logger.disabled = True

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def setUp(self):
        self.temp_case = tempfile.TemporaryDirectory(); self.addCleanup(self.temp_case.cleanup)
        self.module.filter_store = FilterStore(self.temp_case.name)
        self.module.cfg = configparser.ConfigParser()
        self.client = self.module.app.test_client()

    def login(self, role='admin'):
        with self.client.session_transaction() as state:
            state.update(user='test-user', role=role, pdns_server='external', _csrf_token='test-token')

    def test_login_required(self):
        self.assertEqual(self.client.get('/filters').status_code, 302)

    def test_filters_never_fetch_authoritative_api(self):
        self.login()
        with patch.object(self.module.requests, 'get', side_effect=AssertionError('must not contact PDNS')):
            response = self.client.get('/filters')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Configuración de recursivos', response.get_data(as_text=True))
        with self.client.session_transaction() as state: self.assertEqual(state['pdns_server'], 'internal')

    def test_consultation_user_cannot_save(self):
        self.login('consulta')
        response = self.client.post('/filters', data=dict(csrf_token='test-token', action='save', blacklist='example.com'))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.module.filter_store.read()['blacklist'], '')

    def test_csrf_required(self):
        self.login()
        self.client.post('/filters', data=dict(action='save', blacklist='example.com'))
        self.assertEqual(self.module.filter_store.read()['blacklist'], '')

    def test_save_and_invalid_input(self):
        self.login()
        response = self.client.post('/filters', data=dict(csrf_token='test-token', action='save', blacklist='0.0.0.0 example.com', whitelist='azurefd.net'))
        self.assertEqual(response.status_code, 302)
        response = self.client.post('/filters', data=dict(csrf_token='test-token', action='save', blacklist='bad domain'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.module.filter_store.read()['blacklist'], '0.0.0.0 example.com')

    def test_apply_requires_four_configured_targets(self):
        self.login()
        with patch.object(self.module.filter_store, 'start') as start:
            response = self.client.post('/filters', data=dict(csrf_token='test-token', action='apply', blacklist='example.com'))
            start.assert_not_called()
        self.assertEqual(response.status_code, 200)

    def test_forwarder_apply_selects_forward_zones(self):
        self.login()
        self.module.cfg.read_string('[filters]\ntargets=recursor1,recursor2,recursor3,recursor4\n')
        for i in range(1, 5): self.module.cfg[f'recursor:recursor{i}'] = {'host': f'192.0.2.{i}'}
        with patch.object(self.module.filter_store, 'start', return_value='a'*32) as start:
            response = self.client.post('/filters', data=dict(csrf_token='test-token', action='apply_forwarders', forwarders='example.org=192.0.2.1'))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(start.call_args.args[-1], 'forward-zones')

    def test_invalid_forwarder_cannot_be_saved(self):
        self.login()
        response = self.client.post('/filters', data=dict(csrf_token='test-token', action='save', forwarders='example.org=192.0.2.1;reboot'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.module.filter_store.read()['forwarders'], '')

    def test_unknown_job_returns_404(self):
        self.login()
        self.assertEqual(self.client.get('/filters/status/not-valid').status_code, 404)

    def test_job_status_is_not_available_to_consultation_user(self):
        self.login('consulta')
        self.assertEqual(self.client.get('/filters/status/' + 'a' * 32).status_code, 302)


if __name__ == '__main__': unittest.main()
