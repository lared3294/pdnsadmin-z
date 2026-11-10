"""A stale page must retain its destination despite session navigation elsewhere."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


class ServerBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        ini = root / 'config.ini'
        ini.write_text(f'[flask]\nsecret_key=test\nsession_secure=False\nsession_file_dir={root}/sessions\n[oidc]\nenabled=False\n')
        with patch.dict(os.environ, DNSADMIN_CONFIG=str(ini)):
            spec = importlib.util.spec_from_file_location('server_binding_app', Path(__file__).resolve().parents[1] / 'pdnsadmin-z.py')
            cls.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.module)
        cls.module.logger.disabled = True

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.client = self.module.app.test_client()
        with self.client.session_transaction() as state:
            state.update(user='admin', role='admin', admin_mode='kamikaze',
                         pdns_server='internal', _csrf_token='csrf', pending_changes=[])
        self.form = dict(csrf_token='csrf', server='external', zone='example.org.',
                         name='www', type='A', ttl='300', content='192.0.2.1')

    def test_staging_and_commit_use_form_server_despite_changed_session(self):
        for route in ('/record/add', '/record/delete'):
            with self.subTest(route=route):
                with patch.object(self.module.requests, 'get', return_value=Mock(status_code=200, json=lambda: {'rrsets': []})) as get:
                    response = self.client.post(route, data=self.form)
                self.assertEqual(response.status_code, 302)
                self.assertIn('server=external', response.location)
                self.assertTrue(get.call_args.args[0].startswith(self.module.PDNS_API_URL_EXTERNAL))
                self.assertEqual(get.call_args.kwargs['headers']['X-API-Key'], self.module.PDNS_API_KEY_EXTERNAL)
                with self.client.session_transaction() as state:
                    self.assertEqual(state['pending_changes'][0]['server'], 'external')
                with patch.object(self.module.requests, 'patch', return_value=Mock(status_code=204)) as send:
                    self.client.post('/commit', data={'csrf_token': 'csrf'})
                self.assertTrue(send.call_args.args[0].startswith(self.module.PDNS_API_URL_EXTERNAL))

    def test_mutations_reject_missing_or_invalid_server_before_api_calls(self):
        for route in ('/record/add', '/record/delete', '/zone/add', '/zone/delete/example.org.'):
            for server in (None, '', 'other'):
                with self.subTest(route=route, server=server):
                    form = dict(self.form)
                    form.pop('server')
                    if server is not None:
                        form['server'] = server
                    with patch.object(self.module.requests, 'get') as get, patch.object(self.module.requests, 'post') as post, patch.object(self.module.requests, 'delete') as delete:
                        self.assertEqual(self.client.post(route, data=form).status_code, 400)
                        get.assert_not_called(); post.assert_not_called(); delete.assert_not_called()

    def test_zone_mutations_use_explicit_server(self):
        with patch.object(self.module.requests, 'post', return_value=Mock(status_code=201)) as post:
            self.client.post('/zone/add', data=dict(csrf_token='csrf', server='external', name='example.org.'))
        self.assertEqual(post.call_args.args[0], self.module.PDNS_API_URL_EXTERNAL + '/zones')
        with patch.object(self.module.requests, 'delete', return_value=Mock(status_code=204)) as delete:
            self.client.post('/zone/delete/example.org.', data=dict(csrf_token='csrf', server='external', confirm_name='example.org'))
        self.assertEqual(delete.call_args.args[0], self.module.PDNS_API_URL_EXTERNAL + '/zones/example.org.')

    def test_commit_rejects_any_pending_without_valid_destination(self):
        for server in (None, 'other'):
            with self.subTest(server=server):
                with self.client.session_transaction() as state:
                    state['pending_changes'] = [dict(id='one', action='DELETE', server='external', zone='example.org.', name='www.example.org.', type='A'), dict(server=server)]
                with patch.object(self.module.requests, 'patch') as send:
                    response = self.client.post('/commit', data={'csrf_token': 'csrf'})
                self.assertTrue(response.location.endswith('/review'))
                send.assert_not_called()

    def test_mixed_pending_commit_routes_each_group_to_its_saved_server(self):
        with self.client.session_transaction() as state:
            state['pending_changes'] = [dict(id=server, action='DELETE', server=server,
                zone='example.org.', name='www.example.org.', type='A')
                for server in ('internal', 'external')]
        with patch.object(self.module.requests, 'patch', return_value=Mock(status_code=204)) as send:
            self.client.post('/commit', data={'csrf_token': 'csrf', 'server': 'internal'})
        self.assertEqual([call.args[0] for call in send.call_args_list], [
            self.module.PDNS_API_URL_INTERNAL + '/zones/example.org.',
            self.module.PDNS_API_URL_EXTERNAL + '/zones/example.org.'])

    def test_zone_page_and_search_preserve_explicit_destination(self):
        zone = {'name': 'example.org.', 'rrsets': []}
        with patch.object(self.module.requests, 'get', return_value=Mock(status_code=200, json=lambda: zone)) as get:
            response = self.client.get('/zone/example.org.?server=external')
        self.assertEqual(response.status_code, 200)
        self.assertIn('name="server" value="external"', response.text)
        self.assertIn('pdnsadmin-single-tab', response.text)
        self.assertTrue(get.call_args.args[0].startswith(self.module.PDNS_API_URL_EXTERNAL))
        with patch.object(self.module.requests, 'get', return_value=Mock(status_code=200, json=lambda: [])) as get:
            self.client.get('/search?q=www&server=external')
        self.assertTrue(get.call_args.args[0].startswith(self.module.PDNS_API_URL_EXTERNAL))
