"""Screen context and mutation edge cases found during local browser QA."""
import unittest
from unittest.mock import Mock, patch
import test_server_binding as binding


class ActionEdgeTests(unittest.TestCase):
    setUpClass = classmethod(binding.ServerBindingTests.setUpClass.__func__)
    tearDownClass = classmethod(binding.ServerBindingTests.tearDownClass.__func__)
    setUp = binding.ServerBindingTests.setUp

    def pending(self):
        with self.client.session_transaction() as state:
            return state['pending_changes']

    def seed_ten(self):
        with self.client.session_transaction() as state:
            state['pending_changes'] = [dict(id=str(i), server='external', zone='example.org.',
                name=('www' if i == 0 else f'host{i}') + '.example.org.', type='A', action='DELETE', readable_records='')
                for i in range(10)]

    def post_record(self, **updates):
        form = dict(self.form, **updates)
        with patch.object(self.module.requests, 'get', return_value=Mock(status_code=200, json=lambda: {'rrsets': []})):
            return self.client.post('/record/add', data=form)

    def test_full_pending_list_allows_replacement_but_rejects_eleventh_record(self):
        self.seed_ten()
        self.post_record(content='192.0.2.42')
        self.assertEqual(len(self.pending()), 10)
        self.assertEqual(next(c for c in self.pending() if c['name']=='www.example.org.')['records'][0]['content'], '192.0.2.42')
        self.post_record(name='eleventh')
        self.assertEqual(len(self.pending()), 10)
        self.assertFalse(any(c['name']=='eleventh.example.org.' for c in self.pending()))
        with patch.object(self.module.requests, 'get', return_value=Mock(status_code=200, json=lambda: {'rrsets': []})):
            self.client.post('/record/delete', data=self.form)
        self.assertEqual(len(self.pending()), 10)
        self.assertEqual(next(c for c in self.pending() if c['name']=='www.example.org.')['action'], 'DELETE')

    def test_absolute_owner_outside_zone_cannot_be_silently_appended(self):
        for route in ('/record/add', '/record/delete'):
            with patch.object(self.module.requests, 'get') as get:
                self.client.post(route, data=dict(self.form, name='outside.net.'))
                get.assert_not_called()
            self.assertEqual(self.pending(), [])

    def test_zone_and_owner_case_are_canonicalized(self):
        self.post_record(zone='EXAMPLE.ORG', name='WWW.Example.ORG.')
        change = self.pending()[0]
        self.assertEqual((change['zone'], change['name']), ('example.org.', 'www.example.org.'))
        self.post_record(zone='example.org.', name='www')
        self.assertEqual(len(self.pending()), 1)

    def test_normalized_owner_cannot_exceed_dns_length(self):
        self.post_record(name='.'.join(['a'*60]*4))
        self.assertEqual(self.pending(), [])

    def test_disabled_states_are_preserved_per_value_including_empty_rows(self):
        self.post_record(**{'content[]':['192.0.2.1', '', '192.0.2.2'], 'disabled[]':['false','true','true']})
        records = self.pending()[0]['records']
        self.assertEqual(records, [dict(content='192.0.2.1', disabled=False),dict(content='192.0.2.2',disabled=True)])
        with patch.object(self.module.requests, 'patch', return_value=Mock(status_code=204)) as send:
            self.client.post('/commit', data={'csrf_token':'csrf'})
        self.assertEqual(send.call_args.kwargs['json']['rrsets'][0]['records'], records)

    def test_stale_or_misaligned_disabled_fields_are_rejected(self):
        for fields in ({'content[]':['192.0.2.1']},
                       {'content[]':['192.0.2.1','192.0.2.2'],'disabled[]':['true']},
                       {'content[]':['192.0.2.1'],'disabled[]':['invalid']}):
            self.post_record(**fields)
            self.assertEqual(self.pending(), [])

    def test_cname_requires_one_value(self):
        self.post_record(type='CNAME', **{'content[]':['a.example.org.','b.example.org.'], 'disabled[]':['false','false']})
        self.assertEqual(self.pending(), [])

    def test_mx_priority_and_srv_fields_and_target_are_validated(self):
        for rtype, content in [('MX','65536 mail.example.org.'), ('SRV','bad target'), ('SRV','1 2 65536 srv.example.org.')]:
            self.post_record(type=rtype, content=content)
            self.assertEqual(self.pending(), [])
        self.post_record(type='MX',content='0 .')
        self.assertEqual(self.pending()[0]['records'][0]['content'], '0 .')
        self.post_record(type='SRV',content='1 2 443 service')
        self.assertEqual(self.pending()[1]['records'][0]['content'], '1 2 443 service.example.org.')

    def test_create_form_does_not_replace_an_existing_rrset(self):
        rr = dict(name='www.example.org.',type='A',records=[dict(content='192.0.2.1',disabled=False)])
        with patch.object(self.module.requests, 'get',return_value=Mock(status_code=200,json=lambda:{'rrsets':[rr]})):
            response=self.client.post('/record/add',data=dict(self.form,operation='create'))
        self.assertEqual(response.status_code,302)
        self.assertEqual(self.pending(), [])
        with patch.object(self.module.requests, 'get',return_value=Mock(status_code=500)):
            self.client.post('/record/add',data=dict(self.form,operation='create'))
        self.assertEqual(self.pending(), [])

    def test_successful_zone_deletion_discards_only_its_own_pending(self):
        self.seed_ten()
        with self.client.session_transaction() as state:
            state['pending_changes'].append(dict(id='internal',server='internal',zone='example.org.',name='www.example.org.',type='A',action='DELETE'))
        with patch.object(self.module.requests,'delete',return_value=Mock(status_code=500,json=lambda:{'error':'failed'})):
            self.client.post('/zone/delete/example.org.',data=dict(csrf_token='csrf',server='external',confirm_name='example.org'))
        self.assertEqual(len(self.pending()),11)
        with patch.object(self.module.requests,'delete',return_value=Mock(status_code=204)):
            self.client.post('/zone/delete/example.org.',data=dict(csrf_token='csrf',server='external',confirm_name='example.org'))
        self.assertEqual([c['id'] for c in self.pending()],['internal'])

    def test_safe_mode_is_rechecked_when_applying_staged_soa(self):
        with self.client.session_transaction() as state:
            state['admin_mode']='seguro'
            state['pending_changes']=[dict(server='external',type='SOA')]
        with patch.object(self.module.requests,'patch') as send:
            response=self.client.post('/commit',data={'csrf_token':'csrf'})
        self.assertTrue(response.location.endswith('/review'))
        send.assert_not_called()

    def test_mode_switch_and_back_links_keep_explicit_server_context(self):
        response=self.client.post('/admin_mode',data=dict(csrf_token='csrf',server='external',mode='seguro'))
        self.assertIn('server=external',response.location)
        with patch.object(self.module.requests,'get',return_value=Mock(status_code=200,json=lambda:dict(name='example.org.',rrsets=[]))):
            response=self.client.get('/zone/example.org.?server=external')
        self.assertIn('/?server=external',response.text)
        with self.client.session_transaction() as state:self.assertEqual(state['pdns_server'],'external')
        self.assertEqual(self.client.get('/?server=invalid').status_code,400)

    def test_editor_shows_pending_values_and_unknown_types_are_read_only(self):
        self.post_record(**{'content[]':['192.0.2.42'],'disabled[]':['true']})
        zone=dict(name='example.org.',rrsets=[dict(name='www.example.org.',type='A',ttl=300,records=[dict(content='192.0.2.1',disabled=False)]),dict(name='example.org.',type='DNSKEY',ttl=300,records=[dict(content='key',disabled=False)])])
        with patch.object(self.module.requests,'get',return_value=Mock(status_code=200,json=lambda:zone)):
            response=self.client.get('/zone/example.org.?server=external')
        self.assertIn('value="192.0.2.42"',response.text)
        self.assertIn('Solo lectura',response.text)
        self.assertIn('<option>AAAA</option>',response.text)
        self.assertIn('<option>SRV</option>',response.text)
        self.assertNotIn('name="type" value="DNSKEY"',response.text)

    def test_short_and_zero_ttls_are_preserved_and_invalid_values_rejected(self):
        for ttl in ('0','30','2147483647'):
            self.post_record(ttl=ttl)
            self.assertEqual(self.pending()[0]['ttl'],int(ttl))
        for ttl in ('-1','+30','2147483648','1.5','１２３'):
            self.assertFalse(self.module.validate_ttl(ttl))
        self.assertEqual(self.module.extract_preferred_ttl({'default_ttl':0}),0)

    def test_partial_commit_keeps_only_failed_changes_and_second_commit_is_not_replayed(self):
        with self.client.session_transaction() as state:
            state['pending_changes']=[dict(id=server,server=server,zone='example.org.',name='www.example.org.',type='A',action='DELETE')
                for server in ('internal','external')]
        with patch.object(self.module.requests,'patch',side_effect=[Mock(status_code=204),Mock(status_code=500,json=lambda:{'error':'simulated failure'})]) as send:
            self.client.post('/commit',data={'csrf_token':'csrf'})
            self.assertEqual(send.call_count,2)
        self.assertEqual([change['server'] for change in self.pending()],['external'])
        with patch.object(self.module.requests,'patch',return_value=Mock(status_code=204)) as send:
            self.client.post('/commit',data={'csrf_token':'csrf'})
            self.client.post('/commit',data={'csrf_token':'csrf'})
        self.assertEqual(send.call_count,1)
        self.assertEqual(self.pending(),[])

    def test_nonstandard_api_error_does_not_double_count_failed_changes(self):
        self.post_record()
        with patch.object(self.module.requests,'patch',return_value=Mock(status_code=502,json=lambda:[],text='Bad gateway')):
            self.client.post('/commit',data={'csrf_token':'csrf'})
        self.assertEqual(len(self.pending()),1)
        with self.client.session_transaction() as state:
            messages=[message for _,message in state.get('_flashes',[])]
        self.assertTrue(any('errores en 1 cambios' in message for message in messages))
        self.assertFalse(any('errores en 2 cambios' in message for message in messages))
        self.assertEqual(self.module.handle_api_error(Mock(status_code=502,json=Mock(side_effect=ValueError()),text='upstream unavailable')),'upstream unavailable')

    def test_search_keeps_unknown_record_types_visible_and_server_in_links(self):
        results=[dict(object_type='record',zone='example.org.',zone_id='example.org.',name='example.org.',type='DNSKEY',ttl=300,content='key')]
        with patch.object(self.module.requests,'get',return_value=Mock(status_code=200,json=lambda:results)):
            response=self.client.get('/search?server=external&q=example')
        self.assertEqual(response.status_code,200)
        self.assertIn('badge-type-DNSKEY bg-secondary',response.text)
        self.assertIn('/zone/example.org.?server=external',response.text)

    def test_consultation_user_has_no_mutation_controls_on_review(self):
        self.seed_ten()
        with self.client.session_transaction() as state:state['role']='consulta'
        response=self.client.get('/review')
        self.assertNotIn('action="/commit"',response.text)
        self.assertNotIn('action="/change/discard"',response.text)
        self.assertNotIn('action="/change/remove/',response.text)
