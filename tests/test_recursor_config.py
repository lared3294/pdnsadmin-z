import configparser
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recursor_config import FilterError, FilterStore, generate_policy, parse_hosts, parse_forwarders, read_targets, deploy_operation

class PolicyTests(unittest.TestCase):
    def test_user_hosts_examples_comments_duplicates_escaping_and_underscores(self):
        names = parse_hosts('# socialnets\\\n0.0.0.0 FACEBOOK.com\\\n0.0.0.0 facebook.com\n0.0.0.0 www\\.googletagmanager.com\\\n0.0.0.0 _analytics.google.com\n')
        self.assertEqual(names, {'facebook.com', 'www.googletagmanager.com', '_analytics.google.com'})

    def test_exact_whitelist_wins_and_no_subdomain_guessing(self):
        state = dict(steven_enabled=True, blacklist='0.0.0.0 facebook.com\n0.0.0.0 azurefd.net', whitelist='0.0.0.0 azurefd.net')
        hosts, stats = generate_policy(state, '0.0.0.0 azurefd.net\n0.0.0.0 www.azurefd.net\n0.0.0.0 facebook.com')
        self.assertEqual(parse_hosts(hosts), {'facebook.com', 'www.azurefd.net'})
        self.assertEqual(stats['excluded'], 1)

    def test_steven_disabled_and_empty_policy_clears_blocks(self):
        state = dict(steven_enabled=False, blacklist='', whitelist='')
        hosts, stats = generate_policy(state, 'invalid text that must not be parsed')
        self.assertEqual(hosts, '')
        self.assertEqual(stats['total'], 0)

    def test_upstream_local_entries_are_ignored(self):
        self.assertEqual(parse_hosts('127.0.0.1 localhost\n::1 ip6-localhost\n0.0.0.0 0.0.0.0\n0.0.0.0 example.com', source=True), {'example.com'})

    def test_invalid_or_injected_domains_fail(self):
        for text in ['0.0.0.0 example.com;reboot', '0.0.0.0 *.example.com', '0.0.0.0 -bad.com', '192.0.2.1 example.com', '0.0.0.0 192.0.2.1']:
            with self.subTest(text=text), self.assertRaises(FilterError):
                parse_hosts(text)

    def test_enabled_empty_upstream_fails(self):
        with self.assertRaises(FilterError):
            generate_policy(dict(steven_enabled=True, blacklist='example.com', whitelist=''), '# empty')

    def test_targets_require_four_distinct_servers_without_credentials(self):
        cfg = configparser.ConfigParser(); cfg.read_string('[filters]\ntargets=a,b,c,d\n')
        for number, name in enumerate('abcd', 1):
            cfg['recursor:' + name] = dict(host=f'192.0.2.{number}')
        targets = read_targets(cfg)
        self.assertEqual(targets[0].host, '192.0.2.1')
        self.assertFalse(hasattr(targets[0], 'identity_file'))
        cfg['recursor:d']['host'] = '192.0.2.1'
        with self.assertRaises(FilterError): read_targets(cfg)

    def test_script_timeout_is_reported_as_uncertain(self):
        import subprocess
        from recursor_config import Target
        target = Target('r1', '192.0.2.1')
        with patch('recursor_config.subprocess.run', side_effect=subprocess.TimeoutExpired('ssh', 150)):
            success, detail = deploy_operation(target, '0.0.0.0 example.org\n')
        self.assertFalse(success); self.assertIn('incierto', detail)


class ForwarderTests(unittest.TestCase):
    def test_domains_prefixes_root_addresses_ports_and_comments(self):
        text = '# internal\nExample.ORG.=192.0.2.1;192.0.2.2:5300 # comment\n+^internal=2001:db8::1,[2001:db8::2]:5353\n+.=8.8.8.8\n'
        self.assertEqual(parse_forwarders(text), 'example.org=192.0.2.1,192.0.2.2:5300\n+^internal=2001:db8::1,[2001:db8::2]:5353\n+.=8.8.8.8\n')

    def test_invalid_entries_and_duplicate_zone_rejected(self):
        for text in ['example.org=bad-host', 'example.org=', 'example.org=192.0.2.1:0', 'example.org=192.0.2.1:65536', 'example.org=192.0.2.1;reboot', 'bad zone=192.0.2.1', '*.org=192.0.2.1', 'example.org=192.0.2.1\n+EXAMPLE.ORG.=192.0.2.2', '++example.org=192.0.2.1', 'example.org=fe80::1%eth0']:
            with self.subTest(text=text), self.assertRaises(FilterError): parse_forwarders(text)

    def test_empty_file_supported(self):
        self.assertEqual(parse_forwarders('# comment only'), '')


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store = FilterStore(self.temp.name)
        self.state = dict(steven_enabled=False, blacklist='example.com', whitelist='')
        self.targets = [type('Target', (), dict(name=f'r{i}', host=f'192.0.2.{i}'))() for i in range(1, 5)]

    def run_job(self, operation):
        data = dict(id='a' * 32, status='running', message='', user='demo', results=[], stats=None)
        self.store._prepare(); path = self.store.directory / 'jobs/test.json'
        with patch('recursor_config.deploy_operation', side_effect=operation), patch('recursor_config.download_steven') as download:
            self.store._apply(self.state, self.targets, data, path)
            download.assert_not_called()
        return data

    def test_copies_four_targets_and_reports_partial_failure(self):
        calls = []
        def operation(target, payload, kind):
            calls.append(target.name)
            self.assertEqual(payload, '0.0.0.0 example.com\n')
            return target.name != 'r2', 'result'
        result = self.run_job(operation)
        self.assertEqual(calls, ['r1', 'r2', 'r3', 'r4'])
        self.assertEqual(result['status'], 'error')
        self.assertEqual([r['status'] for r in result['results']], ['success', 'error', 'success', 'success'])

    def test_forwarders_deploy_only_forward_zones_without_steven_download(self):
        data = dict(id='b' * 32, status='running', kind='forward-zones', results=[], stats=None)
        state = dict(self.state, steven_enabled=True, forwarders='example.org=192.0.2.1')
        self.store._prepare()
        with patch('recursor_config.download_steven') as download, patch('recursor_config.deploy_operation', return_value=(True, 'ok')) as deploy:
            self.store._apply(state, self.targets, data, self.store.directory / 'jobs/test.json')
            download.assert_not_called()
        self.assertEqual(deploy.call_count, 4)
        for call in deploy.call_args_list:
            self.assertEqual(call.args[1:], ('example.org=192.0.2.1\n', 'forward-zones'))
        self.assertEqual(data['stats'], {'zones': 1})
        self.assertEqual(data['status'], 'success')

    def test_concurrent_apply_or_save_rejected(self):
        fd = self.store._lock()
        try:
            with self.assertRaises(FilterError): self.store.save(self.state)
        finally: os.close(fd)

    def test_interrupted_job_does_not_claim_success(self):
        self.store._write(self.store.directory / 'jobs' / ('a' * 32 + '.json'), {'status': 'running'})
        self.assertEqual(self.store.job('a' * 32)['status'], 'error')

    def test_background_job_completes_and_persists_results(self):
        import time
        with patch('recursor_config.deploy_operation', return_value=(True, 'mock result')):
            job_id = self.store.start(self.state, self.targets, 'demo')
            for _ in range(100):
                job = self.store.job(job_id)
                if job['status'] != 'running': break
                time.sleep(.01)
            self.assertEqual(job['status'], 'success')
            self.assertEqual(len(job['results']), 4)
            self.assertEqual(self.store.read()['blacklist'], 'example.com')


if __name__ == '__main__': unittest.main()
