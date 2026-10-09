import configparser
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dns_filters import FilterError, FilterStore, generate_policy, parse_hosts, read_targets, ssh_operation

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('rpz_helper', str(ROOT / 'scripts/pdnsadmin-rpz'))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec); loader.exec_module(helper)


class PolicyTests(unittest.TestCase):
    def test_user_hosts_examples_comments_duplicates_escaping_and_underscores(self):
        names = parse_hosts('# socialnets\\\n0.0.0.0 FACEBOOK.com\\\n0.0.0.0 facebook.com\n0.0.0.0 www\\.googletagmanager.com\\\n0.0.0.0 _analytics.google.com\n')
        self.assertEqual(names, {'facebook.com', 'www.googletagmanager.com', '_analytics.google.com'})

    def test_exact_whitelist_wins_and_no_subdomain_guessing(self):
        state = dict(steven_enabled=True, blacklist='0.0.0.0 facebook.com\n0.0.0.0 azurefd.net', whitelist='0.0.0.0 azurefd.net')
        rpz, hosts, stats = generate_policy(state, '0.0.0.0 azurefd.net\n0.0.0.0 www.azurefd.net\n0.0.0.0 facebook.com')
        self.assertEqual(parse_hosts(hosts), {'facebook.com', 'www.azurefd.net'})
        self.assertEqual(stats['excluded'], 1)
        self.assertEqual(helper.validate_policy(rpz), 2)

    def test_steven_disabled_and_empty_policy_clears_blocks(self):
        state = dict(steven_enabled=False, blacklist='', whitelist='')
        rpz, hosts, stats = generate_policy(state, 'invalid text that must not be parsed')
        self.assertEqual(hosts, '')
        self.assertEqual(stats['total'], 0)
        self.assertEqual(helper.validate_policy(rpz), 0)

    def test_upstream_local_entries_are_ignored(self):
        self.assertEqual(parse_hosts('127.0.0.1 localhost\n::1 ip6-localhost\n0.0.0.0 0.0.0.0\n0.0.0.0 example.com', source=True), {'example.com'})

    def test_invalid_or_injected_domains_fail(self):
        for text in ['0.0.0.0 example.com;reboot', '0.0.0.0 *.example.com', '0.0.0.0 -bad.com', '192.0.2.1 example.com', '0.0.0.0 192.0.2.1']:
            with self.subTest(text=text), self.assertRaises(FilterError):
                parse_hosts(text)

    def test_enabled_empty_upstream_fails(self):
        with self.assertRaises(FilterError):
            generate_policy(dict(steven_enabled=True, blacklist='example.com', whitelist=''), '# empty')

    def test_targets_require_four_distinct_servers_and_safe_ssh(self):
        cfg = configparser.ConfigParser(); cfg.read_string('[filters]\ntargets=a,b,c,d\n')
        for number, name in enumerate('abcd', 1):
            cfg['recursor:' + name] = dict(host=f'192.0.2.{number}', user='deploy', identity_file='/tmp/key', known_hosts_file='/tmp/known')
        targets = read_targets(cfg)
        self.assertIn('StrictHostKeyChecking=yes', targets[0].ssh_command('--apply'))
        cfg['recursor:d']['host'] = '192.0.2.1'
        with self.assertRaises(FilterError): read_targets(cfg)

    def test_ssh_timeout_is_reported_as_uncertain(self):
        import subprocess
        from dns_filters import Target
        target = Target('r1', '192.0.2.1', 'deploy', 22, '/tmp/key', '/tmp/known')
        with patch('dns_filters.subprocess.run', side_effect=subprocess.TimeoutExpired('ssh', 150)):
            success, detail = ssh_operation(target, '--apply', '{}')
        self.assertFalse(success); self.assertIn('incierto', detail)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store = FilterStore(self.temp.name)
        self.state = dict(steven_enabled=False, blacklist='example.com', whitelist='')
        self.targets = [type('Target', (), dict(name=f'r{i}', host=f'192.0.2.{i}'))() for i in range(1, 5)]

    def run_job(self, operation):
        data = dict(id='a' * 32, status='running', message='', user='demo', results=[], stats=None)
        self.store._prepare(); path = self.store.directory / 'jobs/test.json'
        with patch('dns_filters.ssh_operation', side_effect=operation), patch('dns_filters.download_steven') as download:
            self.store._apply(self.state, self.targets, data, path)
            download.assert_not_called()
        return data

    def test_failed_preflight_changes_no_server(self):
        calls = []
        def operation(target, action, payload=None):
            calls.append(action); return target.name != 'r2', 'check'
        result = self.run_job(operation)
        self.assertEqual(calls, ['--check'] * 4)
        self.assertEqual(result['status'], 'error')

    def test_four_prechecks_precede_four_applies_and_partial_failures_visible(self):
        calls = []
        def operation(target, action, payload=None):
            calls.append(action)
            if action == '--apply': helper.validate_policy(json.loads(payload)['rpz'])
            return not (action == '--apply' and target.name == 'r2'), 'result'
        result = self.run_job(operation)
        self.assertEqual(calls, ['--check'] * 4 + ['--apply'] * 4)
        self.assertEqual(result['status'], 'error')
        self.assertEqual([r['status'] for r in result['results']], ['success', 'error', 'success', 'success'])

    def test_concurrent_apply_or_save_rejected(self):
        fd = self.store._lock()
        try:
            with self.assertRaises(FilterError): self.store.save(self.state)
        finally: os.close(fd)

    def test_interrupted_job_does_not_claim_success(self):
        self.store._write(self.store.directory / 'jobs' / ('a' * 32 + '.json'), {'status': 'running'})
        self.assertEqual(self.store.job('a' * 32)['status'], 'error')

    def test_running_recursor_must_confirm_lua_activation(self):
        from types import SimpleNamespace
        root = Path(self.temp.name)
        policy = root / 'policy.rpz'; policy.write_text('initial')
        lua = root / 'recursor.lua'; lua.write_text(f'rpzFile("{policy}")')
        cfg = dict(policy_file=str(policy), lua_file=str(lua), service='pdns-recursor', init_system='sysv')
        with patch.object(helper, 'run_service', return_value=True), patch.object(helper.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='lua-config-file=' + str(lua))):
            helper.check_ready(cfg)
        with patch.object(helper, 'run_service', return_value=True), patch.object(helper.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='lua-config-file=/other.lua')):
            with self.assertRaisesRegex(ValueError, 'Lua activo'): helper.check_ready(cfg)

    def test_background_job_completes_and_persists_results(self):
        import time
        with patch('dns_filters.ssh_operation', return_value=(True, 'mock result')):
            job_id = self.store.start(self.state, self.targets, 'demo')
            for _ in range(100):
                job = self.store.job(job_id)
                if job['status'] != 'running': break
                time.sleep(.01)
            self.assertEqual(job['status'], 'success')
            self.assertEqual(len(job['results']), 4)
            self.assertEqual(self.store.read()['blacklist'], 'example.com')

    def test_remote_restart_failure_restores_original_policy(self):
        policy = Path(self.temp.name) / 'policy.rpz'; policy.write_text('original')
        new, _, _ = generate_policy(self.state)
        cfg = dict(policy_file=str(policy))
        with patch.object(helper, 'check_ready'), patch.object(helper, 'run_service', side_effect=[False, True]), patch.object(helper, 'wait_active', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'anterior restaurada'):
                helper.apply_policy(cfg, new)
        self.assertEqual(policy.read_text(), 'original')
        self.assertEqual(policy.with_name('policy.rpz.previous').read_text(), 'original')


if __name__ == '__main__': unittest.main()
