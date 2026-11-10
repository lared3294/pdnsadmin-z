"""Run the real transaction against temporary files and simulated SSH/services."""
import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from recursor_config import Target, deploy_operation

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/pdnsadmin-update-recursors'


class SystemDeployTests(unittest.TestCase):
    def test_web_sends_hosts_to_fixed_system_script(self):
        with patch('recursor_config.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout='ok')) as run:
            self.assertEqual(deploy_operation(Target('recursor1', '192.0.2.11'), '0.0.0.0 example.org\n'), (True, 'ok'))
        self.assertEqual(run.call_args.args[0], ['/usr/bin/sudo', '-n', '/usr/local/sbin/pdnsadmin-update-recursors', 'recursor1', 'hosts'])
        self.assertEqual(run.call_args.kwargs['input'], '0.0.0.0 example.org\n')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'powerdns'; self.config.mkdir()
        self.bin = self.root / 'bin'; self.bin.mkdir()
        self.destination = self.config / 'hosts'
        self.destination.write_text('0.0.0.0 old.example\n')
        self.destination.chmod(0o640)
        self.env = dict(os.environ, TEST_ROOT=str(self.root), TEST_BIN=str(self.bin))
        # Only this test copy uses a private PATH and configuration directory.
        self.script = self.root / 'deploy'
        self.script.write_text(SCRIPT.read_text().replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin',
            'PATH=$TEST_BIN:/usr/bin:/bin').replace('config_dir=/etc/powerdns', f'config_dir={self.config}'))
        self.program('ssh', '''for remote do :; done
if [ "${TEST_TRANSFER_FAIL:-0}" = 1 ]; then
    head -c 60 | sh -c "$remote"
else
    sh -c "$remote"
fi
''')
        self.program('pdns_recursor', '''echo check >> "$TEST_ROOT/log"
cp "${2#*=}" "$TEST_ROOT/checked"
if [ -f "$TEST_ROOT/powerdns/hosts" ]; then cp "$TEST_ROOT/powerdns/hosts" "$TEST_ROOT/active-at-check"; fi
exit "${TEST_CHECK_FAIL:-0}"
''')
        self.program('service', self.restart_program())
        self.program('systemctl', self.restart_program())
        self.program('rec_control', '''echo ping >> "$TEST_ROOT/log"
count=0; [ ! -f "$TEST_ROOT/count" ] || count=$(cat "$TEST_ROOT/count")
[ "${TEST_PREFLIGHT_FAIL:-0}" != 1 ] || exit 1
if [ "${TEST_HEALTH_FAIL:-0}" = 1 ] && [ "$count" = 1 ]; then exit 1; fi
exit 0
''')
        self.program('sleep', 'exit 0\n')

    def program(self, name, text):
        path = self.bin / name
        path.write_text('#!/bin/sh\nset -eu\n' + text)
        path.chmod(0o755)

    def restart_program(self):
        return '''echo restart >> "$TEST_ROOT/log"
count=0; [ ! -f "$TEST_ROOT/count" ] || count=$(cat "$TEST_ROOT/count")
count=$((count + 1)); echo "$count" > "$TEST_ROOT/count"
case "${TEST_RESTART_FAIL:-0}" in always) exit 1 ;; first) [ "$count" != 1 ] || exit 1 ;; esac
exit 0
'''

    def run_script(self, payload='0.0.0.0 example.org\n', target='recursor1', kind='hosts', **env):
        return subprocess.run(['/bin/sh', str(self.script), target, kind], input=payload,
            text=True, capture_output=True, env=dict(self.env, **env), timeout=10)

    def calls(self):
        log = self.root / 'log'
        return log.read_text().splitlines() if log.exists() else []

    def test_success_validates_before_replacement_and_keeps_backup_and_permissions(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'active-at-check').read_text(), '0.0.0.0 old.example\n')
        self.assertEqual(self.destination.read_text(), '0.0.0.0 example.org\n')
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.config / '.pdnsadmin-backups/hosts.previous').read_text(), '0.0.0.0 old.example\n')
        self.assertEqual(self.calls(), ['check', 'ping', 'restart', 'ping'])
        self.assertEqual(list(self.config.glob('.pdnsadmin-stage.*')), [])

    def test_interrupted_upload_never_executes_transaction(self):
        result = self.run_script(TEST_TRANSFER_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.destination.read_text(), '0.0.0.0 old.example\n')
        self.assertEqual(self.calls(), [])

    def test_config_check_failure_never_replaces_or_restarts(self):
        result = self.run_script(TEST_CHECK_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.destination.read_text(), '0.0.0.0 old.example\n')
        self.assertEqual(self.calls(), ['check'])

    def test_invalid_payload_never_replaces_or_restarts(self):
        for kind, payload in [('hosts', '0.0.0.0 example.org;reboot\n'), ('forward-zones', 'example.org=1.2.3.4;reboot\n')]:
            with self.subTest(kind=kind):
                result = self.run_script(payload=payload, kind=kind)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), [])
                self.assertEqual(self.destination.read_text(), '0.0.0.0 old.example\n')

    def test_preexisting_unhealthy_service_is_not_modified(self):
        result = self.run_script(TEST_PREFLIGHT_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('restart', self.calls())
        self.assertEqual(self.destination.read_text(), '0.0.0.0 old.example\n')

    def test_failed_restart_restores_previous_and_recovers_service(self):
        result = self.run_script(TEST_RESTART_FAIL='first')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.destination.read_text(), '0.0.0.0 old.example\n')
        self.assertEqual(self.calls().count('restart'), 2)
        self.assertIn('recursor recuperado', result.stderr)

    def test_failed_health_check_also_rolls_back(self):
        result = self.run_script(TEST_HEALTH_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.destination.read_text(), '0.0.0.0 old.example\n')
        self.assertEqual(self.calls().count('restart'), 2)
        self.assertIn('recursor recuperado', result.stderr)

    def test_failed_recovery_is_explicit(self):
        result = self.run_script(TEST_RESTART_FAIL='always')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.destination.read_text(), '0.0.0.0 old.example\n')
        self.assertIn('Requiere intervención', result.stderr)

    def test_signal_after_atomic_replace_restores_previous(self):
        self.program('mv', """/usr/bin/mv "$@"
case "$*" in *'/candidate '*) kill -TERM "$PPID" ;; esac
""")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.destination.read_text(), '0.0.0.0 old.example\n')
        self.assertIn('recursor recuperado', result.stderr)
        self.assertEqual(list(self.config.glob('.pdnsadmin-stage.*')), [])

    def test_service_restart_does_not_inherit_deployment_lock(self):
        self.program('service', 'if [ -e /proc/$$/fd/9 ]; then exit 1; fi\n' + self.restart_program())
        self.program('systemctl', 'if [ -e /proc/$$/fd/9 ]; then exit 1; fi\n' + self.restart_program())
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_new_forwarders_are_readable_and_empty_file_is_supported(self):
        result = self.run_script(kind='forward-zones', payload='')
        self.assertEqual(result.returncode, 0, result.stderr)
        destination = self.config / 'forward-zones'
        self.assertEqual(destination.read_text(), '')
        self.assertEqual(destination.stat().st_mode & 0o777, 0o644)

    def test_forwarder_payload_and_failure_without_previous_file(self):
        result = self.run_script(kind='forward-zones', payload='+example.org=[2001:db8::1]:5353,192.0.2.1\n', TEST_RESTART_FAIL='first')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls().count('restart'), 2)
        self.assertFalse((self.config / 'forward-zones').exists())

    def test_symlink_destination_is_rejected(self):
        self.destination.unlink()
        other = self.root / 'other'; other.write_text('untouched')
        self.destination.symlink_to(other)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(other.read_text(), 'untouched')
        self.assertEqual(self.calls(), [])

    def test_concurrent_remote_transaction_is_rejected(self):
        with (self.config / '.pdnsadmin-deploy.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_unknown_target_and_arbitrary_path_never_connect(self):
        for args in (dict(target='example.org;reboot'), dict(kind='/etc/shadow')):
            result = self.run_script(**args)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.calls(), [])
