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

    def run_script(self, fail_copy=False, target='recursor1', fail_restart=False, kind='hosts'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for command in ('scp', 'ssh'):
                program = root / command
                program.write_text('#!/bin/sh\necho ' + command + ' >> "$TEST_LOG"\n' +
                                   ('for arg do if [ -f "$arg" ]; then cat "$arg" > "$TEST_HOSTS"; fi; done\nexit "$TEST_COPY_EXIT"\n' if command == 'scp' else 'exit "$TEST_RESTART_EXIT"\n'))
                program.chmod(0o755)
            result = subprocess.run(['/bin/sh', str(SCRIPT), target, kind], input='0.0.0.0 example.org\n', text=True, capture_output=True,
                                    env=dict(os.environ, PATH=directory + ':' + os.environ['PATH'], TEST_LOG=str(root/'log'), TEST_HOSTS=str(root/'hosts'), TEST_COPY_EXIT='1' if fail_copy else '0', TEST_RESTART_EXIT='1' if fail_restart else '0'))
            calls = (root/'log').read_text().splitlines() if (root/'log').exists() else []
            hosts = (root/'hosts').read_text() if (root/'hosts').exists() else ''
            return result, calls, hosts

    def test_copy_then_restart(self):
        result, calls, hosts = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls, ['scp', 'ssh'])
        self.assertEqual(hosts, '0.0.0.0 example.org\n')

    def test_failed_copy_does_not_restart(self):
        result, calls, _ = self.run_script(fail_copy=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ['scp'])

    def test_failed_restart_is_reported(self):
        result, calls, _ = self.run_script(fail_restart=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ['scp', 'ssh'])

    def test_forward_zones_destination_is_fixed(self):
        result, calls, _ = self.run_script(kind='forward-zones')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls, ['scp', 'ssh'])

    def test_arbitrary_remote_path_rejected(self):
        result, calls, _ = self.run_script(kind='/etc/shadow')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_unknown_target_never_connects(self):
        result, calls, _ = self.run_script(target='example.org;reboot')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
