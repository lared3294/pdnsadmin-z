"""Detached executor lifecycle and the restricted system launcher."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from recursor_config import FilterError, FilterStore, Target

ROOT = Path(__file__).resolve().parents[1]


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.store = FilterStore(self.directory)
        self.state = dict(steven_enabled=False, blacklist='example.org', whitelist='', forwarders='')
        self.targets = [Target(f'recursor{i}', f'192.0.2.{i}') for i in range(1, 5)]

    def queue(self):
        with patch('recursor_config.subprocess.Popen') as launch:
            launch.return_value.poll.return_value = None
            return self.store.start(self.state, self.targets, 'admin')

    def test_snapshot_does_not_change_with_later_edits(self):
        job_id = self.queue()
        self.state['blacklist'] = 'other.org'
        self.targets.clear()
        with patch('recursor_config.deploy_operation', return_value=(True, 'ok')) as deploy:
            self.assertTrue(self.store.run_job(job_id))
        self.assertEqual(deploy.call_count, 4)
        for call in deploy.call_args_list:
            self.assertEqual(call.args[1], '0.0.0.0 example.org\n')

    def test_startup_reservation_blocks_second_start_and_save(self):
        job_id = self.queue()
        with self.assertRaisesRegex(FilterError, 'iniciándose'):
            self.store.start(self.state, self.targets, 'other')
        with self.assertRaisesRegex(FilterError, 'iniciándose'):
            self.store.save(self.state)
        self.assertEqual(self.store.job(job_id)['status'], 'running')

    def test_missing_launcher_reports_error_and_releases_lock(self):
        with patch('recursor_config.subprocess.Popen', side_effect=OSError('missing launcher')):
            with self.assertRaises(FilterError):
                self.store.start(self.state, self.targets, 'admin')
        self.assertEqual(self.store.latest_job()['status'], 'error')
        self.store.save(self.state)

    def test_startup_failure_becomes_persisted_error_without_reexecution(self):
        job_id = self.queue()
        path = self.directory / 'jobs' / (job_id + '.json')
        data = json.loads(path.read_text()); data['startup_deadline'] = 0
        self.store._write(path, data)
        (self.directory / 'jobs' / (job_id + '.log')).write_text('sudo: command not allowed')
        result = self.store.job(job_id)
        self.assertEqual(result['status'], 'error')
        self.assertIn('command not allowed', result['message'])
        self.assertEqual(json.loads(path.read_text())['status'], 'error')
        with self.assertRaises(FilterError), patch('recursor_config.deploy_operation') as deploy:
            self.store.run_job(job_id)
        deploy.assert_not_called()

    def test_executor_crash_marks_remote_state_uncertain(self):
        job_id = self.queue()
        path = self.directory / 'jobs' / (job_id + '.json')
        data = json.loads(path.read_text())
        data.update(runner_started=True, results=[dict(name='recursor1', host='192.0.2.1', status='applying', detail='')])
        self.store._write(path, data)
        result = self.store.job(job_id)
        self.assertEqual(result['status'], 'error')
        self.assertIn('incierto', result['results'][0]['detail'])

    def test_real_isolated_entrypoint_persists_generation_failure(self):
        self.state['steven_enabled'] = True
        job_id = self.queue()
        result = subprocess.run([sys.executable, '-I', str(ROOT / 'recursor_job.py'), str(self.directory), job_id],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        job = self.store.job(job_id)
        self.assertEqual(job['status'], 'error')
        self.assertIn('steven_url', job['message'])
        self.assertEqual(job['results'], [])

    def test_running_executor_survives_caller_termination(self):
        # An actual child process runs the production executor, with only the
        # remote operation simulated. Kill its launcher after the executor owns the lock.
        worker_code = '''
import sys,time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import recursor_config as r
root=Path(sys.argv[2]); job_id=sys.argv[3]
def deploy(target,payload,kind):
    if target.name=='recursor1':
        (root/'ready').touch()
        deadline=time.monotonic()+8
        while not (root/'release').exists():
            if time.monotonic()>deadline: return False,'test timeout'
            time.sleep(.02)
    return True,'mock remote completed'
r.deploy_operation=deploy
r.FilterStore(root).run_job(job_id)
(root/'done').touch()
'''
        parent_code = '''
import sys,time,subprocess
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import recursor_config as r
root=Path(sys.argv[2]); worker=sys.argv[3]
real_popen=subprocess.Popen
def launch(args,**kwargs):
    return real_popen([sys.executable,'-c',worker,sys.argv[1],str(root),args[-2]],**kwargs)
r.subprocess.Popen=launch
store=r.FilterStore(root)
job_id=store.start(dict(steven_enabled=False,blacklist='example.org',whitelist=''),
    [r.Target('recursor'+str(i),'192.0.2.'+str(i)) for i in range(1,5)],'admin')
(root/'job-id').write_text(job_id)
time.sleep(15)
'''
        parent = subprocess.Popen([sys.executable, '-c', parent_code, str(ROOT), str(self.directory), worker_code],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self.wait_file('ready')
            parent.terminate(); parent.wait(timeout=3)
            job_id = (self.directory / 'job-id').read_text()
            self.assertEqual(self.store.job(job_id)['status'], 'running')
            with self.assertRaises(FilterError):
                self.store.start(self.state, self.targets, 'other')
            (self.directory / 'release').touch()
            self.wait_file('done')
            result = self.store.job(job_id)
            self.assertEqual(result['status'], 'success')
            self.assertEqual(len(result['results']), 4)
        finally:
            (self.directory / 'release').touch()
            if parent.poll() is None:
                parent.terminate()
            parent.wait(timeout=3)

    def wait_file(self, name):
        deadline = time.monotonic() + 4
        while not (self.directory / name).exists():
            if time.monotonic() > deadline:
                self.fail('Timed out waiting for ' + name)
            time.sleep(.02)


class LauncherTests(unittest.TestCase):
    def run_launcher(self, mode, args=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            systemd = root / 'systemd'
            if mode == 'systemd': systemd.mkdir()
            log = root / 'args'
            stub = root / 'stub'
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "' + str(log) + '"\n' +
                            'test -z "${PYTHONPATH:-}"\n')
            stub.chmod(0o755)
            script = root / 'launch'
            script.write_text((ROOT / 'scripts/pdnsadmin-start-recursor-job').read_text()
                              .replace('/run/systemd/system', str(systemd))
                              .replace('/usr/bin/systemd-run', str(stub))
                              .replace('/usr/sbin/runuser', str(stub)))
            result = subprocess.run(['/bin/sh', str(script), *(args if args is not None else ['a'*32, '/var/lib/pdnsadmin/filters'])],
                                    capture_output=True, text=True, env=dict(os.environ, PYTHONPATH='/untrusted'))
            return result, log.read_text().splitlines() if log.exists() else []

    def test_systemd_uses_scope_and_fixed_unprivileged_executor(self):
        result, args = self.run_launcher('systemd')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--scope', args)
        self.assertIn('--unit=pdnsadmin-recursor-' + 'a'*32, args)
        self.assertEqual(args[-8:], ['-u', 'pdnsadmin', '--', '/opt/pdnsadmin-z/.venv/bin/python', '-I',
                                    '/opt/pdnsadmin-z/recursor_job.py', '/var/lib/pdnsadmin/filters', 'a'*32])

    def test_sysv_uses_fixed_executor_without_systemd(self):
        result, args = self.run_launcher('sysv')
        self.assertEqual(result.returncode, 0)
        self.assertNotIn('--scope', args)
        self.assertEqual(args[0:3], ['-u', 'pdnsadmin', '--'])
        self.assertIn('-I', args)

    def test_invalid_identifier_path_or_extra_arguments_never_launch(self):
        for args in ([], ['a'*32], ['../bad', '/tmp'], ['g'*32, '/tmp'], ['a'*32, 'relative'],
                     ['a'*32, '/tmp', 'arbitrary-command']):
            with self.subTest(args=args):
                result, calls = self.run_launcher('systemd', args)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
