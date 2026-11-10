"""Retention removes only deployment artifacts and never races the executor."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recursor_config import FilterStore, Target, JOB_RETENTION_SECONDS


class JobRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = FilterStore(self.temp.name)
        self.store._prepare()
        self.jobs = Path(self.temp.name) / 'jobs'
        self.now = 2_000_000_000
        self.clock = patch('recursor_config.time.time', return_value=self.now)
        self.clock.start(); self.addCleanup(self.clock.stop)

    def add_job(self, number, created=None, status='success', **extra):
        job_id = f'{number:032x}'
        data = dict(id=job_id, created=self.now - number if created is None else created,
                    status=status, results=[], **extra)
        self.store._write(self.jobs / (job_id + '.json'), data)
        for suffix in ('request.json', 'log', 'hosts', 'forward-zones', 'json.' + 'f'*32 + '.tmp'):
            (self.jobs / (job_id + '.' + suffix)).write_text('artifact')
        return job_id

    def latest(self, job_id):
        self.store._write(self.store.directory / 'latest.json', {'id': job_id})

    def ids(self):
        return {path.stem for path in self.jobs.glob('*.json') if len(path.stem) == 32}

    def test_keeps_only_newest_twenty_and_removes_all_associated_files(self):
        for number in range(1, 31):
            self.add_job(number)
        self.latest(f'{30:032x}')
        self.store.cleanup()
        self.assertEqual(self.ids(), {f'{number:032x}' for number in range(1, 21)})
        self.assertEqual(len(list(self.jobs.iterdir())), 20 * 6)
        self.assertEqual(self.store.latest_job()['id'], f'{1:032x}')

    def test_fifteen_days_is_a_maximum_even_when_latest_is_expired(self):
        old = self.add_job(1, created=self.now - JOB_RETENTION_SECONDS)
        self.latest(old)
        self.assertIsNone(self.store.latest_job())
        self.assertEqual(list(self.jobs.iterdir()), [])
        self.assertFalse((self.store.directory / 'latest.json').exists())

    def test_recent_last_result_is_preserved(self):
        recent = self.add_job(1, created=self.now - JOB_RETENTION_SECONDS + 1)
        self.add_job(2, created=self.now - JOB_RETENTION_SECONDS - 1)
        self.latest(recent)
        self.assertEqual(self.store.latest_job()['id'], recent)
        self.assertEqual(self.ids(), {recent})

    def test_cleanup_skips_everything_while_executor_holds_lock(self):
        active = self.add_job(1, created=0, status='running', runner_started=True)
        self.latest(active)
        before = {file.name for file in self.jobs.iterdir()}
        fd = self.store._lock()
        try:
            self.store.cleanup()
            self.assertEqual({file.name for file in self.jobs.iterdir()}, before)
            self.assertEqual(json.loads((self.jobs / (active + '.json')).read_text())['status'], 'running')
        finally:
            os.close(fd)
        self.store.cleanup()
        self.assertEqual(list(self.jobs.iterdir()), [])

    def test_startup_reservation_counts_toward_twenty_and_is_protected(self):
        for number in range(1, 25):
            self.add_job(number)
        reserved = self.add_job(25, created=0, status='running', runner_started=False,
                                startup_deadline=self.now + 30)
        self.latest(reserved)
        self.store.cleanup()
        self.assertEqual(len(self.ids()), 20)
        self.assertIn(reserved, self.ids())
        self.assertEqual(self.store.latest_job()['status'], 'running')

    def test_stale_running_jobs_are_marked_interrupted_and_eventually_expire(self):
        job_id = self.add_job(1, status='running', runner_started=True,
                              user='test')
        self.latest(job_id)
        self.store.cleanup()
        data = self.store.job(job_id)
        self.assertEqual(data['status'], 'error')
        self.assertIn('interrumpió', data['message'])
        with patch('recursor_config.time.time', return_value=self.now + JOB_RETENTION_SECONDS):
            self.assertIsNone(self.store.latest_job())

    def test_old_orphan_artifacts_are_deleted_but_unrelated_files_are_untouched(self):
        job_id = 'a' * 32
        orphan = self.jobs / (job_id + '.request.json')
        orphan.write_text('incomplete job')
        os.utime(orphan, (self.now - JOB_RETENTION_SECONDS - 1,) * 2)
        unrelated = self.jobs / 'manual-notes.txt'; unrelated.write_text('keep')
        unknown = self.jobs / (job_id + '.custom'); unknown.write_text('keep')
        self.store._write(self.store.directory / 'lists.json', {'blacklist': 'example.org'})
        self.store.cleanup()
        self.assertFalse(orphan.exists())
        self.assertEqual(unrelated.read_text(), 'keep')
        self.assertEqual(unknown.read_text(), 'keep')
        self.assertEqual(self.store.read()['blacklist'], 'example.org')
        self.assertTrue((self.store.directory / 'apply.lock').exists())

    def test_corrupt_or_missing_latest_pointer_is_repaired(self):
        job_id = self.add_job(1)
        (self.store.directory / 'latest.json').write_text('invalid json')
        self.assertEqual(self.store.latest_job()['id'], job_id)
        self.latest('f'*32)
        self.assertEqual(self.store.latest_job()['id'], job_id)

    def test_cleanup_io_failure_does_not_hide_the_latest_result(self):
        job_id = self.add_job(1)
        self.latest(job_id)
        import logging
        with patch.object(logging.getLogger('pdnsadmin'), 'disabled', False), patch.object(self.store, '_prune_locked', side_effect=OSError('read-only history')):
            with self.assertLogs('pdnsadmin', level='WARNING'):
                self.assertEqual(self.store.latest_job()['id'], job_id)

    def test_new_job_triggers_cleanup_automatically(self):
        for number in range(1, 25):
            self.add_job(number)
        targets = [Target(f'recursor{i}', f'192.0.2.{i}') for i in range(1, 5)]
        with patch('recursor_config.subprocess.Popen') as launch:
            launch.return_value.poll.return_value = None
            job_id = self.store.start(dict(steven_enabled=False, blacklist='', whitelist=''), targets, 'admin')
        self.assertEqual(len(self.ids()), 20)
        self.assertIn(job_id, self.ids())
        self.assertEqual(self.store.latest_job()['id'], job_id)
