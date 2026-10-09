"""Exercise installer plans and config/service generation inside temporary folders."""
from pathlib import Path
import configparser
import os
import subprocess
import tempfile
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'install.sh'

# Ignore account ownership in tests; never invoke package or service managers.
SAFE_RUN = r'''
run() {
    if [[ "$1" == chown ]]; then return 0; fi
    if [[ "$1" == install ]]; then
        shift; local args=()
        while (($#)); do
            case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
        done
        command install "${args[@]}"
    elif [[ "$1" == systemctl || "$1" == update-rc.d || "$1" == chkconfig ]]; then
        printf 'MANAGER %s\n' "$*"
    else "$@"; fi
}
'''


class InstallerTests(unittest.TestCase):
    def shell(self, code, check=True):
        return subprocess.run(['bash', '-c', 'source "$1"\n' + code, 'test', str(INSTALLER)],
                              text=True, capture_output=True, check=check)

    def test_help_and_argument_errors(self):
        help_result = subprocess.run([str(INSTALLER), '--help'], capture_output=True, text=True, check=True)
        self.assertIn('--dry-run', help_result.stdout)
        for args in [['--init'], ['--init', 'other'], ['--ref'], ['--ref', '-bad'], ['--unknown']]:
            result = subprocess.run([str(INSTALLER), *args], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_systemd_detection_requires_running_manager(self):
        self.assertEqual(self.shell('systemd_running() { return 0; }; detect_init').stdout.strip(), 'systemd')

    def test_sysv_detection_and_override(self):
        code = '''systemd_running() { return 1; }
command() { if [[ "$*" == "-v update-rc.d" ]]; then return 0; else builtin command "$@"; fi; }
detect_init'''
        if Path('/etc/init.d').is_dir():
            self.assertEqual(self.shell(code).stdout.strip(), 'sysv')
        self.assertEqual(self.shell('INIT_MODE=sysv; detect_init').stdout.strip(), 'sysv')

    def test_package_manager_selection(self):
        for manager, expected in [('apt-get', 'apt'), ('dnf', 'dnf'), ('yum', 'yum'), ('zypper', 'zypper')]:
            code = 'command() { [[ "$*" == "-v ' + manager + '" ]]; }; detect_packages'
            self.assertEqual(self.shell(code).stdout.strip(), expected)

    def test_dry_run_plans_never_start_or_enable_service(self):
        for mode in ['systemd', 'sysv']:
            result = subprocess.run([str(INSTALLER), '--dry-run', '--no-packages', '--init', mode],
                                    text=True, capture_output=True, check=True)
            plan = '\n'.join(line for line in result.stdout.splitlines() if line.startswith('  '))
            # Final instructions may mention activation; planned commands must not activate.
            actions = plan.split('  sudoedit ')[0]
            self.assertNotIn('systemctl enable', actions)
            self.assertNotIn('service pdnsadmin start', actions)
            self.assertIn('pip check', actions)

    def test_new_configuration_is_secure_and_preserved_on_reinstall(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            venv_bin = root / 'app/.venv/bin'; venv_bin.mkdir(parents=True)
            (venv_bin / 'python').symlink_to('/usr/bin/python3')
            (root / 'app/config.example.ini').write_bytes((ROOT / 'config.example.ini').read_bytes())
            env = f'APP_DIR="{root}/app"; CONFIG_DIR="{root}/etc"; STATE_DIR="{root}/state"; SERVICE_USER=test\n'
            result = self.shell(SAFE_RUN + env + 'prepare_config')
            config = root / 'etc/config.ini'; cfg = configparser.ConfigParser(); cfg.read(config)
            self.assertEqual(len(cfg['flask']['secret_key']), 64)
            self.assertNotIn(cfg['flask']['secret_key'], result.stdout)
            self.assertEqual(cfg['flask']['session_file_dir'], str(root / 'state/sessions'))
            self.assertEqual(config.stat().st_mode & 0o777, 0o640)
            self.assertEqual((root / 'state/sessions').stat().st_mode & 0o777, 0o700)
            config.write_text(config.read_text() + '\n# keep my settings\n')
            before = config.read_bytes()
            self.shell(SAFE_RUN + env + 'prepare_config')
            self.assertEqual(config.read_bytes(), before)

    def test_rejects_symlink_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'etc').mkdir(); (root / 'private').write_text('do not replace')
            (root / 'etc/config.ini').symlink_to(root / 'private')
            result = self.shell(SAFE_RUN + f'CONFIG_DIR="{root}/etc"; STATE_DIR="{root}/state"; SERVICE_USER=test; prepare_config', check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / 'private').read_text(), 'do not replace')

    def test_installs_both_service_types_and_backs_up_previous_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for mode in ['systemd', 'sysv']:
                env = f'SELECTED_INIT={mode}; SYSTEMD_DIR="{root}/systemd"; SYSV_DIR="{root}/sysv"\n'
                self.shell(SAFE_RUN + env + 'install_service')
                target = root / ('systemd/pdnsadmin.service' if mode == 'systemd' else 'sysv/pdnsadmin')
                self.assertIn('pdnsadmin', target.read_text())
                self.assertNotIn('www-data', target.read_text())
                target.write_text('previous service')
                self.shell(SAFE_RUN + env + 'install_service')
                backups = list(target.parent.glob(target.name + '.bak.*'))
                self.assertEqual(len(backups), 1)
                self.assertEqual(backups[0].read_text(), 'previous service')

    def test_stdin_and_standalone_download_without_git(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / 'project.tar.gz'
            required = ['pdnsadmin-z.py', 'dns_filters.py', 'scripts/pdnsadmin-rpz', 'template/filters.html', 'wsgi.py', 'gunicorn.conf.py', 'requirements.txt',
                        'config.example.ini', 'README.md', 'install.sh', 'init/pdnsadmin',
                        'systemd/pdnsadmin.service', 'template/dashboard.html',
                        'template/login.html', 'template/review.html']
            with tarfile.open(archive, 'w:gz') as tar:
                for name in required:
                    tar.add(ROOT / name, arcname='pdnsadmin-z/' + name)
            env = dict(os.environ, PDNS_TEST_ARCHIVE=str(archive))
            wrapper = r"""curl() { cp "$PDNS_TEST_ARCHIVE" "${@: -1}"; }; export -f curl
"""
            standalone = root / 'install.sh'; standalone.write_bytes(INSTALLER.read_bytes())
            for mode in ['stdin', 'standalone']:
                command = 'bash -s --' if mode == 'stdin' else 'bash "$1"'
                result = subprocess.run(['bash', '-c', wrapper + command +
                                         ' --dry-run --init sysv --no-packages',
                                         'test', str(standalone)],
                                        input=INSTALLER.read_text() if mode == 'stdin' else None,
                                        text=True, capture_output=True, env=env, check=True)
                self.assertIn('Descargando pdnsadmin-z', result.stdout)
                self.assertIn('pip check', result.stdout)
                self.assertNotIn('git clone', result.stdout)
                # The extracted project must be removed by the EXIT trap.
                import re
                download = re.search(r'/tmp/pdnsadmin-source\.[A-Za-z0-9]+', result.stdout)
                self.assertIsNotNone(download)
                self.assertFalse(Path(download.group()).exists())

    def test_failed_download_stops_before_installing(self):
        wrapper = 'curl() { return 22; }; export -f curl; bash -s -- --dry-run --init systemd'
        result = subprocess.run(['bash', '-c', wrapper], input=INSTALLER.read_text(),
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('apt-get install', result.stdout)
        self.assertNotIn('pip install', result.stdout)

    def test_active_service_is_rejected_before_changes(self):
        result = self.shell('systemd_running() { return 0; }; systemctl() { return 0; }; check_running_services', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('está activo', result.stderr)

    def test_application_copy_allowlist_excludes_private_files(self):
        plan = self.shell('DRY_RUN=1; APP_DIR=/tmp/pdnsadmin-install-test; copy_application').stdout
        self.assertIn('config.example.ini', plan)
        self.assertNotIn('/config.ini ', plan)
        self.assertNotIn('privkey.pem', plan)
        self.assertNotIn('.zip ', plan)
        self.assertNotIn('/.git', plan)


if __name__ == '__main__':
    unittest.main()
