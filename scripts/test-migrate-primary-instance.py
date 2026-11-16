#!/usr/bin/env python3
"""Test the primary rename transaction without accessing launchd or a real phone."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('migration', ROOT / 'scripts/migrate-primary-instance.py')
if SPEC is None or SPEC.loader is None:
    raise RuntimeError('Migration module is missing')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
PREFIX = MODULE.PREFIX


class PrimaryMigrationTests(unittest.TestCase):
    """Keep two phones isolated through migration and rollback."""

    def setUp(self):
        """Create a legacy default and an unrelated i12 in one fake home."""
        self.tmp = tempfile.TemporaryDirectory(prefix='iphone-primary-test-')
        self.home = Path(self.tmp.name).resolve()
        self.base = self.home / '.iphone-use'
        self.agents = self.home / 'Library/LaunchAgents'
        self.agents.mkdir(parents=True)
        (self.home / 'Applications').mkdir()
        for relative in ['auth', 'wifi-paired/device', 'runner-build', 'runner', 'bin', 'instances/i12']:
            (self.base / relative).mkdir(parents=True)
        for relative in ['auth/secret', 'wifi-paired/device/pairing.json', 'runner-build/product',
                         'runner/shared-source', 'bin/ocr', 'instances/i12/secret']:
            (self.base / relative).write_bytes(b'fixture data: ' + relative.encode())
        (self.base / 'setup-runner.sh').write_text('# fixture helper\n')
        (self.base / 'uninstall.sh').write_text('# fixture uninstall\n')
        (self.base / 'runner-product.json').write_text(json.dumps({
            'product': str(self.base / 'runner-build/product'), 'source': str(self.base / 'runner')}))
        self.originals = {}
        binary = str(self.home / 'Applications/iPhoneUse.app/Contents/MacOS/iphone-use')
        for label, args, env in [
            (PREFIX, [binary, 'serve'], {'IPHONE_USE_PORT': '44321', 'IPHONE_USE_AGENT_TOKEN': 'fixture-agent',
                                       'IPHONE_USE_UDID': 'AABB', 'IPHONE_USE_CUSTOM': 'keep-me'}),
            (PREFIX + '.runner', ['/bin/bash', str(self.base / 'setup-runner.sh')],
             {'IPU_RUNNER_PORT': '8100', 'MJPEG_PORT': '9100', 'IPU_RUNNER_TEAM_ID': 'FIXTURE'})]:
            raw = plistlib.dumps({'Label': label, 'ProgramArguments': args, 'EnvironmentVariables': env})
            path = self.agents / (label + '.plist')
            path.write_bytes(raw);path.chmod(0o600)
            self.originals[path] = raw
        self.active = {PREFIX}
        self.disabled = {PREFIX + '.runner'}

    def tearDown(self):
        """Remove the private fake home."""
        self.tmp.cleanup()

    def run_command(self, args, check=True):
        """Emulate only the launchctl and plist validation operations used here."""
        code = 0; output = ''
        if args[0] == 'launchctl':
            action = args[1];label = args[-1].rsplit('/', 1)[-1]
            if action == 'print-disabled':
                output = '\n'.join('"' + item + '" => disabled' for item in sorted(self.disabled))
            elif action == 'print':
                code = 0 if label in self.active else 1
            elif action == 'bootout':
                self.active.discard(label)
            elif action == 'disable':
                self.disabled.add(label)
            elif action == 'enable':
                self.disabled.discard(label)
            elif action == 'bootstrap':
                config = plistlib.loads(Path(args[-1]).read_bytes())
                self.active.add(config['Label'])
        elif args[0] == 'plutil':
            plistlib.loads(Path(args[-1]).read_bytes())
        else:
            raise RuntimeError('Unexpected test command')
        if check and code:
            raise subprocess.CalledProcessError(code, args)
        return subprocess.CompletedProcess(args, code, output, '')

    def status(self, config):
        """Return only safe paused-phone status for the selected fake daemon."""
        return {'instance': config['EnvironmentVariables'].get('IPHONE_USE_INSTANCE', 'default'),
                'released': True, 'runner': False, 'runner_parked': False, 'owner': None, 'viewer_count': 0}

    def execute(self, failure=False):
        """Exercise the production migration with system calls isolated."""
        with patch.object(MODULE, 'run', self.run_command), patch.object(MODULE, 'status', self.status), \
                patch.object(MODULE, 'verify_daemon_job'), patch.object(MODULE.signal, 'signal'), \
                contextlib.redirect_stdout(io.StringIO()):
            if failure:
                with patch.object(MODULE, 'wait_status', side_effect=RuntimeError('fixture readiness failure')):
                    MODULE.migrate(self.home, 'i16', True)
            else:
                MODULE.migrate(self.home, 'i16', True)

    def test_preview_is_read_only(self):
        """Dry-run never changes files or launchd."""
        with contextlib.redirect_stdout(io.StringIO()):
            MODULE.migrate(self.home, 'i16', False)
        self.assertFalse((self.base / 'instances/i16').exists())
        self.assertTrue(all(path.read_bytes() == raw for path, raw in self.originals.items()))

    def test_migration_keeps_credentials_cache_ports_and_peer(self):
        """Rename identity and state paths while retaining actual phone data."""
        self.execute()
        target = self.base / 'instances/i16'
        self.assertEqual((self.base / 'primary-instance').read_text(), 'i16\n')
        for relative in ['auth/secret', 'wifi-paired/device/pairing.json', 'runner-build/product', 'bin/ocr']:
            self.assertEqual((target / relative).read_bytes(), b'fixture data: ' + relative.encode())
            self.assertFalse((self.base / relative).exists())
        for relative in ['runner/shared-source', 'instances/i12/secret']:
            self.assertEqual((self.base / relative).read_bytes(), b'fixture data: ' + relative.encode())
        cache = json.loads((target / 'runner-product.json').read_text())
        self.assertEqual(cache, {'product': str(target / 'runner-build/product'), 'source': str(self.base / 'runner')})
        config = plistlib.loads((self.agents / (PREFIX + '.i16.plist')).read_bytes())
        env = config['EnvironmentVariables']
        self.assertEqual([env[key] for key in ['IPHONE_USE_PORT', 'IPU_RUNNER_PORT', 'MJPEG_PORT']],
                         ['44321', '8100', '9100'])
        self.assertEqual(env['IPHONE_USE_CUSTOM'], 'keep-me')
        self.assertEqual(env['IPHONE_USE_AGENT_TOKEN'], 'fixture-agent')
        self.assertEqual(self.active, {PREFIX + '.i16'})
        self.assertIn(PREFIX + '.runner.i16', self.disabled)

    def test_failed_start_rolls_back_identity_and_all_moved_data(self):
        """Readiness failure restores the legacy phone and its original paths."""
        with self.assertRaisesRegex(RuntimeError, 'fixture readiness failure'):
            self.execute(failure=True)
        self.assertTrue(all(path.read_bytes() == raw for path, raw in self.originals.items()))
        self.assertFalse((self.base / 'primary-instance').exists())
        self.assertFalse((self.base / 'instances/i16').exists())
        self.assertEqual(self.active, {PREFIX})
        self.assertEqual((self.base / 'auth/secret').read_bytes(), b'fixture data: auth/secret')
        cache = json.loads((self.base / 'runner-product.json').read_text())
        self.assertEqual(cache['product'], str(self.base / 'runner-build/product'))

    def test_conflicting_destination_is_never_overwritten(self):
        """Existing state is never merged with the renamed phone."""
        (self.base / 'instances/i16').mkdir()
        with self.assertRaisesRegex(RuntimeError, 'Destination already exists'):
            self.execute()
        self.assertTrue((self.base / 'auth/secret').exists())

    def test_interrupt_immediately_after_auth_rename_restores_credentials(self):
        """A signal after the atomic rename cannot leave credentials in the target."""
        rename = MODULE.os.rename
        interrupted = False

        def inject(source, destination):
            """Raise immediately after moving auth, before control returns to the caller."""
            nonlocal interrupted
            rename(source, destination)
            if Path(source) == self.base / 'auth' and not interrupted:
                interrupted = True
                raise MODULE.MigrationInterrupted('fixture post-rename interrupt')

        with patch.object(MODULE.os, 'rename', inject):
            with self.assertRaisesRegex(MODULE.MigrationInterrupted, 'fixture post-rename'):
                self.execute()
        self.assertEqual((self.base / 'auth/secret').read_bytes(), b'fixture data: auth/secret')
        self.assertEqual(self.active, {PREFIX})
        self.assertFalse((self.base / 'instances/i16').exists())

    def test_readiness_does_not_swallow_cancellation(self):
        """Migration cancellation must bypass ordinary socket retry handling."""
        with patch.object(MODULE, 'status', side_effect=MODULE.MigrationInterrupted('cancel')):
            with self.assertRaises(MODULE.MigrationInterrupted):
                MODULE.wait_status({}, 'i16')

    def test_loaded_disabled_daemon_stays_loaded_disabled(self):
        """Persistent disablement is restored after bootstrap, including rollback."""
        self.disabled.add(PREFIX)
        self.execute()
        self.assertIn(PREFIX + '.i16', self.active)
        self.assertIn(PREFIX + '.i16', self.disabled)

    def test_state_directory_override_is_removed_or_rejected(self):
        """A renamed identity must never keep pointing at the old auth directory."""
        config = plistlib.loads(next(iter(self.originals.values())))
        config['EnvironmentVariables']['IPHONE_USE_STATE_DIR'] = str(self.base)
        updated = MODULE.renamed_config(config, self.home, 'i16', ['auth'])
        self.assertNotIn('IPHONE_USE_STATE_DIR', updated['EnvironmentVariables'])
        config['EnvironmentVariables']['IPHONE_USE_STATE_DIR'] = '/custom/phone-data'
        with self.assertRaisesRegex(RuntimeError, 'Custom state directory'):
            MODULE.renamed_config(config, self.home, 'i16', ['auth'])

    def test_ipv6_status_probe_normalizes_brackets_and_wildcards(self):
        """Preserved IPv6 bind settings yield a valid local health-check URL."""
        for host in ['::1', '[::1]', '::', '[::]']:
            with self.subTest(host=host):
                response = io.BytesIO(b'{}')
                response.status = 200
                config = {'EnvironmentVariables': {'IPHONE_USE_HOST': host, 'IPHONE_USE_PORT': '44321'}}
                with patch.object(MODULE.urllib.request, 'urlopen', return_value=response) as opener:
                    MODULE.status(config)
                self.assertEqual(opener.call_args.args[0].full_url, 'http://[::1]:44321/agent/status')


if __name__ == '__main__':
    unittest.main()
