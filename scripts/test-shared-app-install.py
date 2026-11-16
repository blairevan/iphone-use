#!/usr/bin/env python3
"""Exercise real installer functions with private fake homes and launchd."""

import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'install.sh').read_text()
PREFIX = 'com.leeguoo.iphone-use'


def function(name):
    """Extract a production shell function, including its heredocs."""
    match = re.search(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
    if not match:
        raise RuntimeError('Missing installer function: ' + name)
    return match.group()


class SharedAppTests(unittest.TestCase):
    """Verify updates, rollback and inactive instances without touching the machine."""

    def setUp(self):
        """Create two independent instances and fake launchd command state."""
        self.temporary = tempfile.TemporaryDirectory(prefix='iphone-shared-install-')
        self.home = Path(self.temporary.name).resolve()
        self.agents = self.home / 'Library/LaunchAgents'
        self.agents.mkdir(parents=True)
        self.app = self.home / 'Applications/iPhoneUse.app'
        (self.app / 'Contents/MacOS').mkdir(parents=True)
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': PREFIX}))
        binary = self.app / 'Contents/MacOS/iphone-use'
        binary.write_text('''#!/usr/bin/env python3
import os, pathlib, plistlib, json, sys
name=os.environ.get('IPHONE_USE_INSTANCE','default')
if sys.argv[1:]==['instance-context']:
 print(json.dumps({'name':name}));sys.exit(0)
if '--supports' in sys.argv:sys.exit(0)
home=pathlib.Path.home();state=home/'.iphone-use/instances'/name
label='com.leeguoo.iphone-use.'+name
p=home/'Library/LaunchAgents'/(label+'.plist')
e=plistlib.loads(p.read_bytes())['EnvironmentVariables'] if p.exists() else {}
for key,value in {'name':name,'state_dir':state,'daemon_label':label,
 'runner_label':'com.leeguoo.iphone-use.runner.'+name,'daemon_plist':p,
 'daemon_port':e.get('IPHONE_USE_PORT','45888'),'runner_port':e.get('IPU_RUNNER_PORT','8500'),
 'mjpeg_port':e.get('MJPEG_PORT','9500'),'udid':e.get('IPHONE_USE_UDID','AABB')}.items():print(str(key)+'='+str(value))
''')
        binary.chmod(0o700)
        self.jobs = {}
        for name, ports in [('i16', [44321, 8100, 9100]), ('i12', [45710, 8410, 9410])]:
            state = self.home / '.iphone-use/instances' / name
            state.mkdir(parents=True)
            (state / 'auth').mkdir()
            (state / 'auth/secret').write_bytes(b'fixture-local-identity')
            (state / 'runner-parked').touch()
            (state / 'setup-runner.sh').write_text('previous helper\n')
            env = {'IPHONE_USE_INSTANCE': name, 'IPHONE_USE_PORT': str(ports[0]),
                   'IPU_RUNNER_PORT': str(ports[1]), 'MJPEG_PORT': str(ports[2]),
                   'IPHONE_USE_UDID': 'AABB' if name == 'i16' else 'CCDD',
                   'IPHONE_USE_AGENT_TOKEN': 'fixture-' + name,
                   'IPHONE_USE_CUSTOM_SETTING': 'keep-' + name}
            daemon = {'Label': PREFIX + '.' + name, 'ProgramArguments': [str(binary), 'serve'],
                      'EnvironmentVariables': env}
            runner = {'Label': PREFIX + '.runner.' + name,
                      'ProgramArguments': ['/bin/bash', str(state / 'setup-runner.sh')],
                      'EnvironmentVariables': {'IPHONE_USE_INSTANCE': name, 'IPU_RUNNER_PORT': str(ports[1]),
                      'MJPEG_PORT': str(ports[2]), 'IPHONE_USE_SETUP_BIN': str(binary)}}
            for config, active in [(daemon, True), (runner, False)]:
                label = config['Label']
                path = self.agents / (label + '.plist')
                path.write_bytes(plistlib.dumps(config));path.chmod(0o600)
                self.jobs[label] = {'loaded': active, 'disabled': not active,
                                    'path': str(path), 'program': config['ProgramArguments'][0]}
        self.state = self.home / 'fake-launchd.json'
        self.state.write_text(json.dumps(self.jobs))
        self.tools = self.home / 'tools'
        self.tools.mkdir()
        launchctl = self.tools / 'launchctl'
        launchctl.write_text('''#!/usr/bin/env python3
import json,os,pathlib,plistlib,sys
p=pathlib.Path(os.environ['FAKE_JOBS']);d=json.loads(p.read_text());a=sys.argv[1:];label=a[-1].rsplit('/',1)[-1]
with open(os.environ['FAKE_EVENTS'],'a') as out:out.write(' '.join(a)+'\\n')
if a[0]=='print-disabled':
 for k,v in d.items():print('"'+k+'" => '+('disabled' if v['disabled'] else 'enabled'))
elif a[0]=='print':
 if label not in d or not d[label]['loaded']:sys.exit(1)
 pathlib.Path(os.environ['FAKE_ACTIVE_JOB']).write_text(label)
 print('pid = 4242\\nprogram = '+d[label]['program'])
 print('IPHONE_USE_INSTANCE => '+label.rsplit('.',1)[-1])
elif a[0]=='bootout':
 if label in d:d[label]['loaded']=False
elif a[0]=='bootstrap':
 f=pathlib.Path(a[-1]);v=plistlib.loads(f.read_bytes());label=v['Label']
 d.setdefault(label,{'disabled':False});d[label].update(loaded=True,path=str(f),program=v['ProgramArguments'][0])
elif a[0] in ['enable','disable']:
 d.setdefault(label,{'loaded':False});d[label]['disabled']=a[0]=='disable'
p.write_text(json.dumps(d))
''')
        launchctl.chmod(0o700)
        ps = self.tools / 'ps'
        ps.write_text('''#!/usr/bin/env python3
import json,os,pathlib,plistlib,sys
if 'uid=' in sys.argv: print(os.getuid())
else:
 label=pathlib.Path(os.environ['FAKE_ACTIVE_JOB']).read_text()
 data=json.loads(pathlib.Path(os.environ['FAKE_JOBS']).read_text())[label]
 args=plistlib.loads(pathlib.Path(data['path']).read_bytes())['ProgramArguments']
 print(data.get('command_override') or ' '.join(args))
''')
        ps.chmod(0o700)
        for name, script in [('codesign', 'exit 0'), ('ditto', '/bin/cp -R "$1" "$2"'), ('sleep', 'exit 0')]:
            path = self.tools / name
            path.write_text('#!/bin/bash\n' + script + '\n');path.chmod(0o700)

    def tearDown(self):
        """Remove only this test's private temporary home."""
        self.temporary.cleanup()

    def invoke(self, fail_peer=False):
        """Run the real named installer with mocked device and process probes."""
        names = ['shared_app_stop_peers', 'shared_app_start_peers', 'shared_app_restore_peers',
                 'shared_app_prepare', 'shared_app_verify_job', 'daemon_probe_host',
                 'launchd_label_is_disabled', '_restore_launchd_job', 'plist_env_get_from',
                 'legacy_env_names', 'named_plist_env', 'plist_own_env_keys', 'install_named_instance']
        script = '\n'.join(function(name) for name in names)
        script += '''
set -eu
INSTALL_DIR="$HOME/Applications"; APP_NAME=iPhoneUse.app; BUNDLE_ID=com.leeguoo.iphone-use
BINARY_INSIDE_APP=Contents/MacOS/iphone-use; MCP_BINARY_INSIDE_APP=Contents/MacOS/iphone-use-mcp
INSTANCE_NAME=i16; INSTANCE_UDID=""; INSTANCE_PORT=""; UID_NUM=$(id -u)
PLIST_LABEL=com.leeguoo.iphone-use; RUNNER_SETTINGS_PLIST="$HOME/Library/LaunchAgents/$PLIST_LABEL.runner.plist"
SCRIPT_IS_LOCAL=1; SCRIPT_DIR="$TEST_REPO"; RUNNER_SRC_DST="$HOME/.iphone-use/runner"
SHARED_APP_PEERS=""; SHARED_APP_LOCK=""; SHARED_APP_PEERS_COMMITTED=0; NAMED_ROLLBACK_PENDING=0
SHARED_APP_PEERS_TOUCHED=0; LAUNCHD_DISABLED_SNAPSHOT=""
BOLD=""; RESET=""
info() { :; }; ok() { :; }; warn() { printf '%s\\n' "$*" >&2; }; die() { warn "$*"; exit 1; }
setup_auto_update() { :; }; retire_pre_rename_runner() { :; }; runner_tree_valid() { return 0; }
install_runner_sources() { [ "${FAIL_SOURCES:-0}" != 1 ]; }; _restore_runner_sources() { :; }; _finish_runner_sources() { :; }
first_run_interactive() { return 1; }
wait_label_gone() { ! launchctl print "$1" >/dev/null 2>&1; }
probe_launchd_daemon() { [ "${FAIL_PEER:-0}" != 1 ] || [ "$1" != "gui/$UID_NUM/com.leeguoo.iphone-use.i12" ]; }
cleanup() {
 rc=$?;trap - EXIT
 if [ "$rc" != 0 ] && [ "$NAMED_ROLLBACK_PENDING" = 1 ]; then named_restore || true; fi
 [ -z "$SHARED_APP_LOCK" ] || rmdir "$SHARED_APP_LOCK"
 exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
install_named_instance "$INSTALL_DIR/$APP_NAME"
'''
        env = {**os.environ, 'HOME': str(self.home), 'PATH': str(self.tools) + ':' + os.environ['PATH'],
               'TEST_REPO': str(ROOT), 'FAKE_JOBS': str(self.state),
               'FAKE_ACTIVE_JOB': str(self.home / 'active-job'), 'IPHONE_USE_PS_BIN': str(self.tools / 'ps'),
               'FAKE_EVENTS': str(self.home / 'events'), 'FAIL_PEER': '1' if fail_peer else '0'}
        return subprocess.run(['/bin/bash', '-c', script], env=env, capture_output=True, text=True, timeout=30)

    def test_signal_after_app_swap_rolls_back(self):
        """A TERM between App rename and plist replacement restores both instances."""
        originals = {p: p.read_bytes() for p in self.agents.iterdir()}
        mv = self.tools / 'mv'
        mv.write_text('''#!/bin/bash
/bin/mv "$@" || exit $?
case "$1" in
 *"/.iPhoneUse.app.new."*) kill -TERM "$PPID" ;;
esac
''')
        mv.chmod(0o700)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all(path.read_bytes() == raw for path, raw in originals.items()), result.stderr)
        self.assertTrue((self.app / 'Contents/MacOS/iphone-use').exists())
        self.assertEqual(json.loads(self.state.read_text()), self.jobs)

    def test_loaded_peer_identity_mismatch_stops_nothing(self):
        """A label occupied by a different loaded executable is rejected before bootout."""
        jobs = json.loads(self.state.read_text())
        jobs[PREFIX + '.i12']['program'] = '/usr/bin/unrelated'
        self.state.write_text(json.dumps(jobs))
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.state.read_text()), jobs)
        events = (self.home / 'events').read_text()
        self.assertNotIn('bootout ', events)

    def test_active_native_runner_exec_is_accepted(self):
        """A shell shim execing the pinned native engine is still the owned runner."""
        jobs = json.loads(self.state.read_text())
        runner = jobs[PREFIX + '.runner.i12']
        runner.update(loaded=True, disabled=False,
                      command_override=str(self.app / 'Contents/MacOS/iphone-use') + ' setup-native setup')
        self.state.write_text(json.dumps(jobs))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        current = json.loads(self.state.read_text())[PREFIX + '.runner.i12']
        self.assertTrue(current['loaded'])
        self.assertFalse(current['disabled'])

    def test_default_backup_rename_window_restores_missing_paths(self):
        """Rollback recognizes successful old-file renames before flags are assigned."""
        app_backup = self.home / 'old-app'
        config = self.agents / (PREFIX + '.i16.plist')
        config_backup = self.home / 'old-daemon.plist'
        original = config.read_bytes()
        self.app.rename(app_backup)
        config.rename(config_backup)
        script = function('_restore_app') + '\n' + function('_restore_daemon_plist') + '''
APP_COMMITTED=0; APP_REPLACED=0; APP_HAD_EXISTING=1
PLIST_COMMITTED=0; PLIST_REPLACED=0; PLIST_HAD_EXISTING=1
warn() { :; }
_restore_app
_restore_daemon_plist
'''
        result = subprocess.run(['/bin/bash', '-eu', '-c', script], capture_output=True, text=True,
                                env={**os.environ, 'APP_BACKUP': str(app_backup), 'DEST': str(self.app),
                                     'PLIST_BACKUP': str(config_backup), 'PLIST_DST': str(config)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.app / 'Contents/MacOS/iphone-use').is_file())
        self.assertEqual(config.read_bytes(), original)

    def test_ipv6_probe_host_normalizes_existing_brackets(self):
        """Both forms of loopback and wildcard IPv6 produce one bracket pair."""
        script = function('daemon_probe_host') + '\ndaemon_probe_host "$1"'
        for host in ['::1', '[::1]', '::', '[::]']:
            with self.subTest(host=host):
                result = subprocess.run(['/bin/bash', '-c', script, 'fixture', host],
                                        capture_output=True, text=True, check=True)
                self.assertEqual(result.stdout, '[::1]')

    def test_reinstall_keeps_shared_app_and_private_data(self):
        """Repeated installs retain ports and credentials without private App copies."""
        for _ in range(2):
            result = self.invoke()
            self.assertEqual(result.returncode, 0, result.stderr)
        for name, ports in [('i16', ['44321', '8100', '9100']), ('i12', ['45710', '8410', '9410'])]:
            data = plistlib.loads((self.agents / (PREFIX + '.' + name + '.plist')).read_bytes())
            env = data['EnvironmentVariables']
            self.assertEqual(data['ProgramArguments'][0], str(self.app / 'Contents/MacOS/iphone-use'))
            self.assertEqual([env[key] for key in ['IPHONE_USE_PORT', 'IPU_RUNNER_PORT', 'MJPEG_PORT']], ports)
            self.assertEqual(env['IPHONE_USE_AGENT_TOKEN'], 'fixture-' + name)
            self.assertEqual(env['IPHONE_USE_CUSTOM_SETTING'], 'keep-' + name)
            state = self.home / '.iphone-use/instances' / name
            self.assertEqual((state / 'auth/secret').read_bytes(), b'fixture-local-identity')
            self.assertTrue((state / 'runner-parked').exists())
            self.assertFalse((state / 'runtime/iPhoneUse.app').exists())
        jobs = json.loads(self.state.read_text())
        for name in ['i16', 'i12']:
            self.assertTrue(jobs[PREFIX + '.' + name]['loaded'])
            self.assertFalse(jobs[PREFIX + '.runner.' + name]['loaded'])
            self.assertTrue(jobs[PREFIX + '.runner.' + name]['disabled'])

    def test_peer_failure_restores_every_plist_and_app(self):
        """A failing shared consumer rolls back both target and sibling configuration."""
        originals = {p: p.read_bytes() for p in self.agents.iterdir()}
        binary = self.app / 'Contents/MacOS/iphone-use'
        original_binary = binary.read_bytes()
        result = self.invoke(fail_peer=True)
        self.assertNotEqual(result.returncode, 0)
        for path, raw in originals.items():
            self.assertEqual(path.read_bytes(), raw, path.name)
        self.assertEqual(binary.read_bytes(), original_binary)
        self.assertEqual((self.home / '.iphone-use/instances/i16/setup-runner.sh').read_text(), 'previous helper\n')
        self.assertEqual(json.loads(self.state.read_text()), self.jobs)

    def test_disabled_target_is_not_started(self):
        """Updating an unloaded disabled target does not activate its phone."""
        jobs = json.loads(self.state.read_text())
        jobs[PREFIX + '.i16'].update(loaded=False, disabled=True)
        self.state.write_text(json.dumps(jobs))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        current = json.loads(self.state.read_text())[PREFIX + '.i16']
        self.assertFalse(current['loaded'])
        self.assertTrue(current['disabled'])

    def test_foreign_lock_is_retained(self):
        """A competing transaction must not remove the existing install lock."""
        lock = self.home / '.iphone-use/.shared-app-install-lock'
        lock.mkdir()
        originals = {p: p.read_bytes() for p in self.agents.iterdir()}
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(lock.is_dir())
        self.assertTrue(all(p.read_bytes() == raw for p, raw in originals.items()))


if __name__ == '__main__':
    unittest.main()
