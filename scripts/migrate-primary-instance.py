#!/usr/bin/env python3
"""Rename a paused legacy default installation without copying another phone's data."""

import argparse
import copy
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import subprocess
import tempfile
import time
import urllib.request

PREFIX = 'com.leeguoo.iphone-use'
SHARED = {'instances', 'runner', 'primary-instance', 'auto-update.disabled',
          '.shared-app-install-lock'}
RESERVED = {'default', 'runner', 'wda', 'autoupdate', 'daily-maintenance', 'flow-reverify'}


class MigrationInterrupted(RuntimeError):
    """An explicit cancellation that must never be treated as a network retry."""


def require(condition, message):
    """Reject an unsafe migration before continuing."""
    if not condition:
        raise RuntimeError(message)


def run(args, check=True):
    """Run an exact local command without printing its configuration."""
    return subprocess.run(args, check=check, capture_output=True, text=True)


def write_private(path, raw):
    """Atomically replace a private configuration file."""
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def paths(home, name):
    """Derive the named paths without accepting an arbitrary destination."""
    require(re.fullmatch('[a-z][a-z0-9-]{0,31}', name) and name not in RESERVED,
            'Expected a non-reserved named instance')
    base = home / '.iphone-use'
    return base, base / 'instances' / name, home / 'Library/LaunchAgents'


def renamed_config(original, home, name, moved):
    """Preserve all settings, changing only identity and relocated file paths."""
    base, target, agents = paths(home, name)
    data = copy.deepcopy(original)
    runner = data['Label'] == PREFIX + '.runner'
    require(data['Label'] in [PREFIX, PREFIX + '.runner'], 'Unexpected source label')
    data['Label'] = PREFIX + ('.runner.' if runner else '.') + name
    env = data.setdefault('EnvironmentVariables', {})
    require(env.get('IPHONE_USE_INSTANCE', 'default') == 'default', 'Source is not default')
    env['IPHONE_USE_INSTANCE'] = name
    override = env.get('IPHONE_USE_STATE_DIR', '')
    require(override in ['', str(base)], 'Custom state directory requires a separate explicit migration')
    env.pop('IPHONE_USE_STATE_DIR', None)
    env['IPHONE_USE_SETUP_BIN'] = str(home / 'Applications/iPhoneUse.app/Contents/MacOS/iphone-use')
    if runner:
        require(data.get('ProgramArguments') == ['/bin/bash', str(base / 'setup-runner.sh')],
                'Unexpected default runner program')
        data['ProgramArguments'] = ['/bin/bash', str(target / 'setup-runner.sh')]
    else:
        require(data.get('ProgramArguments') == [env['IPHONE_USE_SETUP_BIN'], 'serve'],
                'Default daemon must use the shared App')
        env['TMPDIR'] = str(target / 'tmp')
        env.setdefault('IPU_RUNNER_PORT', '8100')
        env.setdefault('MJPEG_PORT', '9100')
    for key, value in list(env.items()):
        if isinstance(value, str):
            env[key] = relocate(value, base, target, moved)
    for key in ['StandardOutPath', 'StandardErrorPath']:
        if key in data:
            data[key] = str(target / 'logs' / Path(data[key]).name)
    return data


def relocate(value, base, target, moved):
    """Rewrite paths only beneath entries that actually move, keeping shared sources."""
    if isinstance(value, str):
        for entry in sorted(moved, key=len, reverse=True):
            value = re.sub(re.escape(str(base / entry)) + r'(?=$|[/|:\s])',
                           lambda match: str(target / entry), value)
        return value
    if isinstance(value, dict):
        return {key: relocate(item, base, target, moved) for key, item in value.items()}
    if isinstance(value, list):
        return [relocate(item, base, target, moved) for item in value]
    return value


def loaded(domain, label):
    """Check whether one precise job is loaded."""
    return run(['launchctl', 'print', domain + '/' + label], check=False).returncode == 0


def stop(domain, label):
    """Boot out an exact service and wait until it is fully unloaded."""
    run(['launchctl', 'bootout', domain + '/' + label], check=False)
    for _ in range(50):
        if not loaded(domain, label):
            return
        time.sleep(0.2)
    raise RuntimeError('LaunchAgent did not unload: ' + label)


def verify_daemon_job(domain, config):
    """Verify the loaded source executable, user and argv before stopping it."""
    text = run(['launchctl', 'print', domain + '/' + config['Label']]).stdout
    program = next((line.split('=', 1)[1].strip() for line in text.splitlines()
                    if line.strip().startswith('program =')), None)
    pid = next((line.split('=', 1)[1].strip() for line in text.splitlines()
                if line.strip().startswith('pid =')), None)
    expected = config['ProgramArguments'][0]
    require(program == expected and pid and pid.isdigit() and int(pid) > 1,
            'Loaded source does not match its plist')
    process = run(['/bin/ps', '-ww', '-p', pid, '-o', 'uid=,command=']).stdout.strip().split(None, 1)
    require(len(process) == 2 and process[0] == str(os.getuid())
            and process[1] == expected + ' serve', 'Loaded source process identity mismatch')


def status(config):
    """Read authenticated status without requesting control or screen data."""
    env = config['EnvironmentVariables']
    token = env.get('IPHONE_USE_AGENT_TOKEN') or env.get('IPHONE_USE_PASSWORD')
    headers = {'Authorization': 'Bearer ' + token} if token else {}
    host = env.get('IPHONE_USE_HOST', '127.0.0.1') or '127.0.0.1'
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    host = {'0.0.0.0': '127.0.0.1', '::': '::1', '0:0:0:0:0:0:0:0': '::1'}.get(host, host)
    host = '[' + host + ']' if ':' in host else host
    request = urllib.request.Request('http://' + host + ':' + env['IPHONE_USE_PORT'] + '/agent/status',
                                     headers=headers)
    with urllib.request.urlopen(request, timeout=3) as response:
        require(response.status == 200, 'Daemon did not return HTTP 200')
        return json.load(response)


def wait_status(config, name):
    """Wait for a released daemon to start under its new identity."""
    for _ in range(60):
        try:
            data = status(config)
            require(data.get('instance') == name, 'Daemon instance mismatch')
            require(data.get('released') and not data.get('runner') and not data.get('owner')
                    and not data.get('viewer_count'), 'Migration changed the paused state')
            return {key: data.get(key) for key in ['instance', 'released', 'runner', 'runner_parked']}
        except OSError:
            time.sleep(0.5)
    raise RuntimeError('Migrated daemon did not recover')


def migrate(home, name, confirm):
    """Perform a reversible, paused-only rename with private recovery records."""
    base, target, agents = paths(home, name)
    require(home.resolve() == home and not base.is_symlink(), 'Unsafe home or state path')
    require(not target.exists() and not target.is_symlink(), 'Destination already exists')
    require(not (base / 'primary-instance').exists() and not (base / 'primary-instance').is_symlink(),
            'A primary rename already exists')
    require(not (agents / (PREFIX + '.' + name + '.plist')).exists(), 'Destination daemon exists')
    require(not (agents / (PREFIX + '.runner.' + name + '.plist')).exists(), 'Destination runner exists')
    originals = {}
    for label in [PREFIX, PREFIX + '.runner']:
        path = agents / (label + '.plist')
        require(path.is_file() and not path.is_symlink(), 'Missing or symlinked source plist')
        require(path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0,
                'Source plist must be private and owned')
        originals[label] = path.read_bytes()
    entries = [p.name for p in base.iterdir() if p.name not in SHARED]
    require(all(not (base / entry).is_symlink() for entry in entries), 'Symlinked state entry')
    configs = {label: renamed_config(plistlib.loads(raw), home, name, entries)
               for label, raw in originals.items()}
    plan = {'from': 'default', 'to': name, 'state_dir': str(target),
            'port': configs[PREFIX]['EnvironmentVariables']['IPHONE_USE_PORT'],
            'moved_entries': entries, 'shared_entries': sorted(SHARED)}
    if not confirm:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return
    domain = 'gui/' + str(os.getuid())
    for config in configs.values():
        require(not loaded(domain, config['Label']), 'Destination LaunchAgent is already loaded')
    require(loaded(domain, PREFIX), 'Source daemon must be running for read-only preflight')
    require(not loaded(domain, PREFIX + '.runner'), 'Pause the source runner before migration')
    initial = status(plistlib.loads(originals[PREFIX]))
    require(initial.get('instance') == 'default' and initial.get('released') and not initial.get('runner') and not initial.get('owner')
            and not initial.get('viewer_count'), 'Source phone must already be released')
    verify_daemon_job(domain, plistlib.loads(originals[PREFIX]))
    backup = Path(tempfile.mkdtemp(prefix='.iphone-use-primary-backup-', dir=home / 'Applications'))
    os.chmod(backup, 0o700)
    disabled_text = run(['launchctl', 'print-disabled', domain]).stdout
    disabled = {label: f'"{label}" => disabled' in disabled_text for label in originals}
    require(disabled[PREFIX + '.runner'], 'Source runner must remain disabled')
    for label, raw in originals.items():
        write_private(backup / (label + '.plist'), raw)
    write_private(backup / 'plan.json', json.dumps(plan, indent=2).encode())
    write_private(backup / 'migration.py', Path(__file__).read_bytes())
    changed = {}
    moved = []
    target_created = False
    mutated = False
    new_started = False
    written = []
    lock = base / '.shared-app-install-lock'
    lock.mkdir(mode=0o700)
    try:
        require(all((agents / (label + '.plist')).read_bytes() == raw for label, raw in originals.items()),
                'Source configuration changed during preflight')
        mutated = True
        stop(domain, PREFIX)
        (base / 'instances').mkdir(mode=0o700, exist_ok=True)
        require(not (base / 'instances').is_symlink(), 'Unsafe instances namespace')
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM, signal.SIGHUP, signal.SIGINT])
        try:
            target.mkdir(mode=0o700)
            target_created = True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        for entry in entries:
            # Register intent before the atomic rename. Rollback inspects both
            # paths, so a signal immediately after rename cannot orphan auth.
            moved.append(entry)
            os.rename(base / entry, target / entry)
        for path in target.rglob('*.json'):
            if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
                continue
            try:
                raw = path.read_bytes()
                value = json.loads(raw)
            except (ValueError, UnicodeError):
                continue
            updated = relocate(value, base, target, entries)
            if value != updated:
                relative = path.relative_to(target)
                changed[str(relative)] = raw
                saved = backup / 'changed' / relative
                saved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                write_private(saved, raw)
                write_private(path, (json.dumps(updated, ensure_ascii=False, indent=2) + '\n').encode())
        (target / 'logs').mkdir(mode=0o700, exist_ok=True)
        (target / 'tmp').mkdir(mode=0o700, exist_ok=True)
        for label, config in configs.items():
            path = agents / (config['Label'] + '.plist')
            require(not path.exists() and not path.is_symlink(), 'Destination configuration appeared concurrently')
            written.append(path)
            write_private(path, plistlib.dumps(config))
            run(['plutil', '-lint', str(path)])
            run(['launchctl', 'disable' if label.endswith('.runner') else 'enable', domain + '/' + config['Label']])
            (agents / (label + '.plist')).unlink()
            run(['launchctl', 'disable', domain + '/' + label])
        write_private(base / 'primary-instance', (name + '\n').encode())
        new_started = True
        run(['launchctl', 'bootstrap', domain, str(agents / (configs[PREFIX]['Label'] + '.plist'))])
        final = wait_status(configs[PREFIX], name)
        if disabled[PREFIX]:
            run(['launchctl', 'disable', domain + '/' + configs[PREFIX]['Label']])
        require(final['runner_parked'] == initial.get('runner_parked'), 'Parked marker changed')
        require(not loaded(domain, PREFIX) and not loaded(domain, configs[PREFIX + '.runner']['Label']),
                'Unexpected old daemon or new runner')
        plan.update({'backup': str(backup), 'status': final, 'changed_json_paths': list(changed)})
        write_private(backup / 'result.json', json.dumps(plan, indent=2).encode())
        print(json.dumps({'state_dir': str(target), 'backup': str(backup), 'status': final}))
    except BaseException:
        if not mutated:
            raise
        # A second interrupt must not abort an already-running rollback.
        for number in [signal.SIGTERM, signal.SIGHUP, signal.SIGINT]:
            signal.signal(number, signal.SIG_IGN)
        if new_started:
            stop(domain, configs[PREFIX]['Label'])
        for relative, raw in changed.items():
            write_private(target / relative, raw)
        for entry in reversed(moved):
            source, destination = target / entry, base / entry
            if source.exists() or source.is_symlink():
                require(not destination.exists() and not destination.is_symlink(),
                        'Conflicting source appeared during rollback; recovery backup retained')
                os.rename(source, destination)
        for path in written:
            path.unlink(missing_ok=True)
        (base / 'primary-instance').unlink(missing_ok=True)
        for label, raw in originals.items():
            write_private(agents / (label + '.plist'), raw)
            run(['launchctl', 'disable' if label.endswith('.runner') else 'enable', domain + '/' + label])
        if target_created:
            for empty in ['logs', 'tmp']:
                path = target / empty
                if path.is_dir() and not any(path.iterdir()):
                    path.rmdir()
            if not any(target.iterdir()):
                target.rmdir()
        run(['launchctl', 'bootstrap', domain, str(agents / (PREFIX + '.plist'))])
        if disabled[PREFIX]:
            run(['launchctl', 'disable', domain + '/' + PREFIX])
        print('Migration failed; restored source instance. Recovery records:', backup)
        raise
    finally:
        lock.rmdir()


def main():
    """Preview by default; execute the migration only with explicit confirmation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--confirm', action='store_true')
    args = parser.parse_args()
    for number in [signal.SIGTERM, signal.SIGHUP, signal.SIGINT]:
        signal.signal(number, interrupted)
    migrate(Path.home(), args.name, args.confirm)


def interrupted(number, frame):
    """Convert an install interruption into the normal reversible failure path."""
    raise MigrationInterrupted('Migration interrupted by signal ' + str(number))


if __name__ == '__main__':
    main()
