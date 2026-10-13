#!/usr/bin/env python3
# Keep the same-user example private and stop it through its own authenticated supervisor.
import argparse, contextlib, fcntl, json, os, re, socket, stat, subprocess, sys, time
from pathlib import Path
from fresh_clone import Refused, environment, preflight, prepare, runtime_command, private_log


def parse_arguments(argv):
    parser = argparse.ArgumentParser(description='Run the disposable-authority example on loopback.')
    def argument_error(message):
        code = message if re.fullmatch(r'example-[a-z-]+', message) else 'example-arguments-invalid'
        parser.exit(2, 'FAIL | ' + code + '\n')
    parser.error = argument_error
    parser.add_argument('command', choices=['up', 'down', 'approve', 'refuse', 'verify'])
    parser.add_argument('--example', action='store_true')
    parser.add_argument('--dir', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--built', type=Path)
    parser.add_argument('--port', type=int)
    parser.add_argument('--allow-dirty', action='store_true')
    seen = [word.split('=', 1)[0] for word in argv if word.startswith('--')]
    if len(seen) != len(set(seen)):
        parser.error('example-option-duplicate')
    args = parser.parse_args(argv)
    if args.command in ('up', 'down') and not args.example:
        parser.error('example-flag-required')
    if args.command not in ('up', 'down') and args.example:
        parser.error('example-option-inapplicable')
    if args.command != 'up' and (args.archive or args.built or args.port is not None or args.allow_dirty):
        parser.error('example-option-inapplicable')
    if args.port is not None and not 0 <= args.port <= 65535:
        parser.error('example-port-invalid')
    return args


def state_directory(value, checkout, create=True):
    selected = Path(value).expanduser().absolute()
    checkout = Path(checkout).resolve()
    if selected.is_symlink():
        raise Refused('example-state-symlink')
    resolved = selected.resolve()
    if resolved == checkout or checkout in resolved.parents:
        raise Refused('example-state-inside-checkout')
    # A private root can live below the shared sticky temporary directory.
    current = selected
    missing = []
    while not current.exists():
        if current.is_symlink():
            raise Refused('example-state-symlink')
        missing.append(current)
        current = current.parent
    info = current.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise Refused('example-state-not-directory')
    if missing and info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
        raise Refused('example-state-parent-writable')
    for ancestor in resolved.parents:
        if ancestor.exists():
            parent_info = ancestor.stat()
            if parent_info.st_mode & 0o022 and not parent_info.st_mode & stat.S_ISVTX:
                raise Refused('example-state-parent-writable')
    if not create and missing:
        return resolved
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
    info = selected.lstat()
    if selected.is_symlink():
        raise Refused('example-state-symlink')
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise Refused('example-state-owner-required')
    if info.st_mode & 0o077:
        raise Refused('example-state-writable-or-not-private')
    if selected.resolve() != resolved:
        raise Refused('example-state-path-changed')
    return resolved


def checkout_state(checkout, allow_dirty=False):
    env = {key: os.environ[key] for key in ('PATH', 'LANG') if key in os.environ}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
    tip = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=checkout, env=env, text=True).strip()
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=checkout, env=env))
    if dirty and not allow_dirty:
        raise Refused('example-dirty-tree: commit changes first or use --allow-dirty (NOT what is committed)')
    return tip, dirty


def read_private(file):
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise Refused('example-state-file-insecure')
        with os.fdopen(fd, 'r', closefd=False) as source:
            return json.load(source)
    finally:
        os.close(fd)


def write_private(file, value):
    temporary = file.with_name(file.name + '.tmp-' + str(os.getpid()))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps(value) + '\n').encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, file)


@contextlib.contextmanager
def state_lock(root):
    fd = os.open(root / 'example.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise Refused('example-lock-insecure')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError:
        raise Refused('example-state-busy')
    finally:
        os.close(fd)


def control(ready, op):
    port, token = ready.get('controlPort'), ready.get('controlToken')
    if not isinstance(port, int) or not 1 <= port <= 65535 or not isinstance(token, str) or not re.fullmatch(r'[a-f0-9]{64}', token):
        raise Refused('example-control-invalid')
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=2) as connection:
            connection.sendall((json.dumps({'op': op, 'token': token}) + '\n').encode())
            output = bytearray()
            while len(output) < 4096 and b'\n' not in output:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                output.extend(chunk)
        reply = json.loads(output)
    except (OSError, ValueError):
        raise Refused('example-supervisor-unavailable')
    if reply.get('ok') is not True or reply.get('supervisorPid') != ready.get('supervisorPid'):
        raise Refused('example-supervisor-identity-mismatch')
    return reply


def live_ready(root, starting=False):
    file = root / 'example-ready.json'
    if not file.exists():
        if not starting and any((root / 'support/state' / name).exists() for name in ('launch.json', 'launch-url.json')):
            raise Refused('example-supervisor-missing-with-launch-state')
        return None
    ready = read_private(file)
    if ready.get('version') != 1 or ready.get('kind') != 'aukora-prime-example/v1' or ready.get('root') != str(root) or ready.get('checkout') != str(root / 'clone') or ready.get('launchFile') != str(root / 'support/state/launch-url.json'):
        raise Refused('example-readiness-for-other-state')
    control(ready, 'status')
    return ready


def report_ready(ready, root):
    from urllib.parse import urlsplit
    address = urlsplit(ready['origin'])
    if address.scheme != 'http' or address.hostname != '127.0.0.1' or address.username or address.password or address.query or address.fragment or address.path not in ('', '/'):
        raise Refused('example-origin-invalid')
    launch = Path(ready['launchFile'])
    if launch != root / 'support/state/launch-url.json':
        raise Refused('example-launch-path-invalid')
    import shlex
    print('ADDRESS | ' + ready['origin'])
    print('SIGN-IN FILE | ' + str(launch))
    print('STOP | ./prime down --example --dir ' + shlex.quote(str(root)))
    print('REAL | boundary gate, action gate, approval path, signed ledger, release floor, screens and apps')
    print('STAND-IN | throwaway owner key on this same user; no model key (assistant cannot answer); no containment; no relay')
    print('PASS | example up', flush=True)


def up(args, checkout):
    preflight()
    tip, dirty = checkout_state(checkout, args.allow_dirty)
    if dirty:
        print('WARNING | --allow-dirty: NOT what is committed; working-tree bytes differ; existing state resumes its saved snapshot', flush=True)
    root = state_directory(args.dir or default_directory(), checkout)
    os.umask(0o077)
    with state_lock(root):
        manifest_file = root / 'example.json'
        if manifest_file.exists():
            record = read_private(manifest_file)
            if record.get('source') != str(checkout.resolve()) or record.get('sourceHead') != tip:
                raise Refused('example-state-for-other-checkout-or-head')
            clone, release = root / 'clone', Path(record['release'])
            if release.parent != root or not re.fullmatch(r'release-[a-f0-9]{7}', release.name):
                raise Refused('example-release-path-invalid')
            spec = {'checkout': clone, 'release': release, 'root': root, 'env': environment(root)}
            if record.get('dirty'):
                print('WARNING | existing example uses a private dirty snapshot; NOT what is committed', flush=True)
        else:
            if (root / 'clone').exists():
                raise Refused('example-incomplete-preparation: choose another --dir')
            spec = prepare(str(checkout), root, args.archive.resolve() if args.archive else None,
                           args.built.resolve() if args.built else None, root / 'build-cache', checkout if dirty else None)
            write_private(manifest_file, {'source': str(checkout.resolve()), 'sourceHead': tip,
                                         'release': str(spec['release']), 'dirty': dirty})
        ready = live_ready(root)
        if ready:
            if args.port and ready['origin'] != 'http://127.0.0.1:' + str(args.port):
                raise Refused('example-port-already-selected')
            report_ready(ready, root)
            return
        ready_file = root / 'example-ready.json'
        if ready_file.exists():
            ready_file.unlink()
        with private_log(root / 'runtime.log') as output:
            child = subprocess.Popen(runtime_command(spec, True, args.port), cwd=spec['checkout'], env=spec['env'],
                                     stdin=subprocess.DEVNULL, stdout=output, stderr=output, start_new_session=True)
        deadline = time.monotonic() + 100
        try:
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    log = (root / 'runtime.log').read_text(errors='replace')
                    unavailable = re.search(r'^UNPERFORMED: ([a-zA-Z0-9.-]+)$', log, re.MULTILINE)
                    if unavailable:
                        raise Refused(unavailable.group(1), True)
                    codes = re.findall(r'^FAIL\s+(?:\| )?([a-zA-Z0-9.-]+)', log, re.MULTILINE)
                    raise Refused(codes[-1] if codes else 'example-start-failed')
                ready = live_ready(root, starting=True)
                if ready:
                    report_ready(ready, root)
                    return
                time.sleep(0.1)
            raise Refused('example-start-timeout')
        finally:
            if not ready and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


def down(args, checkout):
    root = state_directory(args.dir or default_directory(), checkout, create=False)
    if not root.exists():
        print('PASS | example down (already stopped)')
        return
    with state_lock(root):
        ready = live_ready(root)
        if not ready:
            print('PASS | example down (already stopped)')
            return
        control(ready, 'stop')
        deadline = time.monotonic() + 20
        while (root / 'example-ready.json').exists():
            if time.monotonic() >= deadline:
                raise Refused('example-stop-timeout')
            time.sleep(0.1)
        print('PASS | example down')


def default_directory():
    return Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state'))) / 'aukora-prime-example'


def main(argv=None):
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    checkout = Path(__file__).resolve().parents[1]
    try:
        if args.command == 'up':
            up(args, checkout)
        elif args.command == 'down':
            down(args, checkout)
        else:
            preflight()
            root = state_directory(args.dir or default_directory(), checkout, create=False)
            if not root.exists():
                raise Refused('example-not-running')
            with state_lock(root):
                if not live_ready(root):
                    raise Refused('example-not-running')
                spec = {'checkout': root / 'clone', 'root': root}
                result = subprocess.run(['node', str(spec['checkout'] / 'scripts/example-commands.mjs'), args.command,
                                         '--root', str(root)], cwd=spec['checkout'], env=environment(root))
                return result.returncode
        return 0
    except Refused as error:
        print(('UNPERFORMED: ' if error.missing else 'FAIL | ') + error.code, flush=True)
        return 2 if error.missing else 1
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError):
        print('FAIL | example-state-or-input-invalid', flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
