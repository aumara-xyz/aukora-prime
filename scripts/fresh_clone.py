# Verify pinned acquisition and materialization in a private snapshot.
import hashlib, json, os, re, shutil, signal, stat, subprocess, time, urllib.error, urllib.request
from pathlib import Path

work = None
rows = []

class Refused(Exception):
    def __init__(self, code, missing=False):
        self.code, self.missing = code, missing

def passed(name):
    rows.append(('PASS', name))
    print('PASS | ' + name, flush=True)

def private_log(file):
    try:
        fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise Refused('example-log-path-insecure')
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
        os.close(fd)
        raise Refused('example-log-path-insecure')
    os.ftruncate(fd, 0)
    return os.fdopen(fd, 'w')


def run(command, name, cwd, env, timeout=660):
    log = work / (name + '.log')
    with private_log(log) as output:
        child = None
        try:
            child = subprocess.Popen(command, cwd=cwd, env=env, stdout=output, stderr=output, start_new_session=True)
            deadline = time.monotonic() + timeout
            while child.poll() is None:
                if time.monotonic() >= deadline:
                    raise Refused(name + '-timeout')
                if name == 'build' and time.monotonic() > deadline - timeout + 30:
                    if re.search(r'ENOTFOUND|EAI_AGAIN|ENETUNREACH|ERR_PNPM_META_FETCH_FAIL', log.read_text(errors='replace')):
                        raise Refused('build-dependency-install-network-unavailable', True)
                time.sleep(0.1)
        except FileNotFoundError:
            raise Refused(name + '-tool-unavailable', True)
        finally:
            if child and child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=45 if name == 'runtime' else 10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
    if child.returncode:
        text = log.read_text(errors='replace')
        missing = re.search(r'^UNPERFORMED: ([a-zA-Z0-9.-]+)$', text, re.MULTILINE)
        if name == 'runtime' and child.returncode == 2 and missing:
            raise Refused(missing.group(1), True)
        if re.search(r'EPERM|Operation not permitted', text) and name == 'runtime':
            raise Refused('loopback-or-ipc-listen-EPERM', True)
        if re.search(r'ENOTFOUND|EAI_AGAIN|ENETUNREACH|ECONNREFUSED|ETIMEDOUT|ERR_PNPM_META_FETCH_FAIL|URLError|Temporary failure in name resolution', text):
            raise Refused(name + '-network-unavailable', True)
        # Emit refusal names, never subprocess logs, launch tokens, keys or endpoint addresses.
        codes = re.findall(r'\b(?:[a-z][a-z0-9]*-){2,}[a-z0-9]+(?=:)', text)
        raise Refused(name + '-failed' + (':' + codes[-1] if codes else ''))

def verify_archive(path, pin):
    if not path.is_file():
        raise Refused('archive-unavailable', True)
    if hashlib.sha256(path.read_bytes()).hexdigest() != pin['archiveSha256']:
        raise Refused('source-digest-mismatch')

def verify_built(path, clone, env):
    run(['python3', str(clone / 'scripts/build-dsh.py'), '--verify-built', '--source', str(path)],
        'build-binding', clone, env)

def preflight():
    for tool in ('node', 'python3', 'git'):
        if shutil.which(tool) is None:
            raise Refused(tool + '-unavailable', True)
    tool_env = dict((name, os.environ[name]) for name in ('PATH', 'LANG') if name in os.environ)
    version = subprocess.check_output(['node', '--version'], env=tool_env, text=True).strip()
    if version != 'v24.11.1':
        raise Refused('node-24.11.1-required', True)

def environment(root):
    global work
    work = root
    home = work / 'home'
    home.mkdir(mode=0o700, exist_ok=True)
    temporary = work / 'tmp'
    temporary.mkdir(mode=0o700, exist_ok=True)
    for directory in (home, temporary):
        info = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Refused('example-environment-path-insecure')
    env = {key: os.environ[key] for key in ('PATH', 'LANG') if key in os.environ}
    env.update(HOME=str(home), TMPDIR=str(temporary), XDG_CACHE_HOME=str(home / '.cache'),
               XDG_CONFIG_HOME=str(home / '.config'), CI='true', PYTHONDONTWRITEBYTECODE='1',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0',
               npm_config_fetch_retries='0')
    return env


def prepare(source, root, archive_input=None, built_input=None, cache=None, dirty_source=None):
    global work
    work = root
    env = environment(root)
    clone = work / 'clone'
    run(['git', 'clone', '--quiet', '--no-local', '--', source, str(clone)], 'clone', work, env)
    if dirty_source:
        snapshot_dirty(dirty_source, clone, env)
    passed('isolated clone (committed HEAD only)' if not dirty_source else 'private dirty snapshot (NOT committed checkout bytes)')
    pin = json.loads((clone / 'upstream-dsh.json').read_text())
    vendor = clone / 'vendor'
    vendor.mkdir(exist_ok=True)
    archive = vendor / 'dsh-source.tar.gz'
    if cache:
        cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        if cache.is_symlink() or cache.stat().st_uid != os.getuid() or cache.stat().st_mode & 0o022:
            raise Refused('cache-path-insecure')
    cached_archive = cache / (pin['archiveSha256'] + '.tar.gz') if cache else None
    supplied = archive_input or (cached_archive if cached_archive and cached_archive.is_file() else None)
    if supplied:
        verify_archive(supplied, pin)
        shutil.copyfile(supplied, archive)
    else:
        try:
            with urllib.request.urlopen(pin['archiveUrl'], timeout=60) as response, archive.open('wb') as output:
                shutil.copyfileobj(response, output)
        except (urllib.error.URLError, TimeoutError, OSError):
            raise Refused('archive-download-network-unavailable', True)
    verify_archive(archive, pin)
    passed('archive SHA-256 matches pin')
    if cached_archive and not cached_archive.exists():
        shutil.copyfile(archive, cached_archive)
    cache_inputs = ['upstream-dsh.json', 'scripts/build-dsh.py', 'scripts/artifact-record.mjs',
                    'scripts/artifacts-coverage.json', 'scripts/lib/artifact-integrity.mjs']
    digest = hashlib.sha256()
    for relative in cache_inputs:
        digest.update((clone / relative).read_bytes())
    platform = subprocess.check_output(['node', '-p', 'process.platform+"-"+process.arch'], env=env, text=True).strip()
    cache_build = cache / (platform + '-node24.11.1-' + digest.hexdigest()) if cache else None
    harness = clone / 'vendor/dsh'
    if built_input:
        verify_built(built_input, clone, env)
        harness = built_input
        print('SKIP | harness build (--built; fresh build NOT PROVED)', flush=True)
    elif cache_build and cache_build.is_dir():
        verify_built(cache_build, clone, env)
        shutil.copytree(cache_build, harness, symlinks=True)
        verify_built(harness, clone, env)
        print('SKIP | harness build (verified cache hit)', flush=True)
    else:
        if shutil.which('pnpm') is None:
            raise Refused('pnpm-unavailable', True)
        manager = subprocess.check_output(['pnpm', '--version'], env=env, text=True).strip()
        if 'pnpm@' + manager != pin['packageManager']:
            raise Refused('pinned-pnpm-required', True)
        if shutil.which('cc') is None:
            raise Refused('native-build-C-compiler-unavailable', True)
        node = Path(shutil.which('node')).resolve()
        if not (node.parent.parent / 'include/node/node_api.h').is_file():
            raise Refused('native-build-node-headers-unavailable', True)
        run(['python3', str(clone / 'scripts/build-dsh.py')], 'build', clone, env)
        verify_built(harness, clone, env)
        passed('pinned harness installed and built')
        if cache_build:
            shutil.copytree(harness, cache_build, symlinks=True)
    passed('built harness provenance and artifact inventory')
    tip = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=clone, env=env, text=True).strip()
    if not re.fullmatch(r'[a-f0-9]{40}', tip):
        raise Refused('clone-revision-invalid')
    release = work / ('release-' + tip[:7])
    env['AUKORA_STATE'] = str(work / 'support')
    run(['python3', str(clone / 'scripts/materialize-aukora-release.py'), '--from', str(harness), '--to', str(release)],
        'materialize', clone, env)
    # The release inherits file modes from the built harness, and a harness built under a group-writable mask
    # (Ubuntu's default 002) yields a release the runtime rightly refuses as unprotected. Group and other never
    # get write access to a release; links are left as they are.
    for folder, names, files in os.walk(release):
        for name in [folder] + [os.path.join(folder, entry) for entry in files]:
            if not os.path.islink(name):
                mode = stat.S_IMODE(os.lstat(name).st_mode)
                if mode & 0o022:
                    os.chmod(name, mode & ~0o022)
    passed('release materialized from clean clone')
    return { 'checkout': clone, 'release': release, 'root': work, 'env': env }


def runtime_command(spec, stay_up=False, port=None):
    command = ['node', str(spec['checkout'] / 'scripts/fresh-clone-runtime.mjs'), '--checkout', str(spec['checkout']),
               '--release', str(spec['release']), '--root', str(spec['root'])]
    if stay_up:
        command.append('--stay-up')
    if port is not None:
        command.extend(['--port', str(port)])
    return command


def snapshot_dirty(source, clone, env):
    files = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=source, env=env).split(b'\0')
    for raw in files:
        if not raw:
            continue
        relative = os.fsdecode(raw)
        original, destination = Path(source) / relative, clone / relative
        for base, file in ((Path(source), original), (clone, destination)):
            cursor = file
            while cursor != base:
                if cursor.is_symlink():
                    raise Refused('dirty-snapshot-symlink')
                cursor = cursor.parent
        if original.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(original, destination)
            os.chmod(destination, original.stat().st_mode & 0o755)
        elif not original.exists() and destination.exists():
            destination.unlink()
    run(['git', 'add', '-A'], 'snapshot-add', clone, env)
    run(['git', '-c', 'user.name=Disposable example', '-c', 'user.email=example@invalid',
         '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'example: private uncommitted checkout snapshot'], 'snapshot-commit', clone, env)
