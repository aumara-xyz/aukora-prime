#!/bin/sh
# Boot a private clone with pinned inputs and real temporary approval.
set -eu
if ! command -v python3 >/dev/null 2>&1; then
    printf 'UNPERFORMED: python3-unavailable\nTOTAL 0.00s | UNPERFORMED\n'
    exit 2
fi
exec python3 - "$0" "$@" <<'PY'
import argparse, hashlib, json, os, re, shutil, signal, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

started = time.monotonic()
parser = argparse.ArgumentParser(description='Clone, build, approve and probe a disposable release; no model key required.')
parser.add_argument('source', nargs='?', help='Git path or URL (default: this checkout HEAD, never its working tree)')
parser.add_argument('--archive', type=Path, help='offline pinned archive; digest is still checked')
parser.add_argument('--built', type=Path, help='read-only built harness; skips ONLY build and still verifies provenance')
parser.add_argument('--cache', type=Path, help='explicit archive/build cache; every hit is verified')
args = parser.parse_args(sys.argv[2:])
caller = Path(sys.argv[1]).resolve().parents[1]
source = args.source or str(caller)
if Path(source).exists():
    source = str(Path(source).resolve())
archive_input = args.archive.resolve() if args.archive else None
built_input = args.built.resolve() if args.built else None
cache = args.cache.resolve() if args.cache else None
rows = []

class Refused(Exception):
    def __init__(self, code, missing=False):
        self.code, self.missing = code, missing

def passed(name):
    rows.append(('PASS', name))
    print('PASS | ' + name, flush=True)

def run(command, name, cwd, env, timeout=660):
    log = work / (name + '.log')
    with log.open('w') as output:
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

def interrupted(signum, frame):
    raise Refused('interrupted')

for sig in (signal.SIGINT, signal.SIGTERM):
    signal.signal(sig, interrupted)

status = 1
work = None
try:
    for tool in ('node', 'python3', 'git'):
        if shutil.which(tool) is None:
            raise Refused(tool + '-unavailable', True)
    version = subprocess.check_output(['node', '--version'], text=True).strip()
    if version != 'v24.11.1':
        raise Refused('node-24.11.1-required', True)
    # mkdtemp creates a private root even under login umask 002 and a shared TMPDIR.
    work = Path(tempfile.mkdtemp(prefix='aukora-fresh-clone-', dir='/tmp')).resolve()
    os.chmod(work, 0o700)
    os.umask(0o077)
    home = work / 'home'
    home.mkdir(mode=0o700)
    temporary = work / 'tmp'
    temporary.mkdir(mode=0o700)
    env = {key: os.environ[key] for key in ('PATH', 'LANG') if key in os.environ}
    env.update(HOME=str(home), TMPDIR=str(temporary), XDG_CACHE_HOME=str(home / '.cache'),
               XDG_CONFIG_HOME=str(home / '.config'), CI='true', PYTHONDONTWRITEBYTECODE='1',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0',
               npm_config_fetch_retries='0')
    clone = work / 'clone'
    run(['git', 'clone', '--quiet', '--no-local', '--', source, str(clone)], 'clone', work, env)
    passed('isolated clone (committed HEAD only)')
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
    passed('release materialized from clean clone')
    print('MODE | temporary same-user authority (not owner enrollment or containment)', flush=True)
    run(['node', str(clone / 'scripts/fresh-clone-runtime.mjs'), '--checkout', str(clone),
         '--release', str(release), '--root', str(work)], 'runtime', clone, env, timeout=110)
    for line in (work / 'runtime.log').read_text().splitlines():
        if re.fullmatch(r'PASS \| [a-zA-Z0-9 ()/.-]+', line):
            print(line, flush=True)
    passed('release boot and all runtime assertions')
    status = 0
except Refused as error:
    status = 2 if error.missing else 1
    print(('UNPERFORMED: ' if error.missing else 'FAIL | ') + error.code, flush=True)
except (OSError, ValueError, KeyError, subprocess.CalledProcessError):
    print('FAIL | fresh-clone-input-invalid', flush=True)
finally:
    if work:
        shutil.rmtree(work, ignore_errors=True)
    print('TOTAL %.2fs | %s' % (time.monotonic() - started, 'PASS' if status == 0 else 'UNPERFORMED' if status == 2 else 'FAIL'), flush=True)
sys.exit(status)
PY
