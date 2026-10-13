#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Install and read back a pinned Linux voice runtime without network access."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import stat
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True
from launch import digest, inventory, verify


PIN_DIRECTORY = Path('/etc/aukora/auma-live-voice')
ENVIRONMENT_PIN = PIN_DIRECTORY / 'environment.sha256'
PYTHON_PIN = PIN_DIRECTORY / 'python.sha256'
HOST_TRUST = 'operator-pinned-interpreter-root-owned-os'
BUILD_SOURCE_NAMES = ('install.py', 'launch.py', 'sidecar.py', 'requirements-linux.lock',
                      'models.lock.json', 'wheels.lock.json')


class VoiceInstallRefusal(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def refuse(code):
    raise VoiceInstallRefusal(code)


def need(condition, code):
    if not condition:
        refuse(code)


def exact_digest(value):
    need(isinstance(value, str) and len(value) == 64
         and all(character in '0123456789abcdef' for character in value), 'DIGEST_INVALID')
    return value


def exact_path(value, code):
    path = Path(value)
    need(path.is_absolute() and str(path) == value and path.resolve(strict=False) == path
         and not any(character.isspace() or ord(character) < 32 for character in value), code)
    return path


def interpreter_path(value):
    path = Path(value)
    need(path.is_absolute() and str(path) == value
         and not any(character.isspace() or ord(character) < 32 for character in value), 'PYTHON_PATH_INVALID')
    need(path.exists(), 'PYTHON_MISSING')
    for parent in path.parents:
        protected(parent, True)
    link = path.lstat()
    need(link.st_uid == 0 and not link.st_mode & 0o022
         and (stat.S_ISREG(link.st_mode) or stat.S_ISLNK(link.st_mode)), 'PYTHON_CUSTODY_INVALID')
    return path.resolve(strict=True)


def protected(path, directory=False, uid=0, gid=None):
    try:
        metadata = path.lstat()
    except OSError:
        refuse('PROTECTED_INPUT_MISSING')
    need(not path.is_symlink() and metadata.st_uid == uid and not metadata.st_mode & 0o022
         and (gid is None or metadata.st_gid == gid)
         and (stat.S_ISDIR(metadata.st_mode) if directory
              else stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1), 'PROTECTED_INPUT_INVALID')
    return metadata


def protected_ancestry(path):
    for entry in (path, *path.parents):
        protected(entry, entry.is_dir())


def verify_artifact(path, record):
    protected_ancestry(path.parent)
    metadata = protected(path)
    need(metadata.st_size == record['size'] and digest(path) == exact_digest(record['sha256']),
         'ARTIFACT_DIGEST_MISMATCH')
    return path


def load_locks(source):
    try:
        wheels = json.loads((source / 'wheels.lock.json').read_text())
        models = json.loads((source / 'models.lock.json').read_text())
        bootstrap = wheels['bootstrap']
        wheel_rows = wheels['wheels']
        model_rows = models['files']
    except (OSError, ValueError, KeyError, TypeError):
        refuse('LOCK_INVALID')
    need(isinstance(wheel_rows, list) and len(wheel_rows) == 54
         and isinstance(model_rows, list) and len(model_rows) == 6, 'LOCK_INVALID')
    return bootstrap, wheel_rows, model_rows


def artifact_path(artifacts, kind, record):
    name = record['filename'] if kind != 'models' else record['path']
    relative = Path(name)
    need(not relative.is_absolute() and '..' not in relative.parts and relative.parts, 'LOCK_INVALID')
    return artifacts / kind / relative


def verify_inputs(source, artifacts):
    protected_ancestry(artifacts)
    bootstrap, wheels, models = load_locks(source)
    verified = {
        'bootstrap': verify_artifact(artifact_path(artifacts, 'bootstrap', bootstrap), bootstrap),
        'wheels': [verify_artifact(artifact_path(artifacts, 'wheels', row), row) for row in wheels],
        'models': [verify_artifact(artifact_path(artifacts, 'models', row), row) for row in models],
    }
    return bootstrap, wheels, models, verified


def verify_wheel_payload(wheel, site):
    checked = 0
    with zipfile.ZipFile(wheel) as archive:
        for entry in archive.infolist():
            if entry.is_dir() or entry.filename.endswith('.dist-info/RECORD'):
                continue
            name = entry.filename
            if '.data/' in name:
                scheme, name = name.split('.data/', 1)[1].split('/', 1)
                need(scheme in ('purelib', 'platlib'), 'WHEEL_PAYLOAD_INVALID')
            relative = Path(name)
            need(not relative.is_absolute() and '..' not in relative.parts, 'WHEEL_PAYLOAD_INVALID')
            target = Path(site) / relative
            need(target.is_file()
                 and hashlib.sha256(target.read_bytes()).hexdigest()
                 == hashlib.sha256(archive.read(entry)).hexdigest(), 'WHEEL_PAYLOAD_MISMATCH')
            checked += 1
    return checked


def platform_check():
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    need(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'LINUX_X86_64_REQUIRED')
    libc, version = platform.libc_ver()
    try:
        accepted = libc == 'glibc' and tuple(map(int, version.split('.')[:2])) >= (2, 28)
    except ValueError:
        accepted = False
    need(accepted, 'GLIBC_2_28_REQUIRED')


def service_identity(name):
    try:
        user = pwd.getpwnam(name)
        group = grp.getgrgid(user.pw_gid)
    except KeyError:
        refuse('SERVICE_USER_MISSING')
    need(user.pw_uid != 0 and group.gr_gid != 0, 'SERVICE_USER_INVALID')
    return user.pw_uid, group.gr_gid


def interpreter_check(python, expected):
    metadata = protected(python)
    need(metadata.st_uid == 0 and metadata.st_mode & 0o111, 'PYTHON_CUSTODY_INVALID')
    need(digest(python) == exact_digest(expected), 'PYTHON_DIGEST_MISMATCH')


def os_run(python, expected, environment, arguments):
    interpreter_check(python, expected)
    try:
        return subprocess.run([str(python), '-I', '-B', *arguments], env=environment,
                              check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        refuse('PYTHON_OPERATION_REFUSED')


def seal_modes(root, gid, uid=0):
    for path in sorted(root.rglob('*'), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            target = path.resolve(strict=True)
            need(target == root or root in target.parents, 'RUNTIME_LINK_ESCAPE')
            os.chown(path, uid, gid, follow_symlinks=False)
            continue
        os.chown(path, uid, gid)
        if path.is_dir():
            path.chmod(0o750)
        else:
            executable = path.is_relative_to(root / '.venv/bin') and path.stat().st_mode & 0o111
            path.chmod(0o750 if executable else 0o640)
    os.chown(root, uid, gid)
    root.chmod(0o750)


def check_runtime_access(root, gid, uid=0):
    metadata = protected(root, True, uid=uid, gid=gid)
    need(stat.S_IMODE(metadata.st_mode) == 0o750, 'RUNTIME_MODE_INVALID')
    for path in root.rglob('*'):
        metadata = path.lstat()
        need(metadata.st_uid == uid and metadata.st_gid == gid and not metadata.st_mode & 0o007,
             'RUNTIME_CUSTODY_INVALID')
        if path.is_symlink():
            target = path.resolve(strict=True)
            need(target == root or root in target.parents, 'RUNTIME_LINK_ESCAPE')
        elif path.is_dir():
            need(stat.S_IMODE(metadata.st_mode) == 0o750, 'RUNTIME_MODE_INVALID')
        elif path.is_file():
            need(stat.S_IMODE(metadata.st_mode) in (0o640, 0o750), 'RUNTIME_MODE_INVALID')
        else:
            refuse('RUNTIME_MEMBER_INVALID')


def write_pins(environment_sha256, python_sha256):
    PIN_DIRECTORY.mkdir(parents=True, exist_ok=True, mode=0o755)
    protected_ancestry(PIN_DIRECTORY)
    need(not ENVIRONMENT_PIN.exists() and not ENVIRONMENT_PIN.is_symlink()
         and not PYTHON_PIN.exists() and not PYTHON_PIN.is_symlink(), 'PIN_EXISTS')
    pending = []
    try:
        for target, value in ((ENVIRONMENT_PIN, environment_sha256), (PYTHON_PIN, python_sha256)):
            temporary = PIN_DIRECTORY / (target.name + '.new')
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(descriptor, 'w') as output:
                output.write(exact_digest(value) + '\n')
                output.flush()
                os.fsync(output.fileno())
            pending.append((temporary, target))
        for temporary, target in pending:
            os.replace(temporary, target)
        directory = os.open(PIN_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        for temporary, _target in pending:
            temporary.unlink(missing_ok=True)


def install(args):
    platform_check()
    source = Path(__file__).resolve().parent
    protected_ancestry(source)
    for name in BUILD_SOURCE_NAMES:
        protected(source / name)
    root = exact_path(args.runtime, 'RUNTIME_PATH_INVALID')
    artifacts = exact_path(args.artifacts, 'ARTIFACT_PATH_INVALID')
    python = interpreter_path(args.python)
    _uid, gid = service_identity(args.service_user)
    interpreter_check(python, args.python_sha256)
    need(not root.exists() and not root.is_symlink(), 'RUNTIME_EXISTS')
    root.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    protected_ancestry(root.parent)
    _bootstrap, wheels, models, verified = verify_inputs(source, artifacts)
    root.mkdir(mode=0o750)
    for name in BUILD_SOURCE_NAMES:
        shutil.copyfile(source / name, root / name)
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'LANG': 'C.UTF-8',
                   'PYTHONDONTWRITEBYTECODE': '1', 'PIP_CONFIG_FILE': '/dev/null',
                   'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INPUT': '1',
                   'http_proxy': '', 'https_proxy': '', 'no_proxy': '*'}
    version = os_run(python, args.python_sha256, environment,
                     ['-c', 'import sys; print(".".join(map(str,sys.version_info[:3])))']).stdout.strip()
    need(version == '3.12.3', 'PYTHON_VERSION_MISMATCH')
    os_run(python, args.python_sha256, environment,
           ['-m', 'venv', '--copies', '--without-pip', str(root / '.venv')])
    stdlib = Path(os_run(python, args.python_sha256, environment,
                         ['-c', 'import sysconfig; print(sysconfig.get_path("stdlib"))']).stdout.strip())
    protected_ancestry(stdlib)
    for path in (stdlib, *stdlib.rglob('*')):
        if not path.is_symlink():
            metadata = path.stat()
            need(metadata.st_uid == 0 and not metadata.st_mode & 0o022, 'STDLIB_CUSTODY_INVALID')
    locked = root / 'offline-requirements.lock'
    locked.write_text(''.join(row['name'] + ' @ ' + artifact.as_uri()
                              + ' --hash=sha256:' + row['sha256'] + '\n'
                              for row, artifact in zip(wheels, verified['wheels'], strict=True)))
    bootstrap_code = 'import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module("pip",run_name="__main__")'
    os_run(python, args.python_sha256, environment,
           ['-c', bootstrap_code, str(verified['bootstrap']), '--python', str(root / '.venv/bin/python'),
            'install', '--no-index', '--no-deps', '--no-compile', '--only-binary=:all:',
            '--require-hashes', '--no-cache-dir', '-r', str(locked)])
    site = root / '.venv/lib/python3.12/site-packages'
    payload_files = sum(verify_wheel_payload(path, site) for path in verified['wheels'])
    for row, artifact in zip(models, verified['models'], strict=True):
        destination = root / 'models' / row['path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(artifact, destination)
    locked.unlink()
    vad = site / 'faster_whisper/assets/silero_vad_v6.onnx'
    need(digest(vad) == '4cbf549b8326f60f80f2536d9eefeb450a9abe83365a098031c89719f1be17d2',
         'VAD_DIGEST_MISMATCH')
    seal_modes(root, gid)
    external = [{'kind': 'file', 'path': str(python), 'sha256': args.python_sha256},
                {'kind': 'tree', 'path': str(stdlib), 'files': inventory(stdlib)}]
    manifest = root / 'environment.json'
    manifest.write_text(json.dumps({'schema': 1, 'platform': 'linux-x86_64-cpython312',
        'baselineTrust': HOST_TRUST, 'files': inventory(root), 'external': external},
        sort_keys=True, indent=2) + '\n')
    os.chown(manifest, 0, gid)
    manifest.chmod(0o640)
    environment_sha256 = digest(manifest)
    verify(root, environment_sha256)
    check_runtime_access(root, gid)
    write_pins(environment_sha256, args.python_sha256)
    print('INSTALLED environment_sha256=' + environment_sha256
          + ' python_sha256=' + args.python_sha256
          + ' wheel_payload_files=' + str(payload_files))


def readback(args):
    platform_check()
    root = exact_path(args.runtime, 'RUNTIME_PATH_INVALID')
    need(root.exists() and not root.is_symlink(), 'RUNTIME_MISSING')
    python = interpreter_path(args.python)
    _uid, gid = service_identity(args.service_user)
    need(PIN_DIRECTORY.is_dir() and not PIN_DIRECTORY.is_symlink(), 'PIN_DIRECTORY_MISSING')
    need(ENVIRONMENT_PIN.is_file() and not ENVIRONMENT_PIN.is_symlink(), 'ENVIRONMENT_PIN_MISSING')
    need(PYTHON_PIN.is_file() and not PYTHON_PIN.is_symlink(), 'PYTHON_PIN_MISSING')
    protected_ancestry(PIN_DIRECTORY)
    protected(ENVIRONMENT_PIN)
    protected(PYTHON_PIN)
    try:
        environment_sha256 = exact_digest(ENVIRONMENT_PIN.read_text().strip())
        python_sha256 = exact_digest(PYTHON_PIN.read_text().strip())
    except (OSError, UnicodeError):
        refuse('PIN_UNREADABLE')
    interpreter_check(python, python_sha256)
    check_runtime_access(root, gid)
    try:
        verify(root, environment_sha256)
    except (OSError, ValueError, KeyError, TypeError):
        refuse('RUNTIME_VERIFY_REFUSED')
    print('READY environment_sha256=' + environment_sha256 + ' python_sha256=' + python_sha256)


def parser():
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest='action', required=True)
    install_parser = subparsers.add_parser('install')
    install_parser.add_argument('--runtime', required=True)
    install_parser.add_argument('--artifacts', required=True)
    install_parser.add_argument('--python', required=True)
    install_parser.add_argument('--python-sha256', required=True)
    install_parser.add_argument('--service-user', default='aukora-host')
    status_parser = subparsers.add_parser('status')
    status_parser.add_argument('--runtime', required=True)
    status_parser.add_argument('--python', required=True)
    status_parser.add_argument('--service-user', default='aukora-host')
    return result


def main():
    args = parser().parse_args()
    try:
        install(args) if args.action == 'install' else readback(args)
    except VoiceInstallRefusal as error:
        label = 'REFUSED ' if args.action == 'install' else 'NOT READY '
        print(label + error.code, file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        label = 'REFUSED ' if args.action == 'install' else 'NOT READY '
        print(label + 'VOICE_INSTALL_OPERATION_FAILED', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
