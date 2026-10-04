#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator-only setup: online fetch once, hash-check, then seal offline runtime."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import urllib.request
sys.dont_write_bytecode = True
from launch import digest, inventory, verify


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--python', required=True)
    parser.add_argument('--python-sha256', required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('this lock requires Linux x86_64 CPython 3.12')
    libc, libc_version = platform.libc_ver()
    if libc != 'glibc' or tuple(map(int, libc_version.split('.')[:2])) < (2, 28):
        raise ValueError('pinned native wheels require glibc >= 2.28')
    if os.geteuid() != 0:
        raise ValueError('operator setup requires root-owned runtime; service runs unprivileged')
    source = Path(__file__).resolve().parent
    root = Path(args.runtime).absolute()
    if root.exists():
        raise ValueError('runtime already exists; never overwrite a live environment')
    baseline = Path(args.python).resolve(strict=True)
    if digest(baseline) != args.python_sha256:
        raise ValueError('operator-pinned baseline interpreter mismatch')
    root.mkdir(parents=True)
    for name in ('sidecar.py', 'launch.py', 'requirements-linux.lock', 'models.lock.json'):
        shutil.copyfile(source / name, root / name)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'LANG': 'C.UTF-8',
           'PYTHONDONTWRITEBYTECODE': '1', 'PIP_CONFIG_FILE': '/dev/null',
           'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INPUT': '1'}

    def baseline_run(argv):
        if digest(baseline) != args.python_sha256:
            raise ValueError('baseline changed before execution')
        return subprocess.run([str(baseline), '-I', '-B', *argv], env=env,
                              check=True, capture_output=True, text=True)

    version = baseline_run(['-c', 'import sys; print(".".join(map(str,sys.version_info[:3])))']).stdout.strip()
    if version != '3.12.3':
        raise ValueError('lock interpreter version mismatch')
    baseline_run(['-m', 'venv', '--copies', str(root / '.venv')])
    stdlib = baseline_run(['-c', 'import sysconfig; print(sysconfig.get_path("stdlib"))']).stdout.strip()
    external = [{'kind': 'file', 'path': str(baseline), 'sha256': args.python_sha256},
                {'kind': 'tree', 'path': stdlib, 'files': inventory(Path(stdlib))}]

    def seal():
        # Root-owned runtime bytes are remeasured; operator must approve this final digest.
        (root / 'environment.json').write_text(json.dumps({
            'schema': 1, 'platform': 'linux-x86_64-cpython312',
            'baseline_sha256': args.python_sha256, 'files': inventory(root), 'external': external,
        }, sort_keys=True, indent=2) + '\n')
        return digest(root / 'environment.json')

    pin = seal()
    verify(root, pin)  # Before pip's interpreter/import/probe, not after it.
    subprocess.run([str(root / '.venv/bin/python'), '-I', '-B', '-m', 'pip',
                    'install', '--index-url', 'https://pypi.org/simple',
                    '--only-binary=:all:', '--require-hashes', '--no-cache-dir',
                    '-r', str(root / 'requirements-linux.lock')], env=env, check=True)
    pin = seal()
    verify(root, pin)
    subprocess.run([str(root / '.venv/bin/python'), '-I', '-B', '-m', 'pip', 'check'],
                   env=env, check=True)
    models = json.loads((root / 'models.lock.json').read_text())
    for item in models['files']:
        path = root / 'models' / item['path']
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + '.download')
        with urllib.request.urlopen(item['url'], timeout=120) as response, open(temporary, 'wb') as output:
            shutil.copyfileobj(response, output, 1024 * 1024)
        if temporary.stat().st_size != item['size'] or digest(temporary) != item['sha256']:
            raise ValueError('model size/hash mismatch')
        temporary.rename(path)
    pin = seal()
    verify(root, pin)
    # Treat the wheel's VAD asset as a named model pin as well as an environment member.
    vad = root / '.venv/lib/python3.12/site-packages/faster_whisper/assets/silero_vad_v6.onnx'
    if digest(vad) != '4cbf549b8326f60f80f2536d9eefeb450a9abe83365a098031c89719f1be17d2':
        raise ValueError('Silero VAD model pin mismatch')
    # This CPU fixture has no microphone input; it proves model loading/synthesis only.
    # Do not create the protected operator pin or activate a service here.
    # Grok's owner-card/config step installs the approved pin, then runs --probe.
    # No service is installed/enabled here. Operator must seal ownership and approve this pin.
    print(json.dumps({'runtime': str(root), 'environment_sha256': pin,
                      'status': 'prepared; operator pin/card and verified CPU probe still required'}))


if __name__ == '__main__':
    main()
