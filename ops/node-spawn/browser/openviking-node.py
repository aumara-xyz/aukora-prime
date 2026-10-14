#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install offline pinned recall bytes with private state and loopback acceptance.
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import stat

RUNTIME = Path('/opt/aukora-openviking')
LLAMA = Path('/opt/llama.cpp/b11381')
HOME = Path('/home/aukora-host/genesis/state/home/openviking')
OVERLAY = Path('/home/aukora-host/genesis/support/kira-deployment-overlay.patch.yml')
UNIT = Path('/etc/systemd/system/aukora-openviking.service')
PYTHON = Path('/usr/bin/python3.11')


def prepare(n, archive, checkout):
    n.need(os.uname().machine == 'x86_64', 'OPENVIKING_ARCH_REQUIRED')
    n.need(PYTHON.is_file(), 'OPENVIKING_PYTHON_REQUIRED')
    n.protected(PYTHON)
    n.run([str(PYTHON), '-I', '-c', 'import sys; assert sys.version_info[:2] == (3,11); import venv, ensurepip'],
          'OPENVIKING_PYTHON_INVALID')
    for path in (RUNTIME, LLAMA, HOME, UNIT):
        n.need(not path.exists() and not path.is_symlink(), 'OPENVIKING_EXISTS')
    if LLAMA.parent.exists() or LLAMA.parent.is_symlink():
        n.protected(LLAMA.parent, True)
    bundle = n.module(checkout / 'ops/node-spawn/browser/openviking-bundle.py')
    n.need(shutil.disk_usage(n.STATE).free >= bundle.MAX_BYTES + 2 * 1024**3,
           'OPENVIKING_DISK_REQUIRED')
    try:
        bundle.extract_bundle(archive, n.STATE / 'openviking-payload', checkout)
    except bundle.Refusal as error:
        raise ValueError('BROWSER_' + str(error)) from None


def readonly(root, executable=False):
    for folder, directories, files in os.walk(root, followlinks=False):
        for entry in [Path(folder), *(Path(folder) / name for name in files)]:
            if not entry.is_symlink():
                entry.chmod(0o555 if executable or entry.is_dir() or entry.stat().st_mode & 0o111 else 0o444)


def install(n, release, config):
    payload = n.STATE / 'openviking-payload'
    RUNTIME.mkdir(mode=0o755)
    LLAMA.parent.mkdir(mode=0o755, exist_ok=True)
    (payload / 'llama').rename(LLAMA)
    (payload / 'models').rename(RUNTIME / 'models')
    n.run([str(PYTHON), '-I', '-m', 'venv', '--copies', str(RUNTIME / 'venv')], 'OPENVIKING_VENV_REFUSED')
    python = str(RUNTIME / 'venv/bin/python')
    n.run([python, '-I', '-m', 'pip', '--isolated', 'install', '--disable-pip-version-check',
           '--no-index', '--no-deps', '--only-binary=:all:', '--require-hashes',
           '--find-links', str(payload / 'wheels'), '-r', str(payload / 'requirements.lock')],
          'OPENVIKING_INSTALL_REFUSED')
    n.run([python, '-I', '-m', 'pip', '--isolated', 'check'], 'OPENVIKING_CLOSURE_REFUSED')
    readonly(RUNTIME)
    readonly(LLAMA, executable=True)
    uid, gid = n.harness_identity()
    HOME.mkdir(mode=0o700)
    (HOME / 'data').mkdir(mode=0o700)
    (HOME / 'venv').symlink_to(RUNTIME / 'venv')
    model = RUNTIME / 'models/Qwen3-Embedding-0.6B-Q8_0.gguf'
    server = {'host': '127.0.0.1', 'port': 1933, 'auth_mode': 'trusted',
              'root_api_key': '${AUKORA_OPENVIKING_ROOT_KEY}', 'cors_origins': []}
    conf = {'server': server, 'storage': {'workspace': '${AUKORA_OPENVIKING_HOME}/data',
            'vectordb': {'name': 'context', 'backend': 'local'}, 'agfs': {'backend': 'local'}},
            'embedding': {'max_input_tokens': 2000, 'dense': {'provider': 'openai',
            'api_base': 'http://127.0.0.1:1934/v1', 'api_key': 'local',
            'model': 'qwen3-embedding-0.6b', 'dimension': 1024, 'encoding_format': 'float'}}}
    bridge = {'url': 'http://127.0.0.1:1933', 'account': 'aukora', 'user': 'owner',
              'scoreThreshold': 0.4, 'window': 0.1, 'limit': 3,
              'queryInstruction': 'Instruct: Given a question from the owner, retrieve the memory notes that answer it\nQuery: ',
              'embedding': {'model': str(model), 'port': 1934, 'context': 2048}}
    for name, text in [('root.key', secrets.token_urlsafe(32) + '\n'),
                       ('ov.conf', json.dumps(conf) + '\n'), ('aukora-bridge.json', json.dumps(bridge) + '\n')]:
        file = HOME / name
        with file.open('x') as output:
            output.write(text)
        file.chmod(0o600)
    for file in (HOME, HOME / 'data', HOME / 'root.key', HOME / 'ov.conf', HOME / 'aukora-bridge.json'):
        os.chown(file, uid, gid)
    template = (release / 'aukora-deployment-overlay.patch.yml').read_text()
    n.need(template.count('    openVikingHome: ' + json.dumps(str(HOME))) == 1,
           'OPENVIKING_OVERLAY_INVALID')
    template = template.replace('${KIRA_STATE_DIR}', json.dumps(str(HOME.parent / 'kira-memory')))
    template = template.replace('${SUBJECT}', json.dumps('aumlok:subject:owner'))
    with OVERLAY.open('x') as output:
        output.write(template)
    OVERLAY.chmod(0o600)
    os.chown(OVERLAY, uid, gid)
    unit = (n.CHECKOUT / 'host/units/aukora-openviking.service').read_text()
    unit = unit.replace('Environment=HOME=/home/aukora-host', 'Environment=HOME=' + str(HOME))
    unit = unit.replace('Environment=PATH=/usr/local/bin:/usr/bin:/bin',
                        'Environment=PATH=/opt/llama.cpp/b11381:/usr/bin:/bin')
    unit = unit.replace('ExecStart=/bin/sh /opt/aukora-genesis/src/scripts/openviking-setup.sh serve',
                        'ExecStart=/usr/bin/python3 -I -B /opt/aukora-genesis/src/scripts/openviking-supervisor.py')
    unit += '\n[Service]\nMemorySwapMax=0\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nIPAddressDeny=any\nIPAddressAllow=localhost\n'
    config.write(UNIT, unit.encode(), Path('/'))
    cost = sum(file.stat().st_size for root in (RUNTIME, LLAMA) for file in root.rglob('*')
               if file.is_file() and not file.is_symlink())
    print('OPENVIKING_RUNTIME_BYTES ' + str(cost) + '; store growth additional')
    shutil.rmtree(payload)


def health(n, port):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        connection.request('GET', '/health')
        response = connection.getresponse()
        n.need(response.status == 200 and len(response.read(4097)) <= 4096, 'OPENVIKING_HEALTH_REFUSED')
    except (OSError, http.client.HTTPException):
        n.refuse('OPENVIKING_HEALTH_UNAVAILABLE')
    finally:
        connection.close()


def accept(n, endpoints, phase):
    uid, _ = n.harness_identity()
    n.protected(HOME, True, uid, True)
    n.protected(HOME / 'root.key', uid=uid, private=True)
    key = HOME / 'root.key'
    n.need(1 <= key.stat().st_size <= 4096, 'OPENVIKING_KEY_INVALID')
    text = key.read_text().strip()
    n.need(bool(text) and '\n' not in text and '\r' not in text, 'OPENVIKING_KEY_INVALID')
    n.need((HOME / 'venv').is_symlink() and (HOME / 'venv').resolve() == RUNTIME / 'venv',
           'OPENVIKING_RUNTIME_LINK_INVALID')
    for root in (RUNTIME, LLAMA):
        for file in (root, *root.rglob('*')):
            if file.is_symlink():
                n.need(file.resolve().is_relative_to(root), 'OPENVIKING_RUNTIME_LINK_INVALID')
            else:
                n.protected(file, file.is_dir())
                n.need(file.stat().st_mode & 0o222 == 0, 'OPENVIKING_RUNTIME_WRITABLE')
    supervisor = n.module(n.CHECKOUT / 'scripts/openviking-supervisor.py')
    try:
        supervisor.verify_llama_server(str(LLAMA / 'llama-server'))
    except supervisor.SetupError:
        n.refuse('OPENVIKING_LLAMA_INVALID')
    n.run(['systemctl', 'is-active', '--quiet', 'aukora-openviking.service'], 'OPENVIKING_INACTIVE')
    n.need(all('127.0.0.1:' + str(port) in endpoints for port in (1933, 1934)),
           'OPENVIKING_LISTENER_MISSING')
    rows = n.run(['ss', '-lun'], 'OPENVIKING_UDP_UNAVAILABLE').splitlines()[1:]
    try:
        local = all(len(row.split()) >= 4 and ipaddress.ip_address(
            row.split()[3].rsplit(':', 1)[0].strip('[]').split('%', 1)[0]).is_loopback for row in rows)
    except ValueError:
        local = False
    n.need(local, 'NON_LOOPBACK_LISTENER')
    n.protected(OVERLAY, uid=uid, private=True)
    n.need(OVERLAY.stat().st_size <= 64 * 1024, 'OPENVIKING_OVERLAY_INVALID')
    overlay = OVERLAY.read_text()
    n.need(overlay.count('    openVikingHome: ' + json.dumps(str(HOME))) == 1,
           'OPENVIKING_OVERLAY_INVALID')
    for port in (1933, 1934):
        health(n, port)
    print('PASS | OpenViking and embedder loopback health, private key and read-only runtime; semantic configured')
