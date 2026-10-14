# SPDX-License-Identifier: AGPL-3.0-or-later
# Exercise offline recall installation and acceptance without root, services or network.
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'ops/node-spawn/browser/openviking-node.py'
NODE = ROOT / 'ops/node-spawn/browser/node.py'
TEXT = SOURCE.read_text()
SCRATCH = ROOT / '.runtime/browser-openviking'
SCRATCH.mkdir(parents=True, exist_ok=True)
os.umask(0o022)


def load(path, text=None):
    module = types.ModuleType('openviking_node_fixture')
    module.__file__ = str(path)
    exec(compile(path.read_text() if text is None else text, str(path), 'exec'), module.__dict__)
    return module


PIPELINE = load(ROOT / 'tests/browser-node-pipeline.py')
ACTUAL_NODE = load(NODE)


class World:
    def __init__(self, text=TEXT):
        self.root = Path(tempfile.mkdtemp(dir=SCRATCH))
        self.m = load(SOURCE, text)
        self.commands, self.custody, self.chowns, self.requests = [], [], [], []
        self.failure, self.bundle_error, self.llama_error = None, False, False
        self.arch, self.free, self.udp = 'x86_64', 8 * 1024**3, 'State Recv-Q Send-Q Local Address:Port Peer Address:Port\n'
        self.status, self.body, self.http_error, self.owners = 200, b'{}', False, {}
        for name, path in [('RUNTIME', 'opt/openviking'), ('LLAMA', 'opt/llama/b11381'),
                           ('HOME', 'home/state/home/openviking'), ('OVERLAY', 'home/support/kira-deployment-overlay.patch.yml'),
                           ('UNIT', 'etc/systemd/aukora-openviking.service'), ('PYTHON', 'usr/bin/python3.11')]:
            value = self.root / path
            value.parent.mkdir(parents=True, exist_ok=True)
            setattr(self.m, name, value)
        self.m.PYTHON.write_bytes(b'synthetic python')
        self.state, self.checkout, self.release = [self.root / name for name in ('state', 'checkout', 'release')]
        for directory in (self.state, self.checkout / 'host/units', self.release):
            directory.mkdir(parents=True, exist_ok=True)
        self.archive = self.root / 'bundle.tar.gz'
        self.archive.write_bytes(b'synthetic pinned archive')
        (self.checkout / 'host/units/aukora-openviking.service').write_bytes(
            (ROOT / 'host/units/aukora-openviking.service').read_bytes())
        self.template = ('- id: aukora-kira\n  config:\n    retrieval: lexical\n    openVikingHome: '
                         + json.dumps(str(self.m.HOME)) + '\n    memoryOwner:\n'
                         '      stateDir: ${KIRA_STATE_DIR}\n      subject: ${SUBJECT}\n      permittedPrivacy: [local]\n')
        (self.release / 'aukora-deployment-overlay.patch.yml').write_text(self.template)
        self.n = types.SimpleNamespace(STATE=self.state, CHECKOUT=self.checkout,
            need=ACTUAL_NODE.need, refuse=ACTUAL_NODE.refuse, protected=self.protected,
            run=self.run, harness_identity=lambda: (1001, 1001), module=self.module)
        self.config = types.SimpleNamespace(write=self.write)
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(patch.object(self.m.os, 'uname', lambda: types.SimpleNamespace(machine=self.arch)))
        self.stack.enter_context(patch.object(self.m.shutil, 'disk_usage', lambda _: types.SimpleNamespace(free=self.free)))
        self.stack.enter_context(patch.object(self.m.os, 'chown', self.chown))
        self.stack.enter_context(patch.object(self.m.secrets, 'token_urlsafe', lambda _: 'synthetic-store-key'))
        world = self
        class Connection:
            def __init__(self, host, port, timeout):
                world.requests.append((host, port, timeout))
                self.closed = False
            def request(self, method, path):
                world.requests.append((method, path))
                if world.http_error:
                    raise OSError('private detail never returned')
            def getresponse(self):
                return types.SimpleNamespace(status=world.status, read=lambda limit: world.body[:limit])
            def close(self):
                self.closed = True
                world.requests.append(('closed',))
        self.stack.enter_context(patch.object(self.m.http.client, 'HTTPConnection', Connection))

    def close(self):
        self.stack.close()
        for root, dirs, files in os.walk(self.root, followlinks=False):
            Path(root).chmod(0o700)
        shutil.rmtree(self.root)

    def protected(self, path, directory=False, uid=0, private=False, linked=False):
        self.custody.append((path, directory, uid, private))
        info = list(path.lstat())
        info[4] = self.owners.get(path, 0)
        with patch.object(Path, 'lstat', return_value=os.stat_result(info)):
            ACTUAL_NODE.protected(path, directory, uid, private, linked)

    def chown(self, path, uid, gid):
        self.chowns.append((path, uid, gid))
        self.owners[path] = uid

    def write(self, file, data, root):
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
        file.chmod(0o644)

    def run(self, command, code):
        self.commands.append((command, code))
        if code == self.failure:
            ACTUAL_NODE.refuse(code)
        if code == 'OPENVIKING_VENV_REFUSED':
            home = Path(command[-1])
            (home / 'bin').mkdir(parents=True)
            (home / 'bin/python').write_bytes(b'synthetic venv python')
            (home / 'bin/python').chmod(0o755)
            (home / 'lib').mkdir()
            (home / 'lib/data').write_bytes(b'synthetic installed wheel')
            (home / 'lib64').symlink_to('lib')
        return self.udp if code == 'OPENVIKING_UDP_UNAVAILABLE' else ''

    def module(self, file):
        class Refusal(ValueError):
            pass
        class SetupError(ValueError):
            pass
        def extract(archive, payload, checkout):
            if self.bundle_error:
                raise Refusal('OPENVIKING_BUNDLE_MODEL_DIGEST_MISMATCH')
            for folder in ('llama', 'models', 'wheels'):
                (payload / folder).mkdir(parents=True, exist_ok=True)
            (payload / 'llama/llama-server').write_bytes(b'pinned synthetic server')
            (payload / 'llama/libggml.so').write_bytes(b'pinned synthetic library')
            (payload / 'llama/libggml-link.so').symlink_to('libggml.so')
            (payload / 'models/Qwen3-Embedding-0.6B-Q8_0.gguf').write_bytes(b'pinned synthetic model')
            (payload / 'wheels/openviking.whl').write_bytes(b'pinned synthetic wheel')
            (payload / 'requirements.lock').write_bytes(b'pinned synthetic lock')
        def verify(server):
            if self.llama_error:
                raise SetupError('synthetic invalid server')
            assert server == str(self.m.LLAMA / 'llama-server')
        if file.name == 'openviking-bundle.py':
            return types.SimpleNamespace(extract_bundle=extract, Refusal=Refusal, MAX_BYTES=6 * 1024**3)
        return types.SimpleNamespace(verify_llama_server=verify, SetupError=SetupError)

    def prepare(self):
        self.m.prepare(self.n, self.archive, self.checkout)

    def install(self):
        self.prepare()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.m.install(self.n, self.release, self.config)
        return output.getvalue()

    def accept(self, endpoints=None, phase='after'):
        with contextlib.redirect_stdout(io.StringIO()):
            self.m.accept(self.n, {'127.0.0.1:1933', '127.0.0.1:1934'} if endpoints is None else endpoints, phase)


class OpenVikingNode(unittest.TestCase):
    helper_text, node_text = TEXT, None

    def world(self):
        world = World(self.helper_text)
        self.addCleanup(world.close)
        return world

    def reject(self, function, code):
        with self.assertRaisesRegex(ValueError, '^BROWSER_' + code + '$'):
            function()

    def test_prepare_platform_python_existing_paths_and_space(self):
        for attack, code in [('arch', 'OPENVIKING_ARCH_REQUIRED'), ('python', 'OPENVIKING_PYTHON_REQUIRED'),
                             ('python-mode', 'CUSTODY_INVALID'), ('python-version', 'OPENVIKING_PYTHON_INVALID'),
                             ('disk', 'OPENVIKING_DISK_REQUIRED'), ('parent-mode', 'CUSTODY_INVALID')]:
            w = self.world()
            if attack == 'arch':
                w.arch = 'aarch64'
            elif attack == 'python':
                w.m.PYTHON.unlink()
            elif attack == 'python-mode':
                w.m.PYTHON.chmod(0o666)
            elif attack == 'python-version':
                w.failure = 'OPENVIKING_PYTHON_INVALID'
            elif attack == 'disk':
                w.free = 8 * 1024**3 - 1
            else:
                w.m.LLAMA.parent.chmod(0o777)
            self.reject(w.prepare, code)
            self.assertFalse((w.state / 'openviking-payload').exists())
        for name in ('RUNTIME', 'LLAMA', 'HOME', 'UNIT'):
            for kind in ('file', 'dangling-link'):
                w = self.world()
                path = getattr(w.m, name)
                path.write_text('existing') if kind == 'file' else path.symlink_to(w.root / 'absent')
                self.reject(w.prepare, 'OPENVIKING_EXISTS')
                self.assertFalse((w.state / 'openviking-payload').exists())

    def test_prepare_forwards_bundle_refusal_and_checks_python(self):
        w = self.world()
        w.bundle_error = True
        self.reject(w.prepare, 'OPENVIKING_BUNDLE_MODEL_DIGEST_MISMATCH')
        command, code = w.commands[0]
        self.assertEqual(code, 'OPENVIKING_PYTHON_INVALID')
        self.assertEqual(command[:3], [str(w.m.PYTHON), '-I', '-c'])
        self.assertIn('sys.version_info[:2] == (3,11)', command[3])
        self.assertIn('import venv, ensurepip', command[3])

    def test_install_offline_closure_private_state_readonly_runtime_and_overlay(self):
        w = self.world()
        output = w.install()
        commands = {code: command for command, code in w.commands}
        self.assertEqual(commands['OPENVIKING_VENV_REFUSED'],
            [str(w.m.PYTHON), '-I', '-m', 'venv', '--copies', str(w.m.RUNTIME / 'venv')])
        self.assertEqual(commands['OPENVIKING_INSTALL_REFUSED'], [str(w.m.RUNTIME / 'venv/bin/python'), '-I', '-m', 'pip',
            '--isolated', 'install', '--disable-pip-version-check', '--no-index', '--no-deps', '--only-binary=:all:',
            '--require-hashes', '--find-links', str(w.state / 'openviking-payload/wheels'), '-r',
            str(w.state / 'openviking-payload/requirements.lock')])
        self.assertEqual(commands['OPENVIKING_CLOSURE_REFUSED'],
            [str(w.m.RUNTIME / 'venv/bin/python'), '-I', '-m', 'pip', '--isolated', 'check'])
        for directory in (w.m.HOME, w.m.HOME / 'data'):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for file in (w.m.HOME / 'root.key', w.m.HOME / 'ov.conf', w.m.HOME / 'aukora-bridge.json', w.m.OVERLAY):
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            self.assertIn((file, 1001, 1001), w.chowns)
        for root in (w.m.RUNTIME, w.m.LLAMA):
            for file in (root, *root.rglob('*')):
                if not file.is_symlink():
                    self.assertEqual(file.stat().st_mode & 0o222, 0)
        self.assertEqual((w.m.LLAMA / 'llama-server').stat().st_mode & 0o111, 0o111)
        self.assertEqual((w.m.RUNTIME / 'models/Qwen3-Embedding-0.6B-Q8_0.gguf').stat().st_mode & 0o111, 0)
        self.assertEqual((w.m.HOME / 'venv').resolve(), w.m.RUNTIME / 'venv')
        self.assertEqual(w.m.OVERLAY.read_text(), w.template.replace('${KIRA_STATE_DIR}',
            json.dumps(str(w.root / 'home/state/home/kira-memory'))).replace('${SUBJECT}', json.dumps('aumlok:subject:owner')))
        conf, bridge = [json.loads((w.m.HOME / name).read_text()) for name in ('ov.conf', 'aukora-bridge.json')]
        self.assertEqual(conf['server']['host'], '127.0.0.1')
        self.assertEqual(conf['server']['root_api_key'], '${AUKORA_OPENVIKING_ROOT_KEY}')
        self.assertEqual(conf['embedding']['dense']['api_base'], 'http://127.0.0.1:1934/v1')
        self.assertEqual(bridge['url'], 'http://127.0.0.1:1933')
        self.assertEqual(bridge['embedding']['context'], 2048)
        self.assertFalse((w.state / 'openviking-payload').exists())
        self.assertRegex(output, r'^OPENVIKING_RUNTIME_BYTES [0-9]+; store growth additional\n$')
        self.assertNotIn('synthetic-store-key', output)

    def test_install_unit_limits_and_direct_offline_supervisor(self):
        w = self.world()
        w.install()
        unit = w.m.UNIT.read_text()
        self.assertIn('Environment=HOME=' + str(w.m.HOME) + '\n', unit)
        fields = dict(line.split('=', 1) for line in unit.splitlines() if '=' in line and not line.startswith('Environment='))
        environment = dict(line[len('Environment='):].split('=', 1) for line in unit.splitlines() if line.startswith('Environment='))
        for key, value in {'MemoryHigh': '2048M', 'MemoryMax': '2304M', 'MemorySwapMax': '0', 'CPUQuota': '200%'}.items():
            self.assertEqual(fields[key], value)
        self.assertEqual(environment['AUKORA_OPENVIKING_EMBED_RSS_MIB'], '1536')
        self.assertEqual(environment['AUKORA_OPENVIKING_EMBED_THREADS'], '2')
        for line in ('User=aukora-host', 'UMask=0077', 'AUKORA_OPENVIKING_EMBED_RSS_MIB=1536',
                     'AUKORA_OPENVIKING_EMBED_THREADS=2', 'MemoryHigh=2048M', 'MemoryMax=2304M', 'CPUQuota=200%',
                     'MemorySwapMax=0', 'IPAddressDeny=any', 'IPAddressAllow=localhost', 'KillMode=control-group',
                     'ProtectSystem=strict', 'NoNewPrivileges=true', 'Environment=PATH=/opt/llama.cpp/b11381:/usr/bin:/bin'):
            self.assertIn(line + '\n', unit)
        self.assertIn('ExecStart=/usr/bin/python3 -I -B /opt/aukora-genesis/src/scripts/openviking-supervisor.py '
                      '/home/aukora-host/genesis/state/home/openviking\n', unit)
        self.assertNotIn('openviking-setup.sh', unit)

    def test_install_command_and_overlay_refusals(self):
        for code in ('OPENVIKING_VENV_REFUSED', 'OPENVIKING_INSTALL_REFUSED', 'OPENVIKING_CLOSURE_REFUSED'):
            w = self.world()
            w.failure = code
            self.reject(w.install, code)
            self.assertFalse(w.m.UNIT.exists())
        for content in ('', '    openVikingHome: "/other/store"\n', None):
            w = self.world()
            (w.release / 'aukora-deployment-overlay.patch.yml').write_text(
                w.template + w.template if content is None else content)
            self.reject(w.install, 'OPENVIKING_OVERLAY_INVALID')
            self.assertFalse(w.m.OVERLAY.exists())
            self.assertFalse(w.m.UNIT.exists())

    def test_accept_both_phases_verify_root_custody_private_key_and_health(self):
        w = self.world()
        w.install()
        for phase in ('after', 'bound'):
            w.requests.clear()
            w.accept(phase=phase)
            self.assertEqual([row for row in w.requests if len(row) == 3],
                [('127.0.0.1', 1933, 5), ('127.0.0.1', 1934, 5)])
            self.assertEqual(w.requests.count(('GET', '/health')), 2)
            self.assertEqual(w.requests.count(('closed',)), 2)
        self.assertIn((w.m.HOME, True, 1001, True), w.custody)
        self.assertIn((w.m.HOME / 'root.key', False, 1001, True), w.custody)
        for root in (w.m.RUNTIME, w.m.LLAMA):
            self.assertIn((root, True, 0, False), w.custody)

    def test_accept_key_modes_size_shape_and_owner_refusals(self):
        for attack, code in [('private-home', 'CUSTODY_INVALID'), ('private-key', 'CUSTODY_INVALID'),
                             ('owner', 'CUSTODY_INVALID'), ('empty', 'OPENVIKING_KEY_INVALID'),
                             ('oversize', 'OPENVIKING_KEY_INVALID'), ('blank', 'OPENVIKING_KEY_INVALID'),
                             ('newline', 'OPENVIKING_KEY_INVALID'), ('carriage', 'OPENVIKING_KEY_INVALID')]:
            w = self.world()
            w.install()
            key = w.m.HOME / 'root.key'
            if attack.startswith('private'):
                (w.m.HOME if attack == 'private-home' else key).chmod(0o744)
            elif attack == 'owner':
                w.owners[key] = 0
            else:
                key.write_text({'empty': '', 'oversize': 'x' * 4097, 'blank': ' \n',
                                'newline': 'one\ntwo', 'carriage': 'one\rtwo'}[attack])
            self.reject(w.accept, code)

    def test_accept_runtime_modes_and_link_refusals(self):
        for attack, code in [('store-link', 'OPENVIKING_RUNTIME_LINK_INVALID'), ('runtime-link', 'OPENVIKING_RUNTIME_LINK_INVALID'),
                             ('runtime-owner', 'CUSTODY_INVALID'), ('writable-runtime', 'OPENVIKING_RUNTIME_WRITABLE')]:
            w = self.world()
            w.install()
            if attack == 'store-link':
                (w.m.HOME / 'venv').unlink()
                (w.m.HOME / 'venv').mkdir()
            elif attack == 'runtime-link':
                w.m.RUNTIME.chmod(0o755)
                (w.m.RUNTIME / 'escape').symlink_to(w.root / 'outside')
                w.m.RUNTIME.chmod(0o555)
            elif attack == 'runtime-owner':
                w.owners[w.m.RUNTIME] = 1001
            else:
                (w.m.RUNTIME / 'venv/bin/python').chmod(0o755)
            self.reject(w.accept, code)

    def test_accept_listener_service_llama_and_overlay_refusals(self):
        for attack, code in [('llama', 'OPENVIKING_LLAMA_INVALID'), ('service', 'OPENVIKING_INACTIVE'),
                             ('udp', 'OPENVIKING_UDP_UNAVAILABLE'), ('overlay-size', 'OPENVIKING_OVERLAY_INVALID'),
                             ('overlay-home', 'OPENVIKING_OVERLAY_INVALID'), ('overlay-mode', 'CUSTODY_INVALID'),
                             ('overlay-link', 'CUSTODY_INVALID'), ('overlay-hardlink', 'CUSTODY_INVALID')]:
            w = self.world()
            w.install()
            if attack == 'llama':
                w.llama_error = True
            elif attack in ('service', 'udp'):
                w.failure = code
            elif attack == 'overlay-mode':
                w.m.OVERLAY.chmod(0o644)
            elif attack == 'overlay-link':
                destination = w.m.OVERLAY.with_name('external-overlay')
                w.m.OVERLAY.rename(destination)
                w.m.OVERLAY.symlink_to(destination)
            elif attack == 'overlay-hardlink':
                os.link(w.m.OVERLAY, w.m.OVERLAY.with_name('overlay-hardlink'))
            else:
                w.m.OVERLAY.write_text(w.template + '#' * (64 * 1024 + 1) if attack == 'overlay-size' else '')
            self.reject(w.accept, code)
        for endpoints in ({'127.0.0.1:1933'}, {'127.0.0.1:1934'}, {'[::1]:1933', '[::1]:1934'}):
            w = self.world()
            w.install()
            self.reject(lambda: w.accept(endpoints), 'OPENVIKING_LISTENER_MISSING')
        for local in ('0.0.0.0:9', '[::]:9', 'not-an-address:9'):
            w = self.world()
            w.install()
            w.udp += 'UNCONN 0 0 ' + local + ' *:*\n'
            self.reject(w.accept, 'NON_LOOPBACK_LISTENER')

    def test_health_status_bound_body_unavailability_and_close(self):
        for attack, code in [('status', 'OPENVIKING_HEALTH_REFUSED'), ('body', 'OPENVIKING_HEALTH_REFUSED'),
                             ('transport', 'OPENVIKING_HEALTH_UNAVAILABLE')]:
            w = self.world()
            if attack == 'status':
                w.status = 503
            elif attack == 'body':
                w.body = b'x' * 4097
            else:
                w.http_error = True
            self.reject(lambda: w.m.health(w.n, 1933), code)
            self.assertEqual(w.requests[-1], ('closed',))

    def pipeline(self, bundled=False):
        w = PIPELINE.World(self.node_text)
        self.addCleanup(w.close)
        w.viking_events = []
        helper = types.SimpleNamespace(HOME=w.root / 'home/aukora-host/genesis/state/home/openviking',
            prepare=lambda n, archive, checkout: w.viking_events.append(('prepare', archive, checkout)),
            install=lambda n, release, config: w.viking_events.append(('install', release)))
        old_module, old_fresh = w.m.module, w.fresh.run
        w.m.module = lambda path: helper if path.name == 'openviking-node.py' else old_module(path)
        def materialize(command, name, cwd, env, timeout=None):
            if name == 'materialize':
                w.materialize_command = command
            return old_fresh(command, name, cwd, env, timeout)
        w.fresh.run = materialize
        if bundled:
            file = w.inputs / 'openviking.tar.gz'
            file.write_bytes(b'synthetic recall bundle')
            w.options.openviking_bundle = str(file)
            w.options.openviking_sha256 = hashlib.sha256(file.read_bytes()).hexdigest()
        return w, helper

    def test_pipeline_optional_install_and_unchanged_lexical_path(self):
        for bundled in (False, True):
            w, helper = self.pipeline(bundled)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                w.m.install(w.options)
            marker = json.loads((w.m.STATE / 'installed.json').read_text())
            if bundled:
                self.assertEqual(marker['inputs']['openviking'], w.options.openviking_sha256)
                self.assertEqual([row[0] for row in w.viking_events], ['prepare', 'install'])
                command = w.materialize_command
                self.assertEqual(command[command.index('--kira-openviking-home') + 1], str(helper.HOME))
                self.assertIn(['systemctl', 'enable', '--now', 'aukora-openviking.service'], w.commands)
                self.assertIn('KIRA_RECALL semantic configured;', output.getvalue())
            else:
                self.assertNotIn('openviking', marker['inputs'])
                self.assertEqual(w.viking_events, [])
                self.assertNotIn('--kira-openviking-home', w.materialize_command)
                self.assertFalse(any('aukora-openviking.service' in command for command in w.commands))
                self.assertIn('KIRA_RECALL lexical; no OpenViking bundle\n', output.getvalue())

    def test_pipeline_acceptance_after_bound_and_no_bundle(self):
        class Reached(Exception):
            pass
        for bundled in (False, True):
            w, helper = self.pipeline(bundled)
            w.installed_world()
            with contextlib.redirect_stdout(io.StringIO()):
                w.m.accept('before')
            w.approved, w.active = True, True
            reached = []
            def check(n, endpoints, phase):
                reached.append(phase)
                raise Reached()
            helper.accept = check
            old_bootstrap = w.m.bootstrap
            def stop(*args):
                if args[:2] == ('floor', 'check'):
                    raise Reached()
                return old_bootstrap(*args)
            w.m.bootstrap = stop
            for phase in ('after', 'bound'):
                binding = w.root / 'home/aukora-host/genesis/state/aumlok-binding/local-control.json'
                binding.parent.mkdir(parents=True, exist_ok=True)
                binding.write_text('synthetic bound control')
                with contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(Reached):
                    w.m.accept(phase)
                if bundled:
                    self.assertEqual(reached[-1], phase)
                else:
                    self.assertEqual(reached, [])
                    self.assertIn('KIRA_RECALL lexical; no OpenViking bundle\n', output.getvalue())
            self.assertEqual(reached, ['after', 'bound'] if bundled else [])

    def test_pipeline_rerun_and_optional_removal_preserve_state(self):
        for bundled in (False, True):
            w, helper = self.pipeline(bundled)
            w.installed_world()
            marker = w.m.STATE / 'installed.json'
            original = marker.read_bytes()
            w.viking_events.clear()
            with contextlib.redirect_stdout(io.StringIO()):
                w.m.install(w.options)
                w.m.main(['remove'])
            self.assertEqual(w.viking_events, [])
            self.assertEqual(marker.read_bytes(), original)

            removal = [command for command in w.commands if command[:3] == ['systemctl', 'disable', '--now']]
            self.assertEqual(removal, [
                ['systemctl', 'disable', '--now', 'aukora-aura-head.timer', 'aukora-aura-head.service'],
                ['systemctl', 'disable', '--now', 'aukora-browser.service', 'aukora-browser-claim.service',
                 'aukora-boundary-gate.service', *(['aukora-openviking.service'] if bundled else [])]])
            if bundled:
                file = Path(w.options.openviking_bundle)
                file.write_bytes(b'a different valid bundle')
                w.options.openviking_sha256 = hashlib.sha256(file.read_bytes()).hexdigest()
                self.reject(lambda: w.m.install(w.options), 'RERUN_CONFLICT')
                del w.options.openviking_bundle
                del w.options.openviking_sha256
                self.reject(lambda: w.m.install(w.options), 'RERUN_CONFLICT')
            self.assertEqual(marker.read_bytes(), original)

    def test_pipeline_bundle_start_refusal_keeps_marker_absent(self):
        w, helper = self.pipeline(True)
        w.fail = 'OPENVIKING_START_REFUSED'
        self.reject(lambda: w.m.install(w.options), 'OPENVIKING_START_REFUSED')
        self.assertFalse((w.m.STATE / 'installed.json').exists())
        self.assertEqual([row[0] for row in w.viking_events], ['prepare', 'install'])

    def test_pipeline_bundle_input_requires_custody(self):
        w, helper = self.pipeline(True)
        selected = Path(w.options.openviking_bundle)
        def custody(file, *args, **kwargs):
            if file == selected:
                raise ValueError('BROWSER_CUSTODY_INVALID')
        with patch.object(w.m, 'protected', custody):
            self.reject(lambda: w.m.checked_inputs(w.options, w.stage), 'CUSTODY_INVALID')
        self.assertEqual(w.commands, [])


def mutations():
    offsets, total = [0], 0
    for line in TEXT.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    methods = {'prepare': ['test_prepare_platform_python_existing_paths_and_space'],
               'install': ['test_install_command_and_overlay_refusals'],
               'health': ['test_health_status_bound_body_unavailability_and_close'],
               'accept': ['test_accept_key_modes_size_shape_and_owner_refusals', 'test_accept_runtime_modes_and_link_refusals',
                          'test_accept_listener_service_llama_and_overlay_refusals']}
    def kill(text, names, label, production=False):
        previous = OpenVikingNode.node_text if production else OpenVikingNode.helper_text
        setattr(OpenVikingNode, 'node_text' if production else 'helper_text', text)
        result = unittest.TestResult()
        with contextlib.redirect_stdout(io.StringIO()):
            for name in names:
                OpenVikingNode(name).run(result)
        setattr(OpenVikingNode, 'node_text' if production else 'helper_text', previous)
        assert result.failures or result.errors, 'mutation survived: ' + label
        print('KILLED browser OpenViking ' + label)
    for function in ast.parse(TEXT).body:
        if not isinstance(function, ast.FunctionDef):
            continue
        for call in ast.walk(function):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == 'need':
                arg = call.args[0]
                start = offsets[arg.lineno - 1] + arg.col_offset
                stop = offsets[arg.end_lineno - 1] + arg.end_col_offset
                kill(TEXT[:start] + 'True' + TEXT[stop:], methods[function.name], 'guard %s:%s' % (function.name, call.lineno))
                total += 1
    cases = [
        ('runtime-readonly', '    readonly(RUNTIME)\n', '', 'test_install_offline_closure_private_state_readonly_runtime_and_overlay'),
        ('llama-executable', 'readonly(LLAMA, executable=True)', 'readonly(LLAMA)', 'test_install_offline_closure_private_state_readonly_runtime_and_overlay'),
        ('offline-pip', "'--no-index', ", '', 'test_install_offline_closure_private_state_readonly_runtime_and_overlay'),
        ('locked-pip', "'--require-hashes',", '', 'test_install_offline_closure_private_state_readonly_runtime_and_overlay'),
        ('closure-pip', "n.run([python, '-I', '-m', 'pip', '--isolated', 'check'], 'OPENVIKING_CLOSURE_REFUSED')", '', 'test_install_offline_closure_private_state_readonly_runtime_and_overlay'),
        ('key-private', 'file.chmod(0o600)', 'file.chmod(0o644)', 'test_install_offline_closure_private_state_readonly_runtime_and_overlay'),
        ('key-owned', '        os.chown(file, uid, gid)\n', '', 'test_install_offline_closure_private_state_readonly_runtime_and_overlay'),
        ('overlay-kira-state', "json.dumps(str(HOME.parent / 'kira-memory'))", "json.dumps(str(HOME.parent.parent / 'kira-memory'))", 'test_install_offline_closure_private_state_readonly_runtime_and_overlay'),
        ('private-key-check', "    n.protected(HOME / 'root.key', uid=uid, private=True)\n", '', 'test_accept_key_modes_size_shape_and_owner_refusals'),
        ('private-overlay-check', "    n.protected(OVERLAY, uid=uid, private=True)\n", '', 'test_accept_listener_service_llama_and_overlay_refusals'),
        ('root-runtime-check', '                n.protected(file, file.is_dir())\n', '', 'test_accept_runtime_modes_and_link_refusals'),
        ('python-custody', '    n.protected(PYTHON)\n', '', 'test_prepare_platform_python_existing_paths_and_space'),
        ('parent-custody', '        n.protected(LLAMA.parent, True)\n', '        pass\n', 'test_prepare_platform_python_existing_paths_and_space'),
        ('unit-swap', 'MemorySwapMax=0', 'MemorySwapMax=1G', 'test_install_unit_limits_and_direct_offline_supervisor'),
        ('unit-private-home', "    unit = unit.replace('Environment=HOME=/home/aukora-host', 'Environment=HOME=' + str(HOME))\n", '', 'test_install_unit_limits_and_direct_offline_supervisor'),
        ('unit-loopback', 'IPAddressAllow=localhost', 'IPAddressAllow=any', 'test_install_unit_limits_and_direct_offline_supervisor'),
        ('server-loopback', "'host': '127.0.0.1'", "'host': '0.0.0.0'", 'test_install_offline_closure_private_state_readonly_runtime_and_overlay'),
        ('health-loopback', "HTTPConnection('127.0.0.1', port, timeout=5)", "HTTPConnection('0.0.0.0', port, timeout=5)", 'test_accept_both_phases_verify_root_custody_private_key_and_health'),
    ]
    for label, before, after, method in cases:
        assert TEXT.count(before) == 1, label
        kill(TEXT.replace(before, after), [method], label)
        total += 1
    for key, value in [('MemoryHigh', 'infinity'), ('MemoryMax', 'infinity'), ('CPUQuota', 'infinity'),
                       ('Environment=AUKORA_OPENVIKING_EMBED_RSS_MIB', '4096'),
                       ('Environment=AUKORA_OPENVIKING_EMBED_THREADS', '4')]:
        before = "    config.write(UNIT, unit.encode(), Path('/'))"
        after = "    unit += '\\n[Service]\\n" + key + '=' + value + "\\n'\n" + before
        kill(TEXT.replace(before, after), ['test_install_unit_limits_and_direct_offline_supervisor'], 'effective-unit-' + key)
        total += 1
    node = NODE.read_text()
    integrations = [
        ('record-bundle', "        binding['openviking'] = options.openviking_sha256\n", '', 'test_pipeline_optional_install_and_unchanged_lexical_path'),
        ('input-bundle-custody', '        file = absolute(options.openviking_bundle)\n        protected(file)\n',
         '        file = absolute(options.openviking_bundle)\n', 'test_pipeline_bundle_input_requires_custody'),
        ('prepare-bundle', '        viking.prepare(SimpleNamespace(**globals()), Path(options.openviking_bundle), checkout)\n', '', 'test_pipeline_optional_install_and_unchanged_lexical_path'),
        ('materialize-home', "*(['--kira-openviking-home', str(viking.HOME)] if viking is not None else [])", '*[]', 'test_pipeline_optional_install_and_unchanged_lexical_path'),
        ('install-bundle', '        viking.install(SimpleNamespace(**globals()), release, config)\n', '', 'test_pipeline_optional_install_and_unchanged_lexical_path'),
        ('start-bundle', "        run(['systemctl', 'enable', '--now', 'aukora-openviking.service'], 'OPENVIKING_START_REFUSED')\n", '        pass\n', 'test_pipeline_optional_install_and_unchanged_lexical_path'),
        ('accept-bundle', "        module(CHECKOUT / 'ops/node-spawn/browser/openviking-node.py').accept(SimpleNamespace(**globals()), endpoints, phase)\n", '        pass\n', 'test_pipeline_acceptance_after_bound_and_no_bundle'),
        ('remove-bundle', "*(['aukora-openviking.service'] if 'openviking' in installed()['inputs'] else [])", '*[]', 'test_pipeline_rerun_and_optional_removal_preserve_state'),
    ]
    for label, before, after, method in integrations:
        assert node.count(before) == 1, label
        kill(node.replace(before, after), [method], label, True)
        total += 1
    print('SOURCE-ONLY browser OpenViking mutations: %d/%d killed; mocked commands and ownership, no node execution' % (total, total))


if __name__ == '__main__':
    if '--mutations' in sys.argv:
        mutations()
    else:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(OpenVikingNode)
        result = unittest.TextTestRunner().run(suite)
        print('SOURCE-ONLY browser OpenViking: %d tests; %d failures; %d errors; no root, services or network' %
              (result.testsRun, len(result.failures), len(result.errors)))
        sys.exit(0 if result.wasSuccessful() else 1)
