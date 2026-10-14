# Execute installer transitions with synthetic commands and paths kept inside the clone.
import contextlib
import hashlib
import base64
import http.client
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
# Scratch directories must not be group-writable whatever umask the runner inherits (Ubuntu's default is 002).
os.umask(0o022)
SOURCE = ROOT / 'ops/node-spawn/browser/node.py'
SCRATCH = ROOT / '.runtime/browser-pipeline'
SCRATCH.mkdir(parents=True, exist_ok=True)
sha = lambda data: hashlib.sha256(data).hexdigest()
REAL_RUN = subprocess.run
PINNED_NODE = shutil.which('node')


class World:
    def __init__(self, text=None):
        self.root = Path(tempfile.mkdtemp(dir=SCRATCH))
        self.events, self.commands = [], []
        self.fail, self.attack = None, None
        self.active, self.approved, self.owner_approved, self.ui_ok = False, False, False, True
        self.bad_journal, self.bad_invocation, self.bad_user, self.bad_groups = False, False, False, False
        self.listener_after_refusal, self.floor_accepts_before, self.starts_before = False, False, False
        self.leak_on_start, self.active_after_refusal, self.hide_app = False, False, False
        self.text = SOURCE.read_text() if text is None else text
        # One pass: a scratch root that itself lies under /home must not be rewritten a second time.
        self.text = re.sub(r'(?<![\w./-])(/var/lib/|/opt/|/etc/|/home/|/usr/local/)', lambda m: str(self.root) + m.group(1), self.text)
        self.m = types.ModuleType('browser_pipeline_fixture')
        self.m.__file__ = str(SOURCE)
        exec(compile(self.text, str(SOURCE), 'exec'), self.m.__dict__)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        for name, data in [('checkout.bundle', b'clean bundle'), ('node.tar.xz', b'pinned node'),
                           ('dependencies.tar.gz', b'offline dependencies'), ('dsh-source.tar.gz', b'pinned harness')]:
            (self.inputs / name).write_bytes(data)
        self.options = types.SimpleNamespace(inputs=str(self.inputs), checkout_sha256=sha(b'clean bundle'),
            node_sha256=sha(b'pinned node'), dependencies_sha256=sha(b'offline dependencies'), revision='a' * 40,
            app_host='app.example.test', owner_host='owner.example.test')
        for name in ('opt', 'home', 'etc', 'var/lib'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        self.stage = types.SimpleNamespace(digest_file=lambda file: sha(file.read_bytes()),
            source_check=self.source_check, public_modes=lambda file: self.events.append(('modes', str(file))))
        self.fresh = types.SimpleNamespace(verify_archive=self.verify_archive, preflight=lambda: self.events.append(('preflight',)),
            run=self.fresh_run, verify_built=self.verify_built)
        self.config = types.SimpleNamespace(write=self.write, parents=lambda file, root: file.parent.mkdir(parents=True, exist_ok=True))
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(patch.dict(os.environ, {}, clear=False))
        for name, replacement in [('root_check', lambda: None), ('protected', lambda *args, **kwargs: None),
            ('module', self.module), ('run', self.run), ('extract', self.extract), ('bootstrap', self.bootstrap),
            ('sockets', self.sockets), ('profile', lambda path, checkout=None: self.events.append(('profile', str(path))))]:
            self.stack.enter_context(patch.object(self.m, name, replacement))
        self.stack.enter_context(patch.object(self.m.subprocess, 'run', self.subprocess))
        if hasattr(self.m, 'aura_custody'):
            self.stack.enter_context(patch.object(self.m, 'aura_custody', lambda: self.events.append(('aura-custody',))))

    def close(self):
        self.stack.close()
        shutil.rmtree(self.root)

    def module(self, file):
        return self.stage if file.name == 'stage.py' else self.fresh if file.name == 'fresh_clone.py' else self.config

    def write(self, file, data, root, mode=0o644):
        self.events.append(('write', file.name))
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
        file.chmod(mode)

    def source_check(self, value):
        self.events.append(('source-check',))
        if self.attack == 'source':
            raise ValueError('BROWSER_FIXTURE_SOURCE_MISMATCH')
        assert value['release_commit'] == self.options.revision

    def verify_archive(self, file, pin):
        self.events.append(('harness-digest',))
        if sha(file.read_bytes()) != pin['archiveSha256']:
            raise ValueError('BROWSER_FIXTURE_HARNESS_MISMATCH')

    def verify_built(self, *args):
        self.events.append(('build-binding',))
        if self.attack == 'build-binding':
            raise ValueError('BROWSER_FIXTURE_BUILD_MISMATCH')

    def extract(self, file, target):
        self.events.append(('extract', file.name))
        target.mkdir()
        if file.name == 'dependencies.tar.gz':
            for name in ('debs', 'pnpm/bin', 'store'):
                (target / name).mkdir(parents=True)
            if self.attack != 'dependencies':
                (target / 'debs/build.deb').write_bytes(b'fixture')
            (target / 'pnpm/bin/pnpm.cjs').write_text('fixture')
        else:
            name = 'node-invalid' if self.attack == 'node-name' else 'node-v24.11.1-linux-x64'
            node = target / name
            (node / 'bin').mkdir(parents=True)
            (node / 'bin/node').write_text('fixture')
            if self.attack != 'node-headers':
                (node / 'include/node').mkdir(parents=True)
                (node / 'include/node/node_api.h').write_text('fixture')

    def clone(self, target):
        target.mkdir()
        for name in ('vendor', 'scripts', 'ops/node-spawn/browser', 'packages/owner-key',
                     'packages/authority', 'packages/contracts', 'plugins/aukora-aumlok',
                     'packages/boundary-gate/host/install', 'packages/boundary-gate/host/systemd'):
            (target / name).mkdir(parents=True, exist_ok=True)
        for name in ('packages/authority', 'packages/contracts', 'plugins/aukora-aumlok'):
            (target / name / 'fixture.mjs').write_text('// synthetic package inventory\n')
        (target / 'upstream-dsh.json').write_text(json.dumps({'archiveSha256': sha(b'pinned harness'), 'packageManager': 'pnpm@11.7.0'}))
        (target / 'ops/node-spawn/browser/keys.mjs').write_text('fixture keys')
        (target / 'packages/boundary-gate/host/install/gate-bootstrap.py').write_text('fixture bootstrap')
        shutil.copyfile(ROOT / 'packages/boundary-gate/host/systemd/aukora-boundary-gate.service',
            target / 'packages/boundary-gate/host/systemd/aukora-boundary-gate.service')

    def fresh_run(self, command, name, cwd, env, timeout=None):
        self.events.append((name,))
        if self.fail == name:
            raise ValueError('BROWSER_FIXTURE_' + name.upper())
        assert env['npm_config_offline'] == 'true'
        assert Path(env['npm_config_store_dir']).is_dir()
        if name == 'materialize':
            assert '--browser-node' in command
            Path(command[command.index('--to') + 1]).mkdir()

    def run(self, command, code, env=None, cwd=None, expected=0):
        self.commands.append(list(map(str, command)))
        self.events.append(('run', code))
        if self.fail == code:
            raise ValueError('BROWSER_' + code)
        if code == 'CLONE_REFUSED':
            self.clone(Path(command[-1]))
        elif code in ('HOME_CREATE_REFUSED', 'STATE_CREATE_REFUSED', 'TARGET_CREATE_REFUSED', 'AURA_STATE_CREATE_REFUSED'):
            Path(command[-1]).mkdir(parents=True, exist_ok=True)
        elif code == 'KEY_GENERATION_REFUSED':
            file = self.root / 'home/aukora-gate/signer-epochs.json'
            file.write_text(json.dumps({'version': 1, 'kind': 'aukora-signer-epochs/v1',
                'epochs': [{'epoch': 1, 'gate_pubkey_sha256': '1' * 64}]}))
        elif code == 'MANIFEST_REFUSED':
            Path(command[-1]).write_text('{"fixture":true}')
        elif code == 'RELEASE_ENV_REFUSED':
            (self.root / 'etc/aukora-genesis').mkdir(parents=True, exist_ok=True)
            (self.root / 'etc/aukora-genesis/release.env').write_text('fixture')
        elif code == 'NODE_INVALID':
            return 'v22.0.0' if self.attack == 'node-version' else 'v24.11.1'
        elif code == 'PNPM_INVALID':
            return '0.0.0' if self.attack == 'pnpm-version' else '11.7.0'
        elif code == 'GROUP_MISSING':
            return 'aukora-host skgate' if command[0] == 'id' and command[-1] == 'aukora-host' and not self.bad_groups else 'skgate' if command[0] == 'id' else 'skgate:x:123:aukora-host'
        elif code == 'USER_MISSING':
            user = command[-1]
            return f'{user}:x:1001:1001::{self.root}/home/{user}:/usr/sbin/nologin' if not self.bad_user else f'{user}:x:0:0::wrong:/bin/sh'
        elif code == 'LISTENERS_UNAVAILABLE':
            app = (self.active and not self.hide_app) or self.listener_after_refusal
            return 'State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 1 127.0.0.1:17792 *:*\n' + ('LISTEN 0 1 127.0.0.1:18735 *:*\n' if app else '')
        elif code == 'UI_PROBE_REFUSED':
            if not self.ui_ok:
                raise ValueError('BROWSER_UI_PROBE_REFUSED')
            return 'UI PROBE: all served'
        elif code == 'JOURNAL_UNAVAILABLE':
            return 'not-an-id' if self.bad_invocation else 'aukora-demo (file:///fixture): Error fixture' if self.bad_journal and command[0] == 'journalctl' else '' if command[0] == 'journalctl' else 'a' * 32
        elif code == 'HARNESS_INACTIVE' and not self.active:
            raise ValueError('BROWSER_HARNESS_INACTIVE')
        elif code == 'HARNESS_START_REFUSED':
            self.active = True
        return ''

    def bootstrap(self, *args):
        self.events.append(('bootstrap', *map(str, args)))
        if self.fail == 'bootstrap-' + '-'.join(map(str, args[:2])):
            raise ValueError('BROWSER_BOOTSTRAP_REFUSED')
        if args[:2] in (('approval', 'install'), ('approval', 'recover-cache')):
            if not self.owner_approved:
                raise ValueError('BROWSER_BOOTSTRAP_REFUSED')
            if args[1] == 'recover-cache' and not self.approved:
                raise ValueError('BROWSER_BOOTSTRAP_REFUSED')
            if args[1] == 'install' and self.approved:
                raise ValueError('BROWSER_BOOTSTRAP_REFUSED')
            self.approved = True
            output = Path(args[args.index('--out') + 1])
            output.mkdir(parents=True, exist_ok=True)
            (output / 'plugin-set-approval.json').write_text('public signed approval')
            floor = self.root / 'etc/aukora-approvals/release-floor.json'
            floor.write_text('public signed floor')
        if args[:2] == ('floor', 'check') and not self.approved:
            raise ValueError('BROWSER_BOOTSTRAP_REFUSED')
        return ''

    def sockets(self):
        self.events.append(('sockets',))
        if self.fail == 'sockets':
            raise ValueError('BROWSER_GATE_SOCKETS_MISSING')

    def subprocess(self, command, **kwargs):
        self.commands.append(list(map(str, command)))
        if command[0] == 'getent':
            code = 0 if self.attack == 'existing-user' else 2
        elif command[:2] == ['systemctl', 'start']:
            if self.leak_on_start:
                self.listener_after_refusal = True
            if self.active_after_refusal:
                self.active = True
            code = 0 if self.starts_before else 1
        elif command[:2] == ['systemctl', 'is-active']:
            code = 0 if self.active else 3
        else:
            code = 0 if self.approved or self.floor_accepts_before else 1
        return subprocess.CompletedProcess(command, code, b'', b'')

    def installed_world(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.m.install(self.options)
        self.events.clear()
        self.commands.clear()


class Pipeline(unittest.TestCase):
    def world(self, text=None):
        result = World(text)
        self.addCleanup(result.close)
        return result

    def refuses(self, function, code):
        with self.assertRaisesRegex(ValueError, '^BROWSER_' + code + '$'):
            function()

    def test_each_input_digest(self):
        for file in ('checkout.bundle', 'node.tar.xz', 'dependencies.tar.gz'):
            with self.subTest(file=file):
                w = self.world()
                (w.inputs / file).write_bytes(b'changed')
                self.refuses(lambda: w.m.install(w.options), 'INPUT_DIGEST_MISMATCH')
                self.assertEqual(w.commands, [])
        w = self.world()
        bundle = w.inputs / 'openviking.tar.gz'
        bundle.write_bytes(b'pinned recall bundle')
        w.options.openviking_bundle, w.options.openviking_sha256 = str(bundle), sha(bundle.read_bytes())
        w.m.checked_inputs(w.options, w.stage)
        bundle.write_bytes(b'changed recall bundle')
        self.refuses(lambda: w.m.install(w.options), 'OPENVIKING_DIGEST_MISMATCH')
        self.assertEqual(w.commands, [])
        w.options.openviking_bundle = 'relative-bundle'
        self.refuses(lambda: w.m.checked_inputs(w.options, w.stage), 'PATH_INVALID')
        w.options.openviking_bundle = str(bundle)
        w.options.openviking_sha256 = 'INVALID'
        self.refuses(lambda: w.m.checked_inputs(w.options, w.stage), 'DIGEST_INVALID')
        def bundle_custody(path, *args, **kwargs):
            if path == bundle:
                raise ValueError('BROWSER_CUSTODY_INVALID')
        w.options.openviking_sha256 = sha(bundle.read_bytes())
        with patch.object(w.m, 'protected', side_effect=bundle_custody):
            self.refuses(lambda: w.m.checked_inputs(w.options, w.stage), 'CUSTODY_INVALID')

    def test_clean_source_and_pinned_harness_precede_build(self):
        for attack, code in [('source', 'FIXTURE_SOURCE_MISMATCH'), ('build-binding', 'FIXTURE_BUILD_MISMATCH')]:
            w = self.world()
            w.attack = attack
            self.refuses(lambda: w.m.install(w.options), code)
            self.assertNotIn(('materialize',), w.events)
        w = self.world()
        (w.inputs / 'dsh-source.tar.gz').write_bytes(b'changed')
        self.refuses(lambda: w.m.install(w.options), 'FIXTURE_HARNESS_MISMATCH')
        self.assertNotIn(('build',), w.events)

    def test_dependency_and_node_package_checks(self):
        for attack, code in [('dependencies', 'DEPENDENCIES_MISSING'), ('node-name', 'NODE_ARCHIVE_INVALID'),
            ('node-headers', 'NODE_HEADERS_MISSING'), ('node-version', 'NODE_VERSION_MISMATCH'), ('pnpm-version', 'PNPM_VERSION_MISMATCH')]:
            with self.subTest(attack=attack):
                w = self.world()
                w.attack = attack
                self.refuses(lambda: w.m.install(w.options), code)
                self.assertNotIn(('build',), w.events)

    def test_fresh_install_does_not_adopt_existing_state_or_users(self):
        for attack, code in [('state', 'PARTIAL_INSTALL_REQUIRES_REVIEW'), ('existing-user', 'USER_EXISTS'), ('package', 'INSTALL_EXISTS')]:
            w = self.world()
            w.attack = attack
            if attack == 'state':
                w.m.STATE.mkdir()
            elif attack == 'package':
                (w.root / 'opt/aukora-node').mkdir()
            self.refuses(lambda: w.m.install(w.options), code)
            self.assertNotIn(('build',), w.events)
        w = self.world()
        w.options.owner_host = w.options.app_host
        self.refuses(lambda: w.m.install(w.options), 'HOST_CONFLICT')
        self.assertEqual(w.commands, [])
        for path in ('/opt/authority', '/opt/contracts', '/opt/aukora-aumlok', '/etc/aukora',
                     '/etc/systemd/system/aukora-browser-claim.service',
                     '/etc/systemd/system/aukora-boundary-gate.service.d',
                     '/var/lib/aukora-aura', '/etc/systemd/system/aukora-aura-head.service',
                     '/etc/systemd/system/aukora-aura-head.timer'):
            w = self.world()
            occupied = w.root / path[1:]
            occupied.mkdir(parents=True)
            self.refuses(lambda: w.m.install(w.options), 'INSTALL_EXISTS')
            self.assertNotIn(('build',), w.events)

    def test_success_publishes_marker_after_sockets_and_raise_without_starting_harness(self):
        w = self.world()
        with contextlib.redirect_stdout(io.StringIO()):
            w.m.install(w.options)
        marker = w.events.index(('write', 'installed.json'))
        self.assertGreater(marker, w.events.index(('sockets',)))
        raise_index = next(i for i, event in enumerate(w.events) if event[:3] == ('bootstrap', 'approval', 'raise'))
        self.assertGreater(marker, raise_index)
        self.assertLess(w.events.index(('harness-digest',)), w.events.index(('build',)))
        self.assertLess(w.events.index(('build-binding',)), w.events.index(('materialize',)))
        self.assertEqual(sum(event == ('run', 'KEY_GENERATION_REFUSED') for event in w.events), 1)
        self.assertFalse(any(command[0] == 'systemctl' and 'aukora-browser.service' in command for command in w.commands))
        self.assertIn(['systemctl', 'enable', '--now', 'aukora-browser-claim.service'], w.commands)
        for name, host in [('public-origin', w.options.app_host), ('owner-public-origin', w.options.owner_host)]:
            file = w.root / 'etc/aukora' / name
            self.assertEqual(file.read_text(), 'https://' + host + '\n')
            self.assertEqual(file.stat().st_mode & 0o777, 0o644)
        manifest = next(command for command in w.commands if any(item.endswith('/generate-manifest.py') for item in command))
        for name, destination, flag in [('authority', 'authority', '--passkey-authority'),
                ('contracts', 'contracts', '--passkey-contracts'),
                ('browser-aumlok', 'aukora-aumlok', '--browser-aumlok')]:
            installed = w.root / 'opt' / destination
            self.assertEqual((installed / 'fixture.mjs').read_text(), '// synthetic package inventory\n')
            self.assertIn(('modes', str(w.m.STATE / name)), w.events)
            self.assertEqual(manifest[manifest.index(flag) + 1], str(w.m.STATE / name))
            self.assertEqual((w.m.STATE / name / 'fixture.mjs').read_bytes(), (installed / 'fixture.mjs').read_bytes())

    def test_external_refusals_never_publish_install_marker(self):
        for failure in ('OS_DEPENDENCIES_REFUSED', 'CLONE_REFUSED', 'BUNDLE_INVALID', 'REVISION_MISSING', 'GROUP_CREATE_REFUSED',
            'USER_CREATE_REFUSED', 'HOME_CREATE_REFUSED', 'KEY_GENERATION_REFUSED', 'MANIFEST_REFUSED',
            'TARGET_CREATE_REFUSED', 'STATE_CREATE_REFUSED', 'RELEASE_ENV_REFUSED', 'GROUP_MISSING',
            'bootstrap-check-package', 'bootstrap-check-runtime', 'SYSTEMD_REFUSED', 'GATE_START_REFUSED', 'CLAIM_START_REFUSED',
            'AURA_USER_CREATE_REFUSED', 'AURA_STATE_CREATE_REFUSED', 'AURA_COLLECT_REFUSED', 'AURA_TIMER_START_REFUSED',
            'sockets', 'bootstrap-approval-raise'):
            with self.subTest(failure=failure):
                w = self.world()
                w.fail = failure
                with self.assertRaises(ValueError):
                    w.m.install(w.options)
                self.assertFalse((w.m.STATE / 'installed.json').exists(), failure)

    def test_aura_collector_install_custody_and_order(self):
        w = self.world()
        with contextlib.redirect_stdout(io.StringIO()):
            w.m.install(w.options)
        user = next(command for command in w.commands if command[0] == 'useradd' and command[-1] == 'aukora-aura')
        self.assertEqual(user[user.index('--home-dir') + 1], str(w.root / 'var/lib/aukora-aura'))
        self.assertEqual(user[user.index('--shell') + 1], '/usr/sbin/nologin')
        self.assertIn('--system', user)
        self.assertIn('--user-group', user)
        self.assertEqual(user[user.index('--groups') + 1], 'skgate')
        for path, owner, group, mode in [('var/lib/aukora-aura', 'root', 'root', 0o755),
                                        ('var/lib/aukora-aura/head', 'aukora-aura', 'aukora-host', 0o2750)]:
            directory = next(command for command in w.commands if command[0] == 'install' and command[-1] == str(w.root / path))
            self.assertEqual(directory[directory.index('-o') + 1], owner)
            self.assertEqual(directory[directory.index('-g') + 1], group)
            self.assertEqual(int(directory[directory.index('-m') + 1], 8), mode)
        for name in ('aukora-aura-head.service', 'aukora-aura-head.timer'):
            file = w.root / 'etc/systemd/system' / name
            self.assertTrue(file.is_file())
            self.assertEqual(file.stat().st_mode & 0o777, 0o644)
        collect = w.events.index(('run', 'AURA_COLLECT_REFUSED'))
        timer = w.events.index(('run', 'AURA_TIMER_START_REFUSED'))
        raised = next(i for i, event in enumerate(w.events) if event[:3] == ('bootstrap', 'approval', 'raise'))
        self.assertGreater(collect, w.events.index(('sockets',)))
        self.assertGreater(collect, raised)
        self.assertGreater(timer, collect)
        self.assertGreater(w.events.index(('write', 'installed.json')), timer)
        self.assertIn(['systemctl', 'start', 'aukora-aura-head.service'], w.commands)
        self.assertIn(['systemctl', 'enable', '--now', 'aukora-aura-head.timer'], w.commands)

    def test_rerun_is_exact_and_never_regenerates_keys(self):
        w = self.world()
        w.installed_world()
        with contextlib.redirect_stdout(io.StringIO()):
            w.m.install(w.options)
        self.assertNotIn(('run', 'KEY_GENERATION_REFUSED'), w.events)
        w.options.app_host = 'other.example.test'
        self.refuses(lambda: w.m.install(w.options), 'RERUN_CONFLICT')
        w.options.app_host = 'app.example.test'
        w.options.revision = 'b' * 40
        self.refuses(lambda: w.m.install(w.options), 'RERUN_CONFLICT')

    def test_install_record_is_closed_and_revision_checked(self):
        w = self.world()
        w.installed_world()
        marker = w.m.STATE / 'installed.json'
        for value in [None, [], {'revision': 'a' * 40}, {'revision': 'a' * 40, 'inputs': []},
                      {'revision': 'a' * 40, 'inputs': {}, 'extra': 'field'}]:
            marker.write_text(json.dumps(value))
            self.refuses(w.m.installed, 'INSTALL_RECORD_INVALID')
        marker.write_text(json.dumps({'revision': 'invalid', 'inputs': {}}))
        self.refuses(w.m.installed, 'DIGEST_INVALID')

    def test_start_requires_approval_and_exact_floor_and_can_restart(self):
        w = self.world()
        w.installed_world()
        self.refuses(w.m.start, 'BOOTSTRAP_REFUSED')
        self.assertNotIn(('run', 'HARNESS_START_REFUSED'), w.events)
        w.events.clear()
        w.owner_approved = True
        with contextlib.redirect_stdout(io.StringIO()):
            w.m.start()
            floor = (w.root / 'etc/aukora-approvals/release-floor.json').read_bytes()
            w.m.start()
        self.assertEqual((w.root / 'etc/aukora-approvals/release-floor.json').read_bytes(), floor)
        self.assertTrue(w.active)
        self.assertTrue(any('recover-cache' in command for command in w.commands))
        floor_checks = [i for i, event in enumerate(w.events) if event == ('run', 'FLOOR_REFUSED')]
        starts = [i for i, event in enumerate(w.events) if event == ('run', 'HARNESS_START_REFUSED')]
        self.assertEqual(len(starts), 2)
        self.assertEqual(len(floor_checks), 2)
        self.assertTrue(all(check < start for check, start in zip(floor_checks, starts)))
        collect = [i for i, event in enumerate(w.events) if event == ('run', 'AURA_COLLECT_REFUSED')]
        self.assertEqual(len(collect), 2)
        self.assertTrue(all(check < refresh < start for check, refresh, start in zip(floor_checks, collect, starts)))
        for failure in ('bootstrap-check-package', 'bootstrap-check-runtime', 'sockets', 'FLOOR_REFUSED', 'AURA_COLLECT_REFUSED', 'HARNESS_START_REFUSED'):
            w.fail = failure
            with self.assertRaises(ValueError):
                w.m.start()

    def test_before_acceptance_refuses_any_floor_start_listener_or_descriptor(self):
        for attack, code in [('approved', 'ALREADY_APPROVED'), ('floor', 'UNAPPROVED_FLOOR_ACCEPTED'),
            ('start', 'UNAPPROVED_HARNESS_STARTED'), ('active', 'UNAPPROVED_HARNESS_ACTIVE'),
            ('listener', 'UNAPPROVED_LISTENER'), ('descriptor', 'UNAPPROVED_DESCRIPTOR')]:
            w = self.world()
            w.installed_world()
            if attack == 'approved':
                folder = w.root / 'etc/aukora-approvals'
                folder.mkdir(exist_ok=True)
                (folder / 'release-floor.json').write_text('fixture')
            elif attack == 'floor':
                w.floor_accepts_before = True
            elif attack == 'start':
                w.starts_before = True
            elif attack == 'active':
                w.active_after_refusal = True
            elif attack == 'listener':
                w.leak_on_start = True
            else:
                (w.root / 'home/aukora-host/genesis/state/launch-url.json').write_text('fixture')
            self.refuses(lambda: w.m.accept('before'), code)

    def test_after_acceptance_requires_signed_in_ui_and_clean_current_invocation(self):
        w = self.world()
        w.installed_world()
        w.approved, w.active = True, True
        self.refuses(lambda: w.m.accept('bound'), 'BINDING_REQUIRED')
        for attack, code in [('inactive', 'HARNESS_INACTIVE'), ('listener', 'HARNESS_LISTENER_MISSING'), ('ui', 'UI_PROBE_REFUSED'),
            ('invocation', 'JOURNAL_UNAVAILABLE'), ('journal', 'PLUGIN_LOAD_FAILED'), ('groups', 'USER_GROUP_INVALID'),
            ('user', 'USER_INVALID'), ('node-version', 'NODE_VERSION_MISMATCH')]:
            w = self.world()
            w.installed_world()
            w.approved, w.active = True, attack != 'inactive'
            w.hide_app = attack == 'listener'
            w.ui_ok, w.bad_invocation, w.bad_journal = attack != 'ui', attack == 'invocation', attack == 'journal'
            w.bad_groups, w.bad_user = attack == 'groups', attack == 'user'
            w.attack = attack
            self.refuses(lambda: w.m.accept('after'), code)
        w = self.world()
        w.installed_world()
        w.approved, w.active = True, True
        (w.root / 'opt/aukora-boundary-gate/escape').symlink_to(w.root / 'inputs')
        self.refuses(lambda: w.m.accept('after'), 'PACKAGE_LINK')
        w = self.world()
        w.installed_world()
        w.fail = 'SIGNER_REFUSED'
        self.refuses(lambda: w.m.accept('after'), 'SIGNER_REFUSED')

    def public_world(self, attack=None, text=None):
        w = self.world(text)
        w.installed_world()
        w.approved, w.active = True, True
        w.public_requests, w.origin_reads = [], []
        floor = {'ledger_seq': 5, 'signer_key_sha256': '1' * 64}
        if attack == 'aura-floor':
            floor['ledger_seq'] = True
        folder = w.root / 'etc/aukora-approvals'
        folder.mkdir(exist_ok=True)
        (folder / 'release-floor.json').write_text(json.dumps(floor))
        aura = {'schema': 'aukora-face/aura-snapshot:v1', 'head': 'a' * 64, 'sources': [
            {'name': 'gate-ledger', 'head': 'b' * 64, 'entries': 5, 'absence': None},
            {'name': 'kira-chain', 'head': None, 'entries': 0, 'absence': 'kira-ledger-missing',
             'browserMemory': {'active': False, 'reason': 'kira.memory:aumlok-not-linked'}},
            {'name': 'code-chain', 'head': 'c' * 64, 'entries': 1, 'absence': None}]}
        gate_head = {'head': 'b' * 64, 'entries': 5}
        kira_head = {'head': None, 'entries': 0, 'absence': 'kira-ledger-missing'}
        w.aura, w.gate_head, w.kira_head = aura, gate_head, kira_head
        if attack in ('aura-kira-present', 'aura-kira-missing', 'aura-kira-head', 'aura-kira-count', 'aura-bound-empty'):
            directory = w.root / 'home/aukora-host/genesis/state/aumlok-binding'
            directory.mkdir()
            (directory / 'local-control.json').write_text('synthetic bound control')
            aura['sources'][1]['browserMemory'] = {'active': True, 'reason': 'kira.memory:aumlok-linked'}
        if attack in ('aura-kira-present', 'aura-kira-missing', 'aura-kira-head', 'aura-kira-count'):
            kira_head.update(head='d' * 64, entries=1, absence=None)
            if attack != 'aura-kira-missing':
                aura['sources'][1].update(kira_head)
            if attack == 'aura-kira-head':
                aura['sources'][1]['head'] = 'e' * 64
            if attack == 'aura-kira-count':
                aura['sources'][1]['entries'] = 2
        if attack == 'aura-gate-missing':
            aura['sources'][0].update(head=None, entries=None, absence='gate-ledger-unavailable')
        if attack == 'aura-gate-short':
            aura['sources'][0]['entries'] = 4
        if attack == 'aura-gate-head':
            aura['sources'][0]['head'] = 'e' * 64
        if attack == 'aura-gate-count':
            gate_head['entries'] = 6
        if attack == 'aura-code-missing':
            aura['sources'][2].update(head=None, entries=None, absence='code-chain-unavailable')
        if attack == 'aura-kira-absence':
            aura['sources'][1]['absence'] = None
        if attack == 'aura-order':
            aura['sources'][1:] = reversed(aura['sources'][1:])
        if attack == 'aura-source-extra':
            aura['sources'][0]['unverified'] = True
        if attack == 'aura-gate-boolean':
            aura['sources'][0]['entries'] = True
        if attack == 'aura-kira-boolean':
            aura['sources'][1]['entries'] = False
        claim_file = ROOT / 'ops/node-spawn/ingress/claim.py'
        spec = importlib.util.spec_from_file_location('claim_acceptance_fixture', claim_file)
        claim = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(claim)
        for name, value in [('public-origin', 'https://app.example.test'), ('owner-public-origin', 'https://owner.example.test')]:
            file = w.root / 'etc/aukora' / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(value + '\n')
            file.chmod(0o644)
        if attack in ('public-invalid', 'owner-invalid'):
            (w.root / 'etc/aukora' / ('public-origin' if attack.startswith('public') else 'owner-public-origin')).write_text('http://invalid.test\n')
        if attack == 'same-authority':
            (w.root / 'etc/aukora/owner-public-origin').write_text('https://app.example.test\n')
        if attack in ('public-custody', 'owner-custody'):
            (w.root / 'etc/aukora' / ('public-origin' if attack.startswith('public') else 'owner-public-origin')).chmod(0o666)
        if attack in ('public-link', 'owner-link'):
            file = w.root / 'etc/aukora' / ('public-origin' if attack.startswith('public') else 'owner-public-origin')
            target = file.with_name(file.name + '-target')
            file.rename(target)
            file.symlink_to(target)
        def origin(file):
            w.origin_reads.append(file.name)
            # Synthetic root is the fixture UID; the production reader enforces actual UID zero.
            if file.resolve() != file or file.lstat().st_uid != os.getuid() or file.lstat().st_mode & 0o022:
                raise claim.ClaimRefusal('PROTECTED_FILE_INVALID')
            return claim.parse_origin(file.read_text())
        claim.read_origin_file = origin
        old_module, old_run = w.m.module, w.m.run
        w.m.module = lambda file: claim if file.name == 'claim.py' else old_module(file)
        def run(command, code, *args, **kwargs):
            if code in ('AURA_GATE_READ_REFUSED', 'AURA_KIRA_READ_REFUSED'):
                w.commands.append(command)
                w.events.append(('run', code))
                if attack == ('aura-gate-read' if code == 'AURA_GATE_READ_REFUSED' else 'aura-kira-read'):
                    raise ValueError('BROWSER_' + code)
                if attack == 'aura-head-invalid':
                    return 'not-json'
                return json.dumps(gate_head if code == 'AURA_GATE_READ_REFUSED' else kira_head)
            if code in ('AURA_TIMER_INACTIVE', 'AURA_COLLECT_REFUSED') and attack == ('aura-timer' if code == 'AURA_TIMER_INACTIVE' else 'aura-collect'):
                raise ValueError('BROWSER_' + code)
            if code == 'CLAIM_INACTIVE' and attack == 'claim-inactive':
                raise ValueError('BROWSER_CLAIM_INACTIVE')
            if code == 'CLAIM_MINT_REFUSED':
                w.commands.append(command)
                if attack == 'mint-refused':
                    raise ValueError('BROWSER_CLAIM_MINT_REFUSED')
                return ('https://other.example.test' if attack == 'claim-link' else 'https://app.example.test') + claim.CLAIM_PATH + '#' + 'P' * 43 + '\n'
            result = old_run(command, code, *args, **kwargs)
            if code == 'LISTENERS_UNAVAILABLE' and attack != 'claim-listener':
                result += 'LISTEN 0 1 127.0.0.1:18736 *:*\n'
            return result
        w.m.run = run
        now = int(w.m.time.time() * 1000)
        audience = 'other.example.test' if attack == 'cookie-authority' else 'app.example.test'
        payload = {'version': 1, 'authority': audience, 'issuedAt': now, 'expiresAt': now + 86400000}
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        cookie = claim.cookie_name('app.example.test') + '=v1.' + encoded + '.PRIVATE_COOKIE; Max-Age=86400; Path=/; Secure; HttpOnly; SameSite=Strict'
        if attack == 'cookie-flags':
            cookie = cookie.replace('; Secure', '')
        if attack == 'cookie-name':
            cookie = cookie.replace(claim.cookie_name('app.example.test'), claim.cookie_name('127.0.0.1:18735'))
        replies = [
            (200 if attack == 'anonymous' else 401, [], b'private' if attack == 'anonymous' else b''),
            (403 if attack == 'exchange-status' else 204,
             [] if attack == 'cookie-missing' else [('Set-Cookie', cookie)] * (2 if attack == 'cookie-multiple' else 1),
             b'unexpected' if attack == 'exchange-body' else b''),
            (401 if attack == 'session-status' else 200, [], b'' if attack == 'session-empty' else b'<html>synthetic</html>'),
            (204 if attack == 'replay-status' else 403,
             [('Set-Cookie', cookie)] if attack == 'replay-cookie' else [],
             b'CLAIM_INVALID\n' if attack == 'replay-reason' else b'CLAIM_SPENT\n'),
            (403 if attack == 'aura-status' else 200, [],
             b'not-json' if attack == 'aura-json' else json.dumps(aura).encode()),
        ]
        class Connection:
            def __init__(self, host, port, timeout):
                assert host == '127.0.0.1' and timeout == 5
                self.port = port
            def request(self, method, target, body=None, headers=None):
                w.public_requests.append((self.port, method, target, body, headers))
                if attack == 'http-unavailable':
                    raise OSError('PRIVATE_NETWORK_DETAIL')
            def getresponse(self):
                status, headers, payload = replies.pop(0)
                if attack == 'response-limit':
                    payload = b'P' * (1024 * 1024 + 1)
                return types.SimpleNamespace(status=status, getheaders=lambda: headers, read=lambda limit: payload[:limit])
            def close(self):
                pass
        w.stack.enter_context(patch.object(http.client, 'HTTPConnection', Connection))
        return w

    def test_bound_phase_requires_same_current_invocation(self):
        for changed in (False, True):
            w = self.public_world('aura-bound-empty')
            old_run, reads = w.m.run, []
            def run(command, code, *args, **kwargs):
                if command[:2] == ['systemctl', 'show'] and 'InvocationID' in command:
                    reads.append(command)
                    return ('b' if changed and len(reads) > 1 else 'a') * 32 + '\n'
                if command[0] == 'journalctl':
                    self.assertEqual(command[-1], '_SYSTEMD_INVOCATION_ID=' + 'a' * 32)
                    return 'aukora-kira: memory active (kira.memory:aumlok-linked)\n'
                return old_run(command, code, *args, **kwargs)
            w.m.run = run
            with patch.object(w.m, 'accept_bound') as bound, contextlib.redirect_stdout(io.StringIO()):
                if changed:
                    self.refuses(lambda: w.m.accept('bound'), 'BOUND_INVOCATION_CHANGED')
                else:
                    w.m.accept('bound')
                bound.assert_called_once()
                self.assertEqual(len(reads), 2)
            w.stack.close()
        w = self.public_world()
        (w.root / 'home/aukora-host/genesis/state/aumlok-binding').mkdir()
        with contextlib.redirect_stdout(io.StringIO()):
            w.m.accept('after')
        probes = [command for command in w.commands if any('ui-probe.mjs' in str(item) for item in command)]
        self.assertEqual(len(probes), 2)
        self.assertIn('--expect-unbound', probes[0])
        self.assertIn('--ui-only', probes[0])
        self.assertIn('--expect-unbound', probes[1])
        self.assertIn('--guard-only', probes[1])
        w.stack.close()

    def bound_world(self, attack=None, text=None):
        w = self.public_world(text=text)
        old_run, connection = w.m.run, http.client.HTTPConnection
        directory = w.root / 'home/aukora-host/genesis/state/aumlok-binding'
        directory.mkdir()
        (directory / 'local-control.json').write_text('synthetic bound control')
        subject = 'aukora:1:' + 'a' * 64
        identity = {'subject': subject, 'overlaySubject': subject,
                    'stateDir': str(w.root / 'home/aukora-host/genesis/state/home/kira-memory')}
        snapshot = json.loads(json.dumps(w.aura))
        snapshot['sources'][1]['browserMemory'] = {'active': True, 'reason': 'kira.memory:aumlok-linked'}
        if attack == 'readiness-active':
            snapshot['sources'][1]['browserMemory']['active'] = False
        elif attack == 'readiness-reason':
            snapshot['sources'][1]['browserMemory']['reason'] = 'kira.memory:aumlok-not-linked'
        elif attack == 'readiness-shape':
            snapshot['sources'][1]['browserMemory']['extra'] = True
        w.bound_snapshot, w.remembered, w.bound_started, w.aura_requests = snapshot, False, False, 0
        def remember(*args):
            w.remembered = True
            w.kira_head.update(head='d' * 64, entries=1, absence=None)
            snapshot['sources'][1].update(w.kira_head)
            if attack == 'aura-order':
                snapshot['sources'][1:] = reversed(snapshot['sources'][1:])
            elif attack == 'aura-source-extra':
                snapshot['sources'][0]['unverified'] = True
            elif attack == 'aura-gate-missing':
                snapshot['sources'][0].update(head=None, entries=None, absence='gate-ledger-unavailable')
            elif attack == 'aura-gate-short':
                snapshot['sources'][0]['entries'] = 4
            elif attack == 'aura-gate-head':
                snapshot['sources'][0]['head'] = 'e' * 64
            elif attack == 'aura-gate-count':
                w.gate_head['entries'] = 6
            elif attack == 'aura-gate-boolean':
                snapshot['sources'][0]['entries'] = True
            elif attack == 'aura-code-missing':
                snapshot['sources'][2].update(head=None, entries=None, absence='code-chain-unavailable')
            elif attack == 'aura-kira-missing':
                snapshot['sources'][1].update(head=None, entries=0, absence='kira-ledger-missing')
            elif attack == 'aura-kira-head':
                snapshot['sources'][1]['head'] = 'e' * 64
            elif attack == 'aura-kira-count':
                snapshot['sources'][1]['entries'] = 2
            elif attack == 'aura-kira-boolean':
                snapshot['sources'][1]['entries'] = True
            elif attack == 'aura-floor':
                file = w.root / 'etc/aukora-approvals/release-floor.json'
                floor = json.loads(file.read_text())
                floor['ledger_seq'] = True
                file.write_text(json.dumps(floor))
        def run(command, code, *args, **kwargs):
            if command[0] == 'journalctl':
                self.assertEqual(command[-1], '_SYSTEMD_INVOCATION_ID=' + 'a' * 32)
                return 'MemoryIdentityError\n' if attack == 'memory-error' else ''
            if w.remembered and code in ('AURA_GATE_READ_REFUSED', 'AURA_KIRA_READ_REFUSED'):
                if attack == ('aura-gate-read' if code == 'AURA_GATE_READ_REFUSED' else 'aura-kira-read'):
                    raise ValueError('BROWSER_' + code)
                if attack == 'aura-head-invalid':
                    return 'not-json'
            return old_run(command, code, *args, **kwargs)
        class BoundConnection:
            def __init__(self, *args, **kwargs):
                self.base = connection(*args, **kwargs)
                self.reply = None
            def request(self, method, target, body=None, headers=None):
                if target == '/api/kira/memories?limit=1':
                    w.bound_started = True
                    self.reply = {'items': []}
                elif target == '/api/session/create':
                    sent = json.loads(body)
                    assert sent['type'] == 'client-request' and sent['method'] == 'session/create'
                    assert sent['payload'] == {'args': {'request': {'sessionId': 'browser-node-bound-acceptance'}}}
                    assert headers['Content-Type'] == 'application/json'
                    self.reply = {'type': 'server-response', 'rpcId': sent['rpcId'],
                                  'result': {'ok': True, 'value': {'sessionId': 'browser-node-bound-acceptance'}}}
                elif target == '/api/session/list':
                    sent = json.loads(body)
                    assert sent['type'] == 'client-request' and sent['payload'] == {'args': {'_request': {}}}
                    assert headers['Content-Type'] == 'application/json'
                    self.reply = {'type': 'server-response', 'rpcId': sent['rpcId'], 'result': {'ok': True, 'value': {'items': []}}}
                elif target == '/stock-apps/auma-lingwa.html':
                    self.reply = b'<html>synthetic app</html>'
                elif target.endswith('/prepare'):
                    self.reply = {'ok': False, 'reason': 'aumlok:bind-already-bound'}
                elif target.endswith('/aura-snapshot'):
                    w.aura_requests += 1
                    if attack == 'aura-initial-guard':
                        snapshot['sources'][0]['head'] = 'e' * 64 if w.bound_started and not w.remembered else w.gate_head['head']
                    self.reply = b'not-json' if w.remembered and attack == 'aura-json' else snapshot
                else:
                    self.base.request(method, target, body, headers)
            def getresponse(self):
                if self.reply is None:
                    return self.base.getresponse()
                body = self.reply if isinstance(self.reply, bytes) else json.dumps(self.reply).encode()
                status = 403 if w.remembered and attack == 'aura-status' and self.reply is snapshot else 200
                return types.SimpleNamespace(status=status, getheaders=lambda: [], read=lambda limit: body[:limit])
            def close(self):
                self.base.close()
        w.m.run = run
        for name, value in [('harness_identity', lambda: (os.getuid(), os.getgid())), ('binding_custody', lambda *args: None),
                            ('bound_identity', lambda *args: identity), ('bound_remember', remember)]:
            w.stack.enter_context(patch.object(w.m, name, value))
        w.stack.enter_context(patch.object(w.m.time, 'sleep', lambda *args: None))
        w.stack.enter_context(patch.object(http.client, 'HTTPConnection', BoundConnection))
        return w

    def test_bound_phase_records_all_live_join_checks(self):
        w = self.bound_world()
        checks = []
        with contextlib.redirect_stdout(io.StringIO()) as output:
            w.m.accept('bound', checks)
        self.assertTrue(w.remembered)
        self.assertIn('KIRA_RECALL lexical; no OpenViking bundle', output.getvalue())
        self.assertEqual(w.events.count(('run', 'AURA_GATE_READ_REFUSED')), 3)
        self.assertEqual(w.events.count(('run', 'AURA_KIRA_READ_REFUSED')), 3)
        self.assertEqual(len(checks), 35)
        probes = [command for command in w.commands if any('ui-probe.mjs' in str(item) for item in command)]
        self.assertEqual(len(probes), 2)
        self.assertTrue(all('--expect-bound' in command for command in probes))
        self.assertEqual(checks[-10:], [{'name': name, 'status': 'PASS'} for name in [
            'binding_custody', 'binding_overlay', 'kira_active', 'bound_rpc', 'bound_app', 'repeat_prepare',
            'aura_gate_code', 'aura_kira_note', 'composition_active', 'bound_current_invocation']])
        w.stack.close()

    def test_bound_aura_matches_independent_heads_after_remember(self):
        for attack in ('memory-error', 'readiness-active', 'readiness-reason', 'readiness-shape'):
            with self.subTest(attack=attack), contextlib.redirect_stdout(io.StringIO()):
                w = self.bound_world(attack)
                checks = []
                self.refuses(lambda: w.m.accept('bound', checks), 'BOUND_KIRA_INACTIVE')
                self.assertFalse(w.remembered)
                self.assertEqual(checks[-1], {'name': 'kira_active' if attack == 'memory-error' else 'aura_sources', 'status': 'FAIL'})
                w.stack.close()
        attacks = [('aura-status', 'AURA_SNAPSHOT_REFUSED'), ('aura-json', 'BOUND_RESPONSE_INVALID'),
            ('aura-floor', 'AURA_FLOOR_INVALID'), ('aura-gate-read', 'AURA_GATE_READ_REFUSED'),
            ('aura-kira-read', 'AURA_KIRA_READ_REFUSED'), ('aura-head-invalid', 'AURA_HEAD_READ_INVALID'),
            ('aura-order', 'AURA_SNAPSHOT_INVALID'), ('aura-source-extra', 'AURA_SNAPSHOT_INVALID'),
            ('aura-gate-missing', 'AURA_GATE_MISSING'), ('aura-gate-short', 'AURA_GATE_BELOW_APPROVAL'),
            ('aura-gate-head', 'AURA_GATE_HEAD_MISMATCH'), ('aura-gate-count', 'AURA_GATE_HEAD_MISMATCH'),
            ('aura-gate-boolean', 'AURA_GATE_MISSING'), ('aura-code-missing', 'AURA_CODE_MISSING'),
            ('aura-kira-missing', 'AURA_KIRA_HEAD_MISMATCH'), ('aura-kira-head', 'AURA_KIRA_HEAD_MISMATCH'),
            ('aura-kira-count', 'AURA_KIRA_HEAD_MISMATCH'), ('aura-kira-boolean', 'AURA_KIRA_HEAD_MISMATCH')]
        for attack, code in attacks:
            with self.subTest(attack=attack), contextlib.redirect_stdout(io.StringIO()):
                w = self.bound_world(attack)
                checks = []
                self.refuses(lambda: w.m.accept('bound', checks), code)
                self.assertTrue(w.remembered)
                self.assertEqual(checks[-1], {'name': 'aura_kira_note', 'status': 'FAIL'})
                self.assertTrue(all(row['status'] == 'PASS' for row in checks[:-1]))
                w.stack.close()
        for change in ({'absence': None}, {'head': 'd' * 64, 'entries': 1, 'absence': None}, {'entries': False}):
            with self.subTest(empty_kira=change), contextlib.redirect_stdout(io.StringIO()):
                w = self.bound_world()
                w.bound_snapshot['sources'][1].update(change)
                checks = []
                self.refuses(lambda: w.m.accept('bound', checks), 'AURA_KIRA_ABSENCE_INVALID')
                self.assertFalse(w.remembered)
                self.assertEqual(checks[-1], {'name': 'aura_sources', 'status': 'FAIL'})
                w.stack.close()

    def test_bound_aura_checks_the_pre_remember_snapshot(self):
        with contextlib.redirect_stdout(io.StringIO()):
            w = self.bound_world('aura-initial-guard')
            checks = []
            self.refuses(lambda: w.m.accept('bound', checks), 'AURA_GATE_HEAD_MISMATCH')
            self.assertFalse(w.remembered)
            self.assertEqual(checks[-1], {'name': 'aura_gate_code', 'status': 'FAIL'})
            w.stack.close()

    def test_openviking_acceptance_dispatches_after_and_bound_only_when_bundled(self):
        for phase in ('after', 'bound'):
            with self.subTest(phase=phase), contextlib.redirect_stdout(io.StringIO()):
                w = self.public_world() if phase == 'after' else self.bound_world()
                file = w.m.STATE / 'installed.json'
                record = json.loads(file.read_text())
                record['inputs']['openviking'] = 'f' * 64
                file.write_text(json.dumps(record))
                old_module, calls = w.m.module, []
                viking = types.SimpleNamespace(accept=lambda node, endpoints, current: calls.append((endpoints, current)))
                w.m.module = lambda path: viking if path.name == 'openviking-node.py' else old_module(path)
                w.m.accept(phase)
                self.assertEqual(calls, [(['127.0.0.1:17792', '127.0.0.1:18735', '127.0.0.1:18736'], phase)])
                w.stack.close()

    def test_public_authority_claim_acceptance_guards(self):
        attacks = [('claim-inactive', 'CLAIM_INACTIVE'), ('claim-listener', 'CLAIM_LISTENER_MISSING'),
            ('public-invalid', 'PUBLIC_ORIGIN_INVALID'), ('owner-invalid', 'PUBLIC_ORIGIN_INVALID'),
            ('public-custody', 'PUBLIC_ORIGIN_INVALID'), ('owner-custody', 'PUBLIC_ORIGIN_INVALID'),
            ('public-link', 'PUBLIC_ORIGIN_INVALID'), ('owner-link', 'PUBLIC_ORIGIN_INVALID'),
            ('same-authority', 'PUBLIC_HOSTS_MUST_DIFFER'), ('anonymous', 'ANONYMOUS_HARNESS_ACCEPTED'),
            ('claim-link', 'CLAIM_LINK_INVALID'), ('mint-refused', 'CLAIM_MINT_REFUSED'),
            ('exchange-status', 'CLAIM_EXCHANGE_REFUSED'), ('exchange-body', 'CLAIM_EXCHANGE_REFUSED'),
            ('cookie-missing', 'CLAIM_COOKIE_INVALID'), ('cookie-multiple', 'CLAIM_COOKIE_INVALID'),
            ('cookie-name', 'CLAIM_COOKIE_INVALID'), ('cookie-authority', 'CLAIM_COOKIE_INVALID'),
            ('cookie-flags', 'CLAIM_COOKIE_INVALID'), ('session-status', 'PUBLIC_SESSION_REFUSED'),
            ('session-empty', 'PUBLIC_SESSION_REFUSED'), ('replay-status', 'CLAIM_REPLAY_ACCEPTED'),
            ('replay-cookie', 'CLAIM_REPLAY_ACCEPTED'), ('replay-reason', 'CLAIM_REPLAY_ACCEPTED'),
            ('http-unavailable', 'ACCEPTANCE_HTTP_UNAVAILABLE'), ('response-limit', 'ACCEPTANCE_RESPONSE_LIMIT')]
        for attack, code in attacks:
            with self.subTest(attack=attack), contextlib.redirect_stdout(io.StringIO()) as output:
                w = self.public_world(attack)
                checks = []
                self.refuses(lambda: w.m.accept('after', checks), code)
                self.assertEqual(checks[-1]['status'], 'FAIL')
                self.assertTrue(all(check['status'] == 'PASS' for check in checks[:-1]))
                self.assertNotIn('PRIVATE_', output.getvalue())
                self.assertNotIn('P' * 43, output.getvalue())
                w.stack.close()
        w = self.public_world()
        checks = []
        with contextlib.redirect_stdout(io.StringIO()) as output:
            w.m.accept('after', checks)
        self.assertEqual([check['name'] for check in checks], [
            'root_platform', 'installation_record', 'browser_profile', 'users_modes', 'aura_collector_custody', 'package_custody',
            'node_version', 'package_pins', 'gate_sockets', 'signer_pin', 'loopback_listeners', 'approved_floor',
            'aura_collector', 'harness_service', 'signed_in_ui', 'browser_binding_guard', 'plugin_load', 'claim_service', 'public_origins',
            'anonymous_session', 'claim_exchange', 'claim_cookie', 'public_session', 'claim_replay', 'aura_sources'])
        self.assertEqual([check['status'] for check in checks], ['PASS'] * 25)
        self.assertIn('anonymous 401 and one-use public-authority claim cookie', output.getvalue())
        self.assertNotIn('PRIVATE_', output.getvalue())
        self.assertNotIn('P' * 43, output.getvalue())
        self.assertEqual(w.origin_reads, ['public-origin', 'owner-public-origin'])
        self.assertEqual([(port, method, target) for port, method, target, _, _ in w.public_requests], [
            (18735, 'GET', '/'), (18736, 'POST', '/__aukora/claim'),
            (18735, 'GET', '/'), (18736, 'POST', '/__aukora/claim'),
            (18735, 'GET', '/api/aukora/aura-snapshot')])
        for _, _, _, _, headers in w.public_requests:
            self.assertEqual(headers['Host'], 'app.example.test')
            self.assertEqual(headers['Origin'], 'https://app.example.test')
            self.assertEqual(headers['Sec-Fetch-Site'], 'same-origin')
        self.assertNotIn('Cookie', w.public_requests[0][4])
        self.assertEqual(w.public_requests[1][3], w.public_requests[3][3])
        self.assertIn('Cookie', w.public_requests[2][4])
        self.assertIn('Cookie', w.public_requests[4][4])

    def test_aura_acceptance_matches_independent_heads_and_preserves_no_notes(self):
        for attack, code in [('aura-timer', 'AURA_TIMER_INACTIVE'), ('aura-collect', 'AURA_COLLECT_REFUSED'),
            ('aura-status', 'AURA_SNAPSHOT_REFUSED'), ('aura-json', 'AURA_SNAPSHOT_INVALID'), ('aura-floor', 'AURA_FLOOR_INVALID'),
            ('aura-gate-read', 'AURA_GATE_READ_REFUSED'), ('aura-kira-read', 'AURA_KIRA_READ_REFUSED'),
            ('aura-head-invalid', 'AURA_HEAD_READ_INVALID'), ('aura-gate-missing', 'AURA_GATE_MISSING'),
            ('aura-order', 'AURA_SNAPSHOT_INVALID'), ('aura-source-extra', 'AURA_SNAPSHOT_INVALID'),
            ('aura-gate-short', 'AURA_GATE_BELOW_APPROVAL'), ('aura-gate-head', 'AURA_GATE_HEAD_MISMATCH'),
            ('aura-gate-count', 'AURA_GATE_HEAD_MISMATCH'), ('aura-gate-boolean', 'AURA_GATE_MISSING'),
            ('aura-code-missing', 'AURA_CODE_MISSING'), ('aura-kira-boolean', 'AURA_KIRA_ABSENCE_INVALID'),
            ('aura-kira-missing', 'AURA_KIRA_HEAD_MISMATCH'), ('aura-kira-head', 'AURA_KIRA_HEAD_MISMATCH'),
            ('aura-kira-count', 'AURA_KIRA_HEAD_MISMATCH'), ('aura-kira-absence', 'AURA_KIRA_ABSENCE_INVALID')]:
            with self.subTest(attack=attack), contextlib.redirect_stdout(io.StringIO()):
                w = self.public_world(attack)
                checks = []
                self.refuses(lambda: w.m.accept('after', checks), code)
                self.assertEqual(checks[-1]['status'], 'FAIL')
                self.assertTrue(all(row['status'] == 'PASS' for row in checks[:-1]))
                if attack == 'aura-floor':
                    self.assertFalse(any(event in [('run', 'AURA_GATE_READ_REFUSED'), ('run', 'AURA_KIRA_READ_REFUSED')]
                                         for event in w.events))
                w.stack.close()
        for attack in (None, 'aura-bound-empty', 'aura-kira-present'):
            with self.subTest(attack=attack), contextlib.redirect_stdout(io.StringIO()) as output:
                w = self.public_world(attack)
                checks = []
                w.m.accept('after', checks)
                self.assertTrue(all(row['status'] == 'PASS' for row in checks))
                self.assertIn('Aura gate head matches verified current ledger through approval', output.getvalue())
                self.assertEqual(w.events.count(('run', 'AURA_GATE_READ_REFUSED')), 1)
                self.assertEqual(w.events.count(('run', 'AURA_KIRA_READ_REFUSED')), 1)
                self.assertEqual(w.events.count(('aura-custody',)), 1)
                gate = next(command for command in w.commands if command[-2:] == ['gate', '1' * 64])
                kira = next(command for command in w.commands if command[-1] == 'kira')
                self.assertEqual(gate[:4], ['runuser', '-u', 'aukora-gate', '--'])
                self.assertEqual(kira[:4], ['runuser', '-u', 'aukora-host', '--'])
                refresh = w.events.index(('run', 'AURA_COLLECT_REFUSED'))
                self.assertLess(refresh, w.events.index(('run', 'UI_PROBE_REFUSED')))
                w.stack.close()

    def test_status_is_read_only_and_remove_retains_state_and_floor(self):
        w = self.world()
        w.installed_world()
        before = (w.m.STATE / 'installed.json').read_bytes()
        floor = w.root / 'etc/aukora-approvals/release-floor.json'
        floor.parent.mkdir(exist_ok=True)
        floor.write_text('retained signed floor')
        with patch.object(w.m, 'model_status') as model_status, contextlib.redirect_stdout(io.StringIO()) as output:
            w.m.main(['status'])
            self.assertEqual(w.commands, [])
            w.m.main(['remove'])
        model_status.assert_called_once_with()
        self.assertIn('protected state and floor retained', output.getvalue())
        self.assertEqual((w.m.STATE / 'installed.json').read_bytes(), before)
        self.assertEqual(floor.read_text(), 'retained signed floor')
        self.assertEqual(w.commands, [
            ['systemctl', 'disable', '--now', 'aukora-aura-head.timer', 'aukora-aura-head.service'],
            ['systemctl', 'disable', '--now', 'aukora-browser.service', 'aukora-browser-claim.service', 'aukora-boundary-gate.service']])
        self.assertFalse(any(command[0] == 'systemctl' and ('start' in command or 'enable' in command) for command in w.commands))
        w.fail = 'REMOVE_REFUSED'
        self.refuses(lambda: w.m.main(['remove']), 'REMOVE_REFUSED')

    def test_claim_and_rotation_require_root_installed_services_and_hide_secrets(self):
        w = self.world()
        w.installed_world()
        for action in ('claim', 'rotate-owner-link'):
            with patch.object(w.m, 'root_check', side_effect=ValueError('BROWSER_ROOT_REQUIRED')):
                self.refuses(lambda: w.m.main([action]), 'ROOT_REQUIRED')
        link = 'https://app.example.test/__aukora/claim#' + 'A' * 43 + '\n'
        original_run = w.run
        def run(command, code, *args, **kwargs):
            result = original_run(command, code, *args, **kwargs)
            return link if code == 'CLAIM_MINT_REFUSED' else result
        with patch.object(w.m, 'run', run), contextlib.redirect_stdout(io.StringIO()) as output:
            w.m.main(['claim'])
        self.assertEqual(output.getvalue(), link)
        mint = next(command for command in w.commands if 'mint' in command)
        self.assertEqual(mint[0:4], ['/usr/bin/python3', '-I', '-S', '-B'])
        self.assertIn(str(w.root / 'etc/aukora/public-origin'), mint)
        self.assertIn(str(w.m.STATE / 'claims.json'), mint)
        self.assertEqual([command[-1] for command in w.commands if command[:2] == ['systemctl', 'is-active']],
                         ['aukora-browser.service', 'aukora-browser-claim.service'])
        for failure in ('CLAIM_SERVICE_INACTIVE', 'CLAIM_MINT_REFUSED'):
            w.fail = failure
            self.refuses(w.m.claim, failure)
        w.fail = None
        w.events.clear()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            w.m.main(['rotate-owner-link'])
        self.assertEqual(output.getvalue(), 'BROWSER_OWNER_LINK_ROTATED; retrieve bearer through the private operator route\n')
        self.assertIn(['systemctl', 'restart', 'aukora-boundary-gate.service'], w.commands)
        self.assertIn(('bootstrap', 'check-package'), w.events)
        self.assertIn(('sockets',), w.events)
        w.fail = 'OWNER_ROTATE_REFUSED'
        self.refuses(w.m.rotate_owner_link, 'OWNER_ROTATE_REFUSED')

    def owner_signin_world(self):
        w = self.world()
        w.installed_world()
        spec = importlib.util.spec_from_file_location('owner_signin_ingress_fixture', ROOT / 'ops/node-spawn/ingress/claim.py')
        ingress = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ingress)
        read_origin = ingress.read_origin_file
        ingress.read_origin_file = lambda path: read_origin(path, require_root=None)
        spec = importlib.util.spec_from_file_location('owner_signin_config_fixture', ROOT / 'ops/node-spawn/configure-host.py')
        config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config)
        write = config.write
        expected = w.root / 'etc/systemd/system/aukora-boundary-gate.service.d/browser-owner.conf'
        def protected_write(path, data, root, mode=0o644):
            self.assertEqual(path, expected)
            self.assertEqual(root, Path('/'))
            self.assertEqual(mode, 0o644)
            w.events.append(('write', path.name))
            write(path, data, w.root, mode)
        config.write = protected_write
        old_module = w.m.module
        w.m.module = lambda path: ingress if path.name == 'claim.py' else config if path.name == 'configure-host.py' else old_module(path)
        return w, expected

    def test_owner_signin_transition_guards(self):
        w, dropin = self.owner_signin_world()
        for name in ('root_check', 'installed'):
            with patch.object(w.m, name, side_effect=ValueError('BROWSER_ROOT_REQUIRED' if name == 'root_check' else 'BROWSER_INSTALL_RECORD_INVALID')):
                self.refuses(w.m.enable_owner_signin, 'ROOT_REQUIRED' if name == 'root_check' else 'INSTALL_RECORD_INVALID')
            self.assertFalse(dropin.exists())
        for failure in ('bootstrap-check-package', 'OWNER_SIGNIN_CONFIG_REFUSED', 'SYSTEMD_REFUSED', 'OWNER_SIGNIN_START_REFUSED', 'sockets'):
            bad, file = self.owner_signin_world()
            bad.fail = failure
            with self.assertRaises(ValueError):
                bad.m.enable_owner_signin()
            if failure in ('bootstrap-check-package', 'OWNER_SIGNIN_CONFIG_REFUSED'):
                self.assertFalse(file.exists())
        with patch.object(w.m, 'run', return_value='skgate:x:invalid:'):
            self.refuses(w.m.enable_owner_signin, 'GROUP_INVALID')
        self.assertFalse(dropin.exists())
        for origin in ('public-origin', 'owner-public-origin'):
            bad, file = self.owner_signin_world()
            (bad.root / 'etc/aukora' / origin).chmod(0o666)
            with self.assertRaises(Exception):
                bad.m.enable_owner_signin()
            self.assertFalse(file.exists())
        with contextlib.redirect_stdout(io.StringIO()) as output:
            w.m.main(['enable-owner-signin'])
        self.assertEqual(output.getvalue(), 'BROWSER_OWNER_SIGNIN_ENABLED; owner enrollment and final binding required\n')
        preflight = next(command for command in w.commands if '--input-type=module' in command)
        self.assertEqual(preflight[:6], ['runuser', '-u', 'aukora-gate', '--', str(w.root / 'opt/aukora-node/bin/node'), '--input-type=module'])
        self.assertEqual(preflight[-2:], ['https://owner.example.test', 'https://app.example.test'])
        script = preflight[preflight.index('-e') + 1]
        for invariant in ('passkeySetupReader(', 'browserJoinReader(', 'setup.origin !== process.argv[1]',
                          'join.app_origin !== process.argv[2]', 'createPublicKey(', 'setup.gate !== createHash('):
            self.assertIn(invariant, script)
        self.assertLess(w.events.index(('bootstrap', 'check-package')), w.events.index(('run', 'OWNER_SIGNIN_CONFIG_REFUSED')))
        ordered = [('run', 'OWNER_SIGNIN_CONFIG_REFUSED'), ('write', 'browser-owner.conf'),
                   ('run', 'SYSTEMD_REFUSED'), ('run', 'OWNER_SIGNIN_START_REFUSED'), ('sockets',)]
        self.assertEqual([event for event in w.events if event in ordered], ordered)
        text = dropin.read_text()
        self.assertEqual(dropin.stat().st_mode & 0o777, 0o644)
        self.assertTrue(text.startswith('[Service]\nExecStart=\nExecStart=/usr/bin/python3 -I -S '))
        for invariant in ('gate-bootstrap serve', '--home ' + str(w.root / 'home/aukora-gate'),
                          '--run /run/aukora-gate', '--port 17792 --gid 123', '--journal-id aukora-gate-pilot',
                          '--passkey-setup ' + str(w.root / 'etc/aukora-boundary-gate/passkey-setup.json'),
                          '--browser-join ' + str(w.root / 'etc/aukora-boundary-gate/browser-join.json')):
            self.assertIn(invariant, text)
        self.assertNotIn('--owner-page', text)
        self.assertNotIn('mint-passkey-claim', script)
        with contextlib.redirect_stdout(io.StringIO()):
            w.m.enable_owner_signin()
        dropin.write_text('different unit\n')
        with self.assertRaisesRegex(ValueError, '^SPAWN_CONFIG_CONFLICT$'):
            w.m.enable_owner_signin()
        dropin.chmod(0o666)
        with self.assertRaisesRegex(ValueError, '^SPAWN_CONFIG_CUSTODY$'):
            w.m.enable_owner_signin()

    def test_owner_signin_preflight_executes_real_schema_origin_and_gate_readers(self):
        w, dropin = self.owner_signin_world()
        old_run = w.m.run
        scripts = []
        def execute(command, code, *args, **kwargs):
            if code != 'OWNER_SIGNIN_CONFIG_REFUSED':
                return old_run(command, code, *args, **kwargs)
            script = command[command.index('-e') + 1]
            script = script.replace(str(w.root / 'opt/aukora-boundary-gate/src'), str(ROOT / 'packages/boundary-gate/src'))
            # Root ownership is simulated; file type, mode, no-follow and exact bytes use the real readers.
            shim = '''import syntheticFs from 'node:fs';
const realLstat = syntheticFs.lstatSync, realFstat = syntheticFs.fstatSync;
syntheticFs.lstatSync = path => { const st = realLstat(path); st.uid = 0;
  if (!String(path).startsWith(process.env.FIXTURE_ROOT + '/')) st.mode &= ~0o022; return st; };
syntheticFs.fstatSync = fd => { const st = realFstat(fd); st.uid = 0; return st; };
'''
            scripts.append(script)
            result = REAL_RUN([str(PINNED_NODE), '--input-type=module', '-e', shim + script, *command[-2:]],
                              capture_output=True, env={**os.environ, 'FIXTURE_ROOT': str(w.root)})
            if result.returncode:
                raise ValueError('BROWSER_OWNER_SIGNIN_CONFIG_REFUSED')
            self.assertEqual(result.stdout, b'')
            return ''
        w.m.run = execute
        setup_file = w.root / 'etc/aukora-boundary-gate/passkey-setup.json'
        join_file = setup_file.with_name('browser-join.json')
        setup_file.parent.mkdir(parents=True, exist_ok=True)
        key = w.root / 'home/aukora-gate/receipt-ed25519.pem'
        keygen = "import{generateKeyPairSync,createHash}from'node:crypto';import fs from'node:fs';const{privateKey,publicKey}=generateKeyPairSync('ed25519');fs.writeFileSync(process.argv[1],privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});console.log(createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex'))"
        generated = REAL_RUN([str(PINNED_NODE), '--input-type=module', '-e', keygen, str(key)], capture_output=True)
        self.assertEqual(generated.returncode, 0)
        setup = {'version': 1, 'kind': 'aukora-gate-passkey-setup/v1', 'gate': generated.stdout.decode().strip(),
                 'node': '2' * 64, 'origin': 'https://owner.example.test', 'rp_id': 'owner.example.test',
                 'claim_sha256': '3' * 64, 'expires_at_ms': 1000,
                 'binding': {'identity': {'authorization_epoch': 1, 'subject': 'aukora:1:' + '4' * 64},
                             'passkey_profile': {'profile': 'https', 'origin': 'https://owner.example.test', 'rp_id': 'owner.example.test'},
                             'existing_credential_ids': []}}
        join = {'version': 1, 'kind': 'aukora-browser-join/v1', 'app_origin': 'https://app.example.test',
                'binding_record': str(w.root / 'home/aukora-host/browser-controller/local-control.json')}
        def reset():
            setup_file.write_text(json.dumps(setup)); setup_file.chmod(0o640)
            join_file.write_text(json.dumps(join)); join_file.chmod(0o644)
        for file, field, value in [(setup_file, 'origin', 'https://wrong.example.test'),
                                  (join_file, 'app_origin', 'https://wrong.example.test'),
                                  (setup_file, 'gate', '5' * 64), (setup_file, 'kind', 'wrong'),
                                  (join_file, 'kind', 'wrong')]:
            reset()
            invalid = json.loads(file.read_text()); invalid[field] = value
            if file == setup_file and field == 'origin':
                invalid['rp_id'] = 'wrong.example.test'
                invalid['binding']['passkey_profile'].update(origin=value, rp_id='wrong.example.test')
            file.write_text(json.dumps(invalid))
            self.refuses(w.m.enable_owner_signin, 'OWNER_SIGNIN_CONFIG_REFUSED')
            self.assertFalse(dropin.exists())
        for file in (setup_file, join_file):
            reset(); file.chmod(0o666)
            self.refuses(w.m.enable_owner_signin, 'OWNER_SIGNIN_CONFIG_REFUSED')
            self.assertFalse(dropin.exists())
        reset()
        with contextlib.redirect_stdout(io.StringIO()):
            w.m.enable_owner_signin()
        self.assertTrue(dropin.exists())
        self.assertEqual(len(scripts), 8)


def mutations():
    cases = [
        ('aura-user-installed', "    run(['useradd', '--system', '--home-dir', '/var/lib/aukora-aura', '--shell', '/usr/sbin/nologin',\n         '--user-group', '--groups', 'skgate', 'aukora-aura'], 'AURA_USER_CREATE_REFUSED')\n", '', 'test_aura_collector_install_custody_and_order'),
        ('aura-system-user', "['useradd', '--system', '--home-dir', '/var/lib/aukora-aura'", "['useradd', '--home-dir', '/var/lib/aukora-aura'", 'test_aura_collector_install_custody_and_order'),
        ('aura-private-group', "'--user-group', '--groups', 'skgate', 'aukora-aura'", "'--groups', 'skgate', 'aukora-aura'", 'test_aura_collector_install_custody_and_order'),
        ('aura-user-shell', "'/var/lib/aukora-aura', '--shell', '/usr/sbin/nologin'", "'/var/lib/aukora-aura', '--shell', '/bin/sh'", 'test_aura_collector_install_custody_and_order'),
        ('aura-user-groups', "'--user-group', '--groups', 'skgate', 'aukora-aura'", "'--user-group', '--groups', 'sudo', 'aukora-aura'", 'test_aura_collector_install_custody_and_order'),
        ('aura-parent-owner', "'-m', '0755', '-o', 'root', '-g', 'root', '/var/lib/aukora-aura'", "'-m', '0755', '-o', 'aukora-aura', '-g', 'root', '/var/lib/aukora-aura'", 'test_aura_collector_install_custody_and_order'),
        ('aura-parent-group', "'-m', '0755', '-o', 'root', '-g', 'root', '/var/lib/aukora-aura'", "'-m', '0755', '-o', 'root', '-g', 'aukora-host', '/var/lib/aukora-aura'", 'test_aura_collector_install_custody_and_order'),
        ('aura-parent-mode', "'-m', '0755', '-o', 'root', '-g', 'root', '/var/lib/aukora-aura'", "'-m', '0777', '-o', 'root', '-g', 'root', '/var/lib/aukora-aura'", 'test_aura_collector_install_custody_and_order'),
        ('aura-output-mode', "'-m', '2750', '-o', 'aukora-aura', '-g', 'aukora-host'", "'-m', '2770', '-o', 'aukora-aura', '-g', 'aukora-host'", 'test_aura_collector_install_custody_and_order'),
        ('aura-output-owner', "'-m', '2750', '-o', 'aukora-aura', '-g', 'aukora-host'", "'-m', '2750', '-o', 'aukora-host', '-g', 'aukora-host'", 'test_aura_collector_install_custody_and_order'),
        ('aura-output-read-group', "'-m', '2750', '-o', 'aukora-aura', '-g', 'aukora-host'", "'-m', '2750', '-o', 'aukora-aura', '-g', 'aukora-aura'", 'test_aura_collector_install_custody_and_order'),
        ('aura-service-write-mode', "collector.encode(), Path('/'))", "collector.encode(), Path('/'), 0o666)", 'test_aura_collector_install_custody_and_order'),
        ('aura-timer-write-mode', "timer.encode(), Path('/'))", "timer.encode(), Path('/'), 0o666)", 'test_aura_collector_install_custody_and_order'),
        ('aura-install-refresh', "    bootstrap('approval', 'raise', '--release-dir', release)\n    run(['systemctl', 'start', 'aukora-aura-head.service'], 'AURA_COLLECT_REFUSED')", "    bootstrap('approval', 'raise', '--release-dir', release)", 'test_aura_collector_install_custody_and_order'),
        ('aura-timer-enabled', "    run(['systemctl', 'enable', '--now', 'aukora-aura-head.timer'], 'AURA_TIMER_START_REFUSED')\n", '', 'test_aura_collector_install_custody_and_order'),
        ('aura-start-refresh', "'FLOOR_REFUSED')\n    run(['systemctl', 'start', 'aukora-aura-head.service'], 'AURA_COLLECT_REFUSED')", "'FLOOR_REFUSED')", 'test_start_requires_approval_and_exact_floor_and_can_restart'),
        ('aura-accept-custody', "    checkpoint('aura_collector_custody')\n    aura_custody()", "    checkpoint('aura_collector_custody')", 'test_aura_acceptance_matches_independent_heads_and_preserves_no_notes'),
        ('aura-accept-timer', "        run(['systemctl', 'is-active', '--quiet', 'aukora-aura-head.timer'], 'AURA_TIMER_INACTIVE')\n", '', 'test_aura_acceptance_matches_independent_heads_and_preserves_no_notes'),
        ('aura-accept-refresh', "        run(['systemctl', 'start', 'aukora-aura-head.service'], 'AURA_COLLECT_REFUSED')\n", '', 'test_aura_acceptance_matches_independent_heads_and_preserves_no_notes'),
        ('aura-accept-guard', "        browser_aura_sources(snapshot, gate, kira, floor, not unbound)\n", '', 'test_aura_acceptance_matches_independent_heads_and_preserves_no_notes'),
        ('aura-bound-initial-guard', "    browser_aura_sources(snapshot, gate, kira, floor, True)\n    checkpoint('aura_kira_note')", "    checkpoint('aura_kira_note')", 'test_bound_aura_checks_the_pre_remember_snapshot'),
        ('aura-bound-note-guard', "            browser_aura_sources(snapshot, gate, kira, floor, True)\n", '', 'test_bound_aura_matches_independent_heads_after_remember'),
        ('browser-memory-active', "state.get('active') is True", 'True', 'test_bound_aura_matches_independent_heads_after_remember'),
        ('browser-memory-reason', "state.get('reason') == 'kira.memory:aumlok-linked'", 'True', 'test_bound_aura_matches_independent_heads_after_remember'),
        ('browser-memory-shape', "set(state) == {'active', 'reason'}", 'True', 'test_bound_aura_matches_independent_heads_after_remember'),
        ('browser-memory-journal-error', "need('MemoryIdentityError' not in journal, 'BOUND_KIRA_INACTIVE')",
         "need(True, 'BOUND_KIRA_INACTIVE')", 'test_bound_aura_matches_independent_heads_after_remember'),
        ('openviking-bound-acceptance', "if phase != 'before' and 'openviking' in value['inputs']:", "if phase == 'after' and 'openviking' in value['inputs']:", 'test_openviking_acceptance_dispatches_after_and_bound_only_when_bundled'),
        ('lexical-without-openviking', "        print('KIRA_RECALL lexical; no OpenViking bundle')\n", '        pass\n', 'test_bound_phase_records_all_live_join_checks'),
        ('aura-snapshot-cookie', "request(18735, 'GET', '/api/aukora/aura-snapshot', cookie=cookie)", "request(18735, 'GET', '/api/aukora/aura-snapshot')", 'test_public_authority_claim_acceptance_guards'),
        ('aura-gate-reader-identity', "['runuser', '-u', 'aukora-gate', '--', NODE, helper, 'gate', floor['signer_key_sha256']]", "['runuser', '-u', 'root', '--', NODE, helper, 'gate', floor['signer_key_sha256']]", 'test_aura_acceptance_matches_independent_heads_and_preserves_no_notes'),
        ('aura-kira-reader-identity', "['runuser', '-u', 'aukora-host', '--', NODE, helper, 'kira']", "['runuser', '-u', 'root', '--', NODE, helper, 'kira']", 'test_aura_acceptance_matches_independent_heads_and_preserves_no_notes'),
        ('aura-remove-timer', "'disable', '--now', 'aukora-aura-head.timer', 'aukora-aura-head.service'", "'disable', '--now', 'aukora-aura-head.service'", 'test_status_is_read_only_and_remove_retains_state_and_floor'),
        ('aura-remove-service', "'disable', '--now', 'aukora-aura-head.timer', 'aukora-aura-head.service'", "'disable', '--now', 'aukora-aura-head.timer'", 'test_status_is_read_only_and_remove_retains_state_and_floor'),
        ('passkey-authority-installed', "profiles = [('authority', checkout / 'packages/authority', '/opt/authority', '--passkey-authority'),\n", 'profiles = [\n', 'test_success_publishes_marker_after_sockets_and_raise_without_starting_harness'),
        ('passkey-contracts-installed', "                ('contracts', checkout / 'packages/contracts', '/opt/contracts', '--passkey-contracts'),\n", '', 'test_success_publishes_marker_after_sockets_and_raise_without_starting_harness'),
        ('passkey-aumlok-installed', "                ('browser-aumlok', checkout / 'plugins/aukora-aumlok', '/opt/aukora-aumlok', '--browser-aumlok')", '', 'test_success_publishes_marker_after_sockets_and_raise_without_starting_harness'),
        ('passkey-profile-modes', '        stage.public_modes(STATE / name)\n', '', 'test_success_publishes_marker_after_sockets_and_raise_without_starting_harness'),
        ('passkey-profile-manifests', '        profile_args += [flag, str(STATE / name)]\n', '', 'test_success_publishes_marker_after_sockets_and_raise_without_starting_harness'),
        ('owner-signin-root', 'def enable_owner_signin():\n    root_check()\n', 'def enable_owner_signin():\n', 'test_owner_signin_transition_guards'),
        ('owner-signin-installed', 'def enable_owner_signin():\n    root_check()\n    installed()\n', 'def enable_owner_signin():\n    root_check()\n', 'test_owner_signin_transition_guards'),
        ('owner-signin-package', "def enable_owner_signin():\n    root_check()\n    installed()\n    bootstrap('check-package')\n", 'def enable_owner_signin():\n    root_check()\n    installed()\n', 'test_owner_signin_transition_guards'),
        ('owner-signin-gate-user', "    run(['runuser', '-u', 'aukora-gate', '--', NODE, '--input-type=module', '-e', script,", "    run(['runuser', '-u', 'root', '--', NODE, '--input-type=module', '-e', script,", 'test_owner_signin_transition_guards'),
        ('owner-signin-app-file-custody', "app_origin, _ = ingress.read_origin_file(Path('/etc/aukora/public-origin'))", "app_origin, _ = ingress.parse_origin(Path('/etc/aukora/public-origin').read_text())", 'test_owner_signin_transition_guards'),
        ('owner-signin-owner-file-custody', "owner_origin, _ = ingress.read_origin_file(Path('/etc/aukora/owner-public-origin'))", "owner_origin, _ = ingress.parse_origin(Path('/etc/aukora/owner-public-origin').read_text())", 'test_owner_signin_transition_guards'),
        ('owner-signin-setup-reader', "passkeySetupReader('/etc/aukora-boundary-gate/passkey-setup.json')()", "JSON.parse(fs.readFileSync('/etc/aukora-boundary-gate/passkey-setup.json', 'utf8'))", 'test_owner_signin_preflight_executes_real_schema_origin_and_gate_readers'),
        ('owner-signin-join-reader', "browserJoinReader('/etc/aukora-boundary-gate/browser-join.json')()", "JSON.parse(fs.readFileSync('/etc/aukora-boundary-gate/browser-join.json', 'utf8'))", 'test_owner_signin_preflight_executes_real_schema_origin_and_gate_readers'),
        ('owner-signin-owner-audience', 'setup.origin !== process.argv[1]', 'false', 'test_owner_signin_preflight_executes_real_schema_origin_and_gate_readers'),
        ('owner-signin-app-audience', 'join.app_origin !== process.argv[2]', 'false', 'test_owner_signin_preflight_executes_real_schema_origin_and_gate_readers'),
        ('owner-signin-signer-pin', "if (setup.gate !== createHash('sha256').update(signer.export({ type: 'spki', format: 'der' })).digest('hex')) throw new Error('BROWSER_OWNER_SIGNIN_GATE_MISMATCH');", '', 'test_owner_signin_preflight_executes_real_schema_origin_and_gate_readers'),
        ('owner-signin-fixed-dropin', '/etc/systemd/system/aukora-boundary-gate.service.d/browser-owner.conf', '/etc/systemd/system/aukora-boundary-gate.service.d/other.conf', 'test_owner_signin_transition_guards'),
        ('owner-signin-clear-execstart', "dropin = '''[Service]\nExecStart=\n", "dropin = '''[Service]\n", 'test_owner_signin_transition_guards'),
        ('owner-signin-passkey-mode', '--passkey-setup /etc/aukora-boundary-gate/passkey-setup.json --browser-join /etc/aukora-boundary-gate/browser-join.json\n', '\n', 'test_owner_signin_transition_guards'),
        ('owner-signin-write-mode', "dropin.encode(), Path('/'))", "dropin.encode(), Path('/'), 0o666)", 'test_owner_signin_transition_guards'),
        ('owner-signin-reload', "    run(['systemctl', 'daemon-reload'], 'SYSTEMD_REFUSED')\n    run(['systemctl', 'restart', 'aukora-boundary-gate.service'], 'OWNER_SIGNIN_START_REFUSED')", "    run(['systemctl', 'restart', 'aukora-boundary-gate.service'], 'OWNER_SIGNIN_START_REFUSED')", 'test_owner_signin_transition_guards'),
        ('owner-signin-restart', "    run(['systemctl', 'restart', 'aukora-boundary-gate.service'], 'OWNER_SIGNIN_START_REFUSED')\n", '', 'test_owner_signin_transition_guards'),
        ('owner-signin-sockets', "    run(['systemctl', 'restart', 'aukora-boundary-gate.service'], 'OWNER_SIGNIN_START_REFUSED')\n    sockets()", "    run(['systemctl', 'restart', 'aukora-boundary-gate.service'], 'OWNER_SIGNIN_START_REFUSED')", 'test_owner_signin_transition_guards'),
        ('app-origin-written', "    config.write(Path('/etc/aukora/public-origin'), ('https://' + app_host + '\\n').encode(), Path('/'))\n", '', 'test_success_publishes_marker_after_sockets_and_raise_without_starting_harness'),
        ('owner-origin-written', "    config.write(Path('/etc/aukora/owner-public-origin'), ('https://' + owner_host + '\\n').encode(), Path('/'))\n", '', 'test_success_publishes_marker_after_sockets_and_raise_without_starting_harness'),
        ('claim-started', "    run(['systemctl', 'enable', '--now', 'aukora-browser-claim.service'], 'CLAIM_START_REFUSED')\n", '', 'test_success_publishes_marker_after_sockets_and_raise_without_starting_harness'),
        ('claim-root', 'def claim():\n    root_check()\n', 'def claim():\n', 'test_claim_and_rotation_require_root_installed_services_and_hide_secrets'),
        ('rotation-root', 'def rotate_owner_link():\n    root_check()\n', 'def rotate_owner_link():\n', 'test_claim_and_rotation_require_root_installed_services_and_hide_secrets'),
        ('claim-active-services', "        run(['systemctl', 'is-active', '--quiet', name], 'CLAIM_SERVICE_INACTIVE')\n", '        pass\n', 'test_claim_and_rotation_require_root_installed_services_and_hide_secrets'),
        ('claim-single-link-output', "    print(link, end='')\n", "    print('claim: ' + link, end='')\n", 'test_claim_and_rotation_require_root_installed_services_and_hide_secrets'),
        ('rotation-restart', "    run(['systemctl', 'restart', 'aukora-boundary-gate.service'], 'OWNER_ROTATE_REFUSED')\n", '', 'test_claim_and_rotation_require_root_installed_services_and_hide_secrets'),
        ('input-digest', 'stage.digest_file(file) == digest(expected)', 'True', 'test_each_input_digest'),
        ('fresh-source', "    stage.source_check({'source_checkout': str(checkout), 'release_commit': options.revision})\n", '', 'test_clean_source_and_pinned_harness_precede_build'),
        ('harness-digest', "    fresh.verify_archive(inputs / 'dsh-source.tar.gz', pin)\n", '', 'test_clean_source_and_pinned_harness_precede_build'),
        ('built-harness', "    fresh.verify_built(checkout / 'vendor/dsh', checkout, env)\n", '', 'test_clean_source_and_pinned_harness_precede_build'),
        ('existing-state', "not STATE.exists() and not STATE.is_symlink()", 'True', 'test_fresh_install_does_not_adopt_existing_state_or_users'),
        ('existing-user', 'result.returncode == 2', 'True', 'test_fresh_install_does_not_adopt_existing_state_or_users'),
        ('node-version', "run([str(node / 'bin/node'), '--version'], 'NODE_INVALID').strip() == 'v24.11.1'", 'True', 'test_dependency_and_node_package_checks'),
        ('pnpm-version', "run([str(tools / 'pnpm'), '--version'], 'PNPM_INVALID', env).strip() == pin['packageManager'].removeprefix('pnpm@')", 'True', 'test_dependency_and_node_package_checks'),
        ('rerun-binding', "installed() == {'revision': options.revision, 'inputs': binding}", 'True', 'test_rerun_is_exact_and_never_regenerates_keys'),
        ('unapproved-floor', "result.returncode != 0, 'UNAPPROVED_FLOOR_ACCEPTED'", "True, 'UNAPPROVED_FLOOR_ACCEPTED'", 'test_before_acceptance_refuses_any_floor_start_listener_or_descriptor'),
        ('unapproved-start', "result.returncode != 0, 'UNAPPROVED_HARNESS_STARTED'", "True, 'UNAPPROVED_HARNESS_STARTED'", 'test_before_acceptance_refuses_any_floor_start_listener_or_descriptor'),
        ('unapproved-active', "active.returncode != 0, 'UNAPPROVED_HARNESS_ACTIVE'", "True, 'UNAPPROVED_HARNESS_ACTIVE'", 'test_before_acceptance_refuses_any_floor_start_listener_or_descriptor'),
        ('listener-readback', "        endpoints = listeners(run(['ss', '-ltn'], 'LISTENERS_UNAVAILABLE'))\n", '', 'test_before_acceptance_refuses_any_floor_start_listener_or_descriptor'),
        ('unapproved-listener', "'127.0.0.1:18735' not in endpoints", 'True', 'test_before_acceptance_refuses_any_floor_start_listener_or_descriptor'),
        ('unapproved-descriptor', "not Path('/home/aukora-host/genesis/state/launch-url.json').exists()", 'True', 'test_before_acceptance_refuses_any_floor_start_listener_or_descriptor'),
        ('binding-guard-probe', "        print(run(['runuser', '-u', 'aukora-host', '--', NODE, str(CHECKOUT / 'ops/pilot/ui-probe.mjs'),\n                   binding_mode, '--guard-only'], 'BINDING_GUARD_PROBE_REFUSED').strip())\n", '', 'test_bound_phase_requires_same_current_invocation'),
        ('plugin-load', "not re.search(r'^aukora-[a-z-]+ \\(file://.*\\): Error', journal, re.M)", 'True', 'test_after_acceptance_requires_signed_in_ui_and_clean_current_invocation'),
        ('installed-listener', "'127.0.0.1:18735' in endpoints", 'True', 'test_after_acceptance_requires_signed_in_ui_and_clean_current_invocation'),
        ('package-link', "entry.resolve().is_relative_to(path)", 'True', 'test_after_acceptance_requires_signed_in_ui_and_clean_current_invocation'),
        ('claim-service', "        run(['systemctl', 'is-active', '--quiet', 'aukora-browser-claim.service'], 'CLAIM_INACTIVE')\n", '', 'test_public_authority_claim_acceptance_guards'),
        ('public-origin-custody', "claim.read_origin_file(Path('/etc/aukora/public-origin'))", "claim.parse_origin(Path('/etc/aukora/public-origin').read_text())", 'test_public_authority_claim_acceptance_guards'),
        ('owner-origin-custody', "claim.read_origin_file(Path('/etc/aukora/owner-public-origin'))", "claim.parse_origin(Path('/etc/aukora/owner-public-origin').read_text())", 'test_public_authority_claim_acceptance_guards'),
        ('cookie-authority', "cookie = claim.bounded_cookie(cookies[0], authority, time.time()).split(';', 1)[0]", "cookie = cookies[0].split(';', 1)[0]", 'test_public_authority_claim_acceptance_guards'),
        ('claim-mint', "'--state-file', '/var/lib/aukora-browser/claims.json'], 'CLAIM_MINT_REFUSED')", "'--state-file', '/var/lib/aukora-browser/claims.json'], 'IGNORED_MINT')", 'test_public_authority_claim_acceptance_guards'),
        ('request-host', "{'Host': authority, 'Origin': public_origin, 'Sec-Fetch-Site': 'same-origin'}", "{'Host': '127.0.0.1', 'Origin': public_origin, 'Sec-Fetch-Site': 'same-origin'}", 'test_public_authority_claim_acceptance_guards'),
        ('session-cookie', "                headers['Cookie'] = cookie\n", '                pass\n', 'test_public_authority_claim_acceptance_guards'),
        ('floor-before-start', "         'floor', 'check', '--release-dir', str(release), '--approval-state-root', str(approval)], 'FLOOR_REFUSED')",
         "         'floor', 'check', '--release-dir', str(release), '--approval-state-root', str(approval)], 'IGNORED_FLOOR')", 'test_start_requires_approval_and_exact_floor_and_can_restart'),
        ('marker-after-raise', "    bootstrap('approval', 'raise', '--release-dir', release)\n",
         "    value = {'revision': options.revision, 'inputs': binding}\n    config.write(STATE / 'installed.json', (json.dumps(value, sort_keys=True) + '\\n').encode(), Path('/'))\n    bootstrap('approval', 'raise', '--release-dir', release)\n", 'test_external_refusals_never_publish_install_marker'),
    ]
    original = SOURCE.read_text()
    killed = 0
    for name, before, after, method in cases:
        assert original.count(before) == 1, name
        mutated = original.replace(before, after)
        suite = Pipeline(method)
        old = World.__init__
        def initialize(self, text=None):
            old(self, mutated)
        with patch.object(World, '__init__', initialize):
            result = unittest.TestResult()
            with contextlib.redirect_stdout(io.StringIO()):
                suite.run(result)
        assert result.failures or result.errors, 'mutation survived: ' + name
        killed += 1
        print('KILLED browser pipeline ' + name)
    print('SOURCE-ONLY browser pipeline guard mutations: %d/%d killed' % (killed, len(cases)))


if __name__ == '__main__':
    if '--mutations' in sys.argv:
        mutations()
    else:
        with contextlib.redirect_stdout(io.StringIO()):
            unittest.main()
