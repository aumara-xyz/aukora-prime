# Execute installer transitions with synthetic commands and paths kept inside the clone.
import contextlib
import hashlib
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
SOURCE = ROOT / 'ops/node-spawn/browser/node.py'
SCRATCH = ROOT / '.runtime/browser-pipeline'
SCRATCH.mkdir(parents=True, exist_ok=True)
sha = lambda data: hashlib.sha256(data).hexdigest()


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
            node_sha256=sha(b'pinned node'), dependencies_sha256=sha(b'offline dependencies'), revision='a' * 40)
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
            ('sockets', self.sockets), ('profile', lambda path: self.events.append(('profile', str(path))))]:
            self.stack.enter_context(patch.object(self.m, name, replacement))
        self.stack.enter_context(patch.object(self.m.subprocess, 'run', self.subprocess))

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
                     'packages/boundary-gate/host/install', 'packages/boundary-gate/host/systemd'):
            (target / name).mkdir(parents=True, exist_ok=True)
        (target / 'upstream-dsh.json').write_text(json.dumps({'archiveSha256': sha(b'pinned harness'), 'packageManager': 'pnpm@10.13.1'}))
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
        elif code in ('HOME_CREATE_REFUSED', 'STATE_CREATE_REFUSED', 'TARGET_CREATE_REFUSED'):
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
            return '0.0.0' if self.attack == 'pnpm-version' else '10.13.1'
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

    def test_external_refusals_never_publish_install_marker(self):
        for failure in ('OS_DEPENDENCIES_REFUSED', 'CLONE_REFUSED', 'BUNDLE_INVALID', 'REVISION_MISSING', 'GROUP_CREATE_REFUSED',
            'USER_CREATE_REFUSED', 'HOME_CREATE_REFUSED', 'KEY_GENERATION_REFUSED', 'MANIFEST_REFUSED',
            'TARGET_CREATE_REFUSED', 'STATE_CREATE_REFUSED', 'RELEASE_ENV_REFUSED', 'GROUP_MISSING',
            'bootstrap-check-package', 'bootstrap-check-runtime', 'SYSTEMD_REFUSED', 'GATE_START_REFUSED', 'sockets', 'bootstrap-approval-raise'):
            with self.subTest(failure=failure):
                w = self.world()
                w.fail = failure
                with self.assertRaises(ValueError):
                    w.m.install(w.options)
                self.assertFalse((w.m.STATE / 'installed.json').exists(), failure)

    def test_rerun_is_exact_and_never_regenerates_keys(self):
        w = self.world()
        w.installed_world()
        with contextlib.redirect_stdout(io.StringIO()):
            w.m.install(w.options)
        self.assertNotIn(('run', 'KEY_GENERATION_REFUSED'), w.events)
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
        for failure in ('bootstrap-check-package', 'bootstrap-check-runtime', 'sockets', 'FLOOR_REFUSED', 'HARNESS_START_REFUSED'):
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

    def test_status_is_read_only_and_remove_retains_state_and_floor(self):
        w = self.world()
        w.installed_world()
        before = (w.m.STATE / 'installed.json').read_bytes()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            w.m.main(['status'])
            w.m.main(['remove'])
        self.assertIn('FLOOR not verified', output.getvalue())
        self.assertIn('protected state and floor retained', output.getvalue())
        self.assertEqual((w.m.STATE / 'installed.json').read_bytes(), before)
        self.assertFalse(any(command[0] == 'systemctl' and ('start' in command or 'enable' in command) for command in w.commands))
        w.fail = 'REMOVE_REFUSED'
        self.refuses(lambda: w.m.main(['remove']), 'REMOVE_REFUSED')


def mutations():
    cases = [
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
        ('plugin-load', "not re.search(r'^aukora-[a-z-]+ \\(file://.*\\): Error', journal, re.M)", 'True', 'test_after_acceptance_requires_signed_in_ui_and_clean_current_invocation'),
        ('installed-listener', "'127.0.0.1:18735' in endpoints", 'True', 'test_after_acceptance_requires_signed_in_ui_and_clean_current_invocation'),
        ('package-link', "entry.resolve().is_relative_to(path)", 'True', 'test_after_acceptance_requires_signed_in_ui_and_clean_current_invocation'),
        ('floor-before-start', "         'floor', 'check', '--release-dir', str(release), '--approval-state-root', str(approval)], 'FLOOR_REFUSED')",
         "         'floor', 'check', '--release-dir', str(release), '--approval-state-root', str(approval)], 'IGNORED_FLOOR')", 'test_start_requires_approval_and_exact_floor_and_can_restart'),
        ('marker-after-raise', "    bootstrap('approval', 'raise', '--release-dir', release)\n    value = {'revision': options.revision, 'inputs': binding}\n    config.write(STATE / 'installed.json', (json.dumps(value, sort_keys=True) + '\\n').encode(), Path('/'))",
         "    value = {'revision': options.revision, 'inputs': binding}\n    config.write(STATE / 'installed.json', (json.dumps(value, sort_keys=True) + '\\n').encode(), Path('/'))\n    bootstrap('approval', 'raise', '--release-dir', release)", 'test_external_refusals_never_publish_install_marker'),
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
