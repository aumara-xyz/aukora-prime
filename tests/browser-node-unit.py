# Exercise browser installer refusals without root, services or network.
import hashlib
import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'ops/node-spawn/browser/node.py'
SCRATCH = ROOT / '.runtime/browser-unit'
SCRATCH.mkdir(parents=True, exist_ok=True)
TEXT = SOURCE.read_text()


def load(text=TEXT):
    result = types.ModuleType('browser_installer_fixture')
    result.__file__ = str(SOURCE)
    exec(compile(text, str(SOURCE), 'exec'), result.__dict__)
    return result


M = load()


def archive(path, entries):
    with tarfile.open(path, 'w:gz') as output:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            info.mode = 0o777
            if kind == 'file':
                info.size = len(payload)
                output.addfile(info, io.BytesIO(payload))
            else:
                info.type = {'link': tarfile.SYMTYPE, 'hard': tarfile.LNKTYPE, 'device': tarfile.CHRTYPE, 'dir': tarfile.DIRTYPE}[kind]
                info.linkname = payload
                output.addfile(info)


def rejects(function, code):
    try:
        function()
    except ValueError as error:
        assert str(error) == 'BROWSER_' + code, str(error)
        return
    raise AssertionError('guard accepted ' + code)


class BrowserInstaller(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=SCRATCH))

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_usage_every_option(self):
        valid = ['install', '--inputs', str(self.root), '--checkout-sha256', 'a' * 64,
                 '--revision', 'a' * 40, '--node-sha256', 'b' * 64, '--dependencies-sha256', 'c' * 64]
        with patch.object(M, 'install') as install:
            M.main(valid)
            self.assertEqual(install.call_count, 1)
            for index in range(1, len(valid), 2):
                rejects(lambda: M.main(valid[:index] + valid[index + 2:]), 'USAGE')
                rejects(lambda: M.main(valid + valid[index:index + 2]), 'USAGE')
            for bad in [[], ['unknown'], ['start', '--revision', 'a' * 40], ['remove', '--phase', 'after'],
                        ['status', '--unknown'], ['accept'], ['accept', '--phase', 'bad'],
                        valid + ['--phase', 'before'], valid[:-1], ['start', 'extra'], ['verify-profile'],
                        ['status', '--release', '/opt/aukora-genesis/release-aaaaaaa']]:
                rejects(lambda: M.main(bad), 'USAGE')
            for index in (4, 6, 8, 10):
                args = valid.copy()
                args[index] = 'INVALID'
                rejects(lambda: M.main(args), 'DIGEST_INVALID')
            args = valid.copy()
            args[2] = '../outside'
            rejects(lambda: M.main(args), 'PATH_INVALID')
        for command in ['start', 'status', 'remove', 'accept']:
            with patch.object(M, 'root_check', side_effect=ValueError('BROWSER_ROOT_REQUIRED')):
                rejects(lambda: M.main([command] + (['--phase', 'before'] if command == 'accept' else [])), 'ROOT_REQUIRED')

    def test_path_and_digest(self):
        self.assertEqual(M.absolute(str(self.root)), self.root)
        link = self.root / 'alias'
        link.symlink_to(self.root)
        for value in ['relative', str(link), str(self.root) + '/../x', str(self.root) + '/.', str(self.root) + '/space path', str(self.root) + '/\n']:
            rejects(lambda: M.absolute(value), 'PATH_INVALID')
        for value in ['', 'A' * 64, 'a' * 63, 'g' * 64, 'a' * 65]:
            rejects(lambda: M.digest(value), 'DIGEST_INVALID')
        for value in ['a' * 39, 'a' * 41, 'a' * 64]:
            rejects(lambda: M.digest(value, True), 'DIGEST_INVALID')

    def test_root_environment(self):
        for key in M.PRELOAD:
            with patch.dict(M.os.environ, {key: ''}, clear=True):
                rejects(M.root_check, 'PRELOAD_FORBIDDEN')
        with patch.dict(M.os.environ, {}, clear=True), patch.object(M.os, 'geteuid', return_value=1):
            rejects(M.root_check, 'ROOT_REQUIRED')
        with patch.dict(M.os.environ, {}, clear=True), patch.object(M.os, 'geteuid', return_value=0), patch.object(M.sys, 'platform', 'darwin'):
            rejects(M.root_check, 'LINUX_REQUIRED')
        with patch.dict(M.os.environ, {}, clear=True), patch.object(M.os, 'geteuid', return_value=0), patch.object(M.sys, 'platform', 'linux'):
            for release in ['ID=debian\nVERSION_ID="24.04"\n', 'ID=ubuntu\nVERSION_ID="22.04"\n']:
                with patch.object(M.Path, 'read_text', return_value=release):
                    rejects(M.root_check, 'UBUNTU_24_04_REQUIRED')
            with patch.object(M.Path, 'read_text', return_value='ID=ubuntu\nVERSION_ID="24.04"\n'):
                M.root_check()

    def test_custody(self):
        file = self.root / 'data'
        file.write_text('data')
        file.chmod(0o600)
        M.protected(file, uid=os.getuid(), private=True)
        for mode in (0o666, 0o604, 0o620):
            file.chmod(mode)
            rejects(lambda: M.protected(file, uid=os.getuid(), private=True), 'CUSTODY_INVALID')
        file.chmod(0o600)
        rejects(lambda: M.protected(file, uid=os.getuid() + 1), 'CUSTODY_INVALID')
        rejects(lambda: M.protected(file, True, os.getuid()), 'CUSTODY_INVALID')
        rejects(lambda: M.protected(self.root, uid=os.getuid()), 'CUSTODY_INVALID')
        alias = self.root / 'alias'
        alias.symlink_to(file)
        rejects(lambda: M.protected(alias, uid=os.getuid()), 'CUSTODY_INVALID')
        alias.unlink()
        os.link(file, alias)
        rejects(lambda: M.protected(file, uid=os.getuid()), 'CUSTODY_INVALID')

    def test_archives(self):
        file = self.root / 'source.tar.gz'
        target = self.root / 'extract'
        archive(file, [('dir/file', 'file', b'hello'), ('link', 'link', 'dir/file')])
        M.extract(file, target)
        self.assertEqual((target / 'link').read_bytes(), b'hello')
        self.assertFalse((target / 'dir/file').stat().st_mode & 0o022)
        rejects(lambda: M.extract(file, target), 'EXTRACT_EXISTS')
        shutil.rmtree(target)
        attacks = [([('../escape', 'file', b'x')], 'ARCHIVE_PATH'),
                   ([('/absolute', 'file', b'x')], 'ARCHIVE_PATH'),
                   ([('a//b', 'file', b'x')], 'ARCHIVE_PATH'),
                   ([('a/./b', 'file', b'x')], 'ARCHIVE_PATH'),
                   ([('a', 'file', b'x'), ('a', 'file', b'x')], 'ARCHIVE_PATH'),
                   ([('device', 'device', '')], 'ARCHIVE_TYPE'),
                   ([('hard', 'hard', 'file')], 'ARCHIVE_TYPE'),
                   ([('alias', 'link', '../escape')], 'ARCHIVE_LINK'),
                   ([('alias', 'link', '/etc')], 'ARCHIVE_LINK'),
                   ([('alias', 'link', 'dir'), ('alias/file', 'file', b'x')], 'ARCHIVE_LINK_PARENT'),
                   ([], 'ARCHIVE_LIMIT')]
        for entries, code in attacks:
            archive(file, entries)
            rejects(lambda: M.extract(file, target), code)
            self.assertFalse(target.exists())

    def test_run_refuses_and_hides_output(self):
        result = subprocess.CompletedProcess([], 1, b'SECRET_VALUE', b'SECRET_VALUE')
        with patch.object(M.subprocess, 'run', return_value=result):
            rejects(lambda: M.run(['fake'], 'FAKE_REFUSED'), 'FAKE_REFUSED')
        result.returncode = 0
        result.stdout = b'public'
        with patch.object(M.subprocess, 'run', return_value=result):
            self.assertEqual(M.run(['fake'], 'FAKE_REFUSED'), 'public')

    def test_sockets_waits_for_both(self):
        with patch.object(M.Path, 'is_socket', return_value=False), patch.object(M.time, 'sleep') as sleep:
            rejects(M.sockets, 'GATE_SOCKETS_MISSING')
            self.assertEqual(sleep.call_count, 60)
        with patch.object(M.Path, 'is_socket', autospec=True, side_effect=lambda path: path.name == 'gate.sock'), patch.object(M.time, 'sleep'):
            rejects(M.sockets, 'GATE_SOCKETS_MISSING')
        with patch.object(M.Path, 'is_socket', return_value=True):
            M.sockets()

    def test_listener_readback(self):
        head = 'State Recv-Q Send-Q Local Address:Port Peer Address:Port\n'
        row = 'LISTEN 0 4096 127.0.0.1:17792 0.0.0.0:*\n'
        self.assertEqual(M.listeners(head + row), ['127.0.0.1:17792'])
        rejects(lambda: M.listeners(head), 'LISTENERS_MISSING')
        rejects(lambda: M.listeners(head + row.replace('127.0.0.1:17792', '0.0.0.0:17792')), 'NON_LOOPBACK_LISTENER')
        rejects(lambda: M.listeners(head + 'bad\n'), 'NON_LOOPBACK_LISTENER')
        rejects(lambda: M.listeners(head + row.replace('17792', '18735')), 'OWNER_LISTENER_MISSING')

    def test_units_preserve_approval_no_preview(self):
        checkout = self.root / 'checkout'
        folder = checkout / 'packages/boundary-gate/host/systemd'
        folder.mkdir(parents=True)
        shutil.copyfile(ROOT / 'packages/boundary-gate/host/systemd/aukora-boundary-gate.service', folder / 'aukora-boundary-gate.service')
        writes = {}
        config = types.SimpleNamespace(write=lambda path, data, root: writes.__setitem__(path.name, data.decode()))
        with patch.object(M, 'CHECKOUT', checkout), patch.object(M, 'run', return_value='skgate:x:123:aukora-host'):
            M.units(config)
        gate = writes['aukora-boundary-gate.service']
        harness = writes['aukora-browser.service']
        self.assertIn('--owner-page --port 17792', gate)
        self.assertIn('--gid 123', gate)
        for invariant in ('UMask=0077', 'NoNewPrivileges=yes', 'ProtectSystem=strict', 'check-package', 'check-runtime',
                          'floor check', '--foreground', '--approval-state-root', '--approved-record-sha', 'Restart=no'):
            self.assertIn(invariant, harness)
        self.assertNotIn('unsafe-preview', harness)
        self.assertNotIn('linux-openshell.patch.yml', harness)
        with patch.object(M, 'run', return_value='skgate:x:not-number:'):
            rejects(lambda: M.units(config), 'GROUP_INVALID')

    def test_profile_integrity(self):
        relative = 'plugins/aukora-action-gate/lib/browser-refusal.mjs'
        source = self.root / relative
        source.parent.mkdir(parents=True)
        source.write_text('guard')
        preset = self.root / 'agent.cordis.yml'
        preset.write_text('disabled: true\n')
        value = {'formatVersion': 1, 'kind': 'aukora-browser-node-profile', 'relay': False, 'buzz': False,
                 'disabledRows': ['tool-bash'], 'presets': {'agent.cordis.yml': hashlib.sha256(preset.read_bytes()).hexdigest()},
                 'refusalEntry': relative, 'refusalSha256': hashlib.sha256(source.read_bytes()).hexdigest()}
        marker = self.root / 'browser-node-profile.patch.yml'
        (self.root / 'aukora-composition.patch.yml').write_text('name: ./' + relative + '\n')
        folder = self.root / 'plugins/aukora-composition-gate'
        folder.mkdir(parents=True)
        (folder / 'policy.json').write_text(json.dumps({'pluginSet': ['aukora-browser-refusal']}))
        write = lambda: marker.write_text('# aukora-browser-node-profile ' + json.dumps(value) + '\n')
        write()
        rules = {'BROWSER_DISABLED_ROWS': ['tool-bash'], 'BROWSER_REFUSAL_ENTRY': relative, 'BROWSER_REFUSAL_SOURCE': 'guard'}
        with patch.object(M, 'profile_rules', return_value=rules):
            self.profile_attacks(value, marker, source, preset, write)

    def profile_attacks(self, value, marker, source, preset, write):
        M.profile(self.root)
        composition = self.root / 'aukora-composition.patch.yml'
        saved = composition.read_text()
        composition.write_text('disabled: true\n')
        rejects(lambda: M.profile(self.root), 'REFUSAL_NOT_MOUNTED')
        composition.write_text(saved)
        marker.write_text('{}\n')
        rejects(lambda: M.profile(self.root), 'PROFILE_INVALID')

        value['buzz'] = True
        write()
        rejects(lambda: M.profile(self.root), 'PROFILE_INVALID')
        value['buzz'] = False
        write()
        (self.root / 'plugins/aukora-buzz-door').mkdir()
        rejects(lambda: M.profile(self.root), 'NETWORK_PLUGIN_PRESENT')
        (self.root / 'plugins/aukora-buzz-door').rmdir()
        source.write_text('changed')
        rejects(lambda: M.profile(self.root), 'REFUSAL_MODULE_CHANGED')
        source.write_text('guard')
        preset.write_text('changed')
        rejects(lambda: M.profile(self.root), 'PRESET_CHANGED')
        value['presets'] = {'../outside': 'a' * 64}
        write()
        rejects(lambda: M.profile(self.root), 'PROFILE_INVALID')


    def test_profile_rules_and_service_preflight(self):
        with patch.object(M, 'protected'), patch.object(M.Path, 'read_text', return_value='BROWSER_DISABLED_ROWS = ()\n'):
            rejects(M.profile_rules, 'PROFILE_RULES_MISSING')
        with patch.object(M, 'protected'), patch.object(M, 'CHECKOUT', ROOT):
            rules = M.profile_rules()
            self.assertTrue(rules['BROWSER_DISABLED_ROWS'])
        with patch.object(M, 'absolute', side_effect=lambda value: Path(value)), patch.object(M, 'protected'), patch.object(M, 'profile') as profile:
            rejects(lambda: M.main(['verify-profile', '--release', '/opt/other/release-aaaaaaa']), 'PROFILE_RELEASE_INVALID')
            M.main(['verify-profile', '--release', '/opt/aukora-genesis/release-aaaaaaa'])
            profile.assert_called_once()


def mutations():
    # Execute guard removals against the same negative assertions, inside this clone.
    cases = [
        ("if not condition:", "if False:", lambda m: rejects(lambda: m.digest('invalid'), 'DIGEST_INVALID')),
        ("path.is_absolute() and str(path) == value and str(path.resolve()) == value", "True", lambda m: rejects(lambda: m.absolute('relative'), 'PATH_INVALID')),
        ("bool(re.fullmatch(r'[a-f0-9]{40}' if revision else r'[a-f0-9]{64}', value))", "True", lambda m: rejects(lambda: m.digest('INVALID'), 'DIGEST_INVALID')),
        ("not any(key in os.environ for key in PRELOAD)", "True", lambda m: root_mutant(m)),
        ("result.returncode == expected", "True", lambda m: run_mutant(m)),
        ("all(Path('/run/aukora-gate/' + name).is_socket() for name in ('gate.sock', 'owner.sock'))", "True", lambda m: sockets_mutant(m)),
        ("len(endpoints) == len(rows) and local", "True", lambda m: rejects(lambda: m.listeners('header\nLISTEN 0 1 0.0.0.0:17792 *:*\n'), 'NON_LOOPBACK_LISTENER')),
    ]
    killed = 0
    for before, after, inspect in cases:
        assert TEXT.count(before) == 1, before
        mutant = load(TEXT.replace(before, after))
        try:
            inspect(mutant)
        except AssertionError:
            killed += 1
        else:
            raise AssertionError('mutation survived: ' + before)
    print('SOURCE-ONLY browser installer guard mutations: %d/%d killed' % (killed, len(cases)))
    guard_mutations()


def guard_mutations():
    # Every named Python refusal is exercised with its actual predicate removed.
    global M
    spec = importlib.util.spec_from_file_location('browser_pipeline_mutation_fixture', ROOT / 'tests/browser-node-pipeline.py')
    pipeline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pipeline)
    unit_methods = {
        'absolute': ['test_path_and_digest'], 'digest': ['test_path_and_digest'],
        'protected': ['test_custody'], 'root_check': ['test_root_environment'],
        'extract': ['test_archives'], 'run': ['test_run_refuses_and_hides_output'],
        'profile': ['test_profile_integrity'], 'profile_rules': ['test_profile_rules_and_service_preflight'],
        'listeners': ['test_listener_readback'], 'units': ['test_units_preserve_approval_no_preview'],
        'main': ['test_usage_every_option', 'test_profile_rules_and_service_preflight'],
    }
    pipeline_methods = {
        'checked_inputs': ['test_each_input_digest'], 'installed': ['test_install_record_is_closed_and_revision_checked'],
        'install': ['test_dependency_and_node_package_checks', 'test_fresh_install_does_not_adopt_existing_state_or_users', 'test_rerun_is_exact_and_never_regenerates_keys'],
        'accept': ['test_before_acceptance_refuses_any_floor_start_listener_or_descriptor', 'test_after_acceptance_requires_signed_in_ui_and_clean_current_invocation'],
    }
    lines = TEXT.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    original_module = M
    guards = []
    for function in ast.parse(TEXT).body:
        if not isinstance(function, ast.FunctionDef):
            continue
        for call in ast.walk(function):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'need':
                guards.append((function.name, call))
    for function, call in guards:
        arg = call.args[0]
        start, stop = offsets[arg.lineno - 1] + arg.col_offset, offsets[arg.end_lineno - 1] + arg.end_col_offset
        mutated = TEXT[:start] + 'True' + TEXT[stop:]
        result = unittest.TestResult()
        M = load(mutated)
        with contextlib.redirect_stdout(io.StringIO()):
            for method in unit_methods.get(function, []):
                BrowserInstaller(method).run(result)
            old = pipeline.World.__init__
            def initialize(world, text=None):
                old(world, mutated)
            with patch.object(pipeline.World, '__init__', initialize):
                for method in pipeline_methods.get(function, []):
                    pipeline.Pipeline(method).run(result)
        M = original_module
        assert result.failures or result.errors, 'named refusal removal survived: %s:%s' % (function, call.lineno)
    print('SOURCE-ONLY browser named Python refusals: %d/%d removals killed' % (len(guards), len(guards)))


def root_mutant(m):
    with patch.dict(m.os.environ, {'NODE_OPTIONS': ''}, clear=True), patch.object(m.os, 'geteuid', return_value=0), patch.object(m.sys, 'platform', 'linux'), patch.object(m.Path, 'read_text', return_value='ID=ubuntu\nVERSION_ID="24.04"\n'):
        rejects(m.root_check, 'PRELOAD_FORBIDDEN')


def run_mutant(m):
    with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'')):
        rejects(lambda: m.run(['fake'], 'FAKE_REFUSED'), 'FAKE_REFUSED')


def sockets_mutant(m):
    with patch.object(m.Path, 'is_socket', return_value=False), patch.object(m.time, 'sleep'):
        rejects(m.sockets, 'GATE_SOCKETS_MISSING')


if __name__ == '__main__':
    if '--mutations' in sys.argv:
        mutations()
    else:
        with contextlib.redirect_stdout(io.StringIO()):
            unittest.main()
