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
                 '--revision', 'a' * 40, '--node-sha256', 'b' * 64, '--dependencies-sha256', 'c' * 64,
                 '--app-host', 'app.example.test', '--owner-host', 'owner.example.test']
        with patch.object(M, 'install') as install:
            M.main(valid)
            self.assertEqual(install.call_count, 1)
            for index in range(1, len(valid), 2):
                rejects(lambda: M.main(valid[:index] + valid[index + 2:]), 'USAGE')
                rejects(lambda: M.main(valid + valid[index:index + 2]), 'USAGE')
            for bad in [[], ['unknown'], ['start', '--revision', 'a' * 40], ['remove', '--phase', 'after'],
                        ['status', '--unknown'], ['accept'], ['accept', '--phase', 'bad'],
                        valid + ['--phase', 'before'], valid[:-1], ['start', 'extra'], ['verify-profile'],
                        ['status', '--release', '/opt/aukora-genesis/release-aaaaaaa'],
                        ['status', '--prompt'], ['remove', '--remove'], ['model-key', '--prompt', '--remove'],
                        ['model-key', 'SECRET_MUST_NOT_BE_AN_ARGUMENT'],
                        ['accept', '--phase', 'before', '--evidence'], ['accept', '--phase', 'passkey', '--evidence'],
                        ['start', '--evidence']]:
                rejects(lambda: M.main(bad), 'USAGE')
            for index in (4, 6, 8, 10):
                args = valid.copy()
                args[index] = 'INVALID'
                rejects(lambda: M.main(args), 'DIGEST_INVALID')
            args = valid.copy()
            args[2] = '../outside'
            rejects(lambda: M.main(args), 'PATH_INVALID')
        for command in ['start', 'status', 'remove', 'accept', 'claim', 'rotate-owner-link', 'enable-owner-signin', 'model-key']:
            with patch.object(M, 'root_check', side_effect=ValueError('BROWSER_ROOT_REQUIRED')):
                rejects(lambda: M.main([command] + (['--phase', 'before'] if command == 'accept' else [])), 'ROOT_REQUIRED')
        with patch.object(M, 'model_key') as model_key:
            M.main(['model-key', '--prompt'])
            model_key.assert_called_once_with(False, True)
        with patch.object(M, 'model_key') as model_key:
            M.main(['model-key', '--remove'])
            model_key.assert_called_once_with(True, False)

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

    def test_hostname(self):
        self.assertEqual(M.hostname('app.example.test'), 'app.example.test')
        for value in ['', 'localhost', 'App.example.test', '*.example.test', '127.0.0.1',
                      'https://app.example.test', 'app.example.test:443', 'app.example.test/path',
                      'app.example.test\n', '-app.example.test', 'a' * 64 + '.test',
                      '.'.join(['a' * 63] * 4) + '.test']:
            rejects(lambda: M.hostname(value), 'HOST_INVALID')

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

    def model_home(self):
        home = self.root / 'home/aukora-host/genesis/state/home'
        home.mkdir(parents=True)
        for path in [home, *list(home.parents)[:3]]:
            path.chmod(0o700)
        return home

    def model_patches(self, home):
        owner = home.stat()
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(M, 'MODEL_HOME', home))
        stack.enter_context(patch.object(M, 'root_check'))
        stack.enter_context(patch.object(M, 'installed', return_value={'revision': 'a' * 40, 'inputs': {}}))
        stack.enter_context(patch.object(M, 'harness_identity', return_value=(owner.st_uid, owner.st_gid)))
        return stack

    def test_model_key_input_refusals_and_prompt(self):
        for value, code in [(b'', 'MODEL_KEY_LENGTH_INVALID'), (b'A' * 4097, 'MODEL_KEY_LENGTH_INVALID'),
                            (b'bad\x00key', 'MODEL_KEY_SHAPE_INVALID'), (b'bad\xffkey', 'MODEL_KEY_SHAPE_INVALID')]:
            rejects(lambda value=value: M.validate_model_key(value), code)
        streams = [(b'one\ntwo\n', False, 'MODEL_KEY_MULTILINE_REFUSED'),
                   (b'key\n', True, 'MODEL_KEY_TTY_REFUSED')]
        for value, terminal, code in streams:
            source = types.SimpleNamespace(isatty=lambda terminal=terminal: terminal, buffer=io.BytesIO(value))
            with patch.object(M.sys, 'stdin', source):
                rejects(M.read_model_key, code)
        with patch.object(M.getpass, 'getpass', return_value='prompt-key') as prompt:
            self.assertEqual(M.read_model_key(True), b'prompt-key')
            prompt.assert_called_once_with('Model key: ')
        with patch.object(M.getpass, 'getpass', side_effect=EOFError):
            rejects(lambda: M.read_model_key(True), 'MODEL_KEY_INPUT_REFUSED')

    def test_model_key_store_status_and_remove(self):
        home = self.model_home()
        secret = b'SYNTHETIC_MODEL_SECRET_123'
        source = types.SimpleNamespace(isatty=lambda: False, buffer=io.BytesIO(secret + b'\n'))
        with self.model_patches(home), patch.object(M.sys, 'stdin', source), \
                contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            M.model_key()
        expected_hash = hashlib.sha256(secret).hexdigest()[:12]
        self.assertEqual(stdout.getvalue(), 'MODEL_KEY_SET provider=deepseek sha256=' + expected_hash + '\n')
        self.assertEqual(stderr.getvalue(), '')
        self.assertNotIn(secret.decode(), stdout.getvalue() + stderr.getvalue())
        store = home / '.credentials.yaml'
        self.assertEqual(store.read_bytes(), b'version: 1\nrefs:\n  DEEPSEEK_API_KEY: "SYNTHETIC_MODEL_SECRET_123"\n')
        self.assertEqual(store.stat().st_mode & 0o777, 0o600)
        self.assertEqual((store.stat().st_uid, store.stat().st_gid),
                         (home.stat().st_uid, home.stat().st_gid))
        self.assertEqual(list(home.glob('.*.tmp-*')), [])
        with self.model_patches(home), contextlib.redirect_stdout(io.StringIO()) as output:
            M.model_status()
        self.assertEqual(output.getvalue(), 'MODEL_KEY provider=deepseek present=yes\n')
        with self.model_patches(home), contextlib.redirect_stdout(io.StringIO()) as output:
            M.model_key(remove=True)
        self.assertEqual(output.getvalue(), 'MODEL_KEY_REMOVED provider=deepseek\n')
        self.assertFalse(store.exists())
        with self.model_patches(home), contextlib.redirect_stdout(io.StringIO()) as output:
            M.model_status()
        self.assertEqual(output.getvalue(), 'MODEL_KEY provider=deepseek present=no\n')

    def test_model_key_custody_and_store_refusals(self):
        home = self.model_home()
        owner = home.stat()
        rejects(lambda: M.open_model_home(owner.st_uid + 1, owner.st_gid), 'MODEL_STORE_CUSTODY_INVALID')
        home.chmod(0o750)
        rejects(lambda: M.open_model_home(owner.st_uid, owner.st_gid), 'MODEL_STORE_CUSTODY_INVALID')
        home.chmod(0o700)
        alias = self.root / 'model-home-link'
        alias.symlink_to(home)
        with patch.object(M, 'MODEL_HOME', alias):
            rejects(lambda: M.open_model_home(owner.st_uid, owner.st_gid), 'MODEL_STORE_CUSTODY_INVALID')
        parent_alias = self.root / 'harness-home-link'
        parent_alias.symlink_to(home.parents[2])
        with patch.object(M, 'MODEL_HOME', parent_alias / 'genesis/state/home'):
            rejects(lambda: M.open_model_home(owner.st_uid, owner.st_gid), 'MODEL_STORE_CUSTODY_INVALID')
        with patch.object(M, 'MODEL_HOME', Path('relative')):
            rejects(lambda: M.open_model_home(owner.st_uid, owner.st_gid), 'MODEL_STORE_PATH_INVALID')
        with patch.object(M.pwd, 'getpwnam', side_effect=KeyError):
            rejects(M.harness_identity, 'MODEL_USER_INVALID')
        with patch.object(M.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=0, pw_gid=0, pw_dir='/root')):
            rejects(M.harness_identity, 'MODEL_USER_INVALID')

        directory = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
        store = home / '.credentials.yaml'
        valid = M.render_model_store(b'synthetic-key')
        try:
            store.write_bytes(valid)
            store.chmod(0o644)
            rejects(lambda: M.model_store_key(directory, owner.st_uid, owner.st_gid), 'MODEL_STORE_INVALID')
            store.chmod(0o600)
            rejects(lambda: M.model_store_key(directory, owner.st_uid + 1, owner.st_gid), 'MODEL_STORE_INVALID')
            original_fstat = M.os.fstat
            def changed_inode(descriptor):
                info = original_fstat(descriptor)
                return types.SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 1)
            with patch.object(M.os, 'fstat', side_effect=changed_inode):
                rejects(lambda: M.model_store_key(directory, owner.st_uid, owner.st_gid), 'MODEL_STORE_INVALID')
            for payload in (b'not yaml\n', b'version: 1\nrefs:\n  DEEPSEEK_API_KEY: unquoted\n',
                            b'version: 1\nrefs:\n  DEEPSEEK_API_KEY:  "synthetic-key"\n'):
                store.write_bytes(payload)
                store.chmod(0o600)
                rejects(lambda: M.model_store_key(directory, owner.st_uid, owner.st_gid), 'MODEL_STORE_INVALID')
            store.unlink()
            target = home / 'target'
            target.write_bytes(valid)
            store.symlink_to(target)
            rejects(lambda: M.model_store_key(directory, owner.st_uid, owner.st_gid), 'MODEL_STORE_INVALID')
            store.unlink()
            os.link(target, store)
            rejects(lambda: M.model_store_key(directory, owner.st_uid, owner.st_gid), 'MODEL_STORE_INVALID')
        finally:
            os.close(directory)

    def test_model_key_write_and_remove_fail_closed(self):
        home = self.model_home()
        owner = home.stat()
        directory = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch.object(M.os, 'replace', side_effect=PermissionError):
                rejects(lambda: M.write_model_store(directory, owner.st_uid, owner.st_gid, M.render_model_store(b'key')),
                        'MODEL_STORE_WRITE_REFUSED')
            self.assertFalse((home / '.credentials.yaml').exists())
        finally:
            os.close(directory)
        store = home / '.credentials.yaml'
        store.write_bytes(M.render_model_store(b'key'))
        store.chmod(0o600)
        with self.model_patches(home), patch.object(M.os, 'unlink', side_effect=PermissionError):
            rejects(lambda: M.model_key(remove=True), 'MODEL_STORE_REMOVE_REFUSED')

    def test_model_key_never_appears_in_output_or_process_arguments(self):
        home = self.model_home()
        owner = home.stat()
        secret = 'SYNTHETIC_PROCESS_MODEL_SECRET_456'
        wrapper = '''import importlib.util,os
spec=importlib.util.spec_from_file_location("browser_node",{source!r})
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.MODEL_HOME=m.Path({home!r});m.root_check=lambda:None;m.installed=lambda:{{}}
m.harness_identity=lambda:({uid},{gid})
m.main(["model-key"])
'''.format(source=str(SOURCE), home=str(home), uid=owner.st_uid, gid=owner.st_gid)
        process = subprocess.Popen([sys.executable, '-c', wrapper], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        observed_arguments = ' '.join(map(str, process.args))
        proc = Path('/proc') / str(process.pid) / 'cmdline'
        if proc.is_file():
            observed_arguments += proc.read_bytes().replace(b'\0', b' ').decode(errors='replace')
        else:
            try:
                command = subprocess.run(['ps', '-o', 'command=', '-p', str(process.pid)],
                                         capture_output=True, text=True)
                observed_arguments += command.stdout
            except PermissionError:
                pass
        stdout, stderr = process.communicate((secret + '\n').encode(), timeout=10)
        visible = observed_arguments + stdout.decode() + stderr.decode()
        self.assertEqual(process.returncode, 0, stderr.decode())
        self.assertNotIn(secret, visible)
        self.assertEqual(stdout.decode(), 'MODEL_KEY_SET provider=deepseek sha256='
                         + hashlib.sha256(secret.encode()).hexdigest()[:12] + '\n')
        self.assertEqual(stderr, b'')
    def test_evidence_reads_bound_public_sources(self):
        file = self.root / 'record.json'
        file.write_text('{"public":true}')
        with patch.object(M, 'protected') as custody:
            self.assertEqual(M.evidence_json(file, 'APPROVER_PIN'), ({'public': True}, b'{"public":true}'))
            self.assertEqual(custody.call_args_list[-1].args, (file,))
            self.assertEqual([call.args for call in custody.call_args_list[:-1]], [(parent, True) for parent in file.parents])
            for label, limit in M.EVIDENCE_JSON_LIMITS.items():
                file.write_bytes(b'{}' + b' ' * (limit - 1))
                rejects(lambda: M.evidence_json(file, label), 'EVIDENCE_' + label + '_LIMIT')
        file.write_text('{}')
        def custody(path, directory=False):
            if path == file.parent:
                raise ValueError('BROWSER_CUSTODY_INVALID')
        with patch.object(M, 'protected', side_effect=custody):
            rejects(lambda: M.evidence_json(file, 'APPROVER_PIN'), 'CUSTODY_INVALID')

    def test_evidence_artifact_digest_is_streamed_and_named(self):
        file = self.root / 'genesis-artifacts.json'
        payload = b'{"artifacts":[]}' + b' ' * (2 * 1024 * 1024)
        file.write_bytes(payload)
        with patch.object(M, 'protected'):
            self.assertEqual(M.evidence_digest(file), hashlib.sha256(payload).hexdigest())
            file.write_bytes(b'x' * (M.EVIDENCE_ARTIFACT_RECORD_MAX_BYTES + 1))
            rejects(lambda: M.evidence_digest(file), 'EVIDENCE_ARTIFACT_RECORD_LIMIT')

    def test_evidence_projection_revision_and_public_schema(self):
        value = {'revision': 'a' * 40, 'inputs': dict(checkout='1' * 64, node='2' * 64,
                 dependencies='3' * 64, harness='4' * 64, app_host='PRIVATE_APP_HOST', owner_host='PRIVATE_OWNER_HOST')}
        sources = {'plugin-set-approver.json': {'gatePubkeyPem': 'public fixture PEM'},
                   'plugin-set-approval.json': {'receipt': {'v': 2, 'kind': 'change'}},
                   'release-floor.json': {'signer_key_sha256': '5' * 64, 'release': 'a' * 40},
                   'plugin-set.json': {'setDigest': '6' * 64}}
        def read(file, label):
            result = sources[file.name]
            return result, json.dumps(result).encode()
        with patch.object(M, 'installed', return_value=value), patch.object(M, 'evidence_json', side_effect=read), patch.object(M, 'protected') as custody, \
                patch.object(M, 'evidence_digest', return_value=hashlib.sha256(b'{"artifacts":[]}').hexdigest()) as artifact_digest, \
                patch.object(M, 'gate_signer', return_value='public fixture PEM') as ping, \
                patch.object(M.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as verifier:
            checks = [{'name': 'root_platform', 'status': 'FAIL'}]
            raw = M.evidence_record(checks)
            record = json.loads(raw)
            self.assertNotIn('PRIVATE_', raw)
            self.assertEqual(record['installer_inputs'], {name: value['inputs'][name] for name in ('checkout', 'node', 'dependencies', 'harness')})
            self.assertEqual(record['release']['record_sha256'], hashlib.sha256(b'{"artifacts":[]}').hexdigest())
            artifact_digest.assert_called_with(Path('/opt/aukora-genesis/release-aaaaaaa/.dsh-build/genesis-artifacts.json'))
            self.assertEqual(record['checks'], checks)
            self.assertIsNone(record['record_signature'])
            self.assertEqual(list(record['approval']['receipt']), ['v', 'kind'])
            self.assertEqual(verifier.call_args.kwargs['input'], raw.encode())
            self.assertEqual(verifier.call_args.args[0][-1], '--stdin-container')
            self.assertIn((Path(M.NODE),), [call.args for call in custody.call_args_list])
            checker = M.CHECKOUT / 'scripts/audit/browser-node-evidence.mjs'
            self.assertIn((checker,), [call.args for call in custody.call_args_list])
            sources['release-floor.json']['release'] = 'b' * 40
            rejects(lambda: M.evidence_record(checks), 'EVIDENCE_REVISION_MISMATCH')
            sources['release-floor.json']['release'] = 'a' * 40
            ping.return_value = 'rotated public fixture PEM'
            rejects(lambda: M.evidence_record(checks), 'EVIDENCE_SIGNER_MISMATCH')
            ping.return_value = 'public fixture PEM'
            verifier.return_value.returncode = 1
            rejects(lambda: M.evidence_record(checks), 'EVIDENCE_PUBLIC_SCHEMA_REFUSED')
            verifier.return_value.returncode = 2
            self.assertEqual(json.loads(M.evidence_record(checks))['checks'], checks)
            def unsafe(file, *args):
                if file == checker:
                    M.refuse('CUSTODY_INVALID')
            custody.side_effect = unsafe
            rejects(lambda: M.evidence_record(checks), 'CUSTODY_INVALID')

    def test_evidence_real_node_sized_inputs_and_installer_modes(self):
        revision = 'a' * 40
        self.root.chmod(0o755)
        release = self.root / ('release-' + revision[:7])
        build = release / '.dsh-build'
        approval = self.root / 'approvals' / revision / 'state'
        gate_state = approval / 'gate-state'
        state = self.root / 'installer'
        for directory in (release, build, approval, gate_state, state):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        installed = {'revision': revision, 'inputs': {'checkout': '1' * 64, 'node': '2' * 64,
            'dependencies': '3' * 64, 'harness': '4' * 64}}
        plugin_files = {f'plugins/synthetic/file-{index:04d}.mjs': '6' * 64 for index in range(630)}
        plugin_set = {'kind': 'aukora-plugin-set/v1', 'setDigest': '5' * 64,
            'files': plugin_files}
        artifact_entries = [{'path': f'plugins/synthetic/{index:05d}-' + 'p' * 44, 'sha256': '7' * 64}
                            for index in range(15700)]
        artifact_bytes = json.dumps({'artifacts': artifact_entries}, separators=(',', ':')).encode()
        self.assertGreater(len(artifact_bytes), 2 * 1024 * 1024)
        strip_entries = [{'path': f'upstream/deleted/{index:04d}-' + 's' * 47, 'bytes': 1, 'sha256': '8' * 64}
                         for index in range(9700)]
        strip_bytes = json.dumps({'deleted': strip_entries}, separators=(',', ':')).encode()
        self.assertGreater(len(strip_bytes), 1536 * 1024)
        files = {
            state / 'installed.json': json.dumps(installed).encode(),
            gate_state / 'plugin-set-approver.json': json.dumps({'gatePubkeyPem': 'public fixture PEM'}).encode(),
            gate_state / 'plugin-set-approval.json': json.dumps({'receipt': {'v': 2}}).encode(),
            self.root / 'release-floor.json': json.dumps({'signer_key_sha256': '9' * 64, 'release': revision}).encode(),
            build / 'plugin-set.json': json.dumps(plugin_set).encode(),
            build / 'genesis-artifacts.json': artifact_bytes,
            release / 'strip-manifest.json': strip_bytes,
            build / 'aukora-release.json': json.dumps({'tipSha': revision, 'dependencies': ['d' * 128] * 40000}).encode(),
            gate_state / 'ledger-export.json': b'x' * (5 * 1024 * 1024),
        }
        for file, payload in files.items():
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(payload)
            file.chmod(0o644)
        (self.root / 'release-floor.json').chmod(0o644)
        self.assertGreater((build / 'aukora-release.json').stat().st_size, 4 * 1024 * 1024)
        observed = set()
        def custody(path, directory=False, uid=0, private=False, linked=False):
            if path != self.root and not path.is_relative_to(self.root):
                return
            info = path.lstat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o755 if directory else 0o644)
            self.assertFalse(info.st_mode & 0o022)
            observed.add(path)
        original_evidence_json = M.evidence_json
        def evidence_json(file, label):
            if file == Path('/etc/aukora-approvals/release-floor.json'):
                file = self.root / 'release-floor.json'
            return original_evidence_json(file, label)
        verifier = subprocess.CompletedProcess([], 0, b'', b'')
        with patch.object(M, 'STATE', state), patch.object(M, 'release_paths', return_value=(release, approval)), \
                patch.object(M, 'protected', side_effect=custody), patch.object(M, 'gate_signer', return_value='public fixture PEM'), \
                patch.object(M, 'evidence_json', side_effect=evidence_json), patch.object(M.subprocess, 'run', return_value=verifier):
            record = json.loads(M.evidence_record([{'name': 'root_platform', 'status': 'FAIL'}]))
        self.assertEqual(record['release']['record_sha256'], hashlib.sha256(artifact_bytes).hexdigest())
        self.assertEqual(record['release']['plugin_set_sha256'], plugin_set['setDigest'])
        self.assertNotIn(build / 'aukora-release.json', observed)
        self.assertNotIn(release / 'strip-manifest.json', observed)
        self.assertNotIn(gate_state / 'ledger-export.json', observed)
        for file in (state / 'installed.json', gate_state / 'plugin-set-approver.json',
                     gate_state / 'plugin-set-approval.json', self.root / 'release-floor.json',
                     build / 'plugin-set.json', build / 'genesis-artifacts.json'):
            self.assertIn(file, observed)

    def test_evidence_custody_accepts_installer_public_modes(self):
        directory = types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755, st_nlink=1)
        regular = types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o644, st_nlink=1)
        with patch.object(M.Path, 'lstat', return_value=directory):
            M.protected(Path('/synthetic-release'), True)
        with patch.object(M.Path, 'lstat', return_value=regular):
            M.protected(Path('/synthetic-release/record.json'))
        regular.st_mode = stat.S_IFREG | 0o664
        with patch.object(M.Path, 'lstat', return_value=regular):
            rejects(lambda: M.protected(Path('/synthetic-release/record.json')), 'CUSTODY_INVALID')

    def test_evidence_gate_ping_is_bounded_read_only_and_public(self):
        response = json.dumps({'ok': True, 'result': {'ok': True, 'pubkey_fp': 'a' * 16, 'pubkey_pem': 'public fixture PEM'}}).encode() + b'\n'
        class Connection:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, value): pass
            def connect(self, path): self.path = path
            def sendall(self, value): self.request = value
            def recv(self, limit):
                result, self.response = self.response, b'\n'
                return result
        connection = Connection()
        with patch.object(M.socket, 'socket', return_value=connection), patch.object(M.time, 'monotonic', return_value=0):
            connection.response = response
            self.assertEqual(M.gate_signer(), 'public fixture PEM')
            self.assertEqual(connection.path, '/run/aukora-gate/gate.sock')
            self.assertEqual(connection.request, b'{"op":"ping","args":{}}\n')
            for connection.response in [b'', b' ' * 4097 + b'\n']:
                rejects(M.gate_signer, 'EVIDENCE_GATE_PING_LIMIT')
            for value in [{'ok': False, 'result': {}}, {'ok': True, 'result': {'ok': False, 'pubkey_fp': 'a', 'pubkey_pem': 'key'}},
                          {'ok': True, 'result': {'ok': True, 'pubkey_fp': 'a', 'pubkey_pem': 'key', 'private': 'PRIVATE'}}]:
                connection.response = json.dumps(value).encode() + b'\n'
                rejects(M.gate_signer, 'EVIDENCE_GATE_PING_INVALID')
            with patch.object(M.time, 'monotonic', side_effect=[0, 6]):
                rejects(M.gate_signer, 'EVIDENCE_GATE_PING_DEADLINE')

    def test_evidence_hides_output_and_preserves_failure(self):
        def observe(phase, checks):
            print('PRIVATE_COMMAND_OUTPUT')
            checks.append({'name': 'root_platform', 'status': 'FAIL'})
            raise ValueError('PRIVATE_FAILURE')
        with patch.object(M, 'root_check'), patch.object(M, 'accept', side_effect=observe), \
                patch.object(M, 'evidence_record', side_effect=lambda checks: json.dumps({'checks': checks})), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            rejects(lambda: M.accept_evidence('before'), 'EVIDENCE_PHASE_INVALID')
            rejects(lambda: M.accept_evidence('after'), 'ACCEPTANCE_FAILED')
            self.assertNotIn('PRIVATE_', output.getvalue())
            self.assertEqual(json.loads(output.getvalue()), {'checks': [{'name': 'root_platform', 'status': 'FAIL'}]})
        with patch.object(M, 'root_check', side_effect=ValueError('BROWSER_ROOT_REQUIRED')), patch.object(M, 'evidence_record') as record:
            rejects(lambda: M.accept_evidence('after'), 'ROOT_REQUIRED')
            record.assert_not_called()

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
        claim = writes['aukora-browser-claim.service']
        self.assertIn('--owner-page --port 17792', gate)
        self.assertIn('--gid 123', gate)
        for invariant in ('UMask=0077', 'NoNewPrivileges=yes', 'ProtectSystem=strict', 'check-package', 'check-runtime',
                          'floor check', '--foreground', '--approval-state-root', '--approved-record-sha', 'Restart=no'):
            self.assertIn(invariant, harness)
        self.assertNotIn('unsafe-preview', harness)
        self.assertNotIn('linux-openshell.patch.yml', harness)
        self.assertIn('--public-origin-file /etc/aukora/public-origin', harness)
        for invariant in ('User=root', 'Group=root', 'UMask=0077', 'NoNewPrivileges=yes',
                          'ProtectSystem=strict', 'ProtectHome=read-only', 'ReadWritePaths=/var/lib/aukora-browser',
                          'python3 -I -S -B', 'ops/node-spawn/ingress/claim.py serve',
                          '--public-origin-file /etc/aukora/public-origin',
                          '--owner-origin-file /etc/aukora/owner-public-origin',
                          '--state-file /var/lib/aukora-browser/claims.json',
                          '--launch-url-file /home/aukora-host/genesis/state/launch-url.json',
                          '--harness-port 18735', '--owner-page-port 17792', '--listen-port 18736'):
            self.assertIn(invariant, claim)
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
    unit_mutations()
    model_mutations()
    guard_mutations()


def unit_mutations():
    global M
    original = M
    cases = [('harness public origin', '--foreground --public-origin-file /etc/aukora/public-origin', '--foreground')]
    for value in ('User=root', 'Group=root', 'UMask=0077', 'NoNewPrivileges=yes',
                  'ProtectSystem=strict', 'ProtectHome=read-only', 'ReadWritePaths=/var/lib/aukora-browser',
                  'python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/ingress/claim.py serve',
                  '--owner-origin-file /etc/aukora/owner-public-origin',
                  '--state-file /var/lib/aukora-browser/claims.json',
                  '--launch-url-file /home/aukora-host/genesis/state/launch-url.json',
                  '--harness-port 18735', '--owner-page-port 17792', '--listen-port 18736'):
        cases.append((value, value, ''))
    start = TEXT.index('    claim_unit = ')
    for label, before, after in cases:
        # Broker policy mutations target its unit, even when the harness uses the same directive.
        mutated = TEXT.replace(before, after, 1) if label == 'harness public origin' else TEXT[:start] + TEXT[start:].replace(before, after, 1)
        assert mutated != TEXT, label
        M = load(mutated)
        result = unittest.TestResult()
        BrowserInstaller('test_units_preserve_approval_no_preview').run(result)
        assert result.failures or result.errors, 'unit mutation survived: ' + label
    M = original
    print('SOURCE-ONLY browser ingress unit mutations: %d/%d killed' % (len(cases), len(cases)))


def model_mutations():
    global M
    original = M
    cases = [
        ('atomic replace',
         "        os.replace(temporary, MODEL_STORE, src_dir_fd=directory, dst_dir_fd=directory)\n",
         "        os.unlink(temporary, dir_fd=directory)\n"),
        ('secret output',
         "    print('MODEL_KEY_SET provider=' + MODEL_PROVIDER + ' sha256=' + prefix)\n",
         "    print(value.decode())\n    print('MODEL_KEY_SET provider=' + MODEL_PROVIDER + ' sha256=' + prefix)\n"),
        ('stdin-only',
         "        value = sys.stdin.buffer.read(MODEL_KEY_MAX_BYTES + 3)\n",
         "        value = os.environ.get('MODEL_KEY', '').encode()\n"),
    ]
    for label, before, after in cases:
        assert TEXT.count(before) == 1, label
        M = load(TEXT.replace(before, after))
        result = unittest.TestResult()
        BrowserInstaller('test_model_key_store_status_and_remove').run(result)
        assert result.failures or result.errors, 'model credential mutation survived: ' + label
    M = original
    print('SOURCE-ONLY model credential mutations: %d/%d killed' % (len(cases), len(cases)))


def guard_mutations():
    # Every named Python refusal is exercised with its actual predicate removed.
    global M
    spec = importlib.util.spec_from_file_location('browser_pipeline_mutation_fixture', ROOT / 'tests/browser-node-pipeline.py')
    pipeline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pipeline)
    unit_methods = {
        'absolute': ['test_path_and_digest'], 'digest': ['test_path_and_digest'], 'hostname': ['test_hostname'],
        'protected': ['test_custody'], 'root_check': ['test_root_environment'],
        'extract': ['test_archives'], 'run': ['test_run_refuses_and_hides_output'],
        'profile': ['test_profile_integrity'], 'profile_rules': ['test_profile_rules_and_service_preflight'],
        'listeners': ['test_listener_readback'], 'units': ['test_units_preserve_approval_no_preview'],
        'harness_identity': ['test_model_key_custody_and_store_refusals'],
        'open_model_home': ['test_model_key_custody_and_store_refusals'],
        'validate_model_key': ['test_model_key_input_refusals_and_prompt'],
        'read_model_key': ['test_model_key_input_refusals_and_prompt'],
        'model_store_key': ['test_model_key_custody_and_store_refusals'],
        'main': ['test_usage_every_option', 'test_profile_rules_and_service_preflight'],
        'evidence_custody': ['test_evidence_reads_bound_public_sources'],
        'evidence_json': ['test_evidence_reads_bound_public_sources'],
        'evidence_digest': ['test_evidence_artifact_digest_is_streamed_and_named'],
        'evidence_record': ['test_evidence_projection_revision_and_public_schema'],
        'accept_evidence': ['test_evidence_hides_output_and_preserves_failure'],
        'gate_signer': ['test_evidence_gate_ping_is_bounded_read_only_and_public'],
    }
    pipeline_methods = {
        'checked_inputs': ['test_each_input_digest'], 'installed': ['test_install_record_is_closed_and_revision_checked'],
        'install': ['test_dependency_and_node_package_checks', 'test_fresh_install_does_not_adopt_existing_state_or_users', 'test_rerun_is_exact_and_never_regenerates_keys'],
        'accept': ['test_before_acceptance_refuses_any_floor_start_listener_or_descriptor', 'test_after_acceptance_requires_signed_in_ui_and_clean_current_invocation',
                   'test_public_authority_claim_acceptance_guards'],
        'enable_owner_signin': ['test_owner_signin_transition_guards'],
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
    controls = [
        ('input privacy', "{name: value['inputs'][name] for name in ('checkout', 'node', 'dependencies', 'harness')}", "dict(value['inputs'])", 'test_evidence_projection_revision_and_public_schema'),
        ('source parent custody', '    for parent in file.parents:\n        protected(parent, True)\n', '', 'test_evidence_reads_bound_public_sources'),
        ('output privacy', 'with contextlib.redirect_stdout(io.StringIO()):', 'with contextlib.nullcontext():', 'test_evidence_hides_output_and_preserves_failure'),
        ('failure status', '    if failed:\n', '    if False:\n', 'test_evidence_hides_output_and_preserves_failure'),
        ('evidence root', "    root_check()\n    checks = []", "    checks = []", 'test_evidence_hides_output_and_preserves_failure'),
        ('verifier custody', '    for file in (Path(NODE), verifier):\n        for parent in file.parents:\n            protected(parent, True)\n        protected(file)\n', '', 'test_evidence_projection_revision_and_public_schema'),
        ('large materialization independence', "    artifact_sha256 = evidence_digest(release / '.dsh-build/genesis-artifacts.json')\n",
         "    evidence_json(release / '.dsh-build/aukora-release.json', 'PLUGIN_SET')\n    artifact_sha256 = evidence_digest(release / '.dsh-build/genesis-artifacts.json')\n",
         'test_evidence_real_node_sized_inputs_and_installer_modes'),
    ]
    for label, before, after, method in controls:
        assert TEXT.count(before) == 1, label
        result = unittest.TestResult()
        M = load(TEXT.replace(before, after))
        with contextlib.redirect_stdout(io.StringIO()):
            BrowserInstaller(method).run(result)
        M = original_module
        assert result.failures or result.errors, 'evidence removal survived: ' + label
    print('SOURCE-ONLY browser evidence exporter mutations: %d/%d killed' % (len(controls), len(controls)))
    observations = [
        ("            checks.append({'name': name, 'status': 'FAIL'})", "            checks.append({'name': name, 'status': 'PASS'})"),
        ("                checks[-1]['status'] = 'PASS'", "                pass"),
        ("    if checks:\n        checks[-1]['status'] = 'PASS'", "    if checks:\n        pass"),
    ]
    for before, after in observations:
        assert TEXT.count(before) == 1
        mutated = TEXT.replace(before, after)
        old = pipeline.World.__init__
        def initialize(world, text=None):
            old(world, mutated)
        result = unittest.TestResult()
        with patch.object(pipeline.World, '__init__', initialize), contextlib.redirect_stdout(io.StringIO()):
            pipeline.Pipeline('test_public_authority_claim_acceptance_guards').run(result)
        assert result.failures, 'observation status removal survived'
    print('SOURCE-ONLY browser evidence observation mutations: 3/3 killed')


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
