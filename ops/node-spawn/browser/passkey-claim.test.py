# Exercise protected activation ordering without services or owner credentials.
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('node.py')
TEXT = SOURCE.read_text()
LINK = 'https://owner.example.test/owner/enroll#claim=' + 'x' * 43 + '\n'


def load(text=TEXT):
    result = types.ModuleType('passkey_claim_fixture')
    exec(compile(text, str(SOURCE), 'exec'), result.__dict__)
    return result


def exercise(text=TEXT, failure=None, link=LINK, group='skgate:x:123:'):
    m = load(text)
    events = []
    output = io.StringIO()

    def step(name, value=None):
        events.append(name)
        if failure == name:
            raise ValueError('BROWSER_FIXTURE_REFUSED')
        return value

    def run(command, code, **options):
        step(code)
        events.append(tuple(command))
        return link if code == 'PASSKEY_CLAIM_REFUSED' else group if code == 'GROUP_MISSING' else ''

    def origin(file):
        value = 'https://' + ('owner' if file.name == 'owner-public-origin' else 'app') + '.example.test'
        return value, value[8:]

    config = types.SimpleNamespace(write=lambda file, data, root: step(('write', file.name, data.decode())))
    ingress = types.SimpleNamespace(read_origin_file=origin)
    with contextlib.ExitStack() as stack:
        for name, value in {
            'root_check': lambda: step('root'),
            'discard_passkey_claim': lambda: step('discard'),
            'installed': lambda: step('installed', {'revision': 'a' * 40}),
            'bootstrap': lambda *args: step(('bootstrap',) + args[:2]),
            'run': run, 'sockets': lambda: step('sockets'),
            'protected': lambda file: step('custody'),
            'module': lambda file: ingress if file.name == 'claim.py' else config,
        }.items():
            stack.enter_context(patch.object(m, name, value))
        stack.enter_context(patch.object(m.os, 'chown', side_effect=lambda *args, **kw: step(('chown', args, kw))))
        stack.enter_context(patch.object(m.Path, 'chmod', side_effect=lambda mode: step(('chmod', mode))))
        stack.enter_context(contextlib.redirect_stdout(output))
        m.main(['passkey-claim'])
    return events, output.getvalue()


class PasskeyClaim(unittest.TestCase):
    def test_passkey_phase_dispatch_and_mutation(self):
        spec = importlib.util.spec_from_file_location('passkey_pipeline_fixture', SOURCE.parents[3] / 'tests/browser-node-pipeline.py')
        pipeline = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pipeline)
        initialize = pipeline.World.__init__

        def check(text):
            def world(w, supplied=None):
                initialize(w, text)
                accept = w.m.accept

                def dispatch(phase, checks=None):
                    value = accept('passkey' if phase == 'after' else phase, checks)
                    if phase == 'after':
                        assert ('run', 'PASSKEY_ACCEPTANCE_REFUSED') in w.events
                    return value
                w.m.accept = dispatch
            result = unittest.TestResult()
            with patch.object(pipeline.World, '__init__', world), contextlib.redirect_stdout(io.StringIO()):
                pipeline.Pipeline('test_public_authority_claim_acceptance_guards').run(result)
            return result

        result = check(TEXT)
        self.assertEqual(result.failures + result.errors, [])
        result = check(TEXT.replace("if phase == 'passkey':", 'if False:'))
        self.assertTrue(result.failures or result.errors)
        print('SOURCE-ONLY passkey phase dispatch mutation: 1/1 killed')

    def test_activation_and_only_owner_link(self):
        events, output = exercise()
        self.assertEqual(output, LINK)
        self.assertEqual(events[:5], ['root', 'discard', 'installed', ('bootstrap', 'check-package'), ('bootstrap', 'floor', 'check')])
        command = next(e for e in events if isinstance(e, tuple) and e and e[0] == '/opt/aukora-node/bin/node')
        self.assertEqual(command[1:], ('/opt/aukora-boundary-gate/bin/browser-passkey-claim.mjs',
            '--owner-origin', 'https://owner.example.test', '--app-origin', 'https://app.example.test',
            '--release', '/opt/aukora-genesis/release-aaaaaaa'))
        write = next(e for e in events if isinstance(e, tuple) and e[0] == 'write')
        self.assertEqual(write[1], 'browser-owner.conf')
        self.assertIn('--passkey-setup /etc/aukora-boundary-gate/passkey-setup.json', write[2])
        self.assertNotIn('--owner-page', write[2])
        self.assertNotIn('--browser-join', write[2])
        self.assertIn('ExecStartPre=+/usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py discard-passkey-claim', write[2])
        self.assertLess(events.index('PASSKEY_CONFIG_REFUSED'), events.index(write))
        self.assertLess(events.index(write), events.index('SYSTEMD_REFUSED'))
        self.assertLess(events.index('SYSTEMD_REFUSED'), events.index('PASSKEY_START_REFUSED'))
        self.assertLess(events.index('sockets'), events.index('PASSKEY_GATE_INACTIVE'))
        self.assertEqual(events[-2], 'PASSKEY_GATE_INACTIVE')
        self.assertIn(('chmod', 0o640), events)
        chown = next(e for e in events if isinstance(e, tuple) and e[0] == 'chown')
        self.assertEqual(chown[1][1:], (0, 123))
        self.assertEqual(chown[2], {'follow_symlinks': False})

    def test_failures_refuse_before_printing_link(self):
        for failure in ['root', 'discard', 'installed', ('bootstrap', 'check-package'), ('bootstrap', 'floor', 'check'),
                        'PASSKEY_CLAIM_REFUSED', 'GROUP_MISSING', 'custody', 'PASSKEY_CONFIG_REFUSED',
                        'SYSTEMD_REFUSED', 'PASSKEY_START_REFUSED', 'sockets', 'PASSKEY_GATE_INACTIVE']:
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                exercise(failure=failure)
        for link in [LINK.replace('owner.', 'app.'), LINK.replace('#claim=', '?claim='), LINK + 'extra\n',
                     LINK.replace('x' * 43, 'x' * 42)]:
            with self.assertRaisesRegex(ValueError, 'BROWSER_PASSKEY_LINK_INVALID'):
                exercise(link=link)
        with self.assertRaisesRegex(ValueError, 'BROWSER_GROUP_INVALID'):
            exercise(group='skgate:x:invalid:')

    def test_guard_removals_fail_negative_assertions(self):
        begin = TEXT.index('def passkey_claim():')
        end = TEXT.index('\ndef enable_owner_signin():', begin)
        function = TEXT[begin:end]
        mutations = [
            ('    root_check()\n', '', 'root'), ('value = installed()', "value = {'revision': 'a' * 40}", 'installed'),
            ('    discard_passkey_claim()\n', '', 'discard'),
            ("bootstrap('check-package')", '', ('bootstrap', 'check-package')),
            ("bootstrap('floor', 'check', '--release-dir', release, '--approval-state-root', approval)", '', ('bootstrap', 'floor', 'check')),
            ("if re.fullmatch(re.escape(owner_public + '/owner/enroll#claim=') + r'[A-Za-z0-9_-]{43}\\n', link) is None:", 'if False:', 'link'),
            ("if not group.isdigit():", 'if False:', 'group'),
            ('protected(setup)', '', 'custody'),
            ("run(['runuser', '-u', 'aukora-gate', '--', NODE, '--input-type=module', '-e', script],\n        'PASSKEY_CONFIG_REFUSED')", '', 'PASSKEY_CONFIG_REFUSED'),
            ("run(['systemctl', 'daemon-reload'], 'SYSTEMD_REFUSED')", '', 'SYSTEMD_REFUSED'),
            ("run(['systemctl', 'restart', 'aukora-boundary-gate.service'], 'PASSKEY_START_REFUSED')", '', 'PASSKEY_START_REFUSED'),
            ('sockets()', '', 'sockets'),
            ("run(['systemctl', 'is-active', '--quiet', 'aukora-boundary-gate.service'], 'PASSKEY_GATE_INACTIVE')", '', 'PASSKEY_GATE_INACTIVE'),
        ]
        killed = 0
        for before, after, failure in mutations:
            self.assertEqual(function.count(before), 1, before)
            mutant = TEXT[:begin] + function.replace(before, after) + TEXT[end:]
            try:
                with self.assertRaises(ValueError):
                    if failure == 'link':
                        exercise(mutant, link=LINK.replace('owner.', 'app.'))
                    elif failure == 'group':
                        # A numeric-but-signed GID reaches chown when its guard is removed.
                        exercise(mutant, group='skgate:x:+123:')
                    else:
                        exercise(mutant, failure=failure)
            except AssertionError:
                killed += 1
            else:
                self.fail('mutation survived: ' + before)
        print('SOURCE-ONLY browser passkey activation mutations: %d/%d killed' % (killed, len(mutations)))

    def sweep(self, text=TEXT, state='unused', unsafe=False):
        scratch = SOURCE.parents[3] / '.runtime/passkey-sweep'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as folder:
            folder = Path(folder)
            claim = folder / 'passkey-claim.txt'
            claim.write_text('x' * 43 + '\n')
            setup = folder / 'passkey-setup.json'
            setup.write_text(json.dumps({'claim_sha256': 'a' * 64, 'state': state}))
            m = load(text.replace("Path('/var/lib/aukora-browser/passkey-claim.txt')", 'Path(' + repr(str(claim)) + ')'))
            syncs, parents, opens = [], [], []
            original_open, original_fsync = os.open, os.fsync

            def protect(parent, directory=False):
                parents.append((parent, directory))
                if unsafe:
                    raise ValueError('BROWSER_CUSTODY_INVALID')

            def opened(parent, flags):
                opens.append((parent, flags))
                return original_open(parent, flags)

            def sync(fd):
                self.assertTrue(m.stat.S_ISDIR(os.fstat(fd).st_mode))
                syncs.append(fd)
                original_fsync(fd)

            with patch.object(m, 'root_check'), patch.object(m, 'model_status'), patch.object(m, 'protected', side_effect=protect), \
                    patch.object(m.os, 'open', side_effect=opened), patch.object(m.os, 'fsync', side_effect=sync):
                if unsafe:
                    with self.assertRaisesRegex(ValueError, 'CUSTODY_INVALID'):
                        m.main(['discard-passkey-claim'])
                    self.assertTrue(claim.exists())
                    return
                m.main(['discard-passkey-claim'])
                self.assertFalse(claim.exists(), state)
                self.assertEqual(setup.read_text(), json.dumps({'claim_sha256': 'a' * 64, 'state': state}))
                self.assertEqual(parents, [(p, True) for p in [folder, *folder.parents]])
                self.assertEqual(len(syncs), 1)
                self.assertEqual(opens, [(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)])
                m.main(['discard-passkey-claim'])
                self.assertEqual(len(syncs), 1, 'absent legacy file is a no-op')

    def test_legacy_raw_claim_removed_before_use_after_use_expiry_and_crash_restart(self):
        for state in ['unused', 'used', 'expired', 'crash-before-cleanup']:
            self.sweep(state=state)
        self.sweep(unsafe=True)
        self.assertEqual(TEXT.count('ExecStartPre=+/usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py discard-passkey-claim'), 2)

    def test_legacy_sweep_mutations(self):
        mutations = [
            ('    claim.unlink()', '    pass', lambda text: self.sweep(text)),
            ('        os.fsync(fd)', '        pass', lambda text: self.sweep(text)),
            ('        protected(parent, True)', '        pass', lambda text: self.sweep(text, unsafe=True)),
            ('os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW', 'os.O_RDONLY | os.O_DIRECTORY', lambda text: self.sweep(text)),
            ("elif options.action == 'discard-passkey-claim':", 'elif False:', lambda text: self.sweep(text)),
        ]
        for before, after, check in mutations:
            begin = TEXT.index('def discard_passkey_claim():')
            head, tail = TEXT[:begin], TEXT[begin:]
            self.assertIn(before, tail)
            with self.assertRaises(AssertionError):
                check(head + tail.replace(before, after, 1))
        for occurrence in [0, 1]:
            line = 'ExecStartPre=+/usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py discard-passkey-claim'
            pieces = TEXT.split(line)
            mutant = line.join(pieces[:occurrence + 1]) + line.join(pieces[occurrence + 1:])
            with self.assertRaises(AssertionError):
                self.assertEqual(mutant.count(line), 2)
        print('SOURCE-ONLY legacy passkey sweep mutations: 7/7 killed')


if __name__ == '__main__':
    unittest.main()
