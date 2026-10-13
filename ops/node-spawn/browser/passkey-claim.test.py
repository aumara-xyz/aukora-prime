# Exercise protected activation ordering without services or owner credentials.
import contextlib
import importlib.util
import io
from pathlib import Path
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

                def dispatch(phase):
                    value = accept('passkey' if phase == 'after' else phase)
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
        self.assertEqual(events[:4], ['root', 'installed', ('bootstrap', 'check-package'), ('bootstrap', 'floor', 'check')])
        command = next(e for e in events if isinstance(e, tuple) and e and e[0] == '/opt/aukora-node/bin/node')
        self.assertEqual(command[1:], ('/opt/aukora-boundary-gate/bin/browser-passkey-claim.mjs',
            '--owner-origin', 'https://owner.example.test', '--app-origin', 'https://app.example.test',
            '--release', '/opt/aukora-genesis/release-aaaaaaa'))
        write = next(e for e in events if isinstance(e, tuple) and e[0] == 'write')
        self.assertEqual(write[1], 'browser-owner.conf')
        self.assertIn('--passkey-setup /etc/aukora-boundary-gate/passkey-setup.json', write[2])
        self.assertNotIn('--owner-page', write[2])
        self.assertNotIn('--browser-join', write[2])
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
        for failure in ['root', 'installed', ('bootstrap', 'check-package'), ('bootstrap', 'floor', 'check'),
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


if __name__ == '__main__':
    unittest.main()
