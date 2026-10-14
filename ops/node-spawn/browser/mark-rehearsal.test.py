# Exercise root marker custody and durability without changing an installed node.
import contextlib
import io
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('node.py')
TEXT = SOURCE.read_text()
SCRATCH = SOURCE.parents[3] / '.runtime/rehearsal-marker'
SCRATCH.mkdir(parents=True, exist_ok=True)


def exercise(text=TEXT, failure=None, existing=False, bound=False):
    with tempfile.TemporaryDirectory(dir=SCRATCH) as folder:
        state = Path(folder) / 'state'
        state.mkdir(mode=0o700)
        gate = Path(folder) / 'gate-config'
        gate.mkdir(mode=0o755)
        marker = gate / 'rehearsal.json'
        record = Path(folder) / 'local-control.json'
        if existing:
            marker.write_bytes(b'preserved')
        if bound:
            record.write_bytes(b'synthetic bound control')
        m = types.ModuleType('rehearsal_marker_fixture')
        text = text.replace("Path('/etc/aukora-boundary-gate/rehearsal.json')", 'Path(' + repr(str(marker)) + ')')
        text = text.replace("Path('/home/aukora-host/genesis/state/aumlok-binding/local-control.json')",
                            'Path(' + repr(str(record)) + ')')
        exec(compile(text,
                     str(SOURCE), 'exec'), m.__dict__)
        m.STATE = state
        state_marker = state / m.REHEARSAL_MARKER
        events, output = [], io.StringIO()
        real_fstat = os.fstat

        def step(name):
            events.append(name)
            if failure == name:
                raise ValueError('BROWSER_FIXTURE_REFUSED')

        def protect(parent, directory=False, private=None):
            assert directory is True
            step(('parent', parent, private))
            if failure == 'unsafe-parent' and parent == gate:
                raise ValueError('BROWSER_CUSTODY_INVALID')

        def owner(fd, uid, gid):
            assert stat.S_ISREG(os.fstat(fd).st_mode)
            step(('owner', uid, gid))

        def sync(fd):
            info = real_fstat(fd)
            identity = (info.st_dev, info.st_ino)
            for name, path in [('state-file', state_marker), ('state-directory', state),
                               ('gate-file', marker), ('gate-directory', gate)]:
                if path.exists() and identity == (path.stat().st_dev, path.stat().st_ino):
                    step('sync-' + name)
                    return
            raise AssertionError('unexpected sync descriptor')

        def root_stat(fd):
            # Simulate root custody while keeping file type, mode, link count and size real.
            fields = list(real_fstat(fd))
            fields[4] = 0
            return os.stat_result(fields)

        with patch.object(m, 'root_check', side_effect=lambda: step('root')), \
                patch.object(m, 'installed', side_effect=lambda: step('installed')), \
                patch.object(m, 'protected', side_effect=protect), \
                patch.object(m.os, 'fchown', side_effect=owner), \
                patch.object(m.os, 'fstat', side_effect=root_stat), \
                patch.object(m.os, 'fsync', side_effect=sync), contextlib.redirect_stdout(output):
            if failure or existing or bound:
                with unittest.TestCase().assertRaisesRegex(ValueError,
                        'REHEARSAL_ALREADY_BOUND' if bound else 'REHEARSAL_MARKER_EXISTS' if existing else
                        'CUSTODY_INVALID' if failure == 'unsafe-parent' else 'FIXTURE_REFUSED'):
                    m.main(['mark-rehearsal'])
                assert output.getvalue() == ''
                if existing:
                    assert marker.read_bytes() == b'preserved'
                if bound:
                    assert not state_marker.exists() and not marker.exists()
                    assert record.read_bytes() == b'synthetic bound control'
                return
            m.main(['mark-rehearsal'])
        assert events[:2] == ['root', 'installed']
        assert [event for event in events if isinstance(event, tuple) and event[0] == 'parent'] == [
            ('parent', parent, parent == state) for parent in [state, *state.parents]] * 2 + [
            ('parent', parent, None) for parent in [gate, *gate.parents]]
        assert events.count(('owner', 0, 0)) == 1
        assert [event for event in events if isinstance(event, str) and event.startswith('sync-')] == [
            'sync-state-file', 'sync-state-directory', 'sync-gate-file', 'sync-gate-directory']
        assert state_marker.is_file() and marker.is_file()
        assert state_marker.stat().st_mode & 0o777 == 0o600
        assert state_marker.read_bytes() == m.REHEARSAL_MARKER_BYTES
        assert marker.stat().st_mode & 0o777 == 0o644
        assert marker.read_bytes() == b'{"version":1,"kind":"aukora-passkey-rehearsal/v1"}\n'
        assert output.getvalue() == 'BROWSER_REHEARSAL_MARKED; never give this node to an owner for binding\n'


class RehearsalMarker(unittest.TestCase):
    def test_exclusive_root_installed_marker_and_private_failures(self):
        exercise()
        for failure in ['root', 'installed', 'unsafe-parent', ('owner', 0, 0),
                        'sync-state-file', 'sync-state-directory', 'sync-gate-file', 'sync-gate-directory']:
            exercise(failure=failure)
        exercise(existing=True)
        exercise(bound=True)

    def test_marker_guard_mutations_fail_the_regressions(self):
        scopes = {'command': ('def mark_rehearsal():', '\ndef claim():'),
                  'gate': ('def mark_gate_rehearsal():', '\ndef passkey_claim():')}
        mutations = [
            ('command', '    root_check()\n', '', 'root', False),
            ('command', '    installed()\n', '', 'installed', False),
            ('gate', '        protected(parent, True)\n', '        pass\n', 'unsafe-parent', False),
            ('gate', "marker.open('xb')", "marker.open('wb')", None, True),
            ('gate', '        os.fchown(output.fileno(), 0, 0)\n', '', ('owner', 0, 0), False),
            ('gate', '        os.fchmod(output.fileno(), 0o644)\n', '', None, False),
            ('gate', '        os.fsync(output.fileno())\n', '', 'sync-gate-file', False),
            ('gate', '        os.fsync(fd)\n', '        pass\n', 'sync-gate-directory', False),
        ]
        killed = 0
        for scope, before, after, failure, existing in mutations:
            start, finish = scopes[scope]
            begin = TEXT.index(start)
            end = TEXT.index(finish, begin)
            function = TEXT[begin:end]
            self.assertEqual(function.count(before), 1)
            mutant = TEXT[:begin] + function.replace(before, after) + TEXT[end:]
            # A private inherited umask needs the explicit readable marker mode.
            previous = os.umask(0o077)
            try:
                with self.assertRaises(AssertionError):
                    exercise(mutant, failure=failure, existing=existing)
                killed += 1
            finally:
                os.umask(previous)
        print('SOURCE-ONLY rehearsal marker write mutations: %d/%d killed' % (killed, len(mutations)))


if __name__ == '__main__':
    unittest.main()
