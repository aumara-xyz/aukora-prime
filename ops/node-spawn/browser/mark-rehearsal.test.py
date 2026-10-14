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


def exercise(text=TEXT, failure=None, existing=False):
    with tempfile.TemporaryDirectory(dir=SCRATCH) as folder:
        marker = Path(folder) / 'rehearsal.json'
        if existing:
            marker.write_bytes(b'preserved')
        m = types.ModuleType('rehearsal_marker_fixture')
        exec(compile(text.replace("Path('/etc/aukora-boundary-gate/rehearsal.json')", 'Path(' + repr(str(marker)) + ')'),
                     str(SOURCE), 'exec'), m.__dict__)
        events, output = [], io.StringIO()

        def step(name):
            events.append(name)
            if failure == name:
                raise ValueError('BROWSER_FIXTURE_REFUSED')

        def protect(parent, directory=False):
            assert directory is True
            step(('parent', parent))
            if failure == 'unsafe-parent':
                raise ValueError('BROWSER_CUSTODY_INVALID')

        def owner(fd, uid, gid):
            assert stat.S_ISREG(os.fstat(fd).st_mode)
            step(('owner', uid, gid))

        def sync(fd):
            step('sync-directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'sync-file')

        with patch.object(m, 'root_check', side_effect=lambda: step('root')), \
                patch.object(m, 'installed', side_effect=lambda: step('installed')), \
                patch.object(m, 'protected', side_effect=protect), \
                patch.object(m.os, 'fchown', side_effect=owner), \
                patch.object(m.os, 'fsync', side_effect=sync), contextlib.redirect_stdout(output):
            if failure or existing:
                with unittest.TestCase().assertRaisesRegex(ValueError,
                        'REHEARSAL_MARKER_EXISTS' if existing else 'CUSTODY_INVALID' if failure == 'unsafe-parent' else 'FIXTURE_REFUSED'):
                    m.main(['mark-rehearsal'])
                assert output.getvalue() == ''
                if existing:
                    assert marker.read_bytes() == b'preserved'
                return
            m.main(['mark-rehearsal'])
        assert events[:2] == ['root', 'installed']
        assert [event for event in events if isinstance(event, tuple) and event[0] == 'parent'] == [
            ('parent', parent) for parent in [marker.parent, *marker.parent.parents]]
        assert ('owner', 0, 0) in events
        assert events[-2:] == ['sync-file', 'sync-directory']
        assert marker.stat().st_mode & 0o777 == 0o644
        assert marker.read_bytes() == b'{"version":1,"kind":"aukora-passkey-rehearsal/v1"}\n'
        assert output.getvalue() == 'BROWSER_REHEARSAL_MARKED; this node must never be given to an owner\n'


class RehearsalMarker(unittest.TestCase):
    def test_exclusive_root_installed_marker_and_private_failures(self):
        exercise()
        for failure in ['root', 'installed', 'unsafe-parent', ('owner', 0, 0), 'sync-file', 'sync-directory']:
            exercise(failure=failure)
        exercise(existing=True)

    def test_marker_guard_mutations_fail_the_regressions(self):
        begin, end = TEXT.index('def mark_rehearsal():'), TEXT.index('\ndef passkey_claim():')
        function = TEXT[begin:end]
        mutations = [
            ('    root_check()\n', '', 'root', False),
            ('    installed()\n', '', 'installed', False),
            ('        protected(parent, True)\n', '        pass\n', 'unsafe-parent', False),
            ("marker.open('xb')", "marker.open('wb')", None, True),
            ('        os.fchown(output.fileno(), 0, 0)\n', '', ('owner', 0, 0), False),
            ('        os.fchmod(output.fileno(), 0o644)\n', '', None, False),
            ('        os.fsync(output.fileno())\n', '', 'sync-file', False),
            ('        os.fsync(fd)\n', '        pass\n', 'sync-directory', False),
        ]
        killed = 0
        for before, after, failure, existing in mutations:
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
