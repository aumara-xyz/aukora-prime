#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Focused descriptor checks with disposable local children and mocked Linux calls.

Real children receive only fixture AF_UNIX sockets, pipes, files and a local lock.
They never execute OpenShell, the wrapper body, guest code, services or providers.
Darwin fixtures exercise the portable source branch, not installed Linux custody.
Both sensitivity mutants exist only in the disposable fixture's Python namespace.
"""

import ast
import ctypes
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock


CHECK = Path(__file__).resolve()
OPEN_SHELL = CHECK.parents[1]
ROOT = CHECK.parents[5]
HELPER = OPEN_SHELL / "custody" / "exec_fds.py"
BODY = OPEN_SHELL / "custody" / "sbx_exec_body.sh"
SHIM = OPEN_SHELL.parent / "sbx-exec"
GUEST_REVISION = "eba2b932cf99f320a9a9236fd35bdc096a46964a"
GUEST_PATH = "plugins/aukora-openshell-confinement/guest/exec.py"
FIXTURE_ENV = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "AUKORA_FDS_CLOSED": "1",
    "AUKORA_SKIP_FD_CLOSE": "1",
    "AUKORA_KEEP_FDS": "7,128",
    "DSH_SUBPROCESS_CONTROL": "pipe",
}
TARGET_FDS = {"socket-low": 7, "lock": 9, "socket-high": 128,
              "file": 129, "pipe": 130}


def source_module(path, name):
    module = ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


# This program runs only in fresh disposable subprocesses. It manufactures all
# capabilities before executing the actual helper API or an explicit control.
FIXTURE = r'''
import errno, fcntl, json, os, socket, stat, sys
from pathlib import Path
from types import ModuleType

helper_path, fixture_root, mode = sys.argv[1:]
module = ModuleType("disposable_exec_fds_source")
module.__file__ = helper_path
exec(compile(Path(helper_path).read_text(), helper_path, "exec"), module.__dict__)

low_peer, low_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
high_peer, high_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
regular = os.open(os.path.join(fixture_root, "regular"), os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
lock_path = os.path.join(fixture_root, "lock")
lock = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
pipe_read, pipe_write = os.pipe()
sources = {"socket-low": low_socket.fileno(), "lock": lock,
           "socket-high": high_socket.fileno(), "file": regular, "pipe": pipe_read}
targets = {"socket-low": 7, "lock": 9, "socket-high": 128, "file": 129, "pipe": 130}
# Copy outside the eventual target slots before closing any original endpoint.
copies = {name: fcntl.fcntl(fd, fcntl.F_DUPFD, 64) for name, fd in sources.items()}
for fd in copies.values():
    os.set_inheritable(fd, False)
for endpoint in (low_peer, low_socket, high_peer, high_socket):
    endpoint.close()
for fd in (regular, lock, pipe_read, pipe_write):
    os.close(fd)
for name, source in copies.items():
    os.dup2(source, targets[name], inheritable=True)
    os.close(source)
fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
before = {name: {"fd": fd, "mode": stat.S_IFMT(os.fstat(fd).st_mode),
                 "inheritable": os.get_inheritable(fd)} for name, fd in targets.items()}

observer = r"""
import errno, fcntl, json, os, stat, sys
before, lock_path = json.loads(sys.argv[1]), sys.argv[2]
after = {}
for name, metadata in before.items():
    try:
        after[name] = {"mode": stat.S_IFMT(os.fstat(metadata["fd"]).st_mode)}
    except OSError as error:
        after[name] = {"errno": error.errno}
lock_reacquired = False
lock = os.open(lock_path, os.O_RDWR)
try:
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_reacquired = True
    except BlockingIOError:
        pass
finally:
    os.close(lock)
payload = sys.stdin.buffer.read(4096).decode("ascii")
sys.stderr.write("fixture-stderr\n")
print(json.dumps({"before": before, "after": after, "stdin": payload,
                  "lock_reacquired": lock_reacquired}), flush=True)
sys.exit(23)
"""
argv = [sys.executable, "-I", "-S", "-c", observer, json.dumps(before), lock_path]
if mode == "bypass":
    # Explicit control: prove the observation detects manufactured inheritance.
    os.execve(argv[0], argv, dict(os.environ))
elif mode == "mutant-no-close":
    module.close_nonstdio = lambda: None
elif mode == "mutant-keep-seven":
    def keep_seven():
        # Fixture-only extra-allowlist mutant; no production bytes change.
        directory = "/proc/self/fd" if sys.platform == "linux" else "/dev/fd"
        for name in os.listdir(directory):
            fd = int(name)
            if fd <= 2 or fd == 7:
                continue
            try:
                os.close(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
    module.close_nonstdio = keep_seven
elif mode == "missing":
    try:
        module.exec_argv([os.path.join(fixture_root, "missing-executable")])
    except OSError as error:
        os.write(2, (json.dumps({"errno": error.errno}) + "\n").encode("ascii"))
        sys.exit(125)
    raise AssertionError("missing executable returned success")
elif mode != "closed":
    raise AssertionError("unknown fixture mode")
module.exec_argv(argv)
raise AssertionError("exec returned without replacing fixture process")
'''


class ExecDescriptorChecks(unittest.TestCase):
    def setUp(self):
        self.module = source_module(HELPER, "checked_exec_fds_source")

    def fixture(self, mode):
        with tempfile.TemporaryDirectory(prefix="aukora-exec-fds-") as directory:
            return subprocess.run(
                [sys.executable, "-I", "-S", "-c", FIXTURE, str(HELPER), directory, mode],
                input="fixture-input\n", text=True, capture_output=True,
                env=FIXTURE_ENV, timeout=5,
            )

    def observation(self, result):
        self.assertEqual(result.returncode, 23, result.stderr[:2048])
        self.assertLess(len(result.stdout), 4096)
        self.assertEqual(result.stderr, "fixture-stderr\n")
        observed = json.loads(result.stdout)
        self.assertEqual(observed["stdin"], "fixture-input\n")
        self.assertEqual(set(observed["before"]), set(TARGET_FDS))
        for name, fd in TARGET_FDS.items():
            self.assertEqual(observed["before"][name]["fd"], fd)
            self.assertTrue(observed["before"][name]["inheritable"])
        for name in ("socket-low", "socket-high"):
            self.assertEqual(observed["before"][name]["mode"], stat.S_IFSOCK)
        self.assertEqual(observed["before"]["pipe"]["mode"], stat.S_IFIFO)
        self.assertEqual(observed["before"]["file"]["mode"], stat.S_IFREG)
        self.assertEqual(observed["before"]["lock"]["mode"], stat.S_IFREG)
        return observed

    def assert_closed(self, observed):
        for name in TARGET_FDS:
            self.assertEqual(observed["after"][name], {"errno": errno.EBADF}, name)
        self.assertTrue(observed["lock_reacquired"])

    @unittest.skipUnless(sys.platform in ("darwin", "linux"), "local closure backend unavailable")
    def test_real_local_closure_preserves_stdio_exit_and_drops_capabilities(self):
        # Deliberate skip/control-looking environment fields cannot retain FD7.
        self.assert_closed(self.observation(self.fixture("closed")))

    @unittest.skipUnless(sys.platform in ("darwin", "linux"), "local fixture unavailable")
    def test_explicit_bypass_control_detects_inherited_socket(self):
        observed = self.observation(self.fixture("bypass"))
        with self.assertRaises(AssertionError):
            self.assert_closed(observed)
        self.assertEqual(observed["after"]["socket-low"], {"mode": stat.S_IFSOCK})
        self.assertEqual(observed["after"]["socket-high"], {"mode": stat.S_IFSOCK})
        self.assertFalse(observed["lock_reacquired"])

    @unittest.skipUnless(sys.platform in ("darwin", "linux"), "local fixture unavailable")
    def test_no_close_guard_removal_mutant_is_detected(self):
        source = HELPER.read_bytes()
        observed = self.observation(self.fixture("mutant-no-close"))
        with self.assertRaises(AssertionError):
            self.assert_closed(observed)
        self.assertEqual(observed["after"]["socket-high"], {"mode": stat.S_IFSOCK})
        self.assertEqual(HELPER.read_bytes(), source)

    @unittest.skipUnless(sys.platform in ("darwin", "linux"), "local fixture unavailable")
    def test_host_fd7_exemption_mutant_is_detected(self):
        source = HELPER.read_bytes()
        observed = self.observation(self.fixture("mutant-keep-seven"))
        with self.assertRaises(AssertionError):
            self.assert_closed(observed)
        self.assertEqual(observed["after"]["socket-low"], {"mode": stat.S_IFSOCK})
        self.assertEqual(observed["after"]["socket-high"], {"errno": errno.EBADF})
        self.assertTrue(observed["lock_reacquired"])
        self.assertEqual(HELPER.read_bytes(), source)

    @unittest.skipUnless(sys.platform in ("darwin", "linux"), "local closure backend unavailable")
    def test_missing_executable_reports_factual_refusal(self):
        result = self.fixture("missing")
        self.assertEqual(result.returncode, 125)
        self.assertEqual(result.stdout, "")
        self.assertEqual(json.loads(result.stderr), {"errno": errno.ENOENT})

    @unittest.skipUnless(sys.platform in ("darwin", "linux"), "local Bash fixture unavailable")
    def test_bash_privileged_startup_skips_bash_env_with_observable_control(self):
        with tempfile.TemporaryDirectory(prefix="aukora-bash-startup-") as directory:
            root = Path(directory)
            startup, body, marker = root / "startup.sh", root / "body.sh", root / "marker"
            startup.write_text('printf startup > "$AUKORA_FIXTURE_MARKER"\nprintf "fixture-startup\\n" >&2\n')
            body.write_text('IFS= read -r fixture_line\nprintf "fixture-stdout:%s\\n" "$fixture_line"\nprintf "fixture-stderr\\n" >&2\nexit 29\n')
            environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "BASH_ENV": str(startup),
                           "AUKORA_FIXTURE_MARKER": str(marker)}
            launch = '''
from pathlib import Path
import sys
from types import ModuleType
module = ModuleType("disposable_bash_exec_fds_source")
exec(compile(Path(sys.argv[1]).read_text(), sys.argv[1], "exec"), module.__dict__)
module.exec_argv(["/bin/bash", "-p", sys.argv[2]])
raise AssertionError("trusted Bash exec returned")
'''
            protected = subprocess.run([sys.executable, "-I", "-S", "-c", launch, str(HELPER), str(body)],
                                       input="fixture-input\n", text=True, capture_output=True,
                                       env=environment, timeout=5)
            self.assertEqual(protected.returncode, 29, protected.stderr[:2048])
            self.assertEqual(protected.stdout, "fixture-stdout:fixture-input\n")
            self.assertEqual(protected.stderr, "fixture-stderr\n")
            self.assertFalse(marker.exists(), "BASH_ENV ran despite the actual -p invocation")
            control = subprocess.run(["/bin/bash", str(body)], input="fixture-input\n", text=True,
                                     capture_output=True, env=environment, timeout=5)
            self.assertEqual(control.returncode, 29, control.stderr[:2048])
            self.assertEqual(control.stdout, protected.stdout)
            self.assertEqual(control.stderr, "fixture-startup\nfixture-stderr\n")
            self.assertEqual(marker.read_text(), "startup")

    def test_mocked_linux_uses_full_physical_range_and_zero_flags(self):
        operation = mock.Mock(return_value=0)
        libc = SimpleNamespace(close_range=operation)
        with mock.patch.object(self.module, "sys", SimpleNamespace(platform="linux")), \
                mock.patch.object(self.module.ctypes, "CDLL", return_value=libc) as load, \
                mock.patch.object(self.module, "_darwin_close_nonstdio") as fallback:
            self.module.close_nonstdio()
        load.assert_called_once_with(None, use_errno=True)
        operation.assert_called_once_with(3, 0xffffffff, 0)
        self.assertEqual(operation.argtypes, [ctypes.c_uint, ctypes.c_uint, ctypes.c_int])
        self.assertIs(operation.restype, ctypes.c_int)
        fallback.assert_not_called()

    def test_mocked_linux_failure_never_executes_or_falls_back(self):
        for number in (errno.EIO, errno.EPERM, errno.ENOSYS, errno.EINVAL):
            with self.subTest(errno=number):
                operation = mock.Mock(return_value=-1)
                libc = SimpleNamespace(close_range=operation)
                with mock.patch.object(self.module, "sys", SimpleNamespace(platform="linux")), \
                        mock.patch.object(self.module.ctypes, "CDLL", return_value=libc), \
                        mock.patch.object(self.module.ctypes, "get_errno", return_value=number), \
                        mock.patch.object(self.module.os, "execve") as execute, \
                        mock.patch.object(self.module, "_darwin_close_nonstdio") as fallback:
                    with self.assertRaises(OSError) as caught:
                        self.module.exec_argv(["/synthetic/fixed-target"])
                self.assertEqual(caught.exception.errno, number)
                operation.assert_called_once_with(3, 0xffffffff, 0)
                execute.assert_not_called()
                fallback.assert_not_called()

    def test_mocked_linux_missing_export_refuses_without_exec(self):
        with mock.patch.object(self.module, "sys", SimpleNamespace(platform="linux")), \
                mock.patch.object(self.module.ctypes, "CDLL", return_value=SimpleNamespace()), \
                mock.patch.object(self.module.os, "execve") as execute, \
                mock.patch.object(self.module, "_darwin_close_nonstdio") as fallback:
            with self.assertRaises(OSError) as caught:
                self.module.exec_argv(["/synthetic/fixed-target"])
        self.assertEqual(caught.exception.errno, errno.ENOSYS)
        execute.assert_not_called()
        fallback.assert_not_called()

    def test_mocked_darwin_closes_nonstdio_and_ignores_only_transient_ebadf(self):
        def close(fd):
            if fd == 9999:
                raise OSError(errno.EBADF, "synthetic closed enumeration descriptor")
        close_call = mock.Mock(side_effect=close)
        fake_os = SimpleNamespace(listdir=mock.Mock(return_value=["0", "1", "2", "7", "9", "128", "9999"]),
                                  close=close_call)
        with mock.patch.object(self.module, "os", fake_os), \
                mock.patch.object(self.module, "sys", SimpleNamespace(platform="darwin")):
            self.module.close_nonstdio()
        fake_os.listdir.assert_called_once_with("/dev/fd")
        self.assertEqual(close_call.call_args_list, [mock.call(fd) for fd in (7, 9, 128, 9999)])

    def test_mocked_darwin_uncertain_close_prevents_exec(self):
        for number in (errno.EIO, errno.EPERM, errno.EINTR):
            with self.subTest(errno=number):
                fake_os = SimpleNamespace(path=os.path, environ={}, listdir=mock.Mock(return_value=["7"]),
                                          close=mock.Mock(side_effect=OSError(number, "synthetic close failure")),
                                          execve=mock.Mock())
                with mock.patch.object(self.module, "os", fake_os), \
                        mock.patch.object(self.module, "sys", SimpleNamespace(platform="darwin")):
                    with self.assertRaises(OSError) as caught:
                        self.module.exec_argv(["/synthetic/fixed-target"])
                self.assertEqual(caught.exception.errno, number)
                fake_os.execve.assert_not_called()

    def test_malformed_trusted_arguments_refuse_before_closure(self):
        for argv in (None, (), [], [None], [""], ["relative"],
                     ["/synthetic/fixed-target", None], ["/synthetic/fixed-target", "\0"]):
            with self.subTest(argv=repr(argv)):
                with mock.patch.object(self.module, "close_nonstdio") as close, \
                        mock.patch.object(self.module.os, "execve") as execute:
                    with self.assertRaises(ValueError):
                        self.module.exec_argv(argv)
                close.assert_not_called()
                execute.assert_not_called()

    def test_cli_has_fixed_target_and_caller_flags_cannot_skip_closure(self):
        arguments = ["--skip-fd-close", "--keep-fd", "7", "/caller-selected-target"]
        for role, prefix in (("openshell", ["/usr/bin/openshell"]),
                             ("wrapper", ["/bin/bash", "-p", "/usr/local/lib/aukora-boundary/openshell/custody/sbx_exec_body.sh"])):
            with self.subTest(role=role):
                events = []
                def close():
                    events.append("close")
                def execute(*args):
                    events.append("exec")
                    raise FileNotFoundError(errno.ENOENT, "synthetic unavailable fixed executable")
                fake_os = SimpleNamespace(path=os.path, environ=dict(FIXTURE_ENV),
                                          execve=mock.Mock(side_effect=execute), write=mock.Mock())
                with mock.patch.object(self.module, "sys", SimpleNamespace(argv=[str(HELPER), role, *arguments])), \
                        mock.patch.object(self.module, "os", fake_os), \
                        mock.patch.object(self.module, "close_nonstdio", side_effect=close) as closer:
                    self.assertEqual(self.module.main(), 125)
                closer.assert_called_once_with()
                fake_os.execve.assert_called_once_with(prefix[0], [*prefix, *arguments], dict(FIXTURE_ENV))
                self.assertEqual(events, ["close", "exec"])
                fake_os.write.assert_called_once_with(2, b"aukora-openshell-confinement: descriptor-launch-unavailable\n")

    def test_missing_or_unknown_cli_role_refuses_without_exec(self):
        for arguments in ([], ["--skip-fd-close"], ["/caller-selected-target"]):
            with self.subTest(arguments=arguments):
                fake_os = SimpleNamespace(execve=mock.Mock(), write=mock.Mock())
                with mock.patch.object(self.module, "sys", SimpleNamespace(argv=[str(HELPER), *arguments])), \
                        mock.patch.object(self.module, "os", fake_os), \
                        mock.patch.object(self.module, "close_nonstdio") as close:
                    self.assertEqual(self.module.main(), 125)
                close.assert_not_called()
                fake_os.execve.assert_not_called()
                fake_os.write.assert_called_once_with(2, b"aukora-openshell-confinement: descriptor-launch-unavailable\n")

    def test_wrapper_fixed_helper_body_and_two_ordinary_routes_source_only(self):
        shim = SHIM.read_text()
        self.assertEqual(shim.splitlines()[0], "#!/bin/bash -p")
        statements = [line for line in shim.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(statements, [
            'exec /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/openshell/custody/exec_fds.py wrapper "$@"',
        ])
        body = BODY.read_text()
        self.assertEqual(body.splitlines()[0], "#!/bin/bash -p")
        routed = "/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/openshell/custody/exec_fds.py openshell sandbox exec"
        self.assertEqual(body.count(routed), 2)
        self.assertNotIn("/usr/bin/openshell sandbox exec", body)
        self.assertIn("close_fds=True, pass_fds=()", body)
        self.assertIn("stdout=1, stderr=subprocess.PIPE, close_fds=True, pass_fds=()", body)

    def test_preserved_guest_constructs_fresh_conditional_fd7_source_only(self):
        result = subprocess.run(["git", "--no-pager", "show", f"{GUEST_REVISION}:{GUEST_PATH}"],
                                cwd=ROOT, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_NO_LAZY_FETCH": "1"},
                                capture_output=True, text=True, timeout=5, check=True)
        source = result.stdout
        tree = ast.parse(source)
        carrier = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Carrier")
        launch = next(node for node in carrier.body if isinstance(node, ast.FunctionDef) and node.name == "launch")
        body = ast.get_source_segment(source, launch)
        self.assertIn("socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)", body)
        self.assertIn("os.dup2(control_copy, 7, inheritable=True)", body)
        self.assertIn("keep = {0, 1, 2, error_fd} | ({7} if control_copy is not None else set())", body)
        self.assertIn('os.listdir("/proc/self/fd")', body)
        self.assertIn("fcntl.F_DUPFD_CLOEXEC", source)
        self.assertLess(body.index('os.listdir("/proc/self/fd")'), body.index("os.execve("))


if __name__ == "__main__":
    unittest.main(verbosity=2)
