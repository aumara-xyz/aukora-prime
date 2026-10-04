# SPDX-License-Identifier: AGPL-3.0-or-later
"""Synthetic byte/tree identity checks; no binary, model or service is run.

Runtime ownership, custody, permissions and the actual installed release remain
unqualified by this fixture. All launch, probe, socket and thread calls are mocks.
"""

from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/openviking-supervisor.py"


def load_supervisor():
    spec = importlib.util.spec_from_file_location("openviking_pin_fixture", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LlamaServerPinTest(unittest.TestCase):
    def test_match_changed_library_and_extra_file_before_probe_or_launch(self):
        supervisor_module = load_supervisor()
        with tempfile.TemporaryDirectory(prefix="openviking-llama-pin-") as temporary:
            root = Path(temporary).resolve()
            install = root / "install"
            install.mkdir()
            home = root / "home"
            home.mkdir()
            fake_bin = root / "bin"
            fake_bin.mkdir()
            entry = install / "llama-server"
            entry.write_bytes(b"Synthetic entry bytes; not an executable program.\n")
            # which() needs an executable fixture, but every execution call below
            # is mocked before it can observe or launch these synthetic bytes.
            entry.chmod(0o755)
            library = install / "libggml.so.0.25.3"
            library_bytes = b"Synthetic pinned library bytes.\n"
            library.write_bytes(library_bytes)
            (install / "libggml.so.0").symlink_to(library.name)
            (install / "libggml.so").symlink_to("libggml.so.0")
            alias = fake_bin / "llama-server"
            alias.symlink_to(entry)
            pin = root / "pin.json"
            pin.write_text(json.dumps({
                "version": "b11381",
                "install_dir": str(install),
                "entry": entry.name,
                "entry_sha256": hashlib.sha256(entry.read_bytes()).hexdigest(),
                "files": [{"path": path.name,
                           "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                          for path in (entry, library)],
                "symlinks": [{"path": "libggml.so", "target": "libggml.so.0"},
                             {"path": "libggml.so.0", "target": library.name}],
            }), encoding="utf-8")

            real_open = Path.open
            log_context = mock.MagicMock(name="synthetic_log_context")
            log_file = mock.MagicMock(name="synthetic_log_file")
            log_context.__enter__.return_value = log_file
            log_open = mock.Mock(name="log_open")

            def open_without_runtime_log(path, *args, **kwargs):
                if path == home / "embed.log":
                    log_open(*args, **kwargs)
                    return log_context
                return real_open(path, *args, **kwargs)

            with ExitStack() as patches:
                patches.enter_context(mock.patch.dict(os.environ, {"PATH": str(fake_bin)}, clear=True))
                patches.enter_context(mock.patch.object(supervisor_module, "LLAMA_SERVER_PIN", pin))
                patches.enter_context(mock.patch.object(Path, "open", open_without_runtime_log))
                capture = patches.enter_context(mock.patch.object(supervisor_module, "capture",
                    return_value=SimpleNamespace(stdout="--load-mode MODE\n", stderr="", returncode=0)))
                socket = patches.enter_context(mock.patch.object(supervisor_module.socket, "socket"))
                popen = patches.enter_context(mock.patch.object(supervisor_module.subprocess, "Popen",
                    return_value=SimpleNamespace(pid=4242, returncode=None)))
                thread = patches.enter_context(mock.patch.object(supervisor_module.threading, "Thread"))
                resolved = str(entry.resolve())

                with self.subTest(tree="match"):
                    self.assertEqual(supervisor_module.command("llama-server"), str(alias))
                    self.assertEqual(supervisor_module.verify_llama_server(alias), resolved)
                    self.assertEqual((install / "libggml.so").resolve(), library)
                    cached_profile = supervisor_module.llama_server_profile()
                    self.assertEqual(cached_profile, (resolved, ["--load-mode", "mmap"]))
                    capture.assert_called_once_with([resolved, "--help"])

                    # Bypass initialization deliberately: this focused start check
                    # neither creates nor reads a model, configuration or key.
                    launch = supervisor_module.Supervisor.__new__(supervisor_module.Supervisor)
                    launch.home = home
                    launch.llama, launch.load_mode = cached_profile
                    launch.port = 1934
                    launch.context = 2048
                    launch.model = str(home / "absent-model.gguf")
                    launch.threads = 2
                    launch.start_embed()
                    socket.assert_called_once_with(supervisor_module.socket.AF_INET,
                                                   supervisor_module.socket.SOCK_STREAM)
                    guard = socket.return_value.__enter__.return_value
                    guard.bind.assert_called_once_with(("127.0.0.1", 1934))
                    guard.listen.assert_called_once_with(1)
                    log_open.assert_called_once_with("wb")
                    popen.assert_called_once()
                    self.assertEqual(popen.call_args.args[0][0], resolved)
                    self.assertEqual(popen.call_args.kwargs["stdout"], log_file)
                    thread.assert_called_once()
                    thread.return_value.start.assert_called_once_with()
                    self.assertFalse((home / "embed.log").exists())
                    self.assertFalse(Path(launch.model).exists())

                def refuse_changed_tree():
                    for called in (capture, socket, popen, thread, log_open):
                        called.reset_mock()
                    with self.assertRaises(supervisor_module.SetupError):
                        supervisor_module.llama_server_profile()
                    capture.assert_not_called()
                    # Keep the cached valid profile on the same launch object:
                    # start_embed must independently recheck before any effect.
                    with self.assertRaises(supervisor_module.SetupError):
                        launch.start_embed()
                    for called in (capture, socket, popen, thread, log_open):
                        called.assert_not_called()
                    self.assertEqual(launch.llama, cached_profile[0])
                    self.assertFalse((home / "embed.log").exists())
                    self.assertFalse(Path(launch.model).exists())

                with self.subTest(tree="changed-library-byte"):
                    changed = bytearray(library_bytes)
                    changed[0] ^= 1
                    library.write_bytes(changed)
                    try:
                        self.assertEqual(sum(left != right for left, right in zip(library.read_bytes(), library_bytes)), 1)
                        refuse_changed_tree()
                    finally:
                        library.write_bytes(library_bytes)

                with self.subTest(tree="extra-file"):
                    self.assertEqual(supervisor_module.verify_llama_server(alias), resolved)
                    extra = install / "unexpected-file"
                    extra.write_bytes(b"toy\n")
                    try:
                        refuse_changed_tree()
                    finally:
                        extra.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
