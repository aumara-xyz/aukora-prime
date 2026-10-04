#!/usr/bin/python3
"""SOURCE-ONLY bootstrap regression; synthetic root metadata, no installation."""

import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = runpy.run_path(str(HERE / "gate-bootstrap.py"), run_name="gate_bootstrap_source")
G = SOURCE["verify_package"].__globals__
Refused = SOURCE["Refused"]


def root_metadata(metadata, directory=False):
    """Only fixture evidence: production validator itself always demands UID 0."""
    fields = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
    fields["st_uid"] = 0
    return SimpleNamespace(**fields)


class World:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gate-bootstrap-source-")
        self.root = Path(os.path.realpath(self.temporary.name)) / "package"
        self.root.mkdir(mode=0o700)
        self.marker = self.root.parent / "executed-marker"
        self.put("bin/gate.mjs", "from pathlib import Path\nPath(" + repr(str(self.marker)) + ").write_text('executed')\n")
        self.put("bin/release-floor.mjs", "// reviewed operator floor entry\n")
        self.put("bin/plugin-set-approval.mjs", "// reviewed operator approval entry\n")
        self.put("src/helper.mjs", "// reviewed transitive helper\n")
        self.put("package.json", '{"type":"module"}\n')
        self.put("host/aura/trusted-context.mjs", "// fixed Aura context validator\n")
        self.files = {str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in self.root.rglob("*") if path.is_file()}
        self.ancestors = set()
        for path in self.root.parents:
            metadata = path.stat()
            self.ancestors.add((metadata.st_dev, metadata.st_ino))

    def put(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(data)
        path.chmod(0o600)
        return path

    def fixture_metadata(self, metadata, directory=False):
        # Synthetic root custody for fixture inodes only; world-writable system
        # temp ancestors are explicit simulated external anchors, not qualified.
        injected = root_metadata(metadata, directory)
        if directory and (metadata.st_dev, metadata.st_ino) in self.ancestors:
            injected.st_mode &= ~0o022
        SOURCE["protected_metadata"](injected, directory)

    def check(self):
        with patch.dict(G, {"protected_metadata": self.fixture_metadata}):
            SOURCE["verify_package"](str(self.root), self.files)

    def launch(self):
        # Actual tiny marker program is dispatched only after the source
        # verification algorithm. This is a Python fixture, not Node acceptance.
        self.check()
        subprocess.run([sys.executable, "-I", "-S", str(self.root / "bin/gate.mjs")], check=True)

    def close(self):
        self.temporary.cleanup()


class BootstrapChecks(unittest.TestCase):
    def setUp(self):
        self.world = World()

    def tearDown(self):
        self.world.close()

    def refuses(self, code):
        return self.assertRaisesRegex(Refused, code)

    def test_matching_complete_inventory_reaches_fixture_dispatch(self):
        self.world.launch()
        self.assertEqual(self.world.marker.read_text(), "executed")

    def test_changed_entry_and_transitive_helpers_never_execute_marker(self):
        for name in ("bin/gate.mjs", "bin/release-floor.mjs", "bin/plugin-set-approval.mjs", "src/helper.mjs", "host/aura/trusted-context.mjs", "package.json"):
            with self.subTest(name=name):
                path = self.world.root / name
                original = path.read_bytes()
                path.write_text("from pathlib import Path\nPath(" + repr(str(self.world.marker)) + ").write_text('unapproved')\n")
                with self.refuses("package-hash"):
                    self.world.launch()
                self.assertFalse(self.world.marker.exists())
                path.write_bytes(original)

    def test_added_and_missing_files_refuse_before_dispatch(self):
        extra = self.world.put("src/unchecked.mjs", "raise Exception('unapproved')\n")
        with self.refuses("package-inventory"):
            self.world.launch()
        extra.unlink()
        (self.world.root / "src/helper.mjs").unlink()
        with self.refuses("package-inventory"):
            self.world.launch()
        self.assertFalse(self.world.marker.exists())

    def test_symlinks_of_every_kind_and_hardlinks_refuse(self):
        for target in ("../../outside.mjs", "/etc/passwd", "missing.mjs", "../bin/gate.mjs"):
            path = self.world.root / "src/link.mjs"
            path.symlink_to(target)
            with self.refuses("protected-(type|mode)"):
                self.world.check()
            path.unlink()
        os.link(self.world.root / "src/helper.mjs", self.world.root / "src/hardlink.mjs")
        with self.refuses("protected-hardlink"):
            self.world.check()

    def test_symlink_directory_and_special_file_refuse(self):
        path = self.world.root / "linked-directory"
        path.symlink_to(self.world.root / "src", target_is_directory=True)
        with self.refuses("protected-(type|mode)"):
            self.world.check()
        path.unlink()
        os.mkfifo(path)
        with self.refuses("protected-type"):
            self.world.check()

    def test_writeable_package_directory_and_file_refuse(self):
        for path in (self.world.root / "src", self.world.root / "src/helper.mjs"):
            previous = path.stat().st_mode
            path.chmod(previous | 0o020)
            with self.refuses("protected-mode"):
                self.world.check()
            path.chmod(previous)

    def test_real_nonroot_and_synthetic_bad_metadata_refuse(self):
        metadata = self.world.root.stat()
        if metadata.st_uid != 0:
            with self.refuses("protected-owner"):
                SOURCE["protected_metadata"](metadata, True)
        root = root_metadata(metadata)
        root.st_mode |= 0o002
        with self.refuses("protected-mode"):
            SOURCE["protected_metadata"](root, True)
        root.st_mode = stat.S_IFREG | 0o600
        root.st_nlink = 2
        with self.refuses("protected-hardlink"):
            SOURCE["protected_metadata"](root)

    def test_open_identity_and_short_read_refuse(self):
        original_fstat = os.fstat
        def changed_identity(fd):
            metadata = root_metadata(original_fstat(fd))
            metadata.st_ino += 1
            return metadata
        with patch.dict(G, {"protected_metadata": self.world.fixture_metadata}), patch.object(os, "fstat", changed_identity):
            with self.refuses("protected-open-identity"):
                SOURCE["protected_read"](str(self.world.root / "src/helper.mjs"))
        with patch.dict(G, {"protected_metadata": self.world.fixture_metadata}), patch.object(os, "read", return_value=b""):
            with self.refuses("protected-short-read"):
                SOURCE["protected_read"](str(self.world.root / "src/helper.mjs"))

    def test_mutation_during_opened_file_read_refuses(self):
        original_read = os.read
        path = self.world.root / "src/helper.mjs"
        fired = False
        def mutate_during_read(fd, count):
            nonlocal fired
            data = original_read(fd, count)
            if data and not fired:
                fired = True
                path.write_text("// mutated after read\n")
            return data
        with patch.dict(G, {"protected_metadata": self.world.fixture_metadata}), patch.object(os, "read", mutate_during_read):
            with self.refuses("protected-read-identity"):
                SOURCE["protected_read"](str(path))

    def manifest(self):
        return {"version": 1, "kind": "aukora-gate-package/v1", "package": SOURCE["PACKAGE"],
                "entry": SOURCE["ENTRY"], "files": self.world.files,
                "external_files": {path: "0" * 64 for path in SOURCE["EXTERNAL_FILES"]}}

    def test_manifest_closed_keys_duplicate_keys_and_paths(self):
        value = self.manifest()
        SOURCE["parse_manifest"](json.dumps(value).encode())
        for name in ("/absolute", "../escape", "a/../b", "a//b", "./a", "a\\b", "a/", "a\n"):
            mutated = self.manifest()
            mutated["files"] = {**self.world.files, name: "0" * 64}
            with self.refuses("manifest-path"):
                SOURCE["parse_manifest"](json.dumps(mutated).encode())
        with self.refuses("json-duplicate-key"):
            SOURCE["parse_manifest"](b'{"version":1,"version":1}')
        for mutate in (lambda m: m.update(extra=True), lambda m: m["files"].pop("package.json"),
                       lambda m: m["external_files"].update({"/tmp/candidate-context.json": "0" * 64})):
            changed = self.manifest()
            changed["files"] = dict(changed["files"])
            mutate(changed)
            with self.refuses("manifest-"):
                SOURCE["parse_manifest"](json.dumps(changed).encode())

    def test_signer_epoch_map_is_closed_sorted_unique_and_full_hash(self):
        def encode(rows):
            return json.dumps({"version": 1, "kind": "aukora-signer-epochs/v1", "epochs": rows}).encode()
        row = {"epoch": 1, "gate_pubkey_sha256": "0" * 64}
        SOURCE["validate_signer_epochs"](encode([row]))
        for rows in ([], [{**row, "epoch": True}], [{**row, "epoch": 9007199254740992}],
                     [{**row, "epoch": 2}], [row, {"epoch": 3, "gate_pubkey_sha256": "1" * 64}],
                     [row, {**row, "epoch": 2}], [{**row, "epoch": 2}, {**row, "gate_pubkey_sha256": "1" * 64}],
                     [{**row, "gate_pubkey_sha256": "0" * 16}], [{**row, "extra": 1}]):
            with self.refuses("signer-epochs-format"):
                SOURCE["validate_signer_epochs"](encode(rows))
        with self.refuses("signer-epochs-format"):
            SOURCE["validate_signer_epochs"](encode([{"epoch": i, "gate_pubkey_sha256": format(i, "064x")} for i in range(1, 66)]))
        with self.refuses("signer-epochs-format"):
            SOURCE["validate_signer_epochs"](encode([row]) + b" " * 16384)

    def test_only_fixed_gate_serve_arguments_are_admitted(self):
        valid = ["serve", "--home", "/home/aukora-gate", "--run", "/run/aukora-gate", "--target-root",
                 "/var/lib/aukora-boundary/targets", "--gid", "123", "--port", "17792", "--time-zone", "Asia/Makassar", "--owner-page"]
        self.assertEqual(SOURCE["serve_arguments"](valid), valid)
        for tail in (["--unsafe-preview"], ["--unsafe-preview", "false"], ["--config", "/tmp/config"],
                     ["--eval", "evil"], ["--import", "evil"], ["--require", "evil"], ["--experimental-loader", "evil"],
                     ["--fixture-root", "/tmp"], ["--uid", "0"], ["--"], ["extra"], ["--port"],
                     ["--gid", "0"], ["--owner-page"]):
            with self.subTest(tail=tail), self.refuses("launch-"):
                SOURCE["serve_arguments"](valid + tail)
        for invalid in (["--import", "evil"] + valid, ["verify"], ["serve", "--home", "/tmp/candidate"]):
            with self.refuses("launch-"):
                SOURCE["serve_arguments"](invalid)
        with self.refuses("aura-context-unconfigured"):
            SOURCE["serve_arguments"](["aura"])

    def test_minimal_node_environment_discards_preloads_and_refuses_preview(self):
        environment = SOURCE["node_environment"]({"NODE_OPTIONS": "--import=evil", "NODE_PATH": "/tmp",
                                                   "LD_PRELOAD": "/tmp/evil.so", "PYTHONPATH": "/tmp", "AUKORA_CONFIG": "/tmp"})
        self.assertEqual(set(environment), {"PATH", "HOME", "LANG", "LC_ALL"})
        for name in ("AUKORA_UNSAFE_PREVIEW", "unsafePreview", "UNSAFE-PREVIEW"):
            with self.refuses("unsafe-preview-environment"):
                SOURCE["node_environment"]({name: "false"})
        for value in ({"unsafePreview": False}, {"policy": {"unsafe-preview-auth": False}},
                      {"settings": [{"unsafe_preview": True}]}):
            with self.refuses("unsafe-preview-config"):
                SOURCE["validate_aura_context"](json.dumps(value).encode())
        with self.refuses("aura-context-unconfigured"):
            SOURCE["validate_aura_context"](b"{}")

    def test_operator_roles_use_fixed_entries_actions_and_per_action_flags(self):
        release = "/opt/aukora-genesis/release-abcdef0"
        state = "/etc/aukora-approvals/" + "0" * 40 + "/state"
        valid = [
            ["floor", "show"],
            ["floor", "check", "--release-dir", release, "--approval-state-root", state],
            ["floor", "check", "--release-dir", release, "--approval-state-root", "/etc/aukora-approvals/" + "1" * 64 + "/state"],
            ["floor", "migrate-clock-floor", "--release-dir", release, "--approval-state-root", state,
             "--floor", "/etc/aukora-approvals/release-floor.json"],
            ["approval", "show", "--release-dir", release, "--operation", "1" * 64],
            ["approval", "raise", "--release-dir", release, "--run", "/run/aukora-gate"],
            ["approval", "install", "--release-dir", release, "--out", state + "/gate-state", "--repin",
             "--target-root", "/var/lib/aukora-boundary/targets"],
            ["approval", "migrate-clock-floor", "--release-dir", release, "--out", state + "/gate-state"],
            ["approval", "recover-cache", "--release-dir", release, "--out", state + "/gate-state"],
        ]
        for arguments in valid:
            with self.subTest(arguments=arguments):
                entry, node_arguments = SOURCE["launch_arguments"](arguments)
                self.assertEqual(entry, SOURCE["OPERATOR_ENTRIES"][arguments[0]])
                self.assertEqual(node_arguments, arguments[1:])
                for tail in (["--unsafe-preview"], ["--eval", "evil"], ["--entry", "/tmp/evil.mjs"],
                             ["--config", "/tmp/config"], ["--"], ["extra"]):
                    with self.refuses("launch-"):
                        SOURCE["launch_arguments"](arguments + tail)
        invalid = [["floor"], ["floor", "install"], ["approval", "check"], ["approval", "install", "--release-dir", release],
                   ["approval", "migrate-clock-floor", "--release-dir", release], ["approval", "recover-cache", "--release-dir", release],
                   ["floor", "show", "--release-dir", release], ["approval", "raise", "--release-dir", release, "--repin"],
                   ["floor", "check", "--release-dir", "/tmp/candidate", "--approval-state-root", state],
                   ["floor", "check", "--release-dir", release, "--approval-state-root", state + "/../state"],
                   ["floor", "check", "--release-dir", release, "--approval-state-root", "/etc/aukora-approvals/" + "1" * 41 + "/state"],
                   ["approval", "show", "--release-dir", release, "--operation", "f" * 16],
                   ["approval", "install", "--release-dir", release, "--out", "/tmp/out"],
                   ["floor", "show", "--floor", "/tmp/floor"],
                   ["floor", "show", "--floor", "/etc/aukora-approvals/release-floor.json", "--floor", "/etc/aukora-approvals/release-floor.json"]]
        for arguments in invalid:
            with self.subTest(arguments=arguments), self.refuses("launch-"):
                SOURCE["launch_arguments"](arguments)

    def test_main_exec_recorder_receives_fixed_node_entry_clean_environment(self):
        class Executed(Exception):
            pass
        calls = []
        def dispatch(path, arguments, environment):
            calls.append((path, arguments, environment))
            raise Executed()
        arguments = ["serve", "--home", "/home/aukora-gate", "--run", "/run/aukora-gate", "--target-root",
                     "/var/lib/aukora-boundary/targets", "--gid", "123"]
        with patch.dict(G, {"verify_installation": self.world.check}), patch.object(sys, "argv", ["fixture"] + arguments), \
                patch.dict(os.environ, {"NODE_OPTIONS": "--import=evil", "NODE_PATH": "/tmp"}, clear=True), \
                patch.object(os, "chdir") as chdir, patch.object(os, "execve", dispatch):
            with self.assertRaises(Executed):
                SOURCE["main"]()
            self.assertEqual(calls[0][0], SOURCE["NODE"])
            self.assertEqual(calls[0][1], [SOURCE["NODE"], SOURCE["PACKAGE"] + "/" + SOURCE["ENTRY"]] + arguments)
            self.assertNotIn("NODE_OPTIONS", calls[0][2])
            self.assertNotIn("NODE_PATH", calls[0][2])
            chdir.assert_called_once_with("/")
            calls.clear()
            self.world.put("bin/gate.mjs", "unapproved changed bytes\n")
            with patch.object(sys, "stderr"):
                self.assertEqual(SOURCE["main"](), 2)
            self.assertEqual(calls, [])

    def test_main_operator_role_exec_recorders_use_only_fixed_bins(self):
        class Executed(Exception):
            pass
        release = "/opt/aukora-genesis/release-abcdef0"
        state = "/etc/aukora-approvals/" + "0" * 40 + "/state"
        for arguments in (["floor", "check", "--release-dir", release, "--approval-state-root", state],
                          ["approval", "show", "--release-dir", release]):
            calls = []
            def dispatch(path, argv, environment):
                calls.append((path, argv, environment))
                raise Executed()
            with patch.dict(G, {"verify_installation": self.world.check}), patch.object(sys, "argv", ["fixture"] + arguments), \
                    patch.dict(os.environ, {"NODE_OPTIONS": "--import=evil"}, clear=True), \
                    patch.object(os, "chdir"), patch.object(os, "execve", dispatch):
                with self.assertRaises(Executed):
                    SOURCE["main"]()
            self.assertEqual(calls[0][0], SOURCE["NODE"])
            self.assertEqual(calls[0][1], [SOURCE["NODE"], SOURCE["PACKAGE"] + "/" + SOURCE["OPERATOR_ENTRIES"][arguments[0]]] + arguments[1:])
            self.assertNotIn("NODE_OPTIONS", calls[0][2])

    def test_check_package_success_and_hash_refusal_never_dispatch(self):
        self.assertEqual(SOURCE["launch_arguments"](["check-package"]), (None, []))
        for tail in (["--entry", "/tmp/evil.mjs"], ["--uid", "0"], ["--"], ["serve"], ["--unsafe-preview"]):
            with self.refuses("launch-option"):
                SOURCE["launch_arguments"](["check-package"] + tail)
        with patch.dict(G, {"verify_installation": self.world.check}), patch.object(sys, "argv", ["fixture", "check-package"]), \
                patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                patch.object(os, "chdir") as chdir, patch.object(sys, "stdout", new_callable=io.StringIO) as output:
            self.assertEqual(SOURCE["main"](), 0)
            self.assertEqual(output.getvalue(), "PACKAGE_VERIFIED\n")
            dispatch.assert_not_called()
            chdir.assert_not_called()
            self.assertFalse(self.world.marker.exists())
            self.world.put("bin/gate.mjs", "from pathlib import Path\nPath(" + repr(str(self.world.marker)) + ").write_text('unapproved')\n")
            output.seek(0)
            output.truncate()
            with patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                self.assertEqual(SOURCE["main"](), 2)
                self.assertIn("package-hash:bin/gate.mjs", refusal.getvalue())
            self.assertEqual(output.getvalue(), "")
            dispatch.assert_not_called()
            chdir.assert_not_called()
            self.assertFalse(self.world.marker.exists())

    def test_external_hashes_and_missing_files_refuse(self):
        epoch_path = self.world.root.parent / "epochs.json"
        epoch_path.write_text(json.dumps({"version": 1, "kind": "aukora-signer-epochs/v1",
                                         "epochs": [{"epoch": 1, "gate_pubkey_sha256": "0" * 64}]}))
        fixed_to_fixture = {SOURCE["SIGNER_EPOCHS"]: epoch_path}
        pins = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in fixed_to_fixture.items()}
        def fixture_read(path, limit):
            return SOURCE["protected_read"](str(fixed_to_fixture[path]), limit)
        with patch.dict(G, {"protected_read": fixture_read, "protected_metadata": self.world.fixture_metadata}):
            SOURCE["verify_external_files"](pins)
            for path in fixed_to_fixture.values():
                original = path.read_bytes()
                path.write_text("changed\n")
                with self.refuses("external-hash"):
                    SOURCE["verify_external_files"](pins)
                path.write_bytes(original)
            epoch_path.unlink()
            with self.assertRaises(FileNotFoundError):
                SOURCE["verify_external_files"](pins)

    def test_staging_generator_is_deterministic_external_and_never_installs(self):
        epochs = self.world.root.parent / "epochs.json"
        epochs.write_text(json.dumps({"version": 1, "kind": "aukora-signer-epochs/v1",
                                      "epochs": [{"epoch": 1, "gate_pubkey_sha256": "0" * 64}]}))
        outputs = [self.world.root.parent / "manifest1.json", self.world.root.parent / "manifest2.json"]
        base = [sys.executable, "-I", "-S", str(HERE / "generate-manifest.py"), "--package", str(self.world.root),
                "--signer-epochs", str(epochs), "--output"]
        for output in outputs:
            result = subprocess.run(base + [str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
        result = subprocess.run(base + [str(self.world.root / "manifest.json")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("manifest-inside-package", result.stderr)
        self.assertFalse(self.world.marker.exists())

    def test_checkout_bootstrap_has_no_production_override(self):
        arguments = ["serve", "--home", "/home/aukora-gate", "--run", "/run/aukora-gate", "--target-root",
                     "/var/lib/aukora-boundary/targets", "--gid", "123"]
        result = subprocess.run([sys.executable, "-I", "-S", str(HERE / "gate-bootstrap.py")] + arguments,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("bootstrap-entrypoint", result.stderr)

    def test_single_guard_mutants_fail_their_specific_regressions(self):
        source = (HERE / "gate-bootstrap.py").read_text()
        guards = {
            "hash": 'require(hashlib.sha256(data).hexdigest() == files[name], "package-hash:" + name)',
            "inventory": 'require(set(package_inventory(root)) == set(files), "package-inventory")',
            "preview": 'require("unsafepreview" not in normalized, "unsafe-preview-environment")',
        }
        killed = 0
        for name, guard in guards.items():
            with self.subTest(guard=name):
                self.assertEqual(source.count(guard), 1, "mutation must change exactly its named guard")
                mutant = {"__name__": "source_mutant", "__file__": str(HERE / "gate-bootstrap.py")}
                replacement = 'require(True, "disabled-source-fixture-guard")'
                exec(compile(source.replace(guard, replacement), "<single-guard-source-mutant>", "exec"), mutant)
                if name == "preview":
                    def regression(namespace):
                        with self.assertRaises(namespace["Refused"]):
                            namespace["node_environment"]({"AUKORA_UNSAFE_PREVIEW": "false"})
                    regression(SOURCE)
                    with self.assertRaises(AssertionError):
                        regression(mutant)
                else:
                    world = World()
                    try:
                        trap = "from pathlib import Path\nPath(" + repr(str(world.marker)) + ").write_text('unapproved')\n"
                        if name == "hash":
                            dispatch_path = world.put("bin/gate.mjs", trap)
                        else:
                            dispatch_path = world.put("src/unchecked.mjs", trap)
                        original_metadata = mutant["protected_metadata"]
                        def fixture_metadata(metadata, directory=False):
                            injected = root_metadata(metadata)
                            if directory and (metadata.st_dev, metadata.st_ino) in world.ancestors:
                                injected.st_mode &= ~0o022
                            original_metadata(injected, directory)
                        mutant["protected_metadata"] = fixture_metadata
                        def regression(namespace):
                            with self.assertRaises(namespace["Refused"]):
                                namespace["verify_package"](str(world.root), world.files)
                                subprocess.run([sys.executable, "-I", "-S", str(dispatch_path)], check=True)
                        with patch.dict(G, {"protected_metadata": world.fixture_metadata}):
                            regression(SOURCE)
                        self.assertFalse(world.marker.exists(), "original guard must stop actual trap dispatch")
                        with self.assertRaises(AssertionError):
                            regression(mutant)
                        self.assertEqual(world.marker.read_text(), "unapproved", "mutant must fail at the relevant nonexecution guard")
                    finally:
                        world.close()
                killed += 1
        self.assertEqual(killed, 3)
        print("SOURCE-ONLY single-guard mutations: 3/3 killed by their specific regressions", flush=True)


if __name__ == "__main__":
    print("SOURCE-ONLY: actual tiny files and marker execution; synthetic root metadata; no installed-host qualification.", flush=True)
    unittest.main(verbosity=2)
