#!/usr/bin/python3
"""SOURCE-ONLY bootstrap regression; synthetic root metadata, no installation."""

import hashlib
from contextlib import contextmanager
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
        self.owner_root = self.root.parent / "owner-key"
        self.owner_root.mkdir(mode=0o700)
        for name in SOURCE["OWNER_KEY_FILES"]:
            self.put(name, "// disposable owner-key source fixture\n", root=self.owner_root)
        self.owner_files = {str(path.relative_to(self.owner_root)): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in self.owner_root.rglob("*") if path.is_file()}
        self.owner_pins = {name: self.owner_files[name] for name in SOURCE["OWNER_KEY_SOURCE_PINS"]}
        self.launcher_root = self.root.parent / "launcher-checkout"
        self.launcher_root.mkdir(mode=0o700)
        for name in SOURCE["LAUNCHER_SOURCE_PINS"]:
            self.put(name, "# disposable named launcher-input fixture\n", root=self.launcher_root)
        self.launcher_files = {name: hashlib.sha256((self.launcher_root / name).read_bytes()).hexdigest()
                               for name in SOURCE["LAUNCHER_SOURCE_PINS"]}
        self.aura_root = self.root.parent / "aura-source"
        self.aura_root.mkdir(mode=0o700)
        for name in SOURCE["AURA_SOURCE_PINS"]:
            self.put(name, "// disposable exact-layout source fixture\n", root=self.aura_root)
        self.put(SOURCE["AURA_ENTRY"], "from pathlib import Path\nPath(" + repr(str(self.marker)) + ").write_text('aura-executed')\n", root=self.aura_root)
        self.aura_files = {str(path.relative_to(self.aura_root)): hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in self.aura_root.rglob("*") if path.is_file()}
        self.store = self.root.parent / "private-store"
        self.store.mkdir(mode=0o700)
        self.db = self.put("source.db", "disposable metadata-only database fixture\n", root=self.root.parent)
        self.secret = self.put("scoped-synthetic.hex", "0" * 64, root=self.root.parent)
        self.configuration = self.root.parent / "public-context.json"
        self.configuration.write_bytes(json.dumps(self.aura_configuration()).encode())
        self.configuration.chmod(0o600)
        self.ancestors = set()
        for path in self.root.parents:
            metadata = path.stat()
            self.ancestors.add((metadata.st_dev, metadata.st_ino))

    def put(self, name, data, root=None):
        path = (self.root if root is None else root) / name
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

    def fixture_data_directory(self, metadata):
        injected = root_metadata(metadata)
        if (metadata.st_dev, metadata.st_ino) in self.ancestors:
            injected.st_mode &= ~0o022
        SOURCE["aura_directory_metadata"](injected)

    def aura_configuration(self):
        subject, author = "aukora:1:" + "0" * 64, "1" * 64
        return {"version": 1, "kind": "aukora-aura-context/v1", "owner_subject": subject,
                "store_dir": str(self.store), "python_executable": SOURCE["PYTHON"],
                "source": {"db_path": str(self.db), "source_id": "synthetic-source",
                           "public_key_pem": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
                           "key_sha256": "4" * 64, "max_rows": 50000, "max_bytes": 16 * 1024 * 1024,
                           "max_record_bytes": 48 * 1024},
                "nostr": {"controller_key_hex": "2" * 64, "author_pubkey_hex": author,
                          "owner_pubkey_hex": "3" * 64, "author_secret_path": str(self.secret),
                          "binding": {"domain": "aukora:nostr-identity-binding:v1", "signature": "0" * 128,
                                      "statement": {"createdAt": "2026-10-04T00:00:00Z", "handle": "synthetic",
                                                    "nostrPubkeyHex": author, "npub": "npub1synthetic", "subject": subject,
                                                    "safetyVersion": 2}, "public_metadata": {"test": True}}},
                "anchors": [{"seq": 1, "head": "5" * 64, "gate_fp": "4" * 16,
                             "entry_at": "2026-10-04T00:00:00Z", "anchored_at": "2026-10-04T00:00:01Z"}]}

    def check(self):
        with patch.dict(G, {"protected_metadata": self.fixture_metadata}):
            SOURCE["verify_package"](str(self.root), self.files)

    def owner_profile(self):
        return {"root": SOURCE["OWNER_KEY_ROOT"], "files": dict(self.owner_files)}

    def launcher_profile(self):
        return {"root": SOURCE["LAUNCHER_ROOT"], "files": dict(self.launcher_files)}

    def installation(self):
        # Only the main() recorder's disposable fixture. Real installation
        # ordering and protected owner-key reads are exercised separately below.
        self.check()
        with patch.dict(G, {"OWNER_KEY_SOURCE_PINS": self.owner_pins,
                            "LAUNCHER_SOURCE_PINS": self.launcher_files,
                            "protected_metadata": self.fixture_metadata}):
            SOURCE["validate_launcher_profile"](self.launcher_profile())
            for name, digest in self.launcher_files.items():
                SOURCE["require"](hashlib.sha256(SOURCE["protected_read"](str(self.launcher_root / name))).hexdigest()
                                  == digest, "launcher-hash:" + name)
            SOURCE["validate_owner_key_profile"](self.owner_profile())
            SOURCE["verify_package"](str(self.owner_root), self.owner_files)
        return {"version": 2, "profiles": {"launcher": self.launcher_profile(), "owner_key": self.owner_profile()}}

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

    def test_nonregular_metadata_refuses_type_before_linux_symlink_mode(self):
        # Linux lstat symlinks have 0777 permissions even under umask022.
        # Their refusal must remain type-specific without dropping any guard.
        for mode in (0o777, 0o755, 0o600):
            for directory in (False, True):
                for uid in (0, 1000):
                    metadata = root_metadata(self.world.root.stat())
                    metadata.st_mode = stat.S_IFLNK | mode
                    metadata.st_uid = uid
                    with self.subTest(mode=mode, directory=directory, uid=uid), self.refuses("protected-type"):
                        SOURCE["protected_metadata"](metadata, directory)
        for uid, mode, links, code in ((1000, 0o600, 1, "protected-owner"),
                                      (0, 0o620, 1, "protected-mode"), (0, 0o600, 2, "protected-hardlink")):
            metadata = root_metadata(self.world.root.stat())
            metadata.st_mode, metadata.st_uid, metadata.st_nlink = stat.S_IFREG | mode, uid, links
            with self.subTest(code=code), self.refuses(code):
                SOURCE["protected_metadata"](metadata)

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

    def test_journal_id_is_optional_exact_and_only_available_to_serve(self):
        base = ["serve", "--home", "/home/aukora-gate", "--run", "/run/aukora-gate", "--target-root",
                "/var/lib/aukora-boundary/targets", "--gid", "123"]
        self.assertEqual(SOURCE["launch_arguments"](base), (SOURCE["ENTRY"], base))
        for selected in (base + ["--journal-id", "aukora-gate-pilot"],
                         ["serve", "--journal-id", "aukora-gate-pilot"] + base[1:]):
            self.assertEqual(SOURCE["launch_arguments"](selected), (SOURCE["ENTRY"], selected))
        for value in ("", "other-journal", "AUKORA-GATE-PILOT", "aukora-gate-pilot ",
                      " aukora-gate-pilot", "aukora-gate-pilot\n", "/tmp/aukora-gate-pilot", "--owner-page"):
            with self.subTest(value=value), self.refuses("launch-journal-id"):
                SOURCE["launch_arguments"](base + ["--journal-id", value])
        with self.refuses("launch-value"):
            SOURCE["launch_arguments"](base + ["--journal-id"])
        for value in ("aukora-gate-pilot", "different"):
            with self.refuses("launch-duplicate"):
                SOURCE["launch_arguments"](base + ["--journal-id", "aukora-gate-pilot", "--journal-id", value])
        for option in ("--journal", "--journal-id=aukora-gate-pilot", "--journalId"):
            with self.refuses("launch-option"):
                SOURCE["launch_arguments"](base + [option, "aukora-gate-pilot"])
        for role in (["floor", "show"], ["approval", "show", "--release-dir", "/opt/aukora-genesis/release-abcdef0"],
                     ["aura", "collect"], ["aura", "verify"], ["check-package"], ["check-runtime"], ["check-runtime-aura"]):
            with self.subTest(role=role), self.refuses("launch-option"):
                SOURCE["launch_arguments"](role + ["--journal-id", "aukora-gate-pilot"])
        with patch.dict(G, {"verify_installation": lambda: self.fail("wrong journal must refuse before metadata access")}), \
                patch.object(sys, "argv", ["fixture"] + base + ["--journal-id", "wrong"]), \
                patch.object(os, "execve") as dispatch, patch.object(os, "chdir") as chdir, \
                patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
            self.assertEqual(SOURCE["main"](), 2)
            self.assertIn("launch-journal-id", refusal.getvalue())
            dispatch.assert_not_called()
            chdir.assert_not_called()

    def test_journal_literal_guard_mutant_reaches_the_disposable_dispatch_witness(self):
        source = (HERE / "gate-bootstrap.py").read_text()
        guard = 'require(value == "aukora-gate-pilot", "launch-journal-id")'
        self.assertEqual(source.count(guard), 1)
        mutant = {"__name__": "journal_literal_mutant", "__file__": str(HERE / "gate-bootstrap.py")}
        exec(compile(source.replace(guard, 'require(True, "disabled-journal-literal-fixture-guard")'),
                     "<journal-literal-single-guard-mutant>", "exec"), mutant)
        arguments = ["serve", "--home", "/home/aukora-gate", "--run", "/run/aukora-gate", "--target-root",
                     "/var/lib/aukora-boundary/targets", "--gid", "123", "--journal-id", "unapproved-journal"]
        calls = []
        def dispatch(path, argv, _environment):
            self.assertEqual((path, argv), (SOURCE["NODE"], [SOURCE["NODE"], SOURCE["PACKAGE"] + "/" + SOURCE["ENTRY"]] + arguments))
            calls.append(True)
            subprocess.run([sys.executable, "-I", "-S", str(self.world.root / "bin/gate.mjs")], check=True)
        def regression(namespace):
            with patch.dict(namespace["main"].__globals__, {"verify_installation": self.world.installation}), \
                    patch.object(sys, "argv", ["fixture"] + arguments), patch.dict(os.environ, {}, clear=True), \
                    patch.object(os, "execve", dispatch), patch.object(os, "chdir"), \
                    patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                self.assertEqual(namespace["main"](), 2)
                self.assertIn("launch-journal-id", refusal.getvalue())
                self.assertEqual(calls, [])
                self.assertFalse(self.world.marker.exists())
        regression(SOURCE)
        with self.assertRaises(AssertionError):
            regression(mutant)
        self.assertEqual(calls, [True])
        self.assertEqual(self.world.marker.read_text(), "executed")
        print("SOURCE-ONLY journal literal mutation: 1/1 killed; wrong-journal mutant reaches the actual disposable dispatch witness", flush=True)

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
        with self.refuses("aura-configuration-format"):
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
        with patch.dict(G, {"verify_installation": self.world.installation}), patch.object(sys, "argv", ["fixture"] + arguments), \
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
            with patch.dict(G, {"verify_installation": self.world.installation}), patch.object(sys, "argv", ["fixture"] + arguments), \
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
        with patch.dict(G, {"verify_installation": self.world.installation}), patch.object(sys, "argv", ["fixture", "check-package"]), \
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

    def v2_manifest(self):
        value = self.manifest()
        value.update(version=2, kind="aukora-gate-package/v2",
                     profiles={"launcher": self.world.launcher_profile(), "owner_key": self.world.owner_profile()})
        return value

    def aura_profile(self):
        return {"root": SOURCE["AURA_ROOT"], "entry": SOURCE["AURA_ENTRY"],
                "files": dict(SOURCE["AURA_SOURCE_PINS"]),
                "configuration": {"path": SOURCE["AURA_CONFIG"], "sha256": "0" * 64}}

    def full_aura_manifest(self):
        value = self.v2_manifest()
        value["profiles"]["aura"] = {"root": SOURCE["AURA_ROOT"], "entry": SOURCE["AURA_ENTRY"],
            "files": dict(self.world.aura_files), "configuration": {"path": SOURCE["AURA_CONFIG"],
            "sha256": hashlib.sha256(self.world.configuration.read_bytes()).hexdigest()}}
        epochs = json.dumps({"version": 1, "kind": "aukora-signer-epochs/v1",
                             "epochs": [{"epoch": 1, "gate_pubkey_sha256": "0" * 64}]}).encode()
        value["external_files"][SOURCE["SIGNER_EPOCHS"]] = hashlib.sha256(epochs).hexdigest()
        return value, epochs

    @contextmanager
    def protected_aura_world(self, manifest, epochs, namespace=SOURCE):
        # All root/pin substitution is confined to these disposable tests.
        namespace_globals = namespace["main"].__globals__
        original_read, original_open = namespace["protected_read"], namespace["protected_open"]
        original_ancestors, original_verify = namespace["protected_ancestors"], namespace["verify_package"]
        read_os = os.read
        secret_identity = (self.world.secret.stat().st_dev, self.world.secret.stat().st_ino)
        phases = []
        def fixture_read(path, limit=SOURCE["MAX_FILE"]):
            if path == SOURCE["BOOTSTRAP"]:
                return b"reviewed fixture launcher"
            if path == SOURCE["MANIFEST"]:
                return json.dumps(manifest).encode()
            if path == SOURCE["SIGNER_EPOCHS"]:
                return epochs
            if path.startswith(SOURCE["LAUNCHER_ROOT"] + "/"):
                name = path[len(SOURCE["LAUNCHER_ROOT"]) + 1:]
                phases.append("launcher:" + name)
                return original_read(str(self.world.launcher_root / name), limit)
            return original_read(str(self.world.configuration) if path == SOURCE["AURA_CONFIG"] else path, limit)
        def fixture_open(path):
            return original_open(str(self.world.root / "src/helper.mjs") if path == SOURCE["NODE"] else path)
        def fixture_ancestors(path):
            if path != SOURCE["PYTHON"]:
                original_ancestors(path)
        def fixture_verify(root, files):
            roots = {SOURCE["PACKAGE"]: ("gate", self.world.root), SOURCE["OWNER_KEY_ROOT"]: ("owner_key", self.world.owner_root),
                     SOURCE["AURA_ROOT"]: ("aura", self.world.aura_root)}
            label, staged = roots[root]
            phases.append(label)
            return original_verify(str(staged), files)
        def metadata_only_read(fd, count):
            metadata = os.fstat(fd)
            self.assertNotEqual((metadata.st_dev, metadata.st_ino), secret_identity, "pre-Node must not read private signer bytes")
            return read_os(fd, count)
        with patch.dict(namespace_globals, {"__file__": SOURCE["BOOTSTRAP"], "OWNER_KEY_SOURCE_PINS": self.world.owner_pins,
                "LAUNCHER_SOURCE_PINS": self.world.launcher_files,
                "AURA_SOURCE_PINS": self.world.aura_files, "protected_metadata": self.world.fixture_metadata,
                "aura_directory_metadata": self.world.fixture_data_directory, "protected_read": fixture_read,
                "protected_open": fixture_open, "protected_ancestors": fixture_ancestors, "verify_package": fixture_verify}), \
                patch.object(os, "read", metadata_only_read):
            yield phases

    def assert_aura_refuses_before_dispatch(self, manifest, epochs, code, namespace=SOURCE):
        for action in ("collect", "verify"):
            with self.protected_aura_world(manifest, epochs, namespace), patch.object(sys, "argv", ["fixture", "aura", action]), \
                    patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                    patch.object(os, "chdir") as chdir, patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                self.assertEqual(namespace["main"](), 2)
                self.assertRegex(refusal.getvalue(), code)
                dispatch.assert_not_called()
                chdir.assert_not_called()
                self.assertFalse(self.world.marker.exists())

    def test_aura_complete_profile_dispatches_fixed_actions_after_all_three_roots(self):
        class Executed(Exception):
            pass
        manifest, epochs = self.full_aura_manifest()
        for action in ("collect", "verify"):
            calls = []
            def dispatch(path, argv, environment):
                calls.append((path, argv, environment))
                subprocess.run([sys.executable, "-I", "-S", str(self.world.aura_root / SOURCE["AURA_ENTRY"])], check=True)
                raise Executed()
            with self.protected_aura_world(manifest, epochs) as phases, patch.object(sys, "argv", ["fixture", "aura", action]), \
                    patch.dict(os.environ, {"NODE_OPTIONS": "--import=evil", "NODE_PATH": "/tmp"}, clear=True), \
                    patch.object(os, "chdir") as chdir, patch.object(os, "execve", dispatch):
                with self.assertRaises(Executed):
                    SOURCE["main"]()
                self.assertEqual(phases, ["gate"] + ["launcher:" + name for name in sorted(self.world.launcher_files)]
                                 + ["owner_key", "aura"])
                self.assertEqual(calls[0][0], SOURCE["NODE"])
                self.assertEqual(calls[0][1], [SOURCE["NODE"], SOURCE["AURA_ROOT"] + "/" + SOURCE["AURA_ENTRY"], action])
                self.assertEqual(set(calls[0][2]), {"PATH", "HOME", "LANG", "LC_ALL"})
                chdir.assert_called_once_with("/")
            self.assertEqual(self.world.marker.read_text(), "aura-executed")
            self.world.marker.unlink()

    def test_aura_source_metadata_licenses_helpers_and_configuration_refuse_before_dispatch(self):
        manifest, epochs = self.full_aura_manifest()
        missing_owner = json.loads(json.dumps(manifest))
        missing_owner["profiles"].pop("owner_key")
        self.assert_aura_refuses_before_dispatch(missing_owner, epochs, "aura-owner-key-profile")
        for name in (SOURCE["AURA_ENTRY"], "packages/boundary-gate/host/aura/context.mjs",
                     "packages/boundary-gate/host/aura/records-provider.mjs", "scripts/aura/collect-gate.mjs",
                     "scripts/aura/verify-collected.mjs", "plugins/aukora-nostr/lib/records.mjs",
                     "plugins/aukora-nostr/lib/vendor/noble-curves/curves/abstract/montgomery.js", "package.json",
                     "packages/boundary-gate/package.json", "packages/contracts/package.json", "plugins/aukora-nostr/package.json",
                     "LICENSE", "plugins/aukora-nostr/lib/vendor/noble-ciphers/licenses/noble-ciphers.LICENSE",
                     "plugins/aukora-nostr/lib/vendor/noble-curves/upstream-noble-curves.json"):
            path = self.world.aura_root / name
            original = path.read_bytes()
            path.write_text("unreviewed source bytes\n")
            self.assert_aura_refuses_before_dispatch(manifest, epochs, "package-hash")
            path.write_bytes(original)
        extra = self.world.put("scripts/aura/candidate.mjs", "unreviewed source\n", root=self.world.aura_root)
        self.assert_aura_refuses_before_dispatch(manifest, epochs, "package-inventory")
        extra.unlink()
        removed = self.world.aura_root / "LICENSE"
        original = removed.read_bytes()
        removed.unlink()
        self.assert_aura_refuses_before_dispatch(manifest, epochs, "package-inventory")
        removed.write_bytes(original)
        original = self.world.configuration.read_bytes()
        value = self.world.aura_configuration()
        value["source"]["source_id"] = "different-but-syntactically-valid"
        self.world.configuration.write_bytes(json.dumps(value).encode())
        self.assert_aura_refuses_before_dispatch(manifest, epochs, "aura-configuration-hash")
        self.world.configuration.write_bytes(original)
        self.world.put("src/helper.mjs", "unreviewed gate bytes\n")
        self.assert_aura_refuses_before_dispatch(manifest, epochs, "package-hash")

    def test_aura_configuration_is_closed_bounded_public_data_with_no_candidate_paths(self):
        def validate(value):
            return SOURCE["validate_aura_context"](json.dumps(value).encode())
        validate(self.world.aura_configuration())
        legacy = self.world.aura_configuration()
        legacy["nostr"]["binding"]["statement"].pop("safetyVersion")
        legacy["nostr"]["binding"]["unsigned_extra"] = {"public": [None, 1, True]}
        legacy["anchors"] = []
        validate(legacy)
        for mutate in (
            lambda c: c.update(version=True), lambda c: c.update(extra=True), lambda c: c.update(owner_subject="guest"),
            lambda c: c.update(python_executable="python3"), lambda c: c.update(python_executable="/tmp/python3"),
            lambda c: c.update(store_dir=c["source"]["db_path"]),
            lambda c: c["source"].update(max_rows=True), lambda c: c["source"].update(max_rows=50001),
            lambda c: c["source"].update(max_bytes=16777217), lambda c: c["source"].update(max_record_bytes=49153),
            lambda c: c["source"].update(key_sha256="4" * 16), lambda c: c["source"].update(source_id="/private/source"),
            lambda c: c["source"].update(public_key_pem="-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
            lambda c: c["source"].update(db_path=SOURCE["AURA_ROOT"] + "/package.json"),
            lambda c: c["source"].update(db_path=SOURCE["AURA_CONFIG"]),
            lambda c: c["source"].update(db_path=str(self.world.store / "source.db")),
            lambda c: c["nostr"].update(author_secret_key_hex="0" * 64),
            lambda c: c["nostr"].update(author_secret_path=c["source"]["db_path"] + "-wal"),
            lambda c: c["nostr"].update(owner_pubkey_hex="3" * 16),
            lambda c: c["nostr"]["binding"]["statement"].update(extra=True),
            lambda c: c["nostr"]["binding"]["statement"].update(safetyVersion=True),
            lambda c: c["nostr"]["binding"]["statement"].update(safetyVersion=9007199254740992),
            lambda c: c["nostr"]["binding"]["statement"].update(createdAt="2026-10-04T00:00:00.000Z"),
            lambda c: c["nostr"]["binding"]["statement"].update(subject="aukora:1:" + "f" * 64),
            lambda c: c["nostr"]["binding"].update(signature="0" * 126),
            lambda c: c["nostr"]["binding"].update(unsigned_extra="hidden\u202evalue"),
            lambda c: c["nostr"]["binding"].update(unsigned_extra=float("inf")),
            lambda c: c["anchors"][0].update(seq=True), lambda c: c["anchors"][0].update(seq=9007199254740992),
            lambda c: c["anchors"][0].update(gate_fp="0" * 16), lambda c: c["anchors"].append(dict(c["anchors"][0])),
            lambda c: c["anchors"][0].update(entry_at=""), lambda c: c["anchors"][0].update(anchored_at="a" * 129),
            lambda c: c.update(unsafePreview=False),
        ):
            value = self.world.aura_configuration()
            mutate(value)
            with self.refuses("(aura-|json-number|unsafe-preview)"):
                validate(value)
        for path in ("//tmp/source", "/tmp/a/../source", "/tmp/source/", "/tmp/a//source", "/tmp/\ud800"):
            value = self.world.aura_configuration()
            value["source"]["db_path"] = path
            with self.refuses("aura-source-format"):
                validate(value)
        with self.refuses("json-duplicate-key"):
            SOURCE["validate_aura_context"](b'{"version":1,"version":1}')
        with self.refuses("json-format"):
            SOURCE["validate_aura_context"](b'\xff')
        with self.refuses("aura-configuration-size"):
            SOURCE["validate_aura_context"](b" " * (SOURCE["AURA_MAX_CONFIG"] + 1))

    def test_aura_custody_checks_secret_metadata_without_reading_bytes(self):
        manifest, epochs = self.full_aura_manifest()
        for path, mode, code in ((self.world.secret, 0o640, "aura-secret-metadata"),
                                 (self.world.configuration, 0o620, "protected-mode"),
                                 (self.world.store, 0o710, "aura-data-mode"), (self.world.db, 0o620, "aura-data-mode")):
            previous = path.stat().st_mode
            path.chmod(mode)
            self.assert_aura_refuses_before_dispatch(manifest, epochs, code)
            path.chmod(previous)
        original = b"0" * 64  # Known toy fixture; no private bytes are read even here.
        self.world.secret.write_text("0" * 63)
        self.assert_aura_refuses_before_dispatch(manifest, epochs, "aura-secret-metadata")
        self.world.secret.write_bytes(original)
        for path, code in ((self.world.secret, "protected-type"), (self.world.store, "aura-data-type"), (self.world.db, "aura-data-type")):
            backup = path.with_name(path.name + ".fixture-backup")
            path.rename(backup)
            path.symlink_to(backup, target_is_directory=backup.is_dir())
            self.assert_aura_refuses_before_dispatch(manifest, epochs, code)
            path.unlink()
            backup.rename(path)
        hardlink = self.world.root.parent / "extra-secret-link"
        os.link(self.world.secret, hardlink)
        self.assert_aura_refuses_before_dispatch(manifest, epochs, "protected-hardlink")
        hardlink.unlink()
        with patch.object(os, "getuid", return_value=self.world.store.stat().st_uid + 1):
            self.assert_aura_refuses_before_dispatch(manifest, epochs, "aura-data-owner-or-link")

    def test_v2_profiles_are_closed_fixed_paths_and_independently_pinned(self):
        def parse(value):
            with patch.dict(G, {"OWNER_KEY_SOURCE_PINS": self.world.owner_pins,
                                "LAUNCHER_SOURCE_PINS": self.world.launcher_files}):
                return SOURCE["parse_manifest"](json.dumps(value).encode())
        parse(self.v2_manifest())
        for mutate in (
            lambda m: m.update(kind="aukora-gate-package/v1"),
            lambda m: m.update(extra=True),
            lambda m: m["profiles"].update(candidate={"root": "/tmp"}),
            lambda m: m["profiles"]["owner_key"].update(entry="src/index.mjs"),
            lambda m: m["profiles"]["owner_key"].update(root="/opt/owner-key/../owner-key"),
            lambda m: m["profiles"]["owner_key"]["files"].pop("package.json"),
            lambda m: m["profiles"]["owner_key"]["files"].pop("checks/gate-caller.test.mjs"),
            lambda m: m["profiles"]["owner_key"]["files"].update({"src/candidate.mjs": "0" * 64}),
            lambda m: m["profiles"]["owner_key"]["files"].update({"src/index.mjs": "0" * 64}),
        ):
            value = self.v2_manifest()
            mutate(value)
            with self.refuses("(manifest|owner-key)-"):
                parse(value)
        # Production pins cannot be replaced by a staging directory's own hashes.
        with patch.dict(G, {"LAUNCHER_SOURCE_PINS": self.world.launcher_files}), self.refuses("owner-key-source-pin"):
            SOURCE["parse_manifest"](json.dumps(self.v2_manifest()).encode())
        # An old ten-file/G0e5 profile cannot select the superseded source.
        selected = self.v2_manifest()
        selected["profiles"]["launcher"]["files"] = dict(SOURCE["LAUNCHER_SOURCE_PINS"])
        selected["profiles"]["owner_key"]["files"].update(SOURCE["OWNER_KEY_SOURCE_PINS"])
        SOURCE["parse_manifest"](json.dumps(selected).encode())
        selected["profiles"]["owner_key"]["files"]["src/authorization.mjs"] = "f2bf5219913436dd2a1d74cb448eb0e145dc7217d1b5ce0bd03043cc5313f47a"
        with self.refuses("owner-key-source-pin"):
            SOURCE["parse_manifest"](json.dumps(selected).encode())
        for name in ("../escape", "/absolute", "a//b", "a\\b", "a%2fb", "a?b", "a#b", "a:b", "a b", "a\n", "é.mjs"):
            value = self.v2_manifest()
            value["profiles"]["aura"] = self.aura_profile()
            value["profiles"]["aura"]["files"][name] = "0" * 64
            with self.refuses("(profile|manifest)-path"):
                parse(value)
        for mutate in (
            lambda p: p.update(root="/tmp/candidate"),
            lambda p: p.update(entry="scripts/aura/collect-gate.mjs"),
            lambda p: p.update(extra=True),
            lambda p: p["configuration"].update(path="/tmp/context.json"),
            lambda p: p["configuration"].update(author_secret_key="0" * 64),
            lambda p: p["files"].pop("package.json"),
        ):
            value = self.v2_manifest()
            value["profiles"]["aura"] = self.aura_profile()
            mutate(value["profiles"]["aura"])
            with self.refuses("aura-"):
                parse(value)

    def test_fixed_aura_actions_have_no_candidate_arguments(self):
        for action in ("collect", "verify"):
            self.assertEqual(SOURCE["launch_arguments"](["aura", action]),
                             (SOURCE["AURA_ROOT"] + "/" + SOURCE["AURA_ENTRY"], [action]))
            for tail in (["/tmp/context.mjs"], ["--context", SOURCE["AURA_CONFIG"]], ["--python", "/tmp/python"],
                         ["--uid", "0"], ["--import", "evil"], ["--unsafe-preview"], ["--"], [action]):
                with self.refuses("launch-option"):
                    SOURCE["launch_arguments"](["aura", action] + tail)
        for arguments in (["aura"], ["aura", "serve"], ["aura", "COLLECT"]):
            with self.refuses("launch-action"):
                SOURCE["launch_arguments"](arguments)

    def test_launcher_profile_is_mandatory_closed_and_independently_pinned(self):
        def parse(value):
            with patch.dict(G, {"OWNER_KEY_SOURCE_PINS": self.world.owner_pins,
                                "LAUNCHER_SOURCE_PINS": self.world.launcher_files}):
                return SOURCE["parse_manifest"](json.dumps(value).encode())
        for mutate, code in (
            (lambda m: m["profiles"].pop("launcher"), "launcher-profile-unconfigured"),
            (lambda m: m["profiles"]["launcher"].update(root="/tmp/candidate"), "launcher-profile"),
            (lambda m: m["profiles"]["launcher"].update(root=SOURCE["LAUNCHER_ROOT"] + "/"), "launcher-profile"),
            (lambda m: m["profiles"]["launcher"].update(extra=True), "launcher-profile"),
            (lambda m: m["profiles"]["launcher"]["files"].pop("upstream-dsh.json"), "launcher-inventory"),
            (lambda m: m["profiles"]["launcher"]["files"].update({"scripts/extra.mjs": "0" * 64}), "launcher-inventory"),
            (lambda m: m["profiles"]["launcher"]["files"].update({"scripts/launch-dsh.py": "0" * 64}), "launcher-source-pin"),
        ):
            value = self.v2_manifest()
            mutate(value)
            with self.subTest(code=code), self.refuses(code):
                parse(value)
        with patch.dict(G, {"OWNER_KEY_SOURCE_PINS": self.world.owner_pins}), self.refuses("launcher-source-pin"):
            SOURCE["parse_manifest"](json.dumps(self.v2_manifest()).encode())
        value = self.v2_manifest()
        value["profiles"]["launcher"]["files"] = dict(SOURCE["LAUNCHER_SOURCE_PINS"])
        value["profiles"]["owner_key"]["files"].update(SOURCE["OWNER_KEY_SOURCE_PINS"])
        SOURCE["parse_manifest"](json.dumps(value).encode())
        manifest, epochs = self.full_aura_manifest()
        manifest["profiles"].pop("launcher")
        for action in (["check-package"], ["aura", "collect"], ["floor", "show"]):
            with self.protected_aura_world(manifest, epochs), patch.object(sys, "argv", ["fixture"] + action), \
                    patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                    patch.object(sys, "stdout", new_callable=io.StringIO) as output, \
                    patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                self.assertEqual(SOURCE["main"](), 2)
                self.assertIn("launcher-profile-unconfigured", refusal.getvalue())
                self.assertEqual(output.getvalue(), "")
                dispatch.assert_not_called()

    def test_six_launcher_inputs_are_protected_before_dispatch_without_checkout_scan(self):
        manifest, epochs = self.full_aura_manifest()
        for name in self.world.launcher_files:
            path = self.world.launcher_root / name
            original = path.read_bytes()
            path.write_text("changed unapproved checkout input\n")
            self.assert_aura_refuses_before_dispatch(manifest, epochs, "launcher-hash")
            path.write_bytes(original)
        path = self.world.launcher_root / "scripts/genesis-check.mjs"
        original = path.read_bytes()
        for mode in (0o620, 0o602):
            path.chmod(mode)
            self.assert_aura_refuses_before_dispatch(manifest, epochs, "protected-mode")
        path.chmod(0o600)
        path.unlink()
        self.assert_aura_refuses_before_dispatch(manifest, epochs, "protected-io")
        path.symlink_to(self.world.root / "src/helper.mjs")
        self.assert_aura_refuses_before_dispatch(manifest, epochs, "protected-type")
        path.unlink()
        path.write_bytes(original)
        path.chmod(0o600)
        extra_link = self.world.launcher_root / "unallocated-link"
        os.link(path, extra_link)
        self.assert_aura_refuses_before_dispatch(manifest, epochs, "protected-hardlink")
        extra_link.unlink()
        library = self.world.launcher_root / "scripts/lib"
        library.chmod(0o720)
        self.assert_aura_refuses_before_dispatch(manifest, epochs, "protected-mode")
        library.chmod(0o700)
        outside = self.world.put("unallocated.txt", "out of named profile; do not read\n", root=self.world.launcher_root)
        read_os, scan_os = os.open, os.scandir
        def no_extra_read(candidate, *args, **kwargs):
            self.assertNotEqual(str(candidate), str(outside))
            return read_os(candidate, *args, **kwargs)
        def no_checkout_scan(candidate):
            self.assertFalse(str(candidate).startswith(str(self.world.launcher_root)))
            return scan_os(candidate)
        with self.protected_aura_world(manifest, epochs), patch.object(sys, "argv", ["fixture", "check-package"]), \
                patch.dict(os.environ, {}, clear=True), patch.object(os, "open", no_extra_read), \
                patch.object(os, "scandir", no_checkout_scan), patch.object(os, "execve") as dispatch, \
                patch.object(sys, "stdout", new_callable=io.StringIO) as output:
            self.assertEqual(SOURCE["main"](), 0)
            self.assertEqual(output.getvalue(), "PACKAGE_VERIFIED\n")
            dispatch.assert_not_called()
        value = self.world.aura_configuration()
        value["source"]["db_path"] = SOURCE["LAUNCHER_ROOT"] + "/scripts/launch-dsh.py"
        with self.refuses("aura-data-source-overlap"):
            SOURCE["validate_aura_context"](json.dumps(value).encode())

    def test_v1_custody_only_and_missing_profiles_never_reach_exec(self):
        gate = ["serve", "--home", "/home/aukora-gate", "--run", "/run/aukora-gate", "--target-root",
                "/var/lib/aukora-boundary/targets", "--gid", "123"]
        for manifest in (self.manifest(), {"version": 2, "profiles": {}}):
            for arguments in (gate, ["floor", "show"], ["approval", "show", "--release-dir", "/opt/aukora-genesis/release-abcdef0"],
                              ["aura", "collect"], ["aura", "verify"]):
                with patch.dict(G, {"verify_installation": lambda: manifest}), patch.object(sys, "argv", ["fixture"] + arguments), \
                        patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                        patch.object(os, "chdir") as chdir, patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                    self.assertEqual(SOURCE["main"](), 2)
                    self.assertIn("owner-key-profile-unconfigured", refusal.getvalue())
                    dispatch.assert_not_called()
                    chdir.assert_not_called()
                    self.assertFalse(self.world.marker.exists())
        with patch.dict(G, {"verify_installation": lambda: self.manifest()}), patch.object(sys, "argv", ["fixture", "check-package"]), \
                patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                patch.object(sys, "stdout", new_callable=io.StringIO) as output:
            self.assertEqual(SOURCE["main"](), 0)
            self.assertEqual(output.getvalue(), "PACKAGE_VERIFIED\n")
            dispatch.assert_not_called()
        for action in ("collect", "verify"):
            with patch.dict(G, {"verify_installation": self.world.installation}), patch.object(sys, "argv", ["fixture", "aura", action]), \
                    patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                    patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                self.assertEqual(SOURCE["main"](), 2)
                self.assertIn("aura-context-unconfigured", refusal.getvalue())
                dispatch.assert_not_called()
                self.assertFalse(self.world.marker.exists())

    def runtime_then_witness(self, manifest, epochs, namespace=SOURCE, action="check-runtime"):
        # Model a service's fixed ExecStartPre success dependency. Only this
        # disposable Python witness stands in for its subsequent Node command.
        with self.protected_aura_world(manifest, epochs, namespace), \
                patch.object(sys, "argv", ["fixture", action]), patch.dict(os.environ, {}, clear=True), \
                patch.object(os, "execve") as dispatch, patch.object(os, "chdir") as chdir, \
                patch.object(sys, "stdout", new_callable=io.StringIO) as output, \
                patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
            result = namespace["main"]()
            dispatch.assert_not_called()
            chdir.assert_not_called()
            if result == 0:
                subprocess.run([sys.executable, "-I", "-S", str(self.world.root / "bin/gate.mjs")], check=True)
            return result, output.getvalue(), refusal.getvalue()

    @contextmanager
    def unavailable_private_data(self):
        # A root0600 author key exists in synthetic custody, but this process
        # has no access to it. Public roles must never attempt the open.
        self.assertEqual(self.world.secret.stat().st_mode & 0o777, 0o600)
        original_open, original_lstat = os.open, os.lstat
        secret_opens, data_probes = [], []
        def private_open(path, *args, **kwargs):
            if str(path) == str(self.world.secret):
                secret_opens.append(str(path))
                raise PermissionError("synthetic root0600 author access unavailable")
            return original_open(path, *args, **kwargs)
        def data_lstat(path, *args, **kwargs):
            if str(path) in (str(self.world.store), str(self.world.db)):
                data_probes.append(str(path))
                raise PermissionError("synthetic private store/database probe unavailable")
            return original_lstat(path, *args, **kwargs)
        with patch.object(os, "open", private_open), patch.object(os, "lstat", data_lstat):
            yield secret_opens, data_probes

    def test_public_aura_preflight_is_finite_and_never_dispatches(self):
        self.assertEqual(SOURCE["launch_arguments"](["check-runtime-aura"]), (None, ["check-runtime-aura"]))
        for tail in (["collect"], ["verify"], ["/tmp/context.mjs"], ["--context", SOURCE["AURA_CONFIG"]],
                     ["--python", "/tmp/python"], ["--entry", "/tmp/evil"], ["--unsafe-preview"], ["--"]):
            with self.subTest(tail=tail), self.refuses("launch-option"):
                SOURCE["launch_arguments"](["check-runtime-aura"] + tail)
        manifest, epochs = self.full_aura_manifest()
        roles = (["check-package"], ["check-runtime"], ["check-runtime-aura"], ["floor", "show"],
                 ["approval", "show", "--release-dir", "/opt/aukora-genesis/release-abcdef0"],
                 ["serve", "--home", "/home/aukora-gate", "--run", "/run/aukora-gate",
                  "--target-root", "/var/lib/aukora-boundary/targets", "--gid", "123"])
        class Executed(Exception):
            pass
        for arguments in roles:
            with self.subTest(role=arguments[0]):
                with self.protected_aura_world(manifest, epochs) as phases, self.unavailable_private_data() as (opens, probes), \
                        patch.object(sys, "argv", ["fixture"] + arguments), patch.dict(os.environ, {}, clear=True), \
                        patch.object(os, "execve", side_effect=Executed) as dispatch, patch.object(os, "chdir") as chdir, \
                        patch.object(sys, "stdout", new_callable=io.StringIO) as output:
                    if arguments[0].startswith("check-"):
                        self.assertEqual(SOURCE["main"](), 0)
                        expected = {"check-package": "PACKAGE_VERIFIED", "check-runtime": "RUNTIME_VERIFIED",
                                    "check-runtime-aura": "RUNTIME_AURA_VERIFIED"}[arguments[0]]
                        self.assertEqual(output.getvalue(), expected + "\n")
                        dispatch.assert_not_called()
                        chdir.assert_not_called()
                    else:
                        with self.assertRaises(Executed):
                            SOURCE["main"]()
                        dispatch.assert_called_once()
                    self.assertEqual(phases, ["gate"] + ["launcher:" + name for name in sorted(self.world.launcher_files)]
                                     + ["owner_key", "aura"])
                    self.assertEqual(opens, [], "public verification must not open private author")
                    self.assertEqual(probes, [], "public verification must not probe mutable data")
                self.assertFalse(self.world.marker.exists())

    def test_actual_aura_dispatch_retains_private_custody_before_node(self):
        manifest, epochs = self.full_aura_manifest()
        for action in ("collect", "verify"):
            with self.subTest(action=action), self.protected_aura_world(manifest, epochs), \
                    self.unavailable_private_data() as (opens, probes), \
                    patch.object(sys, "argv", ["fixture", "aura", action]), patch.dict(os.environ, {}, clear=True), \
                    patch.object(os, "execve") as dispatch, patch.object(os, "chdir") as chdir, \
                    patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                self.assertEqual(SOURCE["main"](), 2)
                self.assertIn("protected-io", refusal.getvalue())
                self.assertEqual(opens, [str(self.world.secret)])
                self.assertEqual(probes, [])
                dispatch.assert_not_called()
                chdir.assert_not_called()
                self.assertFalse(self.world.marker.exists())

    def test_public_aura_preflight_blocks_dynamic_fixture_without_public_pins(self):
        manifest, epochs = self.full_aura_manifest()
        missing_aura = self.v2_manifest()
        missing_aura["external_files"] = dict(manifest["external_files"])
        legacy = self.manifest()
        legacy["external_files"] = dict(manifest["external_files"])
        missing_owner = json.loads(json.dumps(missing_aura))
        missing_owner["profiles"].pop("owner_key")
        missing_launcher = json.loads(json.dumps(manifest))
        missing_launcher["profiles"].pop("launcher")
        cases = ((missing_aura, "aura-context-unconfigured"), (legacy, "owner-key-profile-unconfigured"),
                 (missing_owner, "owner-key-profile-unconfigured"), (missing_launcher, "launcher-profile-unconfigured"))
        for candidate, code in cases:
            with self.subTest(code=code), self.unavailable_private_data() as (opens, probes):
                result, output, refusal = self.runtime_then_witness(candidate, epochs, action="check-runtime-aura")
                self.assertEqual(result, 2)
                self.assertEqual(output, "")
                self.assertIn(code, refusal)
                self.assertEqual((opens, probes), ([], []))
                self.assertFalse(self.world.marker.exists())
        for path, code in ((self.world.aura_root / "packages/boundary-gate/host/aura/context.mjs", "package-hash"),
                           (self.world.configuration, "aura-configuration-hash")):
            original = path.read_bytes()
            path.write_text("changed public source/configuration\n")
            try:
                with self.unavailable_private_data() as (opens, probes):
                    result, output, refusal = self.runtime_then_witness(manifest, epochs, action="check-runtime-aura")
                    self.assertEqual(result, 2)
                    self.assertEqual(output, "")
                    self.assertIn(code, refusal)
                    self.assertEqual((opens, probes), ([], []))
                    self.assertFalse(self.world.marker.exists())
            finally:
                path.write_bytes(original)
        with self.unavailable_private_data() as (opens, probes):
            result, output, refusal = self.runtime_then_witness(manifest, epochs, action="check-runtime-aura")
            self.assertEqual((result, output, refusal), (0, "RUNTIME_AURA_VERIFIED\n", ""))
            self.assertEqual((opens, probes), ([], []))
            self.assertEqual(self.world.marker.read_text(), "executed")
            self.world.marker.unlink()

    def test_fixed_runtime_preflight_has_no_dispatch_and_blocks_unqualified_composed_service(self):
        self.assertEqual(SOURCE["launch_arguments"](["check-runtime"]), (None, ["check-runtime"]))
        for tail in (["bin/selfcheck.mjs"], ["/tmp/candidate"], ["--entry", "/tmp/evil.mjs"],
                     ["--python", "/tmp/python"], ["--unsafe-preview"], ["--"], ["check-package"]):
            with self.subTest(tail=tail), self.refuses("launch-option"):
                SOURCE["launch_arguments"](["check-runtime"] + tail)
        manifest, epochs = self.full_aura_manifest()
        result, output, refusal = self.runtime_then_witness(manifest, epochs)
        self.assertEqual((result, output, refusal), (0, "RUNTIME_VERIFIED\n", ""))
        self.assertEqual(self.world.marker.read_text(), "executed")
        self.world.marker.unlink()
        legacy = self.manifest()
        legacy["external_files"] = dict(manifest["external_files"])
        missing_owner = self.v2_manifest()
        missing_owner["external_files"] = dict(manifest["external_files"])
        missing_owner["profiles"].pop("owner_key")
        missing_launcher = json.loads(json.dumps(manifest))
        missing_launcher["profiles"].pop("launcher")
        for candidate, code in ((legacy, "owner-key-profile-unconfigured"),
                                (missing_owner, "owner-key-profile-unconfigured"),
                                (missing_launcher, "launcher-profile-unconfigured")):
            with self.subTest(code=code):
                result, output, refusal = self.runtime_then_witness(candidate, epochs)
                self.assertEqual(result, 2)
                self.assertEqual(output, "")
                self.assertIn(code, refusal)
                self.assertFalse(self.world.marker.exists())
        path = self.world.launcher_root / "scripts/launch-dsh.py"
        path.write_text("changed preflight launcher bytes\n")
        result, output, refusal = self.runtime_then_witness(manifest, epochs)
        self.assertEqual(result, 2)
        self.assertEqual(output, "")
        self.assertIn("launcher-hash", refusal)
        self.assertFalse(self.world.marker.exists())

    def test_public_aura_preflight_and_private_role_mutants_fail_their_regressions(self):
        source = (HERE / "gate-bootstrap.py").read_text()
        guards = {
            "public-profile": ('require_node_profile(manifest, AURA_ROOT + "/" + AURA_ENTRY)',
                               'require(True, "disabled-public-aura-profile-fixture-guard")'),
            "public-private-separation": ('return verify_aura_configuration(profile)',
                'value = verify_aura_configuration(profile)\n    verify_aura_custody(value)\n    return value'),
            "private-custody": ('verify_aura_custody(verify_aura_configuration(manifest["profiles"]["aura"]))',
                                'require(True, "disabled-private-aura-custody-fixture-guard")'),
        }
        for name, (guard, replacement) in guards.items():
            with self.subTest(guard=name):
                self.assertEqual(source.count(guard), 1)
                mutant = {"__name__": "public_aura_role_mutant", "__file__": str(HERE / "gate-bootstrap.py")}
                exec(compile(source.replace(guard, replacement), "<public-aura-role-single-guard-mutant>", "exec"), mutant)
                manifest, epochs = self.full_aura_manifest()
                if name == "public-profile":
                    manifest["profiles"].pop("aura")
                    def regression(namespace):
                        with self.unavailable_private_data() as (opens, probes):
                            result, output, refusal = self.runtime_then_witness(manifest, epochs, namespace, "check-runtime-aura")
                            self.assertEqual(result, 2)
                            self.assertEqual(output, "")
                            self.assertIn("aura-context-unconfigured", refusal)
                            self.assertEqual((opens, probes), ([], []))
                            self.assertFalse(self.world.marker.exists())
                    regression(SOURCE)
                    with self.assertRaises(AssertionError):
                        regression(mutant)
                    self.assertEqual(self.world.marker.read_text(), "executed")
                    self.world.marker.unlink()
                elif name == "public-private-separation":
                    attempts = []
                    def regression(namespace):
                        with self.unavailable_private_data() as (opens, probes):
                            try:
                                result, output, refusal = self.runtime_then_witness(manifest, epochs, namespace, "check-runtime-aura")
                                self.assertEqual((result, output, refusal), (0, "RUNTIME_AURA_VERIFIED\n", ""))
                                self.assertEqual((opens, probes), ([], []))
                            finally:
                                attempts.extend(opens)
                    regression(SOURCE)
                    self.assertEqual(attempts, [])
                    self.assertEqual(self.world.marker.read_text(), "executed")
                    self.world.marker.unlink()
                    with self.assertRaises(AssertionError):
                        regression(mutant)
                    self.assertEqual(attempts, [str(self.world.secret)], "mutant must violate the private boundary")
                    self.assertFalse(self.world.marker.exists())
                else:
                    for action in ("collect", "verify"):
                        def regression(namespace):
                            with self.protected_aura_world(manifest, epochs, namespace), \
                                    self.unavailable_private_data() as (opens, probes), \
                                    patch.object(sys, "argv", ["fixture", "aura", action]), patch.dict(os.environ, {}, clear=True), \
                                    patch.object(os, "chdir"), patch.object(os, "execve", side_effect=lambda *_args:
                                        subprocess.run([sys.executable, "-I", "-S", str(self.world.aura_root / SOURCE["AURA_ENTRY"])], check=True)), \
                                    patch.object(sys, "stderr", new_callable=io.StringIO):
                                self.assertEqual(namespace["main"](), 2)
                                self.assertEqual(opens, [str(self.world.secret)])
                                self.assertEqual(probes, [])
                                self.assertFalse(self.world.marker.exists())
                        regression(SOURCE)
                        with self.assertRaises(AssertionError):
                            regression(mutant)
                        self.assertEqual(self.world.marker.read_text(), "aura-executed")
                        self.world.marker.unlink()
        print("SOURCE-ONLY public-Aura role mutations: 3/3 killed; missing-profile/private-custody mutants reach disposable witnesses; public-role mutant attempts forbidden private open", flush=True)

    def test_runtime_preflight_guard_mutant_reaches_only_the_composed_service_witness(self):
        source = (HERE / "gate-bootstrap.py").read_text()
        guard = 'require_node_profile(manifest, "bin/selfcheck.mjs")'
        self.assertEqual(source.count(guard), 1)
        mutant = {"__name__": "runtime_preflight_mutant", "__file__": str(HERE / "gate-bootstrap.py")}
        exec(compile(source.replace(guard, 'require(True, "disabled-runtime-profile-fixture-guard")'),
                     "<runtime-preflight-single-guard-mutant>", "exec"), mutant)
        original, epochs = self.full_aura_manifest()
        legacy = self.manifest()
        legacy["external_files"] = dict(original["external_files"])
        missing_owner = self.v2_manifest()
        missing_owner["external_files"] = dict(original["external_files"])
        missing_owner["profiles"].pop("owner_key")
        for manifest in (legacy, missing_owner):
            def regression(namespace):
                result, output, refusal = self.runtime_then_witness(manifest, epochs, namespace)
                self.assertEqual(result, 2)
                self.assertEqual(output, "")
                self.assertIn("owner-key-profile-unconfigured", refusal)
                self.assertFalse(self.world.marker.exists(), "service must not continue to subsequent Node effect")
            regression(SOURCE)
            with self.assertRaises(AssertionError):
                regression(mutant)
            self.assertEqual(self.world.marker.read_text(), "executed")
            self.world.marker.unlink()
        print("SOURCE-ONLY runtime-preflight guard mutation: 1/1 killed; v1 and missing-G mutant paths reach the composed disposable witness", flush=True)

    def test_actual_installation_algorithm_verifies_gate_then_owner(self):
        manifest = self.v2_manifest()
        epochs = json.dumps({"version": 1, "kind": "aukora-signer-epochs/v1",
                             "epochs": [{"epoch": 1, "gate_pubkey_sha256": "0" * 64}]}).encode()
        manifest["external_files"][SOURCE["SIGNER_EPOCHS"]] = hashlib.sha256(epochs).hexdigest()
        original_read, original_open = SOURCE["protected_read"], SOURCE["protected_open"]
        original_ancestors, original_verify = SOURCE["protected_ancestors"], SOURCE["verify_package"]
        phases = []
        def fixture_read(path, limit=SOURCE["MAX_FILE"]):
            fixed = {SOURCE["BOOTSTRAP"]: b"reviewed fixture launcher", SOURCE["MANIFEST"]: json.dumps(manifest).encode(),
                     SOURCE["SIGNER_EPOCHS"]: epochs}
            if path in fixed:
                return fixed[path]
            if path.startswith(SOURCE["LAUNCHER_ROOT"] + "/"):
                name = path[len(SOURCE["LAUNCHER_ROOT"]) + 1:]
                phases.append("launcher:" + name)
                return original_read(str(self.world.launcher_root / name), limit)
            return original_read(path, limit)
        def fixture_open(path):
            return original_open(str(self.world.root / "src/helper.mjs") if path == SOURCE["NODE"] else path)
        def fixture_ancestors(path):
            if path != SOURCE["PYTHON"]:
                original_ancestors(path)
        def fixture_verify(root, files):
            if root == SOURCE["PACKAGE"]:
                phases.append("gate")
                return original_verify(str(self.world.root), files)
            self.assertEqual(root, SOURCE["OWNER_KEY_ROOT"])
            phases.append("owner_key")
            return original_verify(str(self.world.owner_root), files)
        with patch.dict(G, {"__file__": SOURCE["BOOTSTRAP"], "OWNER_KEY_SOURCE_PINS": self.world.owner_pins,
                            "LAUNCHER_SOURCE_PINS": self.world.launcher_files,
                            "protected_metadata": self.world.fixture_metadata, "protected_read": fixture_read,
                            "protected_open": fixture_open, "protected_ancestors": fixture_ancestors, "verify_package": fixture_verify}):
            self.assertEqual(SOURCE["verify_installation"]()["version"], 2)
            self.assertEqual(phases, ["gate"] + ["launcher:" + name for name in sorted(self.world.launcher_files)] + ["owner_key"])
            for name in ("src/index.mjs", "src/authorization.mjs", "package.json", "PROVENANCE.json", "checks/mutants.mjs", "checks/gate-caller.test.mjs"):
                path = self.world.owner_root / name
                original = path.read_bytes()
                path.write_text("unreviewed source\n")
                phases.clear()
                with self.refuses("package-hash"):
                    SOURCE["verify_installation"]()
                self.assertEqual(phases, ["gate"] + ["launcher:" + name for name in sorted(self.world.launcher_files)] + ["owner_key"])
                self.assertFalse(self.world.marker.exists())
                path.write_bytes(original)
            self.world.put("src/helper.mjs", "unreviewed gate bytes\n")
            phases.clear()
            with self.refuses("package-hash"):
                SOURCE["verify_installation"]()
            self.assertEqual(phases, ["gate"])
            self.assertFalse(self.world.marker.exists())

    def test_owner_key_staging_v2_is_deterministic_complete_and_noninstalling(self):
        generator = runpy.run_path(str(HERE / "generate-manifest.py"), run_name="generator_source_fixture")
        generator_globals = generator["SOURCE"]["parse_manifest"].__globals__
        epochs = self.world.root.parent / "epochs.json"
        epochs.write_text(json.dumps({"version": 1, "kind": "aukora-signer-epochs/v1",
                                      "epochs": [{"epoch": 1, "gate_pubkey_sha256": "0" * 64}]}))
        outputs = [self.world.root.parent / "v2-one.json", self.world.root.parent / "v2-two.json"]
        argv = ["fixture", "--package", str(self.world.root), "--signer-epochs", str(epochs),
                "--owner-key", str(self.world.owner_root), "--launcher-checkout", str(self.world.launcher_root), "--output"]
        with patch.dict(generator_globals, {"OWNER_KEY_SOURCE_PINS": self.world.owner_pins,
                                            "LAUNCHER_SOURCE_PINS": self.world.launcher_files}), \
                patch.object(sys, "stdout", new_callable=io.StringIO):
            for output in outputs:
                with patch.object(sys, "argv", argv + [str(output)]):
                    self.assertEqual(generator["main"](), 0)
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
            value = json.loads(outputs[0].read_bytes())
            self.assertEqual(value["version"], 2)
            self.assertEqual(value["profiles"]["owner_key"]["root"], SOURCE["OWNER_KEY_ROOT"])
            self.assertNotIn(str(self.world.owner_root), outputs[0].read_text())
            for output, expected in ((self.world.owner_root / "manifest.json", "manifest-inside-profile"),
                                     (outputs[0], "staging-io")):
                with patch.object(sys, "argv", argv + [str(output)]), patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                    self.assertEqual(generator["main"](), 2)
                    self.assertIn(expected, refusal.getvalue())
            for output in (SOURCE["MANIFEST"], SOURCE["AURA_CONFIG"], SOURCE["BOOTSTRAP"],
                           SOURCE["NODE"], SOURCE["PACKAGE"] + "/manifest.json", SOURCE["OWNER_KEY_ROOT"] + "/manifest.json",
                           SOURCE["AURA_ROOT"] + "/manifest.json", SOURCE["LAUNCHER_ROOT"] + "/manifest.json"):
                with patch.object(sys, "argv", argv + [output]), patch.object(sys, "stderr", new_callable=io.StringIO) as refusal, \
                        patch.object(generator["os"], "open") as opened:
                    self.assertEqual(generator["main"](), 2)
                    self.assertIn("manifest-installed-path", refusal.getvalue())
                    opened.assert_not_called()
            (self.world.owner_root / "checks/gate-caller.test.mjs").unlink()
            missing_output = self.world.root.parent / "missing-manifest.json"
            with patch.object(sys, "argv", argv + [str(missing_output)]), patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                self.assertEqual(generator["main"](), 2)
                self.assertIn("owner-key-inventory", refusal.getvalue())
                self.assertFalse(missing_output.exists())
        self.assertFalse(self.world.marker.exists())

    def test_aura_staging_requires_complete_reviewed_source_and_public_configuration(self):
        generator = runpy.run_path(str(HERE / "generate-manifest.py"), run_name="aura_generator_source_fixture")
        generator_globals = generator["SOURCE"]["parse_manifest"].__globals__
        epochs = self.world.root.parent / "epochs.json"
        epochs.write_text(json.dumps({"version": 1, "kind": "aukora-signer-epochs/v1",
                                      "epochs": [{"epoch": 1, "gate_pubkey_sha256": "0" * 64}]}))
        output = self.world.root.parent / "aura-manifest.json"
        argv = ["fixture", "--package", str(self.world.root), "--signer-epochs", str(epochs),
                "--owner-key", str(self.world.owner_root), "--aura-source", str(self.world.aura_root),
                "--aura-context", str(self.world.configuration), "--launcher-checkout", str(self.world.launcher_root),
                "--output", str(output)]
        original_open = os.open
        def no_secret_open(path, *args, **kwargs):
            self.assertNotEqual(str(path), str(self.world.secret), "staging must not open author secret")
            return original_open(path, *args, **kwargs)
        with patch.dict(generator_globals, {"OWNER_KEY_SOURCE_PINS": self.world.owner_pins,
                "AURA_SOURCE_PINS": self.world.aura_files, "LAUNCHER_SOURCE_PINS": self.world.launcher_files}), \
                patch.object(sys, "stdout", new_callable=io.StringIO), patch.object(os, "open", no_secret_open):
            with patch.object(sys, "argv", argv):
                self.assertEqual(generator["main"](), 0)
            manifest = json.loads(output.read_bytes())
            self.assertEqual(manifest["profiles"]["aura"]["root"], SOURCE["AURA_ROOT"])
            self.assertEqual(manifest["profiles"]["aura"]["files"], self.world.aura_files)
            self.assertEqual(manifest["profiles"]["aura"]["configuration"]["path"], SOURCE["AURA_CONFIG"])
            self.assertEqual(manifest["profiles"]["aura"]["configuration"]["sha256"], hashlib.sha256(self.world.configuration.read_bytes()).hexdigest())
            output.unlink()
            def refuses(candidate, code):
                with patch.object(sys, "argv", candidate), patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                    self.assertEqual(generator["main"](), 2)
                    self.assertIn(code, refusal.getvalue())
                    self.assertFalse(output.exists())
            refuses(argv[:9] + argv[11:], "staging-aura-required")
            refuses(argv[:5] + argv[7:], "staging-aura-owner-key-required")
            for flag, installed in (("--package", SOURCE["PACKAGE"]), ("--owner-key", SOURCE["OWNER_KEY_ROOT"]),
                                    ("--aura-source", SOURCE["AURA_ROOT"]), ("--aura-context", SOURCE["AURA_CONFIG"]),
                                    ("--signer-epochs", SOURCE["SIGNER_EPOCHS"]), ("--launcher-checkout", SOURCE["LAUNCHER_ROOT"])):
                candidate = list(argv)
                candidate[candidate.index(flag) + 1] = installed
                refuses(candidate, "staging-installed-path")
            for flag in ("--package", "--owner-key", "--aura-source", "--launcher-checkout"):
                for ancestor in ("/", "/opt", "/etc", "/usr/local/lib"):
                    with self.subTest(flag=flag, ancestor=ancestor):
                        candidate = list(argv)
                        candidate[candidate.index(flag) + 1] = ancestor
                        with patch.object(generator["os"], "open") as opened, \
                                patch.object(generator["os"], "scandir") as scanned:
                            refuses(candidate, "staging-installed-path")
                            opened.assert_not_called()
                            scanned.assert_not_called()
            for staged in (str(self.world.root) + "/../package", str(self.world.root) + "/", "relative-stage"):
                candidate = list(argv)
                candidate[candidate.index("--package") + 1] = staged
                refuses(candidate, "staging-input-path")
            selected = self.world.aura_root / "scripts/aura/collect-gate.mjs"
            original = selected.read_bytes()
            selected.write_text("candidate code\n")
            refuses(argv, "aura-source-pin")
            selected.write_bytes(original)
            (self.world.aura_root / "LICENSE").unlink()
            refuses(argv, "aura-source-inventory")
        self.assertFalse(self.world.marker.exists())

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

    def test_launcher_staging_reads_only_the_six_named_inputs_and_requires_reviewed_pins(self):
        generator = runpy.run_path(str(HERE / "generate-manifest.py"), run_name="launcher_generator_source_fixture")
        generator_globals = generator["SOURCE"]["parse_manifest"].__globals__
        epochs = self.world.root.parent / "epochs.json"
        epochs.write_text(json.dumps({"version": 1, "kind": "aukora-signer-epochs/v1",
                                      "epochs": [{"epoch": 1, "gate_pubkey_sha256": "0" * 64}]}))
        output = self.world.root.parent / "launcher-manifest.json"
        argv = ["fixture", "--package", str(self.world.root), "--signer-epochs", str(epochs),
                "--launcher-checkout", str(self.world.launcher_root), "--output", str(output)]
        extra = self.world.put("unallocated.txt", "outside named inputs; must not read\n", root=self.world.launcher_root)
        open_os, scan_os = os.open, os.scandir
        def named_open(path, *args, **kwargs):
            self.assertNotEqual(str(path), str(extra))
            return open_os(path, *args, **kwargs)
        def no_checkout_scan(path):
            self.assertFalse(str(path).startswith(str(self.world.launcher_root)))
            return scan_os(path)
        with patch.dict(generator_globals, {"LAUNCHER_SOURCE_PINS": self.world.launcher_files}), \
                patch.object(os, "open", named_open), patch.object(os, "scandir", no_checkout_scan), \
                patch.object(sys, "stdout", new_callable=io.StringIO):
            with patch.object(sys, "argv", argv):
                self.assertEqual(generator["main"](), 0)
            value = json.loads(output.read_bytes())
            self.assertEqual(value["version"], 2)
            self.assertEqual(set(value["profiles"]), {"launcher"})
            self.assertEqual(value["profiles"]["launcher"], self.world.launcher_profile())
            self.assertNotIn(str(self.world.launcher_root), output.read_text())
            with self.refuses("owner-key-profile-unconfigured"):
                SOURCE["require_node_profile"](value, SOURCE["ENTRY"])
            output.unlink()
            def refuses(candidate, code):
                with patch.object(sys, "argv", candidate), patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                    self.assertEqual(generator["main"](), 2)
                    self.assertIn(code, refusal.getvalue())
                    self.assertFalse(output.exists())
            missing_launcher = argv[:5] + ["--owner-key", str(self.world.owner_root)] + argv[7:]
            refuses(missing_launcher, "staging-launcher-required")
            inside = list(argv)
            inside[-1] = str(self.world.launcher_root / "manifest.json")
            refuses(inside, "manifest-inside-profile")
            for name in self.world.launcher_files:
                path = self.world.launcher_root / name
                original = path.read_bytes()
                path.write_text("candidate launcher input\n")
                refuses(argv, "launcher-source-pin")
                path.write_bytes(original)
            path = self.world.launcher_root / "scripts/genesis-check.mjs"
            original = path.read_bytes()
            path.unlink()
            refuses(argv, "staging-io")
            path.symlink_to(self.world.root / "src/helper.mjs")
            refuses(argv, "staging-regular-file")
            path.unlink()
            path.write_bytes(original)
            link = self.world.launcher_root / "extra-hardlink"
            os.link(path, link)
            refuses(argv, "staging-regular-file")
            link.unlink()
            directory = self.world.launcher_root / "scripts/lib"
            renamed = directory.with_name("library-preserved")
            directory.rename(renamed)
            directory.symlink_to(renamed, target_is_directory=True)
            refuses(argv, "staging-directory")
            directory.unlink()
            renamed.rename(directory)
        with patch.object(sys, "argv", argv), patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
            self.assertEqual(generator["main"](), 2)
            self.assertIn("launcher-source-pin", refusal.getvalue())
        self.assertFalse(output.exists())
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

    def test_owner_profile_guard_mutants_fail_with_an_actual_dispatch_trap(self):
        source = (HERE / "gate-bootstrap.py").read_text()
        guards = {
            "required-profile": 'require(manifest["version"] == 2 and "owner_key" in manifest["profiles"], "owner-key-profile-unconfigured")',
            "independent-source-pin": 'require(all(files[name] == digest for name, digest in OWNER_KEY_SOURCE_PINS.items()), "owner-key-source-pin")',
        }
        for name, guard in guards.items():
            with self.subTest(guard=name):
                self.assertEqual(source.count(guard), 1)
                mutant = {"__name__": "owner_profile_source_mutant", "__file__": str(HERE / "gate-bootstrap.py")}
                exec(compile(source.replace(guard, 'require(True, "disabled-source-fixture-guard")'),
                             "<owner-profile-single-guard-mutant>", "exec"), mutant)
                if name == "independent-source-pin":
                    def regression(namespace):
                        with patch.dict(namespace["main"].__globals__, {"LAUNCHER_SOURCE_PINS": self.world.launcher_files}), \
                                self.assertRaisesRegex(namespace["Refused"], "owner-key-source-pin"):
                            namespace["parse_manifest"](json.dumps(self.v2_manifest()).encode())
                    regression(SOURCE)
                    with self.assertRaises(AssertionError):
                        regression(mutant)
                    self.assertFalse(self.world.marker.exists())
                else:
                    arguments = ["serve", "--home", "/home/aukora-gate", "--run", "/run/aukora-gate", "--target-root",
                                 "/var/lib/aukora-boundary/targets", "--gid", "123"]
                    def regression(namespace):
                        calls = []
                        def dispatch(_path, _arguments, _environment):
                            calls.append(True)
                            subprocess.run([sys.executable, "-I", "-S", str(self.world.root / "bin/gate.mjs")], check=True)
                        namespace_globals = namespace["main"].__globals__
                        with patch.dict(namespace_globals, {"verify_installation": lambda: self.manifest()}), \
                                patch.object(sys, "argv", ["fixture"] + arguments), patch.dict(os.environ, {}, clear=True), \
                                patch.object(os, "chdir"), patch.object(os, "execve", dispatch), \
                                patch.object(sys, "stderr", new_callable=io.StringIO):
                            self.assertEqual(namespace["main"](), 2)
                        self.assertEqual(calls, [], "v1 must not reach the Node dispatch boundary")
                    regression(SOURCE)
                    self.assertFalse(self.world.marker.exists())
                    with self.assertRaises(AssertionError):
                        regression(mutant)
                    self.assertEqual(self.world.marker.read_text(), "executed")
                    self.world.marker.unlink()
        print("SOURCE-ONLY owner-profile guard mutations: 2/2 killed; missing-profile mutant executes the disposable trap", flush=True)

    def test_launcher_pin_and_hash_mutants_fail_at_the_dispatch_boundary(self):
        source = (HERE / "gate-bootstrap.py").read_text()
        guards = {
            "source-pin": 'require(files == LAUNCHER_SOURCE_PINS, "launcher-source-pin")',
            "runtime-hash": 'require(hashlib.sha256(data).hexdigest() == profile["files"][name], "launcher-hash:" + name)',
        }
        for name, guard in guards.items():
            with self.subTest(guard=name):
                self.assertEqual(source.count(guard), 1)
                mutant = {"__name__": "launcher_source_mutant", "__file__": str(HERE / "gate-bootstrap.py")}
                exec(compile(source.replace(guard, 'require(True, "disabled-source-fixture-guard")'),
                             "<launcher-single-guard-mutant>", "exec"), mutant)
                manifest, epochs = self.full_aura_manifest()
                path = self.world.launcher_root / "scripts/lib/release-strip.mjs"
                original = path.read_bytes()
                path.write_text("unapproved changed checkout verifier input\n")
                if name == "source-pin":
                    manifest["profiles"]["launcher"]["files"]["scripts/lib/release-strip.mjs"] = hashlib.sha256(path.read_bytes()).hexdigest()
                    code = "launcher-source-pin"
                else:
                    code = "launcher-hash"
                try:
                    self.assert_aura_refuses_before_dispatch(manifest, epochs, code)
                    calls = []
                    def dispatch(_path, _argv, _environment):
                        calls.append(True)
                        subprocess.run([sys.executable, "-I", "-S", str(self.world.aura_root / SOURCE["AURA_ENTRY"])], check=True)
                    def regression():
                        with self.protected_aura_world(manifest, epochs, mutant), patch.object(sys, "argv", ["fixture", "aura", "collect"]), \
                                patch.dict(os.environ, {}, clear=True), patch.object(os, "chdir"), \
                                patch.object(os, "execve", dispatch), patch.object(sys, "stderr", new_callable=io.StringIO):
                            self.assertEqual(mutant["main"](), 2)
                        self.assertEqual(calls, [], "unsafe launcher profile must refuse before dispatch")
                    with self.assertRaises(AssertionError):
                        regression()
                    self.assertEqual(calls, [True])
                    self.assertEqual(self.world.marker.read_text(), "aura-executed")
                finally:
                    path.write_bytes(original)
                    if self.world.marker.exists():
                        self.world.marker.unlink()
        print("SOURCE-ONLY launcher guard mutations: 2/2 killed; each mutant reaches the actual disposable dispatch trap", flush=True)

    def test_aura_guard_mutants_fail_at_the_dispatch_boundary(self):
        source = (HERE / "gate-bootstrap.py").read_text()
        guards = {
            "source-pin": 'require(files == AURA_SOURCE_PINS, "aura-source-pin")',
            "configuration-hash": 'require(hashlib.sha256(data).hexdigest() == profile["configuration"]["sha256"], "aura-configuration-hash")',
            "private-metadata": 'require(metadata.st_mode & 0o077 == 0 and metadata.st_size in (64, 65), "aura-secret-metadata")',
        }
        for name, guard in guards.items():
            with self.subTest(guard=name):
                self.assertEqual(source.count(guard), 1)
                mutant = {"__name__": "aura_source_mutant", "__file__": str(HERE / "gate-bootstrap.py")}
                exec(compile(source.replace(guard, 'require(True, "disabled-source-fixture-guard")'),
                             "<aura-single-guard-mutant>", "exec"), mutant)
                manifest, epochs = self.full_aura_manifest()
                entry = self.world.aura_root / SOURCE["AURA_ENTRY"]
                original_entry, original_config = entry.read_bytes(), self.world.configuration.read_bytes()
                secret_mode = self.world.secret.stat().st_mode
                if name == "source-pin":
                    entry.write_text("from pathlib import Path\nPath(" + repr(str(self.world.marker)) + ").write_text('aura-unapproved')\n")
                    manifest["profiles"]["aura"]["files"][SOURCE["AURA_ENTRY"]] = hashlib.sha256(entry.read_bytes()).hexdigest()
                    code, marker = "aura-source-pin", "aura-unapproved"
                elif name == "configuration-hash":
                    value = self.world.aura_configuration()
                    value["source"]["source_id"] = "altered-valid-source"
                    self.world.configuration.write_bytes(json.dumps(value).encode())
                    code, marker = "aura-configuration-hash", "aura-executed"
                else:
                    self.world.secret.chmod(0o640)
                    code, marker = "aura-secret-metadata", "aura-executed"
                try:
                    self.assert_aura_refuses_before_dispatch(manifest, epochs, code)
                    calls = []
                    def dispatch(_path, _argv, _environment):
                        calls.append(True)
                        subprocess.run([sys.executable, "-I", "-S", str(entry)], check=True)
                    def regression():
                        with self.protected_aura_world(manifest, epochs, mutant), patch.object(sys, "argv", ["fixture", "aura", "collect"]), \
                                patch.dict(os.environ, {}, clear=True), patch.object(os, "chdir"), \
                                patch.object(os, "execve", dispatch), patch.object(sys, "stderr", new_callable=io.StringIO):
                            self.assertEqual(mutant["main"](), 2)
                        self.assertEqual(calls, [], "unsafe Aura profile must refuse before dispatch")
                    with self.assertRaises(AssertionError):
                        regression()
                    self.assertEqual(calls, [True])
                    self.assertEqual(self.world.marker.read_text(), marker)
                finally:
                    entry.write_bytes(original_entry)
                    self.world.configuration.write_bytes(original_config)
                    self.world.secret.chmod(secret_mode)
                    if self.world.marker.exists():
                        self.world.marker.unlink()
        print("SOURCE-ONLY Aura guard mutations: 3/3 killed; each mutant reaches the actual disposable dispatch trap", flush=True)


if __name__ == "__main__":
    print("SOURCE-ONLY: actual tiny files and marker execution; synthetic root metadata; no installed-host qualification.", flush=True)
    unittest.main(verbosity=2)
