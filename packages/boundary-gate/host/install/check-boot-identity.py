#!/usr/bin/python3
"""SOURCE-ONLY BootIdentity controls; actual verifier, synthetic UID0 custody."""

from contextlib import contextmanager
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = runpy.run_path(str(HERE / "gate-bootstrap.py"), run_name="boot_identity_source")
G = SOURCE["verify_boot_profile"].__globals__
Refused = SOURCE["Refused"]


def private_fixture_parent():
    """Create only a new private source-fixture root; never repair an old root."""
    home = Path(os.path.expanduser("~"))
    parent = home / ".aukora-h-boot-fixtures"
    if not home.is_absolute() or os.path.realpath(str(parent)) != str(parent):
        raise RuntimeError("private fixture path alias refused")
    try:
        parent.mkdir(mode=0o700)
    except FileExistsError:
        pass
    metadata = os.lstat(parent)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() \
            or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeError("private fixture root custody refused")
    return parent


class BootFixture:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="prime-boot-identity-source-", dir=private_fixture_parent()))
        metadata = os.lstat(self.root)
        if os.path.realpath(str(self.root)) != str(self.root) or not stat.S_ISDIR(metadata.st_mode) \
                or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise RuntimeError("new private fixture custody refused")
        self.mirror = self.root / "installed"
        self.mirror.mkdir(mode=0o700)
        self.package = self.root / "package"
        self.owner = self.root / "owner-key"
        self.launcher = self.root / "launcher"
        self.override = self.root / "unit-overrides"
        for path in (self.package, self.owner, self.launcher, self.override):
            path.mkdir(mode=0o700)
        self.files = {}
        for installed, reference in SOURCE["BOOT_FILE_REFERENCES"].items():
            data = ("reviewed fixture: " + reference + "\n").encode()
            if installed == SOURCE["AURA_CONFIG"]:
                # Invented flat public bytes only; no real controller, signer,
                # enrollment, source database or Nostr verification claim.
                data = json.dumps({"version": 1, "kind": "synthetic-public-carrier/v1",
                    "source_id": "synthetic-gate", "key_sha256": "0" * 64}, sort_keys=True).encode()
            self.put(self.path(installed), data)
            digest = hashlib.sha256(data).hexdigest()
            self.files[installed] = {"source": reference, "source_sha256": digest, "sha256": digest}
        package_files = {}
        for name in (SOURCE["ENTRY"], "package.json", *SOURCE["OPERATOR_ENTRIES"].values()):
            data = b"// complete disposable gate fixture\n"
            self.put(self.package / name, data)
            package_files[name] = hashlib.sha256(data).hexdigest()
        self.owner_files = {}
        for name in SOURCE["OWNER_KEY_FILES"]:
            self.put(self.owner / name, b"// disposable owner-key fixture\n")
            self.owner_files[name] = hashlib.sha256((self.owner / name).read_bytes()).hexdigest()
        self.launcher_files = {}
        for name in SOURCE["LAUNCHER_SOURCE_PINS"]:
            self.put(self.launcher / name, b"// disposable launcher fixture\n")
            self.launcher_files[name] = hashlib.sha256((self.launcher / name).read_bytes()).hexdigest()
        self.epochs = self.root / "signer-epochs.json"
        self.put(self.epochs, json.dumps({"version": 1, "kind": "aukora-signer-epochs/v1",
            "epochs": [{"epoch": 1, "gate_pubkey_sha256": "0" * 64}]}).encode())
        self.node = self.root / "node"
        self.put(self.node, b"not executed: fixture Node anchor\n")
        self.manifest = {"version": 2, "kind": "aukora-gate-package/v2", "package": str(self.package),
            "entry": SOURCE["ENTRY"], "files": package_files,
            "external_files": {SOURCE["SIGNER_EPOCHS"]: hashlib.sha256(self.epochs.read_bytes()).hexdigest()},
            "profiles": {"launcher": {"root": str(self.launcher), "files": self.launcher_files},
                         "owner_key": {"root": str(self.owner), "files": self.owner_files}}}
        self.manifest["profiles"]["boot"] = {"kind": SOURCE["BOOT_KIND"], "files": self.files,
            "digest": SOURCE["boot_identity_digest"](self.manifest, self.files)}
        self.manifest_path = self.root / "manifest.json"
        self.write_manifest()
        self.ancestors = {(p.stat().st_dev, p.stat().st_ino) for p in self.root.parents}

    def path(self, installed):
        return self.mirror / installed.lstrip("/")

    def put(self, path, data):
        missing = []
        directory = path.parent
        while not directory.exists():
            missing.append(directory)
            directory = directory.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
        path.write_bytes(data)
        path.chmod(0o600)

    def write_manifest(self):
        self.put(self.manifest_path, json.dumps(self.manifest).encode())

    @contextmanager
    def custody(self, namespace=G):
        original_read = namespace["protected_read"]
        original_metadata = namespace["protected_metadata"]
        def fixture_metadata(metadata, directory=False):
            fields = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
            fields["st_uid"] = 0
            if directory and (metadata.st_dev, metadata.st_ino) in self.ancestors:
                fields["st_mode"] &= ~0o022
            original_metadata(SimpleNamespace(**fields), directory)
        def fixture_read(path, limit=SOURCE["MAX_FILE"]):
            if path in SOURCE["BOOT_FILE_REFERENCES"]:
                path = str(self.path(path))
            elif path == SOURCE["SIGNER_EPOCHS"]:
                path = str(self.epochs)
            return original_read(path, limit)
        with patch.dict(namespace, {"protected_metadata": fixture_metadata, "protected_read": fixture_read,
                "PACKAGE": str(self.package), "OWNER_KEY_ROOT": str(self.owner),
                "LAUNCHER_ROOT": str(self.launcher), "NODE": str(self.node),
                "MANIFEST": str(self.manifest_path), "__file__": SOURCE["BOOTSTRAP"],
                "OWNER_KEY_SOURCE_PINS": {name: self.owner_files[name] for name in SOURCE["OWNER_KEY_SOURCE_PINS"]},
                "LAUNCHER_SOURCE_PINS": self.launcher_files, "BOOT_OVERRIDE_ROOTS": (str(self.override),)}):
            yield

    def close(self):
        print("RETAINED_SOURCE_FIXTURE: " + str(self.root))


class BootIdentityChecks(unittest.TestCase):
    def setUp(self):
        self.world = BootFixture()

    def tearDown(self):
        self.world.close()

    def check(self, manifest=None, namespace=G):
        with self.world.custody(namespace):
            return namespace["verify_boot_profile"](self.world.manifest if manifest is None else manifest)

    def test_real_full_verifier_reaches_pure_boot_action_without_dispatch(self):
        with self.world.custody(), patch.object(sys, "argv", ["fixture", "check-boot"]), \
                patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                patch.object(os, "chdir") as chdir, patch.object(sys, "stdout", new_callable=io.StringIO) as output:
            self.assertEqual(SOURCE["main"](), 0)
        self.assertEqual(output.getvalue(), "BOOT_VERIFIED PrimeBootIdentity=" + self.world.manifest["profiles"]["boot"]["digest"] + "\n")
        dispatch.assert_not_called()
        chdir.assert_not_called()

    def test_fixed_action_rejects_every_extra_path_or_option(self):
        self.assertEqual(SOURCE["launch_arguments"](["check-boot"]), (None, ["check-boot"]))
        for extra in (str(self.world.root), "--manifest", "--skip", "--unsafe-preview"):
            with self.assertRaisesRegex(Refused, "launch-option"):
                SOURCE["launch_arguments"](["check-boot", extra])

    def test_readiness_seam_is_fixed_and_absent_boot_profile_fails_before_dispatch(self):
        self.assertEqual(SOURCE["launch_arguments"](["check-ready"]), (SOURCE["ENTRY"], ["check-ready"]))
        for extra in ("--run", str(self.world.root), "--skip"):
            with self.assertRaisesRegex(Refused, "launch-option"):
                SOURCE["launch_arguments"](["check-ready", extra])
        self.world.manifest["profiles"].pop("boot")
        self.world.write_manifest()
        with self.world.custody(), patch.object(sys, "argv", ["fixture", "check-ready"]), \
                patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
            self.assertEqual(SOURCE["main"](), 2)
        self.assertIn("boot-profile-unconfigured", refusal.getvalue())
        dispatch.assert_not_called()

    def test_readiness_dispatch_is_pinned_to_one_verified_package_client(self):
        with self.world.custody(), patch.object(sys, "argv", ["fixture", "check-ready"]), \
                patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                patch.object(os, "chdir") as chdir:
            self.assertEqual(SOURCE["main"](), 2)  # Mock exec returns; production replaces the process.
        dispatch.assert_called_once_with(str(self.world.node),
            [str(self.world.node), str(self.world.package / SOURCE["ENTRY"]), "check-ready"], SOURCE["node_environment"]({}))
        chdir.assert_called_once_with("/")

    def test_every_installed_code_unit_and_data_hash_refuses_changed_bytes(self):
        self.check()
        for installed in self.world.files:
            with self.subTest(installed=installed):
                path = self.world.path(installed)
                original = path.read_bytes()
                path.write_bytes(original + b"unreviewed change\n")
                with self.assertRaisesRegex(Refused, "boot-carrier-hash" if installed == SOURCE["AURA_CONFIG"] else "boot-hash"):
                    self.check()
                path.write_bytes(original)

    def gate_actions(self):
        return (["check-ready"], ["serve", "--home", "/home/aukora-gate", "--run", "/run/aukora-gate",
            "--target-root", "/var/lib/aukora-boundary/targets", "--gid", "1003"])

    def assert_gate_refused(self, expected, namespace=G):
        for action in self.gate_actions():
            with self.world.custody(namespace), patch.object(sys, "argv", ["fixture", *action]), \
                    patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                    patch.object(sys, "stdout", new_callable=io.StringIO) as output, \
                    patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                self.assertEqual(namespace["main"](), 2)
            self.assertIn(expected, refusal.getvalue())
            self.assertEqual(output.getvalue(), "")
            dispatch.assert_not_called()

    def test_gate_and_readiness_require_boot_without_optional_aura_profile(self):
        self.assertNotIn("aura", self.world.manifest["profiles"])
        self.world.manifest["profiles"].pop("boot")
        self.world.write_manifest()
        self.assert_gate_refused("boot-profile-unconfigured")
        # Existing nongate runtime preflight keeps its explicitly narrower scope.
        with self.world.custody(), patch.object(sys, "argv", ["fixture", "check-runtime"]), \
                patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                patch.object(sys, "stdout", new_callable=io.StringIO) as output:
            self.assertEqual(SOURCE["main"](), 0)
        self.assertEqual(output.getvalue(), "RUNTIME_VERIFIED\n")
        dispatch.assert_not_called()

    def test_public_carrier_inventory_omission_refuses_before_gate_or_readiness(self):
        self.world.manifest["profiles"]["boot"]["files"].pop(SOURCE["AURA_CONFIG"])
        self.world.manifest["profiles"]["boot"]["digest"] = SOURCE["boot_identity_digest"](
            self.world.manifest, self.world.manifest["profiles"]["boot"]["files"])
        self.world.write_manifest()
        self.assert_gate_refused("boot-inventory")

    def test_public_carrier_tamper_missing_links_and_mode_refuse_before_node(self):
        path = self.world.path(SOURCE["AURA_CONFIG"])
        reviewed = path.read_bytes()
        path.write_bytes(reviewed + b"\n ")
        self.assert_gate_refused("boot-carrier-hash")
        path.rename(self.world.root / "refused-carrier-changed-bytes")
        self.assert_gate_refused("protected-io")
        target = self.world.root / "retained-carrier-alias-target"
        self.world.put(target, reviewed)
        path.symlink_to(target)
        self.assert_gate_refused("protected-type")
        path.rename(self.world.root / "refused-carrier-symlink")
        os.link(target, path)
        self.assert_gate_refused("protected-hardlink")
        path.rename(self.world.root / "refused-carrier-hardlink")
        self.world.put(path, reviewed)
        path.chmod(0o620)
        self.assert_gate_refused("protected-mode")

    def test_named_public_carrier_hash_guard_detects_actual_dispatch_witness(self):
        text = (HERE / "gate-bootstrap.py").read_text()
        guard = 'require(hashlib.sha256(data).hexdigest() == profile["files"][AURA_CONFIG]["sha256"], "boot-carrier-hash")'
        self.assertEqual(text.count(guard), 1)
        mutant = {"__name__": "public_carrier_hash_guard_mutant", "__file__": str(HERE / "gate-bootstrap.py")}
        exec(compile(text.replace(guard, 'require(True, "disabled-fixture-carrier-hash-guard")'),
            "<public-carrier-single-guard-mutant>", "exec"), mutant)
        path = self.world.path(SOURCE["AURA_CONFIG"])
        path.write_bytes(path.read_bytes() + b"\n ")
        self.assert_gate_refused("boot-carrier-hash")
        for action in self.gate_actions():
            with self.world.custody(mutant), patch.object(sys, "argv", ["fixture", *action]), \
                    patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                    patch.object(os, "chdir") as chdir:
                self.assertEqual(mutant["main"](), 2)  # The actual exec seam returns only in this recorder.
            dispatch.assert_called_once_with(str(self.world.node),
                [str(self.world.node), str(self.world.package / SOURCE["ENTRY"]), *action], SOURCE["node_environment"]({}))
            chdir.assert_called_once_with("/")
        print("SOURCE-ONLY public-carrier-hash guard mutation: 1/1 killed; actual changed carrier bytes reach gate/readiness dispatch only after this exact guard is removed.")

    def test_missing_symlink_hardlink_and_writable_actual_helpers_refuse(self):
        installed = "/usr/local/lib/aukora-boundary/openshell/custody/sbx_exec_body.sh"
        path = self.world.path(installed)
        saved = path.read_bytes()
        path.rename(self.world.root / "missing-body-original")
        with self.assertRaises(FileNotFoundError):
            self.check()
        target = self.world.root / "alias-target"
        self.world.put(target, saved)
        path.symlink_to(target)
        with self.assertRaisesRegex(Refused, "protected-type"):
            self.check()
        path.rename(self.world.root / "refused-body-symlink")
        os.link(target, path)
        with self.assertRaisesRegex(Refused, "protected-hardlink"):
            self.check()
        path.rename(self.world.root / "refused-body-hardlink")
        self.world.put(path, saved)
        path.chmod(0o620)
        with self.assertRaisesRegex(Refused, "protected-mode"):
            self.check()

    def test_closed_inventory_refs_and_digest_removal_refuse(self):
        for mutation, expected in (
                (lambda m: m["profiles"]["boot"]["files"].pop(SOURCE["BOOTSTRAP"]), "boot-inventory"),
                (lambda m: m["profiles"]["boot"]["files"].update({"/tmp/extra": self.world.files[SOURCE["BOOTSTRAP"]]}), "boot-inventory"),
                (lambda m: m["profiles"]["boot"]["files"][SOURCE["BOOTSTRAP"]].update(source="workspace/candidate.py"), "boot-source-reference"),
                (lambda m: m["profiles"]["boot"]["files"][SOURCE["BOOTSTRAP"]].pop("source_sha256"), "boot-source-reference"),
                (lambda m: m["profiles"]["boot"].pop("digest"), "boot-profile"),
                (lambda m: m["profiles"].pop("boot"), "boot-profile-unconfigured")):
            candidate = copy.deepcopy(self.world.manifest)
            mutation(candidate)
            with self.assertRaisesRegex(Refused, expected):
                self.check(candidate)

    def test_digest_binds_whole_package_existing_profiles_and_public_epoch_map(self):
        for mutate in (
                lambda m: m["files"].update({SOURCE["ENTRY"]: "0" * 64}),
                lambda m: m["external_files"].update({SOURCE["SIGNER_EPOCHS"]: "0" * 64}),
                lambda m: m["profiles"]["launcher"]["files"].update({"upstream-dsh.json": "0" * 64}),
                lambda m: m["profiles"]["owner_key"]["files"].update({"package.json": "0" * 64}),
                lambda m: m["profiles"]["boot"]["files"][SOURCE["BOOTSTRAP"]].update(source_sha256="0" * 64)):
            candidate = copy.deepcopy(self.world.manifest)
            mutate(candidate)
            with self.assertRaisesRegex(Refused, "boot-digest"):
                self.check(candidate)

    def test_extra_local_unit_dropins_refuse_before_verification_success(self):
        for name in ("aukora-genesis.service.d", "aukora-.service.d", "service.d",
                     "aukora-genesis-failclosed@aukora-selfcheck.service.service.d",
                     "aukora-genesis.service", "aukora-genesis-failclosed@aukora-selfcheck.service.service"):
            path = self.world.override / name
            path.mkdir(mode=0o700)
            with self.assertRaisesRegex(Refused, "boot-unit-override"):
                self.check()
            path.rename(self.world.root / ("refused-unit-override-" + name))

    def test_missing_or_changed_manifest_never_reaches_success_or_dispatch(self):
        original = self.world.manifest_path.read_bytes()
        for data in (None, original.replace(b'"digest": "sha256:', b'"digest": "sha256:0')):
            if data is None:
                self.world.manifest_path.rename(self.world.root / "missing-manifest-original.json")
            else:
                self.world.put(self.world.manifest_path, data)
            with self.world.custody(), patch.object(sys, "argv", ["fixture", "check-boot"]), \
                    patch.dict(os.environ, {}, clear=True), patch.object(os, "execve") as dispatch, \
                    patch.object(sys, "stdout", new_callable=io.StringIO) as output, \
                    patch.object(sys, "stderr", new_callable=io.StringIO) as refusal:
                self.assertEqual(SOURCE["main"](), 2)
                self.assertTrue(refusal.getvalue().startswith("REFUSED:"))
                self.assertEqual(output.getvalue(), "")
                dispatch.assert_not_called()

    def test_unlisted_failure_instance_fragment_refuses_in_primary_unit_root(self):
        path = self.world.override / "aukora-genesis-failclosed@aukora-selfcheck.service.service"
        self.world.put(path, b"[Service]\nExecStart=/unreviewed/handler\n")
        with patch.dict(G, {"BOOT_SYSTEMD_ROOT": str(self.world.override)}):
            with self.assertRaisesRegex(Refused, "boot-unit-override"):
                self.check()

    def test_actual_tamper_detects_single_hash_and_digest_guard_removal(self):
        text = (HERE / "gate-bootstrap.py").read_text()
        mutations = {
            "hash": 'require(hashlib.sha256(data).hexdigest() == profile["files"][path]["sha256"], "boot-hash:" + path)',
            "digest": 'require(value["digest"] == boot_identity_digest(manifest, files), "boot-digest")',
        }
        for name, guard in mutations.items():
            self.assertEqual(text.count(guard), 1)
            mutant = {"__name__": "boot_identity_guard_mutant", "__file__": str(HERE / "gate-bootstrap.py")}
            exec(compile(text.replace(guard, 'require(True, "disabled-fixture-guard")'), "<boot-single-guard-mutant>", "exec"), mutant)
            if name == "hash":
                path = self.world.path(SOURCE["BOOTSTRAP"])
                original = path.read_bytes()
                path.write_bytes(b"changed actual installed fixture bytes\n")
                candidate = self.world.manifest
            else:
                candidate = copy.deepcopy(self.world.manifest)
                candidate["profiles"]["boot"]["digest"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(Refused, "boot-" + name):
                self.check(candidate)
            self.check(candidate, namespace=mutant)
            if name == "hash":
                path.write_bytes(original)

    def test_generator_reads_reviewed_source_and_public_data_once_into_deterministic_v2(self):
        generator = runpy.run_path(str(HERE / "generate-manifest.py"), run_name="boot_generator_source")
        namespace = generator["SOURCE"]["parse_manifest"].__globals__
        checkout = self.world.root / "reviewed-checkout"
        staged = self.world.root / "staged-boot"
        data_root = self.world.root / "reviewed-public-data"
        for path in (checkout, staged, data_root):
            path.mkdir(mode=0o700)
        # Real selected source files, including the actual closer/body and units.
        repo = HERE.parents[3]
        for installed, source in SOURCE["BOOT_SOURCE_FILES"].items():
            data = (repo / source).read_bytes()
            self.world.put(checkout / source, data)
            if installed == "/etc/systemd/system/aukora-boundary-gate.service":
                data = data.replace(b"--gid SKGATE_GID", b"--gid 1003")
            self.world.put(staged / installed.lstrip("/"), data)
        for installed in SOURCE["BOOT_DATA_FILES"]:
            data = self.world.path(installed).read_bytes()
            self.world.put(data_root / installed.lstrip("/"), data)
            self.world.put(staged / installed.lstrip("/"), data)
        outputs = [self.world.root / "boot-one.json", self.world.root / "boot-two.json"]
        argv = ["fixture", "--package", str(self.world.package), "--signer-epochs", str(self.world.epochs),
                "--owner-key", str(self.world.owner), "--launcher-checkout", str(self.world.launcher),
                "--boot-root", str(staged), "--boot-checkout", str(checkout),
                "--boot-data-root", str(data_root), "--skgate-gid", "1003", "--output"]
        with patch.dict(namespace, {
                "OWNER_KEY_SOURCE_PINS": {name: self.world.owner_files[name] for name in SOURCE["OWNER_KEY_SOURCE_PINS"]},
                "LAUNCHER_SOURCE_PINS": self.world.launcher_files}), \
                patch.object(sys, "stdout", new_callable=io.StringIO):
            for output in outputs:
                with patch.object(sys, "argv", argv + [str(output)]):
                    self.assertEqual(generator["main"](), 0)
        self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
        manifest = json.loads(outputs[0].read_bytes())
        profile = manifest["profiles"]["boot"]
        self.assertEqual(profile["digest"], SOURCE["boot_identity_digest"](manifest, profile["files"]))
        self.assertEqual(set(profile["files"]), set(SOURCE["BOOT_FILE_REFERENCES"]))
        self.assertEqual(len(profile["files"]), 32)
        carrier = profile["files"][SOURCE["AURA_CONFIG"]]
        self.assertEqual(carrier["source"], "operator-data:aura-context/v1")
        self.assertEqual(carrier["source_sha256"], carrier["sha256"])
        self.assertNotIn(str(self.world.root), outputs[0].read_text())
        gate_unit = profile["files"]["/etc/systemd/system/aukora-boundary-gate.service"]
        self.assertNotEqual(gate_unit["source_sha256"], gate_unit["sha256"])
        staging = generator["staging_boot_files"]
        extra = staged / "usr/local/lib/aukora-boundary/extra-executable"
        self.world.put(extra, b"unreviewed extra\n")
        with self.assertRaisesRegex(generator["SOURCE"]["Refused"], "staging-boot-inventory"):
            staging(str(staged), str(checkout), str(data_root), "1003")
        extra.rename(self.world.root / "refused-staged-extra-executable")
        for installed, expected in (("/usr/local/lib/aukora-boundary/sbx-exec", "staging-boot-source"),
                                    ("/etc/aukora-genesis/release.env", "staging-boot-data"),
                                    (SOURCE["AURA_CONFIG"], "staging-boot-data")):
            path = staged / installed.lstrip("/")
            original = path.read_bytes()
            path.write_bytes(original + b"unreviewed change\n")
            with self.assertRaisesRegex(generator["SOURCE"]["Refused"], expected):
                staging(str(staged), str(checkout), str(data_root), "1003")
            path.write_bytes(original)
        reviewed_carrier = data_root / SOURCE["AURA_CONFIG"].lstrip("/")
        retained = self.world.root / "missing-reviewed-carrier-original.json"
        reviewed_carrier.rename(retained)
        with self.assertRaisesRegex(generator["SOURCE"]["Refused"], "staging-boot-data-inventory"):
            staging(str(staged), str(checkout), str(data_root), "1003")
        retained.rename(reviewed_carrier)
        for gid in ("0", "01003", "1003;exit", "4294967295", "4294967296", "1" * 4301):
            with self.assertRaisesRegex(generator["SOURCE"]["Refused"], "staging-boot-gid"):
                staging(str(staged), str(checkout), str(data_root), gid)


if __name__ == "__main__":
    print("SOURCE-ONLY: production boot verifier with actual disposable files; synthetic UID0 custody; no installed qualification.")
    unittest.main()
