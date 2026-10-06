#!/usr/bin/python3
"""Deterministic operator staging recipe; never installs. AGPL-3.0-or-later."""

import argparse
import hashlib
import json
import os
import runpy
import stat
import sys

SOURCE = runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate-bootstrap.py"), run_name="gate_bootstrap_source")


def staging_read(path):
    before = os.lstat(path)
    SOURCE["require"](stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "staging-regular-file")
    SOURCE["require"](before.st_size <= SOURCE["MAX_FILE"], "staging-size")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        SOURCE["require"](SOURCE["identity"](before) == SOURCE["identity"](opened), "staging-open-identity")
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            SOURCE["require"](count <= SOURCE["MAX_FILE"], "staging-size")
        SOURCE["require"](SOURCE["identity"](opened) == SOURCE["identity"](os.fstat(fd)) and count == opened.st_size, "staging-read-identity")
        return b"".join(chunks)
    finally:
        os.close(fd)


def staging_inventory(root):
    require = SOURCE["require"]
    require(os.path.isabs(root) and os.path.realpath(root) == root, "staging-root-alias")
    result, total = {}, 0
    def walk(directory, prefix):
        nonlocal total
        require(stat.S_ISDIR(os.lstat(directory).st_mode), "staging-directory")
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                name = prefix + entry.name
                require(SOURCE["relative_name"](name), "staging-name")
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    walk(entry.path, name + "/")
                else:
                    data = staging_read(entry.path)
                    total += len(data)
                    require(total <= SOURCE["MAX_TOTAL"], "staging-size")
                    result[name] = hashlib.sha256(data).hexdigest()
                    require(len(result) <= SOURCE["MAX_FILES"], "staging-count")
    walk(root, "")
    return result


def staging_launcher_files(root):
    # Deliberately read only the reviewed six paths, not the checkout tree.
    require = SOURCE["require"]
    require(stat.S_ISDIR(os.lstat(root).st_mode), "staging-directory")
    files, total = {}, 0
    for name in sorted(SOURCE["LAUNCHER_SOURCE_PINS"]):
        require(SOURCE["closure_name"](name), "staging-name")
        directory = root
        for part in name.split("/")[:-1]:
            directory += "/" + part
            require(stat.S_ISDIR(os.lstat(directory).st_mode), "staging-directory")
        data = staging_read(root + "/" + name)
        total += len(data)
        require(total <= SOURCE["MAX_TOTAL"], "staging-size")
        files[name] = hashlib.sha256(data).hexdigest()
    return files


def staging_named_read(root, name):
    require = SOURCE["require"]
    # The fixed boot map includes systemd's literal @.service template syntax;
    # the launcher/Aura profile grammars keep their existing narrower rules.
    require(SOURCE["relative_name"](name), "staging-name")
    directory = root
    require(stat.S_ISDIR(os.lstat(directory).st_mode), "staging-directory")
    for part in name.split("/")[:-1]:
        directory += "/" + part
        require(stat.S_ISDIR(os.lstat(directory).st_mode), "staging-directory")
    return staging_read(root + "/" + name)


def staging_boot_files(root, checkout, data_root, skgate_gid):
    """Inspect a complete disposable mirror, never the installed host paths."""
    require = SOURCE["require"]
    expected = {path.lstrip("/") for path in SOURCE["BOOT_FILE_REFERENCES"]}
    require(set(staging_inventory(root)) == expected, "staging-boot-inventory")
    require(set(staging_inventory(data_root)) == {path.lstrip("/") for path in SOURCE["BOOT_DATA_FILES"]}, "staging-boot-data-inventory")
    references = {}
    for path, source in sorted(SOURCE["BOOT_SOURCE_FILES"].items()):
        reviewed = staging_named_read(checkout, source)
        materialized = staging_named_read(root, path.lstrip("/"))
        if path == "/etc/systemd/system/aukora-boundary-gate.service":
            require(skgate_gid is not None and len(skgate_gid) <= 10 and skgate_gid.isascii() and skgate_gid.isdecimal()
                    and str(int(skgate_gid)) == skgate_gid and 0 < int(skgate_gid) <= 4294967294, "staging-boot-gid")
            require(reviewed.count(b"--gid SKGATE_GID") == 1, "staging-boot-gid-template")
            approved = reviewed.replace(b"--gid SKGATE_GID", b"--gid " + skgate_gid.encode("ascii"))
        else:
            approved = reviewed
        require(materialized == approved, "staging-boot-source:" + source)
        references[path] = {"source": source, "source_sha256": hashlib.sha256(reviewed).hexdigest(),
                            "sha256": hashlib.sha256(materialized).hexdigest()}
    for path, source in sorted(SOURCE["BOOT_DATA_FILES"].items()):
        reviewed = staging_named_read(data_root, path.lstrip("/"))
        materialized = staging_named_read(root, path.lstrip("/"))
        require(materialized == reviewed, "staging-boot-data:" + path)
        digest = hashlib.sha256(reviewed).hexdigest()
        references[path] = {"source": source, "source_sha256": digest, "sha256": digest}
    return references


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, help="reviewed complete staged package directory")
    parser.add_argument("--signer-epochs", required=True, help="staged public signer epoch map")
    parser.add_argument("--owner-key", help="reviewed complete staged owner-key package; selects v2")
    parser.add_argument("--launcher-checkout", help="staged checkout containing six reviewed inputs; mandatory for v2, no launcher execution")
    parser.add_argument("--aura-source", help="exact reviewed complete staged Aura source; requires owner-key and aura-context")
    parser.add_argument("--aura-context", help="staged public Aura configuration; no private signer reads")
    parser.add_argument("--boot-root", help="complete staged mirror of the fixed installed boot closure; requires v2")
    parser.add_argument("--boot-checkout", help="reviewed checkout for boot source references; never executed")
    parser.add_argument("--boot-data-root", help="reviewed public operator-data mirror for every fixed boot data path; no private keys")
    parser.add_argument("--skgate-gid", help="verified existing numeric skgate GID used only to materialize the gate unit")
    parser.add_argument("--output", required=True, help="new staging file outside the package")
    options = parser.parse_args()
    try:
        require = SOURCE["require"]
        root, output = os.path.abspath(options.package), os.path.abspath(options.output)
        installed_roots = (SOURCE["PACKAGE"], SOURCE["AURA_ROOT"], SOURCE["OWNER_KEY_ROOT"],
                           os.path.dirname(SOURCE["MANIFEST"]), os.path.dirname(SOURCE["BOOTSTRAP"]),
                           os.path.dirname(SOURCE["NODE"]), SOURCE["LAUNCHER_ROOT"],
                           *(os.path.dirname(path) for path in SOURCE["BOOT_FILE_REFERENCES"]))
        require(all(os.path.commonpath([installed, output]) != installed for installed in installed_roots), "manifest-installed-path")
        for supplied in (options.package, options.signer_epochs, options.owner_key, options.aura_source,
                         options.aura_context, options.launcher_checkout, options.boot_root, options.boot_checkout, options.boot_data_root):
            if supplied is None:
                continue
            require(SOURCE["aura_data_path"](supplied), "staging-input-path")
            require(all(os.path.commonpath([installed, supplied]) not in (installed, supplied)
                        for installed in installed_roots), "staging-installed-path")
            require(os.path.realpath(supplied) == supplied, "staging-input-path")
        require(os.path.commonpath([root, output]) != root, "manifest-inside-package")
        owner_root = os.path.abspath(options.owner_key) if options.owner_key else None
        require(owner_root is None or options.launcher_checkout is not None, "staging-launcher-required")
        require(bool(options.aura_source) == bool(options.aura_context), "staging-aura-required")
        require(not options.aura_source or owner_root is not None, "staging-aura-owner-key-required")
        require(bool(options.boot_root) == bool(options.boot_checkout) == bool(options.boot_data_root)
                == bool(options.skgate_gid), "staging-boot-required")
        require(not options.boot_root or owner_root is not None, "staging-boot-owner-key-required")
        aura_root = os.path.abspath(options.aura_source) if options.aura_source else None
        launcher_root = os.path.abspath(options.launcher_checkout) if options.launcher_checkout else None
        boot_root = os.path.abspath(options.boot_root) if options.boot_root else None
        boot_checkout = os.path.abspath(options.boot_checkout) if options.boot_checkout else None
        boot_data_root = os.path.abspath(options.boot_data_root) if options.boot_data_root else None
        for staged_boot in (boot_root, boot_checkout, boot_data_root):
            if staged_boot is not None:
                require(os.path.commonpath([staged_boot, output]) != staged_boot, "manifest-inside-profile")
        if boot_root is not None:
            require(all(os.path.commonpath([boot_root, staged]) not in (boot_root, staged)
                        for staged in (root, owner_root, aura_root, launcher_root, boot_checkout, boot_data_root) if staged is not None), "staging-profile-overlap")
        if launcher_root is not None:
            require(os.path.commonpath([launcher_root, output]) != launcher_root, "manifest-inside-profile")
            require(all(os.path.commonpath([launcher_root, staged]) not in (launcher_root, staged)
                        for staged in (root, owner_root, aura_root) if staged is not None), "staging-profile-overlap")
        if owner_root is not None:
            require(os.path.commonpath([owner_root, output]) != owner_root, "manifest-inside-profile")
            require(os.path.commonpath([owner_root, root]) not in (owner_root, root), "staging-profile-overlap")
        if aura_root is not None:
            require(os.path.commonpath([aura_root, output]) != aura_root, "manifest-inside-profile")
            require(all(os.path.commonpath([aura_root, staged]) not in (aura_root, staged)
                        for staged in (root, owner_root)), "staging-profile-overlap")
        require(os.path.realpath(os.path.dirname(output)) == os.path.dirname(output), "output-parent-alias")
        epoch_data = staging_read(options.signer_epochs)
        SOURCE["validate_signer_epochs"](epoch_data)
        manifest = {"version": 1, "kind": "aukora-gate-package/v1", "package": SOURCE["PACKAGE"],
                    "entry": SOURCE["ENTRY"], "files": staging_inventory(root),
                    "external_files": {SOURCE["SIGNER_EPOCHS"]: hashlib.sha256(epoch_data).hexdigest()}}
        if launcher_root is not None:
            launcher_profile = {"root": SOURCE["LAUNCHER_ROOT"], "files": staging_launcher_files(launcher_root)}
            SOURCE["validate_launcher_profile"](launcher_profile)
            manifest.update(version=2, kind="aukora-gate-package/v2", profiles={"launcher": launcher_profile})
        if owner_root is not None:
            owner_profile = {"root": SOURCE["OWNER_KEY_ROOT"], "files": staging_inventory(owner_root)}
            SOURCE["validate_owner_key_profile"](owner_profile)
            manifest["profiles"]["owner_key"] = owner_profile
        if aura_root is not None:
            configuration = staging_read(options.aura_context)
            SOURCE["validate_aura_context"](configuration)
            aura_profile = {"root": SOURCE["AURA_ROOT"], "entry": SOURCE["AURA_ENTRY"],
                            "files": staging_inventory(aura_root),
                            "configuration": {"path": SOURCE["AURA_CONFIG"], "sha256": hashlib.sha256(configuration).hexdigest()}}
            SOURCE["validate_aura_profile"](aura_profile)
            manifest["profiles"]["aura"] = aura_profile
        if boot_root is not None:
            boot_files = staging_boot_files(boot_root, boot_checkout, boot_data_root, options.skgate_gid)
            manifest["profiles"]["boot"] = {"kind": SOURCE["BOOT_KIND"], "files": boot_files,
                "digest": SOURCE["boot_identity_digest"](manifest, boot_files)}
        encoded = (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        SOURCE["parse_manifest"](encoded)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
        print("SOURCE-ONLY staged manifest: " + str(len(manifest["files"])) + " package files; no installation performed")
        return 0
    except (SOURCE["Refused"], OSError) as error:
        print("REFUSED: " + (str(error) if isinstance(error, SOURCE["Refused"]) else "staging-io"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
