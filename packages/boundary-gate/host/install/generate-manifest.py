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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, help="reviewed complete staged package directory")
    parser.add_argument("--signer-epochs", required=True, help="staged public signer epoch map")
    parser.add_argument("--owner-key", help="reviewed complete staged owner-key package; selects v2")
    parser.add_argument("--launcher-checkout", help="staged checkout containing six reviewed inputs; mandatory for v2, no launcher execution")
    parser.add_argument("--aura-source", help="exact reviewed complete staged Aura source; requires owner-key and aura-context")
    parser.add_argument("--aura-context", help="staged public Aura configuration; no private signer reads")
    parser.add_argument("--output", required=True, help="new staging file outside the package")
    options = parser.parse_args()
    try:
        require = SOURCE["require"]
        root, output = os.path.abspath(options.package), os.path.abspath(options.output)
        installed_roots = (SOURCE["PACKAGE"], SOURCE["AURA_ROOT"], SOURCE["OWNER_KEY_ROOT"],
                           os.path.dirname(SOURCE["MANIFEST"]), os.path.dirname(SOURCE["BOOTSTRAP"]),
                           os.path.dirname(SOURCE["NODE"]), SOURCE["LAUNCHER_ROOT"])
        require(all(os.path.commonpath([installed, output]) != installed for installed in installed_roots), "manifest-installed-path")
        for supplied in (options.package, options.signer_epochs, options.owner_key, options.aura_source,
                         options.aura_context, options.launcher_checkout):
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
        aura_root = os.path.abspath(options.aura_source) if options.aura_source else None
        launcher_root = os.path.abspath(options.launcher_checkout) if options.launcher_checkout else None
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
