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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, help="reviewed complete staged package directory")
    parser.add_argument("--signer-epochs", required=True, help="staged public signer epoch map")
    parser.add_argument("--output", required=True, help="new staging file outside the package")
    options = parser.parse_args()
    try:
        require = SOURCE["require"]
        root, output = os.path.abspath(options.package), os.path.abspath(options.output)
        require(os.path.commonpath([root, output]) != root, "manifest-inside-package")
        require(os.path.realpath(os.path.dirname(output)) == os.path.dirname(output), "output-parent-alias")
        epoch_data = staging_read(options.signer_epochs)
        SOURCE["validate_signer_epochs"](epoch_data)
        manifest = {"version": 1, "kind": "aukora-gate-package/v1", "package": SOURCE["PACKAGE"],
                    "entry": SOURCE["ENTRY"], "files": staging_inventory(root),
                    "external_files": {SOURCE["SIGNER_EPOCHS"]: hashlib.sha256(epoch_data).hexdigest()}}
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
