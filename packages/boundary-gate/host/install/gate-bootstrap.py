#!/usr/bin/python3
"""Root-custodied pre-Node gate launcher. AGPL-3.0-or-later.

Install this reviewed file extensionless at BOOTSTRAP and invoke fixed Python
with -I -S. Production has no path, UID, manifest, or fixture overrides.
"""

import hashlib
import json
import os
import re
import stat
import sys

BOOTSTRAP = "/usr/local/lib/aukora-boundary/gate-bootstrap"
PYTHON = "/usr/bin/python3"
NODE = "/opt/aukora-node/bin/node"
PACKAGE = "/opt/aukora-boundary-gate"
ENTRY = "bin/gate.mjs"
OPERATOR_ENTRIES = {"floor": "bin/release-floor.mjs", "approval": "bin/plugin-set-approval.mjs"}
MANIFEST = "/etc/aukora-boundary-gate/gate-package-manifest.json"
SIGNER_EPOCHS = "/etc/aukora-boundary-gate/signer-epochs.json"
EXTERNAL_FILES = (SIGNER_EPOCHS,)
MAX_FILE = 8 * 1024 * 1024
MAX_FILES = 4096
MAX_TOTAL = 64 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def protected_metadata(metadata, directory=False):
    """Pure metadata validator; source fixtures supply synthetic root metadata."""
    require(metadata.st_uid == 0, "protected-owner")
    require(metadata.st_mode & 0o022 == 0, "protected-mode")
    require(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode), "protected-type")
    if not directory:
        require(metadata.st_nlink == 1, "protected-hardlink")


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def canonical_absolute(path):
    return (isinstance(path, str) and path.startswith("/") and not path.startswith("//")
            and os.path.normpath(path) == path and "\x00" not in path)


def protected_directory(path):
    require(canonical_absolute(path), "protected-path")
    before = os.lstat(path)
    protected_metadata(before, directory=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        protected_metadata(opened, directory=True)
        require(identity(before) == identity(opened), "protected-open-identity")
    finally:
        os.close(fd)


def protected_ancestors(path):
    require(canonical_absolute(path), "protected-path")
    protected_directory("/")
    parent = os.path.dirname(path)
    current = ""
    for part in parent.split("/")[1:]:
        current += "/" + part
        protected_directory(current)


def protected_open(path):
    protected_ancestors(path)
    before = os.lstat(path)
    protected_metadata(before)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        protected_metadata(opened)
        require(identity(before) == identity(opened), "protected-open-identity")
        return fd, opened
    except BaseException:
        os.close(fd)
        raise


def protected_read(path, limit=MAX_FILE):
    fd, opened = protected_open(path)
    try:
        require(opened.st_size <= limit, "protected-size")
        pieces, count = [], 0
        while True:
            piece = os.read(fd, min(65536, limit + 1 - count))
            if not piece:
                break
            pieces.append(piece)
            count += len(piece)
            require(count <= limit, "protected-size")
        require(identity(opened) == identity(os.fstat(fd)), "protected-read-identity")
        require(count == opened.st_size, "protected-short-read")
        return b"".join(pieces)
    finally:
        os.close(fd)


def no_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "json-duplicate-key")
        value[key] = item
    return value


def closed_json(data):
    def invalid_constant(_value):
        raise Refused("json-number")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicate_keys,
                          parse_constant=invalid_constant)
    except (UnicodeError, ValueError, TypeError) as error:
        raise Refused("json-format") from error


def relative_name(name):
    return (isinstance(name, str) and bool(name) and not name.startswith("/")
            and "\\" not in name and all(ord(c) >= 32 and ord(c) != 127 for c in name)
            and all(part not in ("", ".", "..") for part in name.split("/")))


def hash_mapping(value, absolute=False):
    require(isinstance(value, dict) and 0 < len(value) <= MAX_FILES, "manifest-files")
    for name, digest in value.items():
        require(canonical_absolute(name) if absolute else relative_name(name), "manifest-path")
        require(isinstance(digest, str) and SHA256.fullmatch(digest), "manifest-sha256")
    return value


def parse_manifest(data):
    value = closed_json(data)
    require(isinstance(value, dict) and set(value) == {"version", "kind", "package", "entry", "files", "external_files"}, "manifest-format")
    require(type(value["version"]) is int and value["version"] == 1
            and value["kind"] == "aukora-gate-package/v1" and value["package"] == PACKAGE
            and value["entry"] == ENTRY, "manifest-format")
    files = hash_mapping(value["files"])
    require({ENTRY, "package.json", *OPERATOR_ENTRIES.values()} <= set(files), "manifest-required-source")
    external = hash_mapping(value["external_files"], absolute=True)
    require(set(external) == set(EXTERNAL_FILES), "manifest-external-files")
    return value


def package_inventory(root):
    """Closed regular-file inventory; all symlinks, hardlinks and specials refuse."""
    protected_ancestors(root)
    names = []
    def walk(directory, prefix):
        protected_directory(directory)
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                name = prefix + entry.name
                require(relative_name(name), "package-path")
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    protected_metadata(metadata, directory=True)
                    walk(entry.path, name + "/")
                else:
                    protected_metadata(metadata)
                    names.append(name)
                    require(len(names) <= MAX_FILES, "package-count")
    walk(root, "")
    return names


def verify_package(root, files):
    """Path-parametrized algorithm used by source fixtures; production fixes root."""
    require(set(package_inventory(root)) == set(files), "package-inventory")
    total = 0
    for name in sorted(files):
        require(relative_name(name), "manifest-path")
        data = protected_read(root + "/" + name)
        total += len(data)
        require(total <= MAX_TOTAL, "package-size")
        require(hashlib.sha256(data).hexdigest() == files[name], "package-hash:" + name)


def validate_signer_epochs(data):
    require(len(data) <= 16384, "signer-epochs-format")
    value = closed_json(data)
    require(isinstance(value, dict) and set(value) == {"version", "kind", "epochs"}
            and type(value["version"]) is int and value["version"] == 1
            and value["kind"] == "aukora-signer-epochs/v1"
            and isinstance(value["epochs"], list) and 0 < len(value["epochs"]) <= 64, "signer-epochs-format")
    previous, hashes = 0, set()
    for row in value["epochs"]:
        require(isinstance(row, dict) and set(row) == {"epoch", "gate_pubkey_sha256"}, "signer-epochs-format")
        epoch, digest = row["epoch"], row["gate_pubkey_sha256"]
        require(type(epoch) is int and epoch == previous + 1 and epoch <= 9007199254740991
                and isinstance(digest, str) and SHA256.fullmatch(digest) and digest not in hashes, "signer-epochs-format")
        previous = epoch
        hashes.add(digest)
    return value


def serve_arguments(arguments):
    if arguments and arguments[0] == "aura":
        raise Refused("aura-context-unconfigured")
    require(arguments and arguments[0] == "serve", "launch-action")
    fixed = {"--home": "/home/aukora-gate", "--run": "/run/aukora-gate",
             "--target-root": "/var/lib/aukora-boundary/targets", "--releases-root": "/opt/aukora-genesis"}
    seen, index = set(), 1
    while index < len(arguments):
        name = arguments[index]
        require(name not in seen, "launch-duplicate")
        seen.add(name)
        if name == "--owner-page":
            index += 1
            continue
        require(name in fixed or name in ("--port", "--gid", "--time-zone"), "launch-option")
        require(index + 1 < len(arguments), "launch-value")
        value = arguments[index + 1]
        if name in fixed:
            require(value == fixed[name], "launch-fixed-path")
        elif name in ("--port", "--gid"):
            require(re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is not None, "launch-number")
            require(1 <= int(value) <= 65535 if name == "--port" else 1 <= int(value) <= 4294967294, "launch-number")
        else:
            require(len(value) <= 128 and (value == "UTC" or re.fullmatch(r"[A-Za-z_]+(?:/[A-Za-z0-9_+-]+){1,3}", value) is not None), "launch-time-zone")
        index += 2
    require({"--home", "--run", "--target-root", "--gid"} <= seen, "launch-required")
    return list(arguments)


def operator_arguments(arguments):
    role, action = arguments[0], arguments[1] if len(arguments) > 1 else None
    options = {
        ("floor", "show"): {"--floor"},
        ("floor", "check"): {"--floor", "--release-dir", "--approval-state-root"},
        ("floor", "migrate-clock-floor"): {"--floor", "--release-dir", "--approval-state-root"},
        ("approval", "show"): {"--release-dir", "--operation"},
        ("approval", "raise"): {"--release-dir", "--operation", "--run", "--floor"},
        ("approval", "install"): {"--release-dir", "--operation", "--run", "--floor", "--out", "--target-root", "--repin"},
    }
    options[("approval", "migrate-clock-floor")] = options[("approval", "install")]
    options[("approval", "recover-cache")] = options[("approval", "install")]
    require((role, action) in options, "launch-action")
    seen, index = set(), 2
    fixed = {"--floor": "/etc/aukora-approvals/release-floor.json", "--run": "/run/aukora-gate",
             "--target-root": "/var/lib/aukora-boundary/targets"}
    patterns = {"--release-dir": r"/opt/aukora-genesis/release-[0-9a-f]{7}",
                "--approval-state-root": r"/etc/aukora-approvals/[0-9a-f]{40}(?:[0-9a-f]{24})?/state",
                "--out": r"/etc/aukora-approvals/[0-9a-f]{40}(?:[0-9a-f]{24})?/state/gate-state",
                "--operation": r"[0-9a-f]{64}"}
    while index < len(arguments):
        name = arguments[index]
        require(name in options[(role, action)], "launch-option")
        require(name not in seen, "launch-duplicate")
        seen.add(name)
        if name == "--repin":
            index += 1
            continue
        require(index + 1 < len(arguments), "launch-value")
        value = arguments[index + 1]
        require(value == fixed[name] if name in fixed else re.fullmatch(patterns[name], value) is not None, "launch-fixed-path")
        index += 2
    required = set()
    if role == "approval" or action != "show":
        required.add("--release-dir")
    if role == "floor" and action != "show":
        required.add("--approval-state-root")
    if role == "approval" and action in ("install", "migrate-clock-floor", "recover-cache"):
        required.add("--out")
    require(required <= seen, "launch-required")
    return OPERATOR_ENTRIES[role], list(arguments[1:])


def launch_arguments(arguments):
    require(bool(arguments), "launch-action")
    if arguments[0] == "check-package":
        require(len(arguments) == 1, "launch-option")
        return None, []
    if arguments[0] in OPERATOR_ENTRIES:
        return operator_arguments(arguments)
    return ENTRY, serve_arguments(arguments)


def node_environment(environment):
    # Inherited configuration and loader settings never become gate inputs.
    for name in environment:
        normalized = re.sub(r"[^a-z]", "", name.lower())
        require("unsafepreview" not in normalized, "unsafe-preview-environment")
    return {"PATH": "/opt/aukora-node/bin:/usr/bin:/bin", "HOME": "/home/aukora-gate",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def refuse_preview_fields(value):
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z]", "", key.lower())
            require("unsafepreview" not in normalized, "unsafe-preview-config")
            refuse_preview_fields(item)
    elif isinstance(value, list):
        for item in value:
            refuse_preview_fields(item)


def validate_aura_context(data):
    value = closed_json(data)
    refuse_preview_fields(value)
    # No Aura launch or context interpretation exists before its exact closed
    # protected-context, fixed-entry and transitive custody contract is reviewed.
    raise Refused("aura-context-unconfigured")


def verify_external_files(pins):
    external = {}
    for path in EXTERNAL_FILES:
        data = protected_read(path, limit=16384)
        require(hashlib.sha256(data).hexdigest() == pins[path], "external-hash")
        external[path] = data
    validate_signer_epochs(external[SIGNER_EPOCHS])
    return external


def verify_installation():
    # This function only uses named operator paths. No candidate code is imported.
    require(os.path.abspath(__file__) == BOOTSTRAP, "bootstrap-entrypoint")
    protected_read(BOOTSTRAP)
    # Distro Python may be a root-managed interpreter symlink. The interpreter,
    # stdlib, system loader and protected service launch are external anchors.
    protected_ancestors(PYTHON)
    fd, _metadata = protected_open(NODE)
    os.close(fd)
    manifest = parse_manifest(protected_read(MANIFEST, limit=2 * 1024 * 1024))
    verify_package(PACKAGE, manifest["files"])
    verify_external_files(manifest["external_files"])


def main():
    try:
        require(sys.flags.isolated == 1 and sys.flags.no_site == 1, "python-isolation")
        entry, arguments = launch_arguments(sys.argv[1:])
        environment = node_environment(os.environ)
        verify_installation()
        if entry is None:
            print("PACKAGE_VERIFIED")
            return 0
        os.chdir("/")
        os.execve(NODE, [NODE, PACKAGE + "/" + entry] + arguments, environment)
    except (Refused, OSError) as error:
        code = str(error) if isinstance(error, Refused) else "protected-io"
        print("REFUSED: " + code, file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
