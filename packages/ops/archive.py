#!/usr/bin/env python3
"""Deterministic Prime packages and DATA-ONLY export recovery staging. No network."""
import argparse
import hashlib
import io
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile

DOMAIN = b"aukora-prime:artifact:v1\0"
MANIFEST = "prime-artifact.json"
LIMIT = 8 * 1024**3
MAX_FILES = 200000
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
SENSITIVE = re.compile(r"(^|/)(\.git|\.ssh|\.aws|\.env(?:\..*)?|credentials|id_(?:rsa|ed25519)|.*\.(?:pem|key|p12|pfx))($|/)", re.I)
AUTHORITY = re.compile(r"(^|/)(authority-state|nonce-book|spent-grants|signer-state|private-memory)(/|$)", re.I)

class Refusal(ValueError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()

def digest(data):
    return hashlib.sha256(data).hexdigest()

def safe_name(name):
    if not isinstance(name, str) or CONTROL.search(name):
        raise Refusal("INVALID_ARTIFACT_PATH")
    p = PurePosixPath(name)
    if not name or p.is_absolute() or ".." in p.parts or "\\" in name or "\x00" in name or name != p.as_posix():
        raise Refusal("INVALID_ARTIFACT_PATH")
    if SENSITIVE.search(name) or AUTHORITY.search(name):
        raise Refusal("SENSITIVE_OR_AUTHORITY_PATH")
    return name

def safe_io_path(value):
    text = os.fspath(value)
    if not isinstance(text, str) or CONTROL.search(text):
        raise Refusal("ARTIFACT_PATH_CONTROL_CHARACTER")
    if CONTROL.search(str(Path(text).resolve())):
        raise Refusal("ARTIFACT_PATH_CONTROL_CHARACTER")
    return value

def safe_link_target(target):
    if isinstance(target, str) and CONTROL.search(target):
        raise Refusal("RELEASE_LINK_CONTROL_CHARACTER")
    if not isinstance(target, str) or not target or posixpath.isabs(target) or "\\" in target:
        raise Refusal("RELEASE_LINK_ESCAPES_ROOT")
    return target

def safe_bytes(data):
    if re.search(rb"(?m)^-----BEGIN (?:(?:OPENSSH|RSA|EC|DSA|ENCRYPTED) )?PRIVATE KEY-----\r?$", data):
        raise Refusal("PRIVATE_KEY_MATERIAL")

def inventory(root, kind):
    safe_io_path(root)
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise Refusal("ROOT_MUST_BE_REAL_DIRECTORY")
    root = root.resolve(strict=True)
    safe_io_path(root)
    rows, total = [], 0
    def link_row(path, rel):
        if kind != "release":
            raise Refusal("SYMLINK_IN_MEMORY_EXPORT")
        target = safe_link_target(os.readlink(path))
        resolved = path.resolve(strict=True)
        if os.path.isabs(target) or "\\" in target or (resolved != root and root not in resolved.parents):
            raise Refusal("RELEASE_LINK_ESCAPES_ROOT")
        rows.append({"path": rel, "type": "l", "target": target, "mode": 0o777})
    for parent, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(parent) / name
            rel = safe_name(path.relative_to(root).as_posix())
            if path.is_symlink():
                link_row(path, rel)
        for name in names:
            path = Path(parent) / name
            rel = safe_name(path.relative_to(root).as_posix())
            if rel == MANIFEST:
                raise Refusal("RESERVED_MANIFEST_PATH")
            st = path.lstat()
            if stat.S_ISLNK(st.st_mode):
                link_row(path, rel)
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise Refusal("NONREGULAR_OR_HARDLINK_FILE")
            data = path.read_bytes()
            safe_bytes(data)
            total += len(data)
            if total > LIMIT or len(rows) >= MAX_FILES:
                raise Refusal("ARTIFACT_BUDGET_EXCEEDED")
            rows.append({"path": rel, "type": "f", "sha256": digest(data), "size": len(data), "mode": 0o755 if st.st_mode & 0o111 else 0o644})
    return sorted(rows, key=lambda r: r["path"])

def build_manifest(root, kind, version, commit, recipe):
    if kind not in ("release", "memory-export"):
        raise Refusal("INVALID_ARTIFACT_KIND")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise Refusal("FULL_SOURCE_COMMIT_REQUIRED")
    if not isinstance(recipe, dict) or not recipe:
        raise Refusal("EXPLICIT_BUILD_RECIPE_REQUIRED")
    rows = inventory(root, kind)
    if len(rows) > MAX_FILES:
        raise Refusal("ARTIFACT_BUDGET_EXCEEDED")
    validate_links(rows, kind)
    value = {"schema": "prime-artifact-v1", "kind": kind, "version": version, "source_commit": commit,
             "build_recipe": recipe, "files": rows, "restore_authority": False}
    value["artifact_digest"] = digest(DOMAIN + canonical(value))
    return value

def info(name, size, mode):
    safe_name(name)
    item = tarfile.TarInfo(name)
    item.size, item.mode, item.mtime = size, mode, 0
    item.uid = item.gid = 0
    item.uname = item.gname = ""
    return item

def package(root, out, kind, version, commit, recipe):
    safe_io_path(root); safe_io_path(out)
    root, out = Path(root).resolve(), Path(out).absolute()
    safe_io_path(root); safe_io_path(out)
    if out.exists() or root == out.parent or root in out.parents:
        raise Refusal("OUTPUT_MUST_BE_NEW_AND_OUTSIDE_INPUT")
    value = build_manifest(root, kind, version, commit, recipe)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".prime-artifact-", dir=out.parent)
    try:
        with os.fdopen(fd, "wb") as handle, tarfile.open(fileobj=handle, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            data = canonical(value)
            archive.addfile(info(MANIFEST, len(data), 0o644), io.BytesIO(data))
            for row in value["files"]:
                path = root / row["path"]
                if row["type"] == "l":
                    if not path.is_symlink() or os.readlink(path) != row["target"]:
                        raise Refusal("SOURCE_CHANGED_DURING_PACKAGE")
                    item = info(row["path"], 0, 0o777)
                    item.type, item.linkname = tarfile.SYMTYPE, row["target"]
                    archive.addfile(item)
                    continue
                st = path.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise Refusal("SOURCE_CHANGED_DURING_PACKAGE")
                data = path.read_bytes()
                if digest(data) != row["sha256"] or len(data) != row["size"] or (0o755 if st.st_mode & 0o111 else 0o644) != row["mode"]:
                    raise Refusal("SOURCE_CHANGED_DURING_PACKAGE")
                archive.addfile(info(row["path"], len(data), row["mode"]), io.BytesIO(data))
            handle.flush()
            os.fsync(handle.fileno())
        # Never replace an existing artifact, including after a concurrent creator.
        os.link(temp, out)
    finally:
        Path(temp).unlink(missing_ok=True)
    return {"status": "PACKAGED", "artifact": str(out), "artifact_digest": value["artifact_digest"], "archive_sha256": digest(out.read_bytes()), "files": len(value["files"])}

def validate_links(rows, kind):
    for row in rows:
        safe_name(row["path"])
        if row.get("type") == "l":
            safe_link_target(row["target"])
    names = {r["path"] for r in rows}
    links = {r["path"]: r["target"] for r in rows if r.get("type") == "l"}
    if links and kind != "release":
        raise Refusal("SYMLINK_IN_MEMORY_EXPORT")
    for name in names:
        safe_name(name)
        if any(p.as_posix() in links for p in PurePosixPath(name).parents):
            raise Refusal("ARCHIVE_MEMBER_UNDER_LINK")
    for name, target in links.items():
        safe_link_target(target)
        path = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
        seen = set()
        for _ in range(40):
            if path == ".." or path.startswith("../") or path.startswith("/"):
                raise Refusal("RELEASE_LINK_ESCAPES_ROOT")
            safe_name(path)
            parts = path.split("/")
            matched = False
            for i in range(1, len(parts) + 1):
                prefix = "/".join(parts[:i])
                if prefix in links:
                    if prefix in seen:
                        raise Refusal("RELEASE_LINK_CYCLE")
                    seen.add(prefix)
                    path = posixpath.normpath(posixpath.join(posixpath.dirname(prefix), links[prefix], *parts[i:]))
                    matched = True
                    break
            if not matched:
                if path not in names and not any(n.startswith(path + "/") for n in names):
                    raise Refusal("DANGLING_RELEASE_LINK")
                break
        else:
            raise Refusal("RELEASE_LINK_DEPTH")

def verify(archive_path, expected_digest, expected_archive=None):
    safe_io_path(archive_path)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise Refusal("INDEPENDENT_EXPECTED_DIGEST_REQUIRED")
    path = Path(archive_path)
    if path.stat().st_size > LIMIT + 128 * 1024**2:
        raise Refusal("ARTIFACT_BUDGET_EXCEEDED")
    if expected_archive and digest(path.read_bytes()) != expected_archive:
        raise Refusal("ARCHIVE_DIGEST_MISMATCH")
    with tarfile.open(path, "r:") as archive:
        entries = archive.getmembers()
        names, total = set(), 0
        for item in entries:
            safe_name(item.name)
            if item.issym():
                safe_link_target(item.linkname)
            total += item.size
            if item.name in names or not (item.isfile() or item.issym()) or item.size < 0 or item.size > LIMIT or item.mode not in (0o644, 0o755, 0o777):
                raise Refusal("INVALID_OR_DUPLICATE_ARCHIVE_MEMBER")
            if total > LIMIT or len(names) >= MAX_FILES:
                raise Refusal("ARTIFACT_BUDGET_EXCEEDED")
            names.add(item.name)
        if MANIFEST not in names:
            raise Refusal("MISSING_MANIFEST")
        manifest_entry = archive.getmember(MANIFEST)
        if not manifest_entry.isfile() or manifest_entry.mode != 0o644:
            raise Refusal("INVALID_MANIFEST_ENTRY")
        if manifest_entry.size > 64 * 1024**2:
            raise Refusal("MANIFEST_BUDGET_EXCEEDED")
        value = json.loads(archive.extractfile(manifest_entry).read())
        if not isinstance(value, dict) or not isinstance(value.get("files", []), list):
            raise Refusal("INVALID_MANIFEST")
        for row in value.get("files", []):
            if not isinstance(row, dict) or "path" not in row:
                raise Refusal("INVALID_MANIFEST")
            safe_name(row["path"])
            if row.get("type") == "l":
                safe_link_target(row.get("target"))
        advertised = value.pop("artifact_digest", None)
        if digest(DOMAIN + canonical(value)) != expected_digest or advertised != expected_digest:
            raise Refusal("ARTIFACT_DIGEST_MISMATCH")
        if value.get("schema") != "prime-artifact-v1" or value.get("restore_authority") is not False or value.get("kind") not in ("release", "memory-export"):
            raise Refusal("INVALID_MANIFEST")
        rows = value.get("files", [])
        if not isinstance(rows, list) or len({r["path"] for r in rows}) != len(rows) or names != {MANIFEST, *(r["path"] for r in rows)}:
            raise Refusal("MANIFEST_CLOSURE_MISMATCH")
        validate_links(rows, value["kind"])
        for row in rows:
            item = archive.getmember(row["path"])
            if row.get("type") == "l":
                if not item.issym() or item.linkname != row["target"] or item.mode != 0o777 or item.size != 0:
                    raise Refusal("LINK_DIGEST_MISMATCH")
                continue
            if row.get("type") != "f" or not item.isfile():
                raise Refusal("INVALID_FILE_TYPE")
            data = archive.extractfile(item).read()
            safe_bytes(data)
            if item.size != row["size"] or item.mode != row["mode"] or digest(data) != row["sha256"]:
                raise Refusal("FILE_DIGEST_MISMATCH")
        value["artifact_digest"] = advertised
    return value

def restore(archive, into, expected_digest, expected_archive=None, release=False):
    safe_io_path(archive); safe_io_path(into)
    value = verify(archive, expected_digest, expected_archive)
    if not release and value["kind"] != "memory-export":
        raise Refusal("RECOVERY_ACCEPTS_MEMORY_EXPORT_ONLY")
    if release and value["kind"] != "release":
        raise Refusal("INSTALL_STAGING_ACCEPTS_RELEASE_ONLY")
    target = Path(into).absolute()
    if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
        raise Refusal("RESTORE_TARGET_MUST_BE_EXISTING_EMPTY_DIRECTORY")
    # macOS /tmp and /var are platform symlinks. Resolve the existing empty target
    # once after refusing a symlink at the target itself; write only to this path.
    target = target.resolve(strict=True)
    safe_io_path(target)
    # Verify-before-stage, then atomic rename into the still-empty destination.
    # This only stages bytes. D owns memory cold verification/tombstone reconciliation.
    with tempfile.TemporaryDirectory(prefix=".prime-recovery-", dir=target.parent) as temp:
        stage = Path(temp) / "payload"
        stage.mkdir(mode=0o700)
        with tarfile.open(archive, "r:") as bundle:
            for item in bundle.getmembers():
                safe_name(item.name)
                if item.issym():
                    safe_link_target(item.linkname)
            for row in value["files"]:
                if row.get("type") == "l":
                    continue
                path = stage / row["path"]
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                data = bundle.extractfile(row["path"]).read()
                if digest(data) != row["sha256"]:
                    raise Refusal("ARCHIVE_CHANGED_DURING_RESTORE")
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, row["mode"])
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(path, row["mode"])
            for row in value["files"]:
                if row.get("type") != "l":
                    continue
                item = bundle.getmember(row["path"])
                if not item.issym() or item.linkname != row["target"]:
                    raise Refusal("ARCHIVE_CHANGED_DURING_RESTORE")
                path = stage / row["path"]
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.symlink_to(row["target"])
        os.rename(stage, target)
    return {"status": "STAGED", "into": str(target), "artifact_digest": expected_digest,
            "authority_restored": False, "activation": "NOT_PERFORMED", "memory_semantics": "PENDING_D_COLD_VERIFY" if not release else "NOT_APPLICABLE"}

def main():
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="command", required=True)
    pack = subs.add_parser("package")
    pack.add_argument("--root", required=True)
    pack.add_argument("--out", required=True)
    pack.add_argument("--kind", choices=["release", "memory-export"], required=True)
    pack.add_argument("--version", required=True)
    pack.add_argument("--commit", required=True)
    pack.add_argument("--recipe", required=True)
    for command in ("verify", "restore", "stage-release"):
        p = subs.add_parser(command)
        p.add_argument("--archive", required=True)
        p.add_argument("--expected-digest", required=True)
        p.add_argument("--expected-archive-sha256")
        if command != "verify":
            p.add_argument("--into", required=True)
    args = parser.parse_args()
    try:
        if args.command == "package":
            safe_io_path(args.recipe)
            result = package(args.root, args.out, args.kind, args.version, args.commit, json.loads(Path(args.recipe).read_text()))
        elif args.command == "verify":
            value = verify(args.archive, args.expected_digest, args.expected_archive_sha256)
            result = {"status": "VERIFIED", "artifact_digest": value["artifact_digest"], "kind": value["kind"], "files": len(value["files"]), "claim": "BYTES_ONLY"}
        else:
            result = restore(args.archive, args.into, args.expected_digest, args.expected_archive_sha256, args.command == "stage-release")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        # Do not echo archive/source bytes or credentials into errors.
        code = str(exc) if isinstance(exc, Refusal) else type(exc).__name__
        print(json.dumps({"status": "REFUSED", "reason": code}))
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
