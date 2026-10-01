#!/usr/bin/env python3
"""Reproduce the pinned upstream build, then apply Aukora's own named patches to it.

THREE REVISIONS, NEVER ONE REPORTED AS ANOTHER:

* the **pinned archive** — `vendor/dsh-source.tar.gz` must hash to `upstream-dsh.json.archiveSha256`;
* the **pristine extraction** — every file must be byte-identical to the archive, so a hand-edited
  tree is refused instead of silently inheriting the upstream pin;
* the **built tree** — the pristine tree plus the patch layer plus the build.

THE PATCH LAYER IS THE ONLY SANCTIONED DIFFERENCE FROM UPSTREAM. `patches/*.patch.json`, each hashed
and named in `upstream-dsh.json` under `localPatches`, is applied to the verified tree **as part of
the build**. What Aukora changed, and why, is therefore constructed and legible rather than a mystery
fork or a hand edit that the next re-materialize erases. A patch that does not apply exactly FAILS
THE BUILD (`patch-find-missing`, `patch-find-ambiguous`, `patch-file-drift`, `patch-pin-mismatch`,
`patch-expect-missing`); nothing here is best-effort and nothing is skipped.

Usage:
    python3 scripts/build-dsh.py                      # the supported build
    python3 scripts/build-dsh.py --patches-only       # apply+verify the patch layer, no build
    python3 scripts/build-dsh.py --root <dir>         # operate on another checkout root (tests)
    python3 scripts/build-dsh.py --verify-built       # read-only release prerequisite
"""
import argparse, contextlib, hashlib, io, json, os, shutil, stat, subprocess, tarfile, tempfile, urllib.request
from pathlib import Path

parser = argparse.ArgumentParser(description='Reproduce the pinned upstream build plus the Aukora patch layer.')
parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1],
                    help='checkout root holding upstream-dsh.json, patches/ and vendor/ (default: this checkout)')
parser.add_argument('--patches-only', action='store_true',
                    help='verify the pin, extract if missing, apply and verify the patch layer, then STOP '
                         'before install/build/record. For patch-layer tests and divergence checks.')
parser.add_argument('--phase', choices=['all', 'apply', 'build'], default=None,
                    help='which expectation phase the patch layer checks: all (the build), apply (the '
                         'patched files), or build (the built artifacts). Defaults to all for a build and '
                         'to apply for --patches-only, whose tree has no built artifacts yet. The court '
                         'uses the explicit phases to exercise each gate on its own.')
parser.add_argument('--skip-pristine', action='store_true',
                    help='patches-only fixture seam: skip the pristine-tree comparison to reach the '
                         'build-phase expectation gate on a pre-patched tree. Never allowed for a build.')
parser.add_argument('--verify-built', action='store_true',
                    help='read-only: require a successful build bound to this archive and complete patch set')
parser.add_argument('--source', type=Path, help='built tree to check with --verify-built')
args = parser.parse_args()
if args.verify_built and (args.patches_only or args.phase or args.skip_pristine):
    parser.error('--verify-built cannot be combined with build/patch phase options')
if args.source and not args.verify_built:
    parser.error('--source requires --verify-built')
if args.skip_pristine and not args.patches_only:
    parser.error('--skip-pristine requires --patches-only; builds must verify the full pristine inventory')

root = args.root.resolve()
pin = json.loads((root / 'upstream-dsh.json').read_text())
archive = root / 'vendor/dsh-source.tar.gz'
source = args.source.resolve() if args.source else root / 'vendor/dsh'
patch_dir = root / 'patches'
binding_path = source / '.dsh-build/pinned-harness-build.json'


def sha256_file(path: Path) -> str:
    """Digest one file, or refuse rather than invent a value for a missing one."""
    if not path.is_file():
        raise SystemExit(f'patch-file-missing: {path}')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_patches() -> list[dict]:
    """Read `patches/*.patch.json` in filename order and bind each one to the pin.

    The pin is the legible record of what Aukora changed and why: every applied patch must appear in
    `localPatches` with its exact digest and reason, and no entry may name a patch that is not on
    disk. A patch edited without re-pinning therefore fails the build instead of changing the release
    quietly, and the set of differences from upstream is exactly the set a reader can enumerate.
    """
    declared = pin.get('localPatches', [])
    if not isinstance(declared, list):
        raise SystemExit('patch-pin-invalid: upstream-dsh.json localPatches must be a list')
    by_file: dict[str, dict] = {}
    for entry in declared:
        if not isinstance(entry, dict) or not all(k in entry for k in ('file', 'sha256', 'reason')):
            raise SystemExit('patch-pin-invalid: every localPatches entry needs file, sha256 and reason')
        if not isinstance(entry['file'], str) or entry['file'] in by_file:
            raise SystemExit('patch-pin-invalid: localPatches must name distinct patch files')
        by_file[entry['file']] = entry
    patches = []
    for path in sorted(patch_dir.glob('*.patch.json')):
        relative = f'patches/{path.name}'
        entry = by_file.get(relative)
        if entry is None:
            raise SystemExit(f'patch-unpinned: {relative} is not recorded in localPatches')
        digest = sha256_file(path)
        if digest != entry['sha256']:
            raise SystemExit(
                f'patch-file-drift: {relative} is {digest} but localPatches records {entry["sha256"]}')
        try:
            spec = json.loads(path.read_text())
        except json.JSONDecodeError as error:
            raise SystemExit(f'patch-invalid-json: {relative}: {error}')
        if spec.get('formatVersion') != 1 or not isinstance(spec.get('edits'), list) or not spec['edits']:
            raise SystemExit(f'patch-invalid: {relative} needs formatVersion 1 and a non-empty edits list')
        if not isinstance(spec.get('reason'), str) or not spec['reason'].strip():
            raise SystemExit(f'patch-invalid: {relative} needs a reason a reader can act on')
        if spec['reason'] != entry['reason']:
            raise SystemExit(f'patch-reason-drift: {relative} reason differs from localPatches')
        patches.append({'file': relative, 'sha256': digest, 'spec': spec})
    for relative in by_file:
        if relative not in {patch['file'] for patch in patches}:
            raise SystemExit(f'patch-pin-mismatch: localPatches names {relative}, which is not an applied patch')
    return patches


def apply_patches(patches: list[dict]) -> list[dict]:
    """Apply every edit in order; a patch that cannot be applied exactly stops the build."""
    applied = []
    for patch in patches:
        relative_patch = patch['file']
        spec = patch['spec']
        buffers: dict[str, str] = {}
        for index, edit in enumerate(spec['edits']):
            for key in ('path', 'find', 'replace'):
                if not isinstance(edit.get(key), str) or edit[key] == '':
                    raise SystemExit(f'patch-invalid: {relative_patch} edit {index} needs a non-empty {key}')
            expected = edit.get('occurrences', 1)
            if not isinstance(expected, int) or expected < 1:
                raise SystemExit(
                    f'patch-invalid: {relative_patch} edit {index} occurrences must be a positive integer')
            target = source / edit['path']
            if edit['path'] not in buffers:
                if not target.is_file():
                    raise SystemExit(f'patch-target-missing: {relative_patch} names {edit["path"]}')
                buffers[edit['path']] = target.read_text()
            text = buffers[edit['path']]
            found = text.count(edit['find'])
            if found != expected:
                kind = 'patch-find-missing' if found == 0 else 'patch-find-ambiguous'
                raise SystemExit(
                    f'{kind}: {relative_patch} edit {index} matched {found} of {expected} occurrence(s) in '
                    f'{edit["path"]}; the patch and the pinned tree have diverged')
            buffers[edit['path']] = text.replace(edit['find'], edit['replace'])
        for path, text in buffers.items():
            (source / path).write_text(text)
        applied.append({'file': relative_patch, 'sha256': patch['sha256'], 'reason': spec['reason'],
                        'edits': len(spec['edits'])})
        print(f"patch: applied {relative_patch} ({patch['sha256'][:12]}, {len(spec['edits'])} edit(s))")
    return applied


def verify_expectations(patches: list[dict], phase: str) -> None:
    """Check a patch's own claims about the tree, in one named phase.

    `expectAfterApply` is checked immediately after the edits land (they name the patched files);
    `expectAfterBuild` is checked after the build (they name artifacts the build produces). A claim
    that is false stops the build with `patch-expect-missing` rather than shipping a release whose
    bytes silently lack the patch — the failure mode this layer exists to make impossible.
    """
    key = 'expectAfterApply' if phase == 'apply' else 'expectAfterBuild'
    for patch in patches:
        for index, expectation in enumerate(patch['spec'].get(key, [])):
            relative = expectation.get('path')
            contains = expectation.get('contains')
            if not isinstance(relative, str) or not isinstance(contains, str) or contains == '':
                raise SystemExit(f'patch-invalid: {patch["file"]} {key} {index} needs path and contains')
            target = source / relative
            if not target.is_file() or contains not in target.read_text():
                raise SystemExit(
                    f'patch-expect-missing: {patch["file"]} requires {contains!r} in {relative} after the '
                    f'{phase}; the patch did not reach the bytes it claims')
            print(f"patch: verified {patch['file']} reached {relative} ({phase})")


def build_inputs(patches: list[dict]) -> dict:
    return {'upstream': {key: pin[key] for key in
                        ('commit', 'archiveSha256', 'lockfileSha256', 'packageManager')},
            'localPatches': [{'file': patch['file'], 'sha256': patch['sha256']} for patch in patches]}


def verify_built(patches: list[dict]) -> None:
    """Presence of patched source is not proof of compiled output: require the post-build receipt.

    The receipt is local build provenance, not an attestation against a malicious same-UID writer.
    Foundation/face edits do not change harness inputs; validate the harness inventory independently
    of the record's Genesis inventory, which the release materializer regenerates for its own commit.
    """
    try:
        binding = json.loads(binding_path.read_text())
    except (OSError, ValueError) as error:
        raise SystemExit(f'harness-patch-set-mismatch: missing/invalid successful build provenance: {error}')
    if (not isinstance(binding, dict) or binding.get('formatVersion') != 2
            or binding.get('kind') != 'pinned-harness-build' or binding.get('inputs') != build_inputs(patches)):
        raise SystemExit('harness-patch-set-mismatch: fresh v2 build with stable identity required; rebuild')
    identity = binding.get('harnessIdentity')
    if (not isinstance(identity, dict) or set(identity) != {'path', 'sha256'}
            or identity['path'] != '.dsh-build/pinned-harness-identity.json'
            or not isinstance(identity['sha256'], str) or len(identity['sha256']) != 64
            or any(c not in '0123456789abcdef' for c in identity['sha256'])):
        raise SystemExit('harness-identity-mismatch: successful stable build identity required; rebuild')
    # Reuse the committed coverage semantics, including the upstream client build record. An empty,
    # truncated, changed or incomplete inventory cannot turn a receipt into proof of a current build.
    check = r'''
import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const [root, source, bindingPath] = process.argv.slice(1);
const { loadCoverage, coveredPaths, aggregateDigest, readUpstreamClientRecord, sha256File, verifyHarnessIdentity } =
  await import(pathToFileURL(resolve(root, 'scripts/lib/artifact-integrity.mjs')));
const fail = (kind, message) => { throw new Error(`${kind}: ${message}`); };
try {
  const binding = JSON.parse(readFileSync(bindingPath, 'utf8'));
  const identity = verifyHarnessIdentity({ root, source });
  if (identity.sha256 !== binding.harnessIdentity.sha256)
    fail('harness-identity-mismatch', 'successful build identity differs from current pinned bytes');
  const coverage = loadCoverage(root);
  const recordPath = resolve(source, coverage.value.record);
  const record = JSON.parse(readFileSync(recordPath, 'utf8'));
  if (sha256File(recordPath) !== binding.provenance?.artifactRecordSha256)
    fail('harness-build-record-mismatch', 'inventory differs from the successful build receipt');
  if (JSON.stringify(record.producer) !== JSON.stringify(binding.provenance?.producer))
    fail('harness-build-provenance-mismatch', 'producer provenance differs from the successful build receipt');
  if (record?.formatVersion !== 1 || record?.kind !== 'genesis-artifact-record')
    fail('harness-build-record-invalid', 'unknown inventory format');
  const paths = coveredPaths(source, coverage.value.hostPatterns, coverage.value.excluded);
  const entries = record.entries;
  if (!Array.isArray(entries) || entries.length === 0 || entries.length !== binding.artifactCount
      || record.host?.fileCount !== entries.length || paths.length !== entries.length)
    fail('harness-build-record-incomplete', 'compiled inventory missing or count differs');
  const byPath = new Map(entries.map(entry => [entry?.path, entry]));
  if (byPath.size !== entries.length || paths.some(path => !byPath.has(path))
      || coverage.value.requiredEntries.some(path => !byPath.has(path))
      || record.coverage?.declarationSha256 !== coverage.sha256)
    fail('harness-build-record-incomplete', 'required/covered compiled files differ');
  for (const key of ['commit', 'archiveSha256', 'lockfileSha256'])
    if (record.upstream?.[key] !== binding.inputs.upstream[key])
      fail('harness-build-record-mismatch', `upstream.${key} differs`);
  for (const path of paths) {
    const entry = byPath.get(path), absolute = resolve(source, path);
    if (!Number.isSafeInteger(entry.bytes) || entry.bytes < 0
        || typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(entry.sha256))
      fail('harness-build-record-invalid', `invalid inventory entry ${path}`);
    if (statSync(absolute).size !== entry.bytes || sha256File(absolute) !== entry.sha256)
      fail('harness-built-artifact-mismatch', path);
  }
  if (aggregateDigest(source, paths) !== record.host.sha256)
    fail('harness-built-artifact-mismatch', 'host aggregate differs');
  const client = readUpstreamClientRecord(source, coverage.value.upstreamClientRecord);
  const clientPaths = coveredPaths(source, coverage.value.clientPatterns, coverage.value.excluded);
  const clientDigest = aggregateDigest(source, clientPaths);
  if (client.sha256 !== record.clientFace?.upstreamRecordSha256
      || clientDigest !== client.digest || clientPaths.length !== client.fileCount
      || clientDigest !== record.clientFace?.sha256 || clientPaths.length !== record.clientFace?.fileCount)
    fail('harness-built-artifact-mismatch', 'client build inventory differs');
  console.log(`harness-build-binding: verified ${paths.length} artifacts; ${binding.inputs.localPatches.length} pinned patches`);
} catch (error) {
  console.error(error.message.startsWith('harness-') ? error.message : `harness-build-record-invalid: ${error.message}`);
  process.exit(1);
}
'''
    checked = subprocess.run(['node', '--input-type=module', '-e', check, str(root), str(source), str(binding_path)])
    if checked.returncode:
        raise SystemExit(checked.returncode)
    lock = source / 'pnpm-lock.yaml'
    if not lock.is_file() or sha256_file(lock) != pin['lockfileSha256']:
        raise SystemExit('harness-lock-mismatch: built tree differs from pinned dependency inputs')
    verify_expectations(patches, 'build')


def archive_path_parts(name: str, directory: bool) -> tuple[str, ...]:
    """Canonical POSIX member names only; extraction never repairs an unsafe name."""
    if (not isinstance(name, str) or not name or name.startswith('/') or '\\' in name
            or any(ord(character) < 32 or ord(character) == 127 for character in name)):
        raise SystemExit('source-archive-path-invalid: noncanonical or control-bearing member name')
    if directory and name.endswith('/'):
        name = name[:-1]
    parts = tuple(name.split('/'))
    if any(part in ('', '.', '..') for part in parts) or ':' in parts[0]:
        raise SystemExit(f'source-archive-path-invalid: {name}')
    return parts


def contained_link_path(relative: str, target: str) -> list[str]:
    if (not isinstance(target, str) or not target or target.startswith('/') or '\\' in target
            or any(ord(character) < 32 or ord(character) == 127 for character in target)):
        raise SystemExit(f'source-archive-link-invalid: {relative}')
    target_parts = target.split('/')
    if any(part in ('', '.') for part in target_parts):
        raise SystemExit(f'source-archive-link-invalid: {relative}')
    # Parent steps must precede named components. Collapsing a/../b before resolving a symlink
    # named a would change POSIX lookup semantics; such noncanonical targets are refused.
    named = False
    parts = relative.split('/')[:-1]
    for part in target_parts:
        if part == '..':
            if named or not parts:
                raise SystemExit(f'source-archive-link-escape: {relative}')
            parts.pop()
        else:
            named = True
            parts.append(part)
    return parts


def archive_inventory(snapshot: tarfile.TarFile) -> dict[str, dict]:
    """Bind all paths/types, including implicit parents and exact contained symlinks.

    The pinned GitHub archive contains regular files, directories and relative symlinks. Hard links,
    devices, FIFO/sparse members, duplicate paths and link-parent children are refused before any
    extraction. File/directory permissions are normalized to the same 0644/0755 extraction policy,
    retaining the archive's executable-file distinction rather than inheriting its group-write bits.
    """
    inventory: dict[str, dict] = {}
    explicit = set()
    top = None
    total_bytes = 0
    members = snapshot.getmembers()
    if not members or len(members) > 200000:
        raise SystemExit('source-archive-inventory-invalid: empty or excessive member inventory')
    for member in members:
        if (not (member.isfile() or member.isdir() or member.issym()) or member.sparse is not None
                or member.mode & 0o7000):
            raise SystemExit(f'source-archive-type-invalid: {member.name}')
        parts = archive_path_parts(member.name, member.isdir())
        if top is None:
            top = parts[0]
        if parts[0] != top:
            raise SystemExit('source-archive-root-mismatch: expected exactly one top-level directory')
        relative = '/'.join(parts[1:])
        if relative in explicit:
            raise SystemExit(f'source-archive-path-duplicate: {relative or "<root>"}')
        explicit.add(relative)
        if not relative:
            if not member.isdir():
                raise SystemExit('source-archive-root-invalid: top-level member must be a directory')
            continue
        for length in range(1, len(parts) - 1):
            parent = '/'.join(parts[1:length + 1])
            existing = inventory.get(parent)
            if existing is not None and existing['type'] != 'directory':
                raise SystemExit(f'source-archive-parent-type-mismatch: {parent}')
            inventory.setdefault(parent, {'type': 'directory', 'mode': 0o755})
        existing = inventory.get(relative)
        kind = 'directory' if member.isdir() else 'symlink' if member.issym() else 'file'
        if existing is not None and (existing['type'] != 'directory' or kind != 'directory'):
            raise SystemExit(f'source-archive-parent-type-mismatch: {relative}')
        entry = {'type': kind, 'mode': 0o755 if member.isdir() or member.mode & 0o111 else 0o644,
                 'member': member}
        if member.isfile():
            total_bytes += member.size
            if member.size < 0 or member.size > 512 * 1024 * 1024 or total_bytes > 2 * 1024 * 1024 * 1024:
                raise SystemExit(f'source-archive-size-invalid: {relative}')
            with snapshot.extractfile(member) as contents:
                body = contents.read(member.size + 1)
            if len(body) != member.size:
                raise SystemExit(f'source-archive-size-mismatch: {relative}')
            entry.update(bytes=member.size, sha256=hashlib.sha256(body).hexdigest())
        elif member.issym():
            entry['target'] = member.linkname
            contained_link_path(relative, member.linkname)
        inventory[relative] = entry
    if not inventory:
        raise SystemExit('source-archive-inventory-invalid: no extracted paths')
    # Resolve links against the complete archive inventory, never the host filesystem. A chain
    # cannot escape, cycle, dangle, or traverse a regular file. Symlink-parent entries above refuse.
    for relative, entry in inventory.items():
        if entry['type'] != 'symlink':
            continue
        pending = contained_link_path(relative, entry['target'])
        resolved = []
        followed = set()
        while pending:
            resolved.append(pending.pop(0))
            path = '/'.join(resolved)
            target_entry = inventory.get(path)
            if target_entry is None:
                raise SystemExit(f'source-archive-link-dangling: {relative}')
            if target_entry['type'] == 'symlink':
                if path in followed or len(followed) >= 40:
                    raise SystemExit(f'source-archive-link-cycle: {relative}')
                followed.add(path)
                pending = contained_link_path(path, target_entry['target']) + pending
                resolved = []
            elif pending and target_entry['type'] != 'directory':
                raise SystemExit(f'source-archive-link-type-mismatch: {relative}')
    return inventory


def verify_pristine_inventory(directory: Path, inventory: dict[str, dict]) -> None:
    """No generated-path exceptions: a supported build starts with exactly archived source bytes.

    In particular node_modules, build outputs, .dsh-build, hooks and additional configuration do not
    survive a reused extraction. `--verify-built` is the separate read-only path for a built tree.
    """
    if directory.is_symlink() or not directory.is_dir():
        raise SystemExit('source-root-type-mismatch: expected a real extracted directory')
    if stat.S_IMODE(directory.stat().st_mode) != 0o755:
        raise SystemExit('source-root-mode-mismatch: expected normalized 0755 extraction directory')
    found = set()

    def visit(parent: Path, prefix: str = '') -> None:
        for child in sorted(os.scandir(parent), key=lambda entry: entry.name):
            relative = f'{prefix}/{child.name}' if prefix else child.name
            expected = inventory.get(relative)
            if expected is None:
                raise SystemExit(f'source-path-unexpected: {relative}; use a fresh verified extraction')
            metadata = child.stat(follow_symlinks=False)
            actual = ('directory' if stat.S_ISDIR(metadata.st_mode) else
                      'symlink' if stat.S_ISLNK(metadata.st_mode) else
                      'file' if stat.S_ISREG(metadata.st_mode) else 'unsupported')
            if actual != expected['type']:
                raise SystemExit(f'source-type-mismatch: {relative}')
            found.add(relative)
            if actual == 'symlink':
                if os.readlink(child.path) != expected['target']:
                    raise SystemExit(f'source-link-mismatch: {relative}')
            else:
                if stat.S_IMODE(metadata.st_mode) != expected['mode']:
                    raise SystemExit(f'source-mode-mismatch: {relative}')
                if actual == 'directory':
                    visit(Path(child.path), relative)
                else:
                    if metadata.st_nlink != 1:
                        raise SystemExit(f'source-file-link-mismatch: {relative}')
                    descriptor = os.open(child.path, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(descriptor, 'rb') as contents:
                        before = os.fstat(contents.fileno())
                        body = contents.read(expected['bytes'] + 1)
                        after = os.fstat(contents.fileno())
                    current = os.stat(child.path, follow_symlinks=False)
                    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                                              value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                    if not (identity(metadata) == identity(before) == identity(after) == identity(current)):
                        raise SystemExit(f'source-file-changed: {relative}')
                    if len(body) != expected['bytes'] or hashlib.sha256(body).hexdigest() != expected['sha256']:
                        raise SystemExit(f'source-file-mismatch: inspect {relative} before building')

    visit(directory)
    missing = sorted(set(inventory) - found)
    if missing:
        raise SystemExit(f'source-path-missing: {missing[0]}')


def extract_pristine(snapshot: tarfile.TarFile, inventory: dict[str, dict]) -> None:
    """Create only validated members in a private fresh tree; publish after complete verification."""
    temporary = Path(tempfile.mkdtemp(prefix='.dsh-pristine-', dir=source.parent))
    try:
        os.chmod(temporary, 0o755)
        for relative, entry in sorted(inventory.items(), key=lambda item: (item[0].count('/'), item[0])):
            if entry['type'] == 'directory':
                (temporary / relative).mkdir(mode=0o755)
                os.chmod(temporary / relative, 0o755)
        for relative, entry in sorted(inventory.items()):
            if entry['type'] != 'file':
                continue
            descriptor = os.open(temporary / relative, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 entry['mode'])
            with os.fdopen(descriptor, 'wb') as output, snapshot.extractfile(entry['member']) as contents:
                shutil.copyfileobj(contents, output)
                os.fchmod(output.fileno(), entry['mode'])
        # Links land last, so archive content is never written through a link.
        for relative, entry in sorted(inventory.items()):
            if entry['type'] == 'symlink':
                os.symlink(entry['target'], temporary / relative)
        verify_pristine_inventory(temporary, inventory)
        if source.exists() or source.is_symlink():
            raise SystemExit('source-extraction-race: destination appeared before publication')
        temporary.rename(source)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def invalidate_build_binding() -> None:
    # Even the fixture-only content bypass cannot unlink a receipt through a contaminated link.
    if source.is_symlink() or (source / '.dsh-build').is_symlink():
        raise SystemExit('source-binding-parent-invalid: symlinked extraction or receipt directory')
    binding_path.unlink(missing_ok=True)


patches = load_patches()
if args.verify_built:
    verify_built(patches)
    raise SystemExit(0)
archive.parent.mkdir(exist_ok=True)
if archive.parent.is_symlink() or archive.parent.resolve() != archive.parent:
    raise SystemExit('source-archive-parent-invalid: expected a canonical vendor directory')
if archive.is_symlink() or (archive.exists() and not archive.is_file()):
    raise SystemExit('source-archive-type-invalid: expected a regular archive, never a link or special file')
if not archive.exists():
    with urllib.request.urlopen(pin['archiveUrl'], timeout=60) as response:
        downloaded = response.read(512 * 1024 * 1024 + 1)
    if len(downloaded) > 512 * 1024 * 1024:
        raise SystemExit('source-archive-size-invalid: archive download exceeds the bounded input size')
    descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(downloaded)
initial = os.stat(archive, follow_symlinks=False)
descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(descriptor, 'rb') as contents:
    metadata = os.fstat(contents.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 512 * 1024 * 1024:
        raise SystemExit('source-archive-type-invalid: expected a bounded regular archive with one link')
    archive_bytes = contents.read(metadata.st_size + 1)
    after = os.fstat(contents.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                              value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if (len(archive_bytes) != metadata.st_size or identity(initial) != identity(metadata)
            or identity(metadata) != identity(after)
            or identity(os.stat(archive, follow_symlinks=False)) != identity(after)):
        raise SystemExit('source-archive-changed: archive changed while reading')
if hashlib.sha256(archive_bytes).hexdigest() != pin['archiveSha256']:
    raise SystemExit('source-digest-mismatch: retain archive and inspect provenance before retrying')
try:
    with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as snapshot:
        inventory = archive_inventory(snapshot)
        if not source.exists() and not source.is_symlink():
            extract_pristine(snapshot, inventory)
        # The sole exemption is an explicitly patches-only synthetic phase fixture. It cannot
        # invoke a package manager, produce a successful build receipt, or qualify a built tree.
        if not args.skip_pristine:
            verify_pristine_inventory(source, inventory)
except (tarfile.TarError, OSError, EOFError) as error:
    raise SystemExit(f'source-archive-invalid: {error}')
# Invalidate success before the first patch mutation, after refusing contaminated path ancestors.
invalidate_build_binding()
phase = args.phase if args.phase is not None else ('apply' if args.patches_only else 'all')
if hashlib.sha256((source / 'pnpm-lock.yaml').read_bytes()).hexdigest() != pin['lockfileSha256']:
    raise SystemExit('lockfile-digest-mismatch: restore the pinned dependency inputs')
# `--phase build` checks the built artifacts and does not touch the tree: that is the seam the court
# uses to exercise the build-phase gate on a hand-made artifact.
applied = [] if phase == 'build' else apply_patches(patches)
if phase in ('all', 'apply'):
    verify_expectations(patches, 'apply')
if args.patches_only:
    if phase in ('all', 'build'):
        verify_expectations(patches, 'build')
    print(f"patches-only: {len(applied)} patch(es) applied; expectations checked for phase '{phase}'; "
          'no install, build or record was run')
    raise SystemExit(0)
env = {**os.environ, 'CI': 'true', 'LEFTHOOK': '0', 'DSH_CLIENT_TITLE': 'AUKORA'}
# NO FACE OVERLAY IS STASHED HERE, AND THAT IS THE POINT. `build-face.py` copies the Aukora faces
# into ITS OWN overlay clone (`.runtime/face-build`), where it also adds the client-solution
# references they need, so the pinned tree never sees them. An earlier revision of this file moved
# `packages/client/aukora-face-*` aside around this install because they broke
# `--frozen-lockfile`; that is now unnecessary and was removed, because a tree that needs a stash
# to install is a tree whose inputs are wrong. If a face package is ever found here again, the
# build should be understood as running against a dirty checkout, not quietly repaired.
manager = subprocess.run(['pnpm', '--version'], cwd=source, env=env, capture_output=True, text=True)
if manager.returncode != 0 or 'pnpm@' + manager.stdout.strip() != pin['packageManager']:
    raise SystemExit(f'package-manager-version-mismatch: require {pin["packageManager"]}; install/build not started')
subprocess.run(['pnpm', 'install', '--frozen-lockfile'], cwd=source, env=env, check=True)
subprocess.run(['pnpm', 'run', 'build'], cwd=source, env=env, check=True)
if phase in ('all', 'build'):
    verify_expectations(patches, 'build')
# Record the built bytes; the check consumes this record and never trusts presence alone.
subprocess.run(['node', str(root / 'scripts/artifact-record.mjs'), '--source', str(source)], cwd=root, env=env, check=True)
# A successful full build alone creates provenance. Skipping pristine verification cannot mint it.
if not args.skip_pristine:
    record_path = source / '.dsh-build/genesis-artifacts.json'
    record = json.loads(record_path.read_text())
    # A stable downstream key covers actual harness inputs/outputs. Volatile
    # Prime commit/platform/source-inventory provenance remains separately named.
    write_identity = r'''
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const [root, source] = process.argv.slice(1);
const { writeHarnessIdentity } = await import(pathToFileURL(resolve(root, 'scripts/lib/artifact-integrity.mjs')));
writeHarnessIdentity({ root, source });
'''
    subprocess.run(['node', '--input-type=module', '-e', write_identity, str(root), str(source)], check=True)
    identity = json.loads((source / '.dsh-build/pinned-harness-identity.json').read_text())
    binding = {'formatVersion': 2, 'kind': 'pinned-harness-build', 'inputs': build_inputs(patches),
               'harnessIdentity': {'path': '.dsh-build/pinned-harness-identity.json', 'sha256': identity['sha256']},
               'artifactCount': len(record['entries']),
               'provenance': {'artifactRecordSha256': sha256_file(record_path), 'producer': record['producer']}}
    temporary = binding_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(binding, indent=2) + '\n')
    temporary.replace(binding_path)
    try:
        verify_built(patches)
    except BaseException:
        binding_path.unlink(missing_ok=True)
        raise
