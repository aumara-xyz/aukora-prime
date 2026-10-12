// SPDX-License-Identifier: AGPL-3.0-or-later
// Snapshot checks bind private copied bytes, links and closure to a retained digest.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const archive = path.join(repo, 'packages/ops/archive.py');
const scratch = fs.mkdtempSync(path.join(repo, 'tests/.ops-state-snapshot-'));
const manifestName = 'prime-state-snapshot.json';
const domain = Buffer.from('aukora-prime:state-snapshot:v1\0');
const source = fs.readFileSync(archive, 'utf8');
const cases = [];
const mutations = [];
let checks = 0;

function fixture() {
  const dir = fs.mkdtempSync(path.join(scratch, 'case-'));
  const state = path.join(dir, 'source');
  const target = path.join(dir, 'snapshot');
  fs.mkdirSync(state);
  fs.writeFileSync(path.join(state, 'sample'), 'synthetic state\n');
  return { dir, state, target };
}
function invoke(args, script = archive, driver = '') {
  const argv = driver ? ['-c', driver, script, ...args] : [script, ...args];
  const result = spawnSync('python3', argv, {
    cwd: repo, encoding: 'utf8', timeout: 10000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });
  if (result.error) throw new Error('snapshot invocation failed', { cause: result.error });
  if (/SyntaxError|IndentationError|Traceback/.test(result.stderr)) throw new Error(`Python failure: ${result.stderr}`);
  let value;
  try { value = JSON.parse(result.stdout); } catch { /* argparse refusals have no JSON */ }
  return { ...result, value };
}
function snapshot(f, script = archive, label = 'synthetic', driver = '') {
  return invoke(['snapshot', '--state', f.state, '--to', f.target, '--label', label], script, driver);
}
function accepted(result, status = 'SNAPSHOTTED') {
  assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
  assert.equal(result.value?.status, status);
  assert.equal(result.value.authority_restored, false);
  assert.equal(result.value.claim, 'BYTES_ONLY');
  return result.value;
}
function refused(result, reason) {
  assert.equal(result.status, 1, `expected ${reason}: ${result.stdout} ${result.stderr}`);
  assert.equal(result.value?.status, 'REFUSED');
  assert.equal(result.value.reason, reason);
}
function retainedDigest(f) {
  return createHash('sha256').update(domain).update(fs.readFileSync(path.join(f.target, manifestName))).digest('hex');
}
function verify(f, digest, script = archive, driver = '') {
  return invoke(['verify-snapshot', '--snapshot', f.target, '--expected-digest', digest], script, driver);
}
function created(script = archive) {
  const f = fixture();
  f.receipt = accepted(snapshot(f, script));
  return f;
}
function noManifest(f) { assert.equal(fs.existsSync(path.join(f.target, manifestName)), false); }
function add(name, run, mutation) {
  cases.push({ name, run });
  if (mutation) mutations.push({ name, run, ...mutation });
}
function changeOnce(text, before, after) {
  assert.equal(text.split(before).length - 1, 1, `mutation anchor must be unique: ${before}`);
  return text.replace(before, after);
}
function lowered(script, from, to) {
  const output = path.join(scratch, `bounded-${mutations.length}-${checks}-${path.basename(script)}`);
  fs.writeFileSync(output, changeOnce(fs.readFileSync(script, 'utf8'), from, to));
  return output;
}
function injected(python) {
  return `import importlib.util, os, sys, types\nfrom pathlib import Path\nspec = importlib.util.spec_from_file_location("snapshot_test", sys.argv[1])\nm = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(m)\nsys.argv = sys.argv[1:]\n${python}\nsys.exit(m.main())`;
}

add('synthetic copy, custody names, links, private modes and independent bytes', script => {
  const f = fixture();
  fs.mkdirSync(path.join(f.state, 'empty'));
  fs.mkdirSync(path.join(f.state, 'authority-state'));
  fs.writeFileSync(path.join(f.state, 'authority-state', 'nonce-book'), 'synthetic custody');
  fs.writeFileSync(path.join(f.state, '.env'), 'SYNTHETIC=only');
  fs.symlinkSync('sample', path.join(f.state, 'relative'));
  fs.symlinkSync(path.join(f.state, 'sample'), path.join(f.state, 'absolute'));
  fs.symlinkSync('missing', path.join(f.state, 'dangling'));
  fs.symlinkSync('empty', path.join(f.state, 'directory-link'));
  const receipt = accepted(snapshot(f, script));
  const manifest = JSON.parse(fs.readFileSync(path.join(f.target, manifestName), 'utf8'));
  assert.equal(receipt.snapshot_digest, retainedDigest(f));
  assert.equal(manifest.schema, 'prime-state-snapshot-v1');
  assert.equal(manifest.restore_authority, false);
  assert.equal(manifest.entries.length, 9);
  for (const name of ['relative', 'absolute', 'dangling', 'directory-link']) {
    assert.equal(fs.readlinkSync(path.join(f.target, 'state', name)), fs.readlinkSync(path.join(f.state, name)));
    assert.equal(manifest.entries.find(row => row.path === name).type, 'l');
  }
  for (const name of ['', 'state', 'state/empty', 'state/authority-state']) {
    assert.equal(fs.statSync(path.join(f.target, name)).mode & 0o777, 0o700);
  }
  for (const name of [manifestName, 'state/sample', 'state/.env', 'state/authority-state/nonce-book']) {
    assert.equal(fs.statSync(path.join(f.target, name)).mode & 0o777, 0o600);
  }
  assert.notEqual(fs.statSync(path.join(f.target, 'state/sample')).ino, fs.statSync(path.join(f.state, 'sample')).ino);
  fs.rmSync(f.state, { recursive: true });
  assert.equal(fs.readFileSync(path.join(f.target, 'state/sample'), 'utf8'), 'synthetic state\n');
  accepted(verify(f, receipt.snapshot_digest, script), 'VERIFIED');
});

for (const [name, target] of [
  ['same root', f => f.state],
  ['destination below source', f => path.join(f.state, 'below')],
  ['source below destination', f => { const moved = path.join(f.dir, 'state'); fs.renameSync(f.state, moved); f.state = moved; return f.dir; }],
  ['alias below source', f => { fs.symlinkSync(f.state, path.join(f.dir, 'alias')); return path.join(f.dir, 'alias', 'below'); }],
]) add(`overlap refuses ${name} before writes`, script => {
  const f = fixture(); f.target = target(f);
  // Stop a removed ancestry guard at creation instead of recursively copying its output.
  const driver = injected('m.snapshot_tree = lambda *args: []');
  refused(snapshot(f, script, 'synthetic', driver), 'SNAPSHOT_PATHS_OVERLAP');
  assert.equal(fs.readFileSync(path.join(f.state, 'sample'), 'utf8'), 'synthetic state\n');
  if (name.includes('below source')) assert.equal(fs.existsSync(f.target), false);
}, name === 'destination below source' ? {
  before: 'if root == target or root in target.parents or target in root.parents:', after: 'if root == target or target in root.parents:',
} : name === 'source below destination' ? {
  before: 'if root == target or root in target.parents or target in root.parents:', after: 'if root == target or root in target.parents:',
} : undefined);

for (const kind of ['directory', 'file', 'dangling link']) add(`existing ${kind} stays untouched`, script => {
  const f = fixture();
  if (kind === 'directory') fs.mkdirSync(f.target);
  if (kind === 'file') fs.writeFileSync(f.target, 'keep');
  if (kind === 'dangling link') fs.symlinkSync('absent', f.target);
  const before = fs.lstatSync(f.target);
  refused(snapshot(f, script), 'SNAPSHOT_DESTINATION_EXISTS');
  assert.equal(fs.lstatSync(f.target).ino, before.ino);
}, kind === 'dangling link' ? { before: 'if os.path.lexists(into):', after: 'if into.exists():' } : undefined);

add('a concurrent destination creator wins without being overwritten', script => {
  const f = fixture();
  const driver = injected(`target = Path(sys.argv[sys.argv.index('--to') + 1]).resolve()\noriginal = Path.mkdir\ndef raced(self, *args, **kwargs):\n    if self == target and not self.exists():\n        original(self, mode=0o700)\n        (self / 'sentinel').write_text('keep')\n    return original(self, *args, **kwargs)\nPath.mkdir = raced`);
  refused(snapshot(f, script, 'synthetic', driver), 'FileExistsError');
  assert.equal(fs.readFileSync(path.join(f.target, 'sentinel'), 'utf8'), 'keep'); noManifest(f);
}, { before: 'target.mkdir(mode=0o700)', after: 'target.mkdir(mode=0o700, exist_ok=True)' });

add('labels refuse traversal and malformed values before writes', script => {
  for (const label of ['', '../escape', '/absolute', 'two/parts', 'space here', 'x\n', 'a'.repeat(65)]) {
    const f = fixture();
    refused(snapshot(f, script, label), 'INVALID_SNAPSHOT_LABEL');
    assert.equal(fs.existsSync(f.target), false);
  }
}, { before: 'if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", label):', after: 'if False:' });

add('symlink source root refuses', script => {
  const f = fixture(); fs.symlinkSync(f.state, path.join(f.dir, 'alias')); f.state = path.join(f.dir, 'alias');
  refused(snapshot(f, script), 'ROOT_MUST_BE_REAL_DIRECTORY');
  assert.equal(fs.existsSync(f.target), false);
}, { before: 'if state.is_symlink() or not state.is_dir():', after: 'if not state.is_dir():' });

add('invalid entry names leave no completion manifest', script => {
  for (const name of ['bad\nname', 'bad\\name']) {
    const f = fixture(); fs.writeFileSync(path.join(f.state, name), 'synthetic');
    refused(snapshot(f, script), 'INVALID_SNAPSHOT_PATH'); noManifest(f);
  }
}, { before: 'if CONTROL.search(name) or "\\\\" in name:', after: 'if False:' });

add('FIFO refuses without reading or completing', script => {
  const f = fixture();
  const mkfifo = spawnSync('python3', ['-c', 'import os,sys; os.mkfifo(sys.argv[1])', path.join(f.state, 'pipe')]);
  assert.equal(mkfifo.status, 0);
  refused(snapshot(f, script), 'SNAPSHOT_SPECIAL_FILE'); noManifest(f);
}, { before: 'raise Refusal("SNAPSHOT_SPECIAL_FILE")', after: 'continue' });

add('entry count is bounded', script => {
  const f = fixture(); fs.writeFileSync(path.join(f.state, 'second'), 'synthetic');
  const bounded = lowered(script, 'MAX_FILES = 200000', 'MAX_FILES = 1');
  refused(snapshot(f, bounded), 'SNAPSHOT_BUDGET_EXCEEDED'); noManifest(f);
}, { before: 'if len(rows) >= MAX_FILES:', after: 'if False:' });

add('copied bytes are bounded', script => {
  const f = fixture();
  const bounded = lowered(script, 'LIMIT = 8 * 1024**3', 'LIMIT = 1');
  refused(snapshot(f, bounded), 'SNAPSHOT_BUDGET_EXCEEDED'); noManifest(f);
}, { before: 'if total > LIMIT:\n                                raise Refusal("SNAPSHOT_BUDGET_EXCEEDED")', after: 'if False:\n                                raise Refusal("SNAPSHOT_BUDGET_EXCEEDED")' });

add('a directory replaced by a link is not traversed', script => {
  const f = fixture();
  fs.mkdirSync(path.join(f.state, 'child'));
  fs.mkdirSync(path.join(f.dir, 'outside'));
  fs.writeFileSync(path.join(f.dir, 'outside/sentinel'), 'synthetic outside bytes');
  const driver = injected(`state = Path(sys.argv[sys.argv.index('--state') + 1])\noriginal = os.open\ndef swapped(name, flags, *args, **kwargs):\n    if name == 'child' and 'dir_fd' in kwargs:\n        (state / 'child').rmdir()\n        (state / 'child').symlink_to(state.parent / 'outside')\n    return original(name, flags, *args, **kwargs)\nos.open = swapped`);
  const result = snapshot(f, script, 'synthetic', driver);
  assert.equal(fs.existsSync(path.join(f.target, 'state/child/sentinel')), false);
  assert.equal(result.status, 1); assert.equal(result.value.status, 'REFUSED'); noManifest(f);
}, { before: 'directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW', after: 'directory_flags = os.O_RDONLY | os.O_DIRECTORY' });

add('a file replaced by a link is not opened', script => {
  const f = fixture();
  fs.writeFileSync(path.join(f.dir, 'outside'), 'synthetic outside bytes');
  const driver = injected(`state = Path(sys.argv[sys.argv.index('--state') + 1])\noriginal = os.open\ndef swapped(name, flags, *args, **kwargs):\n    if name == 'sample' and 'dir_fd' in kwargs:\n        outside = state.parent / 'outside'\n        (state / 'sample').unlink()\n        (state / 'sample').symlink_to(outside)\n        fd = original(name, flags, *args, **kwargs)\n        if os.fstat(fd).st_ino == outside.stat().st_ino:\n            (state.parent / 'followed').write_text('opened')\n        return fd\n    return original(name, flags, *args, **kwargs)\nos.open = swapped`);
  const result = snapshot(f, script, 'synthetic', driver);
  assert.equal(fs.existsSync(path.join(f.dir, 'followed')), false);
  assert.equal(result.status, 1); assert.equal(result.value.status, 'REFUSED'); noManifest(f);
}, { before: 'source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)', after: 'source = os.open(name, os.O_RDONLY | os.O_NONBLOCK, dir_fd=fd)' });

for (const [name, field, at, subject, condition] of [
  ['opened file identity', 'st_ino', 1, 'sample', '(opened.st_dev, opened.st_ino, opened.st_mode) != (st.st_dev, st.st_ino, st.st_mode)'],
  ['file changes during reading', 'st_mtime_ns', 2, 'sample', 'size != opened.st_size or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)'],
  ['directory changes during copying', 'st_mtime_ns', 2, '', '(before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns)'],
]) add(`${name} refuses (injected descriptor metadata)`, script => {
  const f = fixture();
  const driver = injected(`subject = (Path(sys.argv[sys.argv.index('--state') + 1]) / ${JSON.stringify(subject)}).stat()\noriginal = os.fstat\ncalls = 0\ndef changed(fd):\n    global calls\n    st = original(fd)\n    if (st.st_dev, st.st_ino) == (subject.st_dev, subject.st_ino):\n        calls += 1\n        if calls == ${at}:\n            st = types.SimpleNamespace(**{key: getattr(st, key) for key in dir(st) if key.startswith('st_')})\n            st.${field} += 1\n    return st\nos.fstat = changed`);
  refused(snapshot(f, script, 'synthetic', driver), 'SNAPSHOT_SOURCE_CHANGED'); noManifest(f);
}, { before: `if ${condition}:`, after: 'if False:' });

add('copied bytes are rechecked before manifest publication', script => {
  const f = fixture();
  const driver = injected(`output = Path(sys.argv[sys.argv.index('--to') + 1]) / 'state' / 'sample'\noriginal = os.fsync\ndef changed(fd):\n    original(fd)\n    if output.exists() and os.fstat(fd).st_ino == output.stat().st_ino:\n        output.write_bytes(b'changed payload')\nos.fsync = changed`);
  refused(snapshot(f, script, 'synthetic', driver), 'SNAPSHOT_COPY_MISMATCH'); noManifest(f);
}, { before: 'if snapshot_tree(payload) != rows:', after: 'if False:' });

add('manifest production is bounded before publication', script => {
  const f = fixture();
  const bounded = lowered(script, 'data = canonical(value)\n    if len(data) > 64 * 1024**2:', 'data = canonical(value)\n    if len(data) > 1:');
  refused(snapshot(f, bounded), 'INVALID_SNAPSHOT_MANIFEST'); noManifest(f);
}, { before: 'if len(data) > 64 * 1024**2:\n        raise Refusal("INVALID_SNAPSHOT_MANIFEST")\n    # A failed copy', after: 'if len(data) > 64 * 1024**2:\n        pass\n    # A failed copy' });

add('independent digest is required', script => {
  const f = created(script);
  for (const digest of ['', 'self', 'A'.repeat(64), 'a'.repeat(63)]) {
    refused(verify(f, digest, script), 'INDEPENDENT_EXPECTED_DIGEST_REQUIRED');
  }
}, { before: 'if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):', after: 'if False:' });

add('manifest edits and wrong retained digest refuse', script => {
  const f = created(script);
  refused(verify(f, '0'.repeat(64), script), 'SNAPSHOT_DIGEST_MISMATCH');
  const manifest = path.join(f.target, manifestName);
  fs.appendFileSync(manifest, '\n');
  refused(verify(f, f.receipt.snapshot_digest, script), 'SNAPSHOT_DIGEST_MISMATCH');
}, { before: 'if digest(SNAPSHOT_DOMAIN + data) != expected_digest:', after: 'if False:' });

for (const [name, edit] of [
  ['content', f => fs.writeFileSync(path.join(f.target, 'state/sample'), 'changed state\n')],
  ['extra file', f => fs.writeFileSync(path.join(f.target, 'state/extra'), 'extra')],
  ['missing file', f => fs.unlinkSync(path.join(f.target, 'state/sample'))],
  ['file type', f => { fs.unlinkSync(path.join(f.target, 'state/sample')); fs.mkdirSync(path.join(f.target, 'state/sample'), { mode: 0o700 }); }],
  ['file mode', f => fs.chmodSync(path.join(f.target, 'state/sample'), 0o644)],
  ['extra directory', f => fs.mkdirSync(path.join(f.target, 'state/empty'), { mode: 0o700 })],
  ['manifest row', f => { const p = path.join(f.target, manifestName); const m = JSON.parse(fs.readFileSync(p)); m.entries = []; fs.writeFileSync(p, JSON.stringify(m)); }],
  ['manifest authority', f => { const p = path.join(f.target, manifestName); const m = JSON.parse(fs.readFileSync(p)); m.restore_authority = true; fs.writeFileSync(p, JSON.stringify(m)); }],
]) add(`verification refuses changed ${name}`, script => {
  const f = created(script); edit(f);
  refused(verify(f, retainedDigest(f), script), 'SNAPSHOT_CLOSURE_MISMATCH');
}, name === 'content' ? {
  before: 'if value != {"schema": "prime-state-snapshot-v1", "label": label, "entries": rows, "restore_authority": False}:', after: 'if False:',
} : undefined);

add('verification binds link target and empty directories', script => {
  for (const kind of ['link', 'directory']) {
    const f = fixture();
    fs.mkdirSync(path.join(f.state, 'empty'));
    fs.symlinkSync('missing', path.join(f.state, 'link'));
    f.receipt = accepted(snapshot(f, script));
    if (kind === 'link') { fs.unlinkSync(path.join(f.target, 'state/link')); fs.symlinkSync('different', path.join(f.target, 'state/link')); }
    else fs.rmdirSync(path.join(f.target, 'state/empty'));
    refused(verify(f, f.receipt.snapshot_digest, script), 'SNAPSHOT_CLOSURE_MISMATCH');
  }
});

add('snapshot wrapper closure refuses extra files', script => {
  const f = created(script); fs.writeFileSync(path.join(f.target, 'extra'), 'extra');
  refused(verify(f, f.receipt.snapshot_digest, script), 'SNAPSHOT_CLOSURE_MISMATCH');
}, { before: 'if set(os.listdir(root)) != {"state", SNAPSHOT_MANIFEST}:', after: 'if False:' });

add('snapshot root must remain private', script => {
  const f = created(script); fs.chmodSync(f.target, 0o755);
  refused(verify(f, f.receipt.snapshot_digest, script), 'SNAPSHOT_ROOT_MUST_BE_PRIVATE_DIRECTORY');
}, { before: 'if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.getuid():', after: 'if False:' });

add('snapshot root owner must match (injected uid)', script => {
  const f = created(script);
  const driver = injected(`root = Path(sys.argv[sys.argv.index('--snapshot') + 1])\noriginal = Path.lstat\ndef changed(self, *args, **kwargs):\n    st = original(self, *args, **kwargs)\n    if self == root:\n        st = types.SimpleNamespace(**{key: getattr(st, key) for key in dir(st) if key.startswith('st_')})\n        st.st_uid += 1\n    return st\nPath.lstat = changed`);
  refused(verify(f, f.receipt.snapshot_digest, script, driver), 'SNAPSHOT_ROOT_MUST_BE_PRIVATE_DIRECTORY');
}, { before: 'or st.st_uid != os.getuid():', after: ':' });

add('payload root must remain private', script => {
  const f = created(script); fs.chmodSync(path.join(f.target, 'state'), 0o755);
  refused(verify(f, f.receipt.snapshot_digest, script), 'SNAPSHOT_ROOT_MUST_BE_PRIVATE_DIRECTORY');
}, { before: 'if stat.S_IMODE(payload.lstat().st_mode) != 0o700:', after: 'if False:' });

add('manifest must remain private and singly linked', script => {
  for (const kind of ['mode', 'hardlink']) {
    const f = created(script);
    if (kind === 'mode') fs.chmodSync(path.join(f.target, manifestName), 0o644);
    else fs.linkSync(path.join(f.target, manifestName), path.join(f.dir, 'manifest-copy'));
    refused(verify(f, f.receipt.snapshot_digest, script), 'INVALID_SNAPSHOT_MANIFEST');
  }
}, { before: 'if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > 64 * 1024**2:', after: 'if False:' });

add('manifest symlinks are not followed', script => {
  const f = created(script); const manifest = path.join(f.target, manifestName); const other = path.join(f.dir, 'other-manifest');
  fs.renameSync(manifest, other); fs.symlinkSync(other, manifest);
  const result = verify(f, f.receipt.snapshot_digest, script);
  assert.equal(result.status, 1); assert.equal(result.value.status, 'REFUSED');
}, { before: 'fd = os.open(root / SNAPSHOT_MANIFEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)', after: 'fd = os.open(root / SNAPSHOT_MANIFEST, os.O_RDONLY | os.O_NONBLOCK)' });

add('manifest reading is bounded even after a stale size stat', script => {
  const f = created(script);
  const bounded = path.join(scratch, `read-limit-${path.basename(script)}`);
  fs.writeFileSync(bounded, fs.readFileSync(script, 'utf8').replaceAll('64 * 1024**2', '64'));
  const driver = injected(`original = os.fstat\ndef stale(fd):\n    value = original(fd)\n    st = types.SimpleNamespace(**{key: getattr(value, key) for key in dir(value) if key.startswith('st_')})\n    st.st_size = 0\n    return st\nos.fstat = stale`);
  refused(verify(f, f.receipt.snapshot_digest, bounded, driver), 'INVALID_SNAPSHOT_MANIFEST');
}, { before: 'raise Refusal("INVALID_SNAPSHOT_MANIFEST")\n    if digest(SNAPSHOT_DOMAIN', after: 'pass # raise Refusal("INVALID_SNAPSHOT_MANIFEST")\n    if digest(SNAPSHOT_DOMAIN' });

add('snapshot does not enter restore or accept a restore command', script => {
  const f = created(script); const into = path.join(f.dir, 'restore'); fs.mkdirSync(into);
  const result = invoke(['restore', '--archive', f.target, '--expected-digest', f.receipt.snapshot_digest, '--into', into], script);
  assert.equal(result.status, 1); assert.equal(result.value.status, 'REFUSED');
  assert.deepEqual(fs.readdirSync(into), []);
  assert.equal(invoke(['restore-snapshot', '--snapshot', f.target], script).status, 2);
});

for (const [name, before, after] of [
  ['symlinks must be represented', 'row.update(type="l", target=target)', 'continue'],
  ['snapshot root is created private', 'target.mkdir(mode=0o700)', 'target.mkdir(mode=0o755)'],
  ['payload root is created private', 'payload.mkdir(mode=0o700)', 'payload.mkdir(mode=0o755)'],
  ['payload directories are created private', 'dest.mkdir(mode=0o700)', 'dest.mkdir(mode=0o755)'],
  ['payload files are created private', 'writer = os.fdopen(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")', 'writer = os.fdopen(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), "wb")'],
  ['manifest is created private', 'fd = os.open(target / SNAPSHOT_MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)', 'fd = os.open(target / SNAPSHOT_MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)'],
]) mutations.push({ name, before, after, run: cases[0].run });

try {
  for (const test of cases) { test.run(archive); checks++; }
  console.log(`PASS ops state snapshot: ${checks} checks`);
  if (process.argv.includes('--mutate')) {
    let killed = 0;
    for (const mutation of mutations) {
      const mutant = path.join(scratch, `mutant-${killed}.py`);
      fs.writeFileSync(mutant, changeOnce(source, mutation.before, mutation.after));
      const syntax = spawnSync('python3', ['-c', 'import ast,sys; ast.parse(open(sys.argv[1]).read())', mutant]);
      assert.equal(syntax.status, 0, `mutant syntax: ${mutation.name}`);
      assert.throws(() => mutation.run(mutant), assert.AssertionError, `surviving mutant: ${mutation.name}`);
      killed++;
    }
    console.log(`PASS ops state snapshot mutation controls: ${killed}/${mutations.length} killed`);
  }
} finally {
  fs.rmSync(scratch, { recursive: true, force: true });
}
