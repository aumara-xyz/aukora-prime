import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { copyFileSync, mkdirSync, readFileSync, writeFileSync, lstatSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const checkRoot = dirname(fileURLToPath(import.meta.url));
const packageRoot = dirname(checkRoot);
const sourceArgument = process.argv.indexOf('--source');
assert(sourceArgument < 0 || typeof process.argv[sourceArgument + 1] === 'string', 'source argument required');
const sourceRoot = sourceArgument < 0 ? join(packageRoot, 'src') : resolve(process.argv[sourceArgument + 1]);
const retainedRoot = join(checkRoot, '.fixtures');
mkdirSync(retainedRoot, { recursive: true, mode: 0o700 });
const runRoot = join(retainedRoot, randomBytes(12).toString('hex'));
mkdirSync(runRoot, { mode: 0o700 });
let fixtureNumber = 0;
const messages = (id = 'one', body = 'synthetic bounded post') => ({ clientRequestId: id, kind: 'chat', body, refs: [] });
function caseDirectory(root) {
  const dir = join(root, String(++fixtureNumber)); mkdirSync(dir, { mode: 0o700 }); return dir;
}
function facts(path) {
  const db = new DatabaseSync(path);
  try {
    return { attempts: db.prepare('SELECT COUNT(*) AS count FROM post_attempts').get().count, messages: db.prepare('SELECT COUNT(*) AS count FROM messages').get().count, meta: db.prepare('SELECT * FROM post_rate_metadata').get() };
  } finally { db.close(); }
}
function edit(path, sql) {
  const db = new DatabaseSync(path); try { db.exec(sql); } finally { db.close(); }
}
const refuses = (fn, code, status) => assert.throws(fn, error => error?.code === code && (status === undefined || error.status === status));

function processPost(modulePath, path, id, now) {
  return new Promise((done, fail) => {
    const child = spawn(process.execPath, [join(checkRoot, 'child.mjs'), modulePath, path, id, String(now)], { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin' } });
    let stdout = ''; let stderrBytes = 0;
    child.stdout.on('data', bytes => { stdout += bytes; if (stdout.length > 4096) child.kill('SIGKILL'); });
    child.stderr.on('data', bytes => { stderrBytes += bytes.length; if (stderrBytes > 16384) child.kill('SIGKILL'); });
    const deadline = setTimeout(() => child.kill('SIGKILL'), 10000);
    child.once('error', error => { clearTimeout(deadline); fail(error); });
    child.once('close', (code, signal) => {
      clearTimeout(deadline);
      if (code !== 0 || signal) return fail(new Error('synthetic_child_failed'));
      try { done(JSON.parse(stdout.trim())); } catch { fail(new Error('synthetic_child_invalid_result')); }
    });
  });
}

async function exercise(moduleRoot, fixtureRoot, { concurrency = true, onlyCase } = {}) {
  const modulePath = join(moduleRoot, 'store.mjs');
  const { createStore, provisionNewRelayStore } = await import(pathToFileURL(modulePath).href);
  const { POST_RATE_POLICY, POST_RATE_POLICY_JSON, validatePostRatePolicy, loadPostRatePolicy } = await import(pathToFileURL(join(moduleRoot, 'post-rate-policy.mjs')).href);
  const { createRelay } = await import(pathToFileURL(join(moduleRoot, 'server.mjs')).href);
  const { createAuthenticator, tokenDigest } = await import(pathToFileURL(join(moduleRoot, 'auth.mjs')).href);
  const rows = [];
  const errors = [];
  async function one(name, body) {
    if (onlyCase !== undefined && name !== onlyCase) return;
    try { await body(); rows.push(name); }
    catch (error) { errors.push({ name, code: error?.code ?? error?.name ?? 'error', assertion: error instanceof assert.AssertionError && error.code === 'ERR_ASSERTION' }); }
  }
  function fresh() {
    const dir = caseDirectory(fixtureRoot); const path = join(dir, 'relay.sqlite');
    provisionNewRelayStore(path, { postRatePolicy: POST_RATE_POLICY });
    return path;
  }
  function opened(path, clock, limits = {}) { return createStore(path, limits, { postRatePolicy: POST_RATE_POLICY, now: clock }); }

  await one('closed fixed policy refuses missing malformed or lowered values', () => {
    refuses(() => validatePostRatePolicy(null), 'invalid_object');
    refuses(() => validatePostRatePolicy({ ...POST_RATE_POLICY, maxAttempts: 21 }), 'post_rate_policy_unavailable');
    refuses(() => validatePostRatePolicy({ ...POST_RATE_POLICY, gapMs: 0 }), 'post_rate_policy_unavailable');
    refuses(() => validatePostRatePolicy({ ...POST_RATE_POLICY, extra: true }), 'invalid_fields');
  });
  await one('setup is explicit and an existing pathname cannot be reprovisioned', () => {
    const path = fresh(); const before = facts(path);
    assert.throws(() => provisionNewRelayStore(path, { postRatePolicy: POST_RATE_POLICY }));
    assert.deepEqual(facts(path), before);
    assert.equal(lstatSync(path).mode & 0o777, 0o600);
  });
  await one('ordinary open never creates a missing store', () => {
    const dir = caseDirectory(fixtureRoot); const path = join(dir, 'absent.sqlite');
    assert.throws(() => opened(path, () => 100000)); assert.equal(existsSync(path), false);
  });
  await one('ordinary open refuses an empty existing file without a baseline', () => {
    const path = join(caseDirectory(fixtureRoot), 'empty.sqlite'); writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
    refuses(() => opened(path, () => 100000), 'storage_unconfigured');
    const db = new DatabaseSync(path); try { assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'").get().n, 0); } finally { db.close(); }
  });
  await one('new reservation and cursor survive close and reopen', () => {
    const path = fresh(); const store = opened(path, () => 100000);
    const result = store.post('gpt', messages()); store.close();
    assert.equal(result.message.cursor, '1'); assert.equal(result.replayed, false);
    const next = opened(path, () => 100001); const replay = next.post('gpt', messages()); next.close();
    assert.equal(replay.replayed, true); assert.deepEqual(replay.message, result.message);
    assert.equal(facts(path).attempts, 1); assert.equal(facts(path).messages, 1);
  });
  await one('missing policy refuses post without creating an attempt', () => {
    const path = fresh(); const store = createStore(path);
    refuses(() => store.post('gpt', messages()), 'post_rate_policy_unavailable', 503);
    assert.equal(store.read({ after: '0', limit: 1 }).messages.length, 0); store.close();
    assert.equal(facts(path).attempts, 0);
  });
  await one('malformed policy refuses post without creating an attempt', () => {
    const path = fresh(); const store = createStore(path, {}, { postRatePolicy: { ...POST_RATE_POLICY, maxAttempts: 19 } });
    refuses(() => store.post('gpt', messages()), 'post_rate_policy_unavailable', 503); store.close();
    assert.equal(facts(path).attempts, 0);
  });
  await one('an earlier store has no automatic durable rate enrollment', () => {
    const original = fresh(); const originalDb = new DatabaseSync(original);
    const schema = originalDb.prepare("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name IN ('messages','status','storage_usage')").all(); originalDb.close();
    const path = join(caseDirectory(fixtureRoot), 'earlier.sqlite'); writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
    const db = new DatabaseSync(path); try { for (const row of schema) db.exec(row.sql); } finally { db.close(); }
    const store = opened(path, () => 100000); refuses(() => store.post('gpt', messages()), 'post_rate_ledger_unconfigured', 503); store.close();
    const check = new DatabaseSync(path); try { assert.equal(check.prepare("SELECT COUNT(*) AS n FROM sqlite_schema WHERE name = 'post_attempts'").get().n, 0); } finally { check.close(); }
  });
  await one('changed persisted policy refuses and is never rebaselined', () => {
    const path = fresh(); edit(path, "UPDATE post_rate_metadata SET policy = 'invalid'");
    const store = opened(path, () => 100000); refuses(() => store.post('gpt', messages()), 'post_rate_ledger_damaged', 503); store.close();
    assert.equal(facts(path).meta.policy, 'invalid'); assert.equal(facts(path).attempts, 0);
  });
  await one('backward global clock refuses before any reservation', () => {
    const path = fresh(); let now = 100000; const store = opened(path, () => now);
    store.post('gpt', messages()); now -= 1;
    refuses(() => store.post('peter', messages('different')), 'post_rate_clock_refused', 503); store.close();
    assert.equal(facts(path).attempts, 1);
  });
  await one('noninteger asynchronous and invalid clocks refuse', () => {
    for (const clock of [() => NaN, () => -1, () => 1.5, () => Promise.resolve(100000)]) {
      const path = fresh(); const store = opened(path, clock);
      refuses(() => store.post('gpt', messages()), 'post_rate_clock_refused', 503); store.close();
      assert.equal(facts(path).attempts, 0);
    }
  });
  await one('thirty second boundary is exact and denied admission is uncharged', () => {
    const path = fresh(); let now = 100000; const store = opened(path, () => now);
    store.post('gpt', messages()); now += 29999;
    refuses(() => store.post('gpt', messages('two')), 'post_rate_gap', 429);
    assert.equal(facts(path).attempts, 1); now += 1;
    assert.equal(store.post('gpt', messages('two')).replayed, false); store.close(); assert.equal(facts(path).attempts, 2);
  });
  await one('twenty attempt rolling hour and half open boundary retain every row', () => {
    const path = fresh(); let now = 100000; const first = now; const store = opened(path, () => now);
    for (let i = 0; i < 20; i++) { store.post('gpt', messages(`item_${i}`)); now += 30000; }
    refuses(() => store.post('gpt', messages('item_20')), 'post_rate_hour', 429);
    assert.equal(facts(path).attempts, 20); now = first + 3600000;
    store.post('gpt', messages('item_20')); store.close(); assert.equal(facts(path).attempts, 21);
  });
  await one('Peter has the same durable post admission rule', () => {
    const path = fresh(); const store = opened(path, () => 100000);
    store.post('peter', { ...messages(), kind: 'decision' });
    refuses(() => store.post('peter', messages('two')), 'post_rate_gap', 429); store.close(); assert.equal(facts(path).attempts, 1);
  });
  await one('invalid body unknown author and unauthorized decision never reserve', () => {
    const path = fresh(); const store = opened(path, () => 100000);
    refuses(() => store.post('gpt', messages('bad', '   ')), 'invalid_string');
    refuses(() => store.post('unknown-author', messages()), 'invalid_author');
    refuses(() => store.post('gpt', { ...messages(), kind: 'decision' }), 'peter_only_decision');
    store.close(); assert.equal(facts(path).attempts, 0);
  });
  await one('conflicting replay refuses without another attempt', () => {
    const path = fresh(); const store = opened(path, () => 100000); store.post('gpt', messages());
    refuses(() => store.post('gpt', messages('one', 'changed synthetic bytes')), 'idempotency_conflict', 409);
    store.close(); assert.equal(facts(path).attempts, 1);
  });
  await one('failed storage retains committed attempt and blocks same request relaunch', () => {
    const path = fresh(); const store = opened(path, () => 100000, { agentQuotaBytes: 1000 });
    refuses(() => store.post('gpt', messages()), 'principal_storage_quota', 507); store.close();
    assert.equal(facts(path).attempts, 1); assert.equal(facts(path).messages, 0);
    const later = opened(path, () => 4000000);
    refuses(() => later.post('gpt', messages()), 'post_outcome_unresolved', 503);
    refuses(() => later.post('gpt', messages('one', 'different bytes')), 'idempotency_conflict', 409);
    later.post('gpt', messages('new_request')); later.close();
    assert.equal(facts(path).attempts, 2); assert.equal(facts(path).messages, 1);
  });
  await one('lost completed response can only return the actual existing receipt', () => {
    const path = fresh(); const store = opened(path, () => 100000); store.post('gpt', messages()); store.close();
    const later = opened(path, () => 100000); const result = later.post('gpt', messages()); later.close();
    assert.equal(result.replayed, true); assert.equal(result.message.cursor, '1'); assert.equal(facts(path).attempts, 1);
  });
  await one('same request identity is separate for independently authenticated authors', () => {
    const path = fresh(); const store = opened(path, () => 100000);
    const first = store.post('gpt', messages()); const second = store.post('peter', messages()); store.close();
    assert.notEqual(first.message.id, second.message.id); assert.equal(second.message.cursor, '2'); assert.equal(facts(path).attempts, 2);
  });
  await one('missing retained attempt accounting refuses rather than resetting', () => {
    const path = fresh(); const store = opened(path, () => 100000); store.post('gpt', messages()); store.close();
    edit(path, 'UPDATE post_rate_metadata SET attempt_count = 0');
    const later = opened(path, () => 4000000); refuses(() => later.post('gpt', messages('two')), 'post_rate_ledger_damaged', 503); later.close();
    assert.equal(facts(path).attempts, 1); assert.equal(facts(path).meta.attempt_count, 0);
  });
  await one('wrong file mode is refused without alteration', () => {
    const path = join(caseDirectory(fixtureRoot), 'public.sqlite'); writeFileSync(path, '', { flag: 'wx', mode: 0o644 });
    refuses(() => opened(path, () => 100000), 'private_regular_file_required'); assert.equal(lstatSync(path).mode & 0o777, 0o644);
  });
  await one('retained narrow authors cannot gain write scopes through the store', () => {
    const path = fresh(); const store = opened(path, () => 100000);
    refuses(() => store.post('ui-read', messages()), 'scope_denied', 403);
    refuses(() => store.post('auma', { ...messages(), kind: 'claim' }), 'scope_denied', 403);
    refuses(() => store.post('auma', messages('oversized', 'x'.repeat(2001))), 'body_too_large_for_author', 413);
    refuses(() => store.setStatus('auma', 'synthetic'), 'scope_denied', 403);
    refuses(() => store.setStatus('ui-read', 'synthetic'), 'scope_denied', 403);
    store.post('auma', messages('chat')); store.close(); assert.equal(facts(path).attempts, 1);
  });
  await one('tail reader and cursor beyond safe integer retain exact sequences', () => {
    const path = fresh(); edit(path, "INSERT INTO sqlite_sequence(name, seq) VALUES ('messages', 9007199254740992)");
    const store = opened(path, () => 100000); const result = store.post('dot', messages());
    assert.equal(result.message.cursor, '9007199254740993');
    assert.deepEqual(store.read({ tail: 1 }).messages, [result.message]);
    assert.equal(store.post('dot', messages()).message.cursor, result.message.cursor); store.close();
  });
  await one('mutable caller cannot change validated message bytes after admission', () => {
    const path = fresh(); const input = messages();
    const store = opened(path, () => { input.body = 'retargeted bytes'; input.refs.push('retargeted'); return 100000; });
    const result = store.post('gpt', input); store.close();
    assert.equal(result.message.body, messages().body); assert.deepEqual(result.message.refs, []);
    const next = opened(path, () => 100000); assert.equal(next.post('gpt', messages()).replayed, true); next.close();
  });
  await one('reservation itself cannot exceed principal quota or Peter headroom', () => {
    const path = fresh(); const store = opened(path, () => 100000, { agentQuotaBytes: 100 });
    refuses(() => store.post('gpt', messages()), 'principal_storage_quota', 507); store.close(); assert.equal(facts(path).attempts, 0);
    const next = opened(path, () => 100000, { maxPages: 32, reservedPeterPages: 24 });
    refuses(() => next.post('gpt', messages()), 'peter_headroom_reserved', 507); assert.equal(facts(path).attempts, 0);
    assert.equal(next.post('peter', messages()).replayed, false); next.close(); assert.equal(facts(path).attempts, 1);
  });
  await one('external policy loader preserves the closed canonical JSON', async () => {
    const dir = caseDirectory(fixtureRoot); const path = join(dir, 'policy.json');
    writeFileSync(path, POST_RATE_POLICY_JSON + '\n', { flag: 'wx', mode: 0o600 });
    // Copies/mutants live in their own package root, so this policy is external.
    let loader = loadPostRatePolicy;
    if (resolve(path).startsWith(dirname(moduleRoot) + '/')) {
      assert.throws(() => loader(path));
      const copyRoot = join(dir, 'module-copy'); mkdirSync(copyRoot, { mode: 0o700 });
      const copySrc = join(copyRoot, 'src'); mkdirSync(copySrc, { mode: 0o700 });
      for (const file of ['post-rate-policy.mjs', 'contract.mjs', 'custody.mjs']) copyFileSync(join(moduleRoot, file), join(copySrc, file));
      loader = (await import(pathToFileURL(join(copySrc, 'post-rate-policy.mjs')).href)).loadPostRatePolicy;
    }
    assert.deepEqual(loader(path), POST_RATE_POLICY);
    const duplicate = join(dir, 'duplicate.json');
    writeFileSync(duplicate, POST_RATE_POLICY_JSON.replace('{', '{"version":2,'), { flag: 'wx', mode: 0o600 });
    assert.throws(() => loader(duplicate));
  });
  await one('HTTP callback uses authenticated author and fails policy without a bind', async () => {
    const path = fresh(); const store = createStore(path); const token = randomBytes(32).toString('hex');
    const authenticate = createAuthenticator({ version: 1, tokenDigests: { gpt: tokenDigest(token) } });
    const server = createRelay({ authenticate, store });
    let listenCalls = 0; server.listen = () => { listenCalls += 1; throw new Error('network_forbidden'); };
    const response = await new Promise(done => {
      const req = { method: 'POST', url: '/v1/messages', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, async *iterator() { yield Buffer.from(JSON.stringify(messages())); } };
      const res = { destroyed: false, headersSent: false, writeHead(status) { this.status = status; this.headersSent = true; }, end(body) { done({ status: this.status, body: JSON.parse(body) }); } };
      server.emit('request', req, res);
    });
    assert.deepEqual(response, { status: 503, body: { error: 'post_rate_policy_unavailable' } });
    assert.equal(listenCalls, 0); store.close(); assert.equal(facts(path).attempts, 0);
  });
  if (concurrency) await one('independent SQLite processes share the same author admission budget', async () => {
    const path = fresh(); const results = await Promise.all([processPost(modulePath, path, 'process_one', 100000), processPost(modulePath, path, 'process_two', 100000)]);
    assert.equal(results.filter(row => row.ok).length, 1);
    assert.equal(results.filter(row => row.code === 'post_rate_gap').length, 1);
    assert.equal(facts(path).attempts, 1); assert.equal(facts(path).messages, 1);
  });
  return { passed: rows.length, failed: errors.length, executed: rows.length + errors.length, passedCases: rows, errors };
}

// Every variant changes actual module source in a retained, isolated directory.
// No network fixture or deletion/pruning command is used by this check.
const variants = [
  { name: 'policy guard removal', targetCase: 'missing policy refuses post without creating an attempt', before: "function ledgerState() {\n    requireCondition(policy !== null, 503, 'post_rate_policy_unavailable');", after: 'function ledgerState() {' },
  { name: 'gap guard removal', targetCase: 'thirty second boundary is exact and denied admission is uncharged', before: "requireCondition(priorTime === null || now - priorTime >= POST_RATE_POLICY.gapMs, 429, 'post_rate_gap');", after: 'void priorTime;' },
  { name: 'hour guard removal', targetCase: 'twenty attempt rolling hour and half open boundary retain every row', before: "requireCondition(windowAttempts.get(author, now - POST_RATE_POLICY.windowMs, now).count < POST_RATE_POLICY.maxAttempts, 429, 'post_rate_hour');", after: 'void windowAttempts;' },
  { name: 'unknown request fence removal', targetCase: 'failed storage retains committed attempt and blocks same request relaunch', before: "throw new RelayError(503, 'post_outcome_unresolved');", after: 'return { reservedAt: previousAttempt.reserved_at };' },
  { name: 'replay byte binding removal', targetCase: 'conflicting replay refuses without another attempt', before: "requireCondition(prior.kind === input.kind && prior.body === input.body && prior.refs === refs, 409, 'idempotency_conflict');", after: 'void prior;' },
  { name: 'clock guard removal', targetCase: 'backward global clock refuses before any reservation', before: "Number.isSafeInteger(now) && now >= meta.last_clock_ms", after: 'Number.isSafeInteger(now) && now >= 0' },
  { name: 'ledger history count guard removal', targetCase: 'missing retained attempt accounting refuses rather than resetting', before: 'meta.attempt_count === facts.count', after: 'true' },
  { name: 'reservation principal quota removal', targetCase: 'reservation itself cannot exceed principal quota or Peter headroom', before: 'account(author, charge(author, input.clientRequestId, requestHash, String(now)));', after: 'void requestHash;' },
  { name: 'reservation Peter headroom removal', targetCase: 'reservation itself cannot exceed principal quota or Peter headroom', before: 'advanceClock.run(now);\n        preserveHeadroom(author);', after: 'advanceClock.run(now);' },
  { name: 'admission and message transaction collapse', targetCase: 'failed storage retains committed attempt and blocks same request relaunch', before: 'const admission = transaction(() => {', after: "const admission = (() => { db.exec('BEGIN IMMEDIATE'); return ((operation) => operation()); })()(() => {", collapse: true },
];
function copyModules(root, variant) {
  mkdirSync(root, { mode: 0o700 }); const src = join(root, 'src'); mkdirSync(src, { mode: 0o700 });
  for (const file of ['store.mjs', 'server.mjs', 'auth.mjs', 'contract.mjs', 'custody.mjs', 'post-rate-policy.mjs']) copyFileSync(join(sourceRoot, file), join(src, file));
  if (variant) {
    let bytes = readFileSync(join(src, 'store.mjs'), 'utf8');
    assert.equal(bytes.split(variant.before).length - 1, 1, 'mutation anchor must be unique');
    bytes = bytes.replace(variant.before, variant.after);
    if (variant.collapse) {
      const anchor = "db.exec(`BEGIN ${mode}`); const result = operation(); db.exec('COMMIT'); return result;";
      assert.equal(bytes.split(anchor).length - 1, 1);
      bytes = bytes.replace(anchor, "if (!db.isTransaction) db.exec(`BEGIN ${mode}`); const result = operation(); db.exec('COMMIT'); return result;");
    }
    writeFileSync(join(src, 'store.mjs'), bytes);
  }
  return src;
}

const baselineFixtures = join(runRoot, 'baseline-fixtures'); mkdirSync(baselineFixtures, { mode: 0o700 });
const baseline = await exercise(sourceRoot, baselineFixtures);
console.log(`RAN ${baseline.passed} source cases PASS; ${baseline.failed} FAIL; zero listen calls; no fixture deletes`);
for (const error of baseline.errors) console.log(`FAIL ${error.name}: ${error.code}`);
function classifyRemoval(outcome, targetCase) {
  if (outcome.executed !== 1) return 'CONTROL_ERROR';
  if (outcome.failed === 0 && outcome.passed === 1 && outcome.passedCases[0] === targetCase) return 'SURVIVED';
  if (outcome.failed === 1 && outcome.passed === 0 && outcome.errors[0]?.name === targetCase && outcome.errors[0]?.assertion === true && outcome.errors[0]?.code === 'ERR_ASSERTION') return 'KILLED';
  return 'CONTROL_ERROR';
}

// Error/target classification has its own negative checks; none is a product
// protection mutant or evidence of an actual mechanism failure.
const classifierTarget = 'synthetic classifier target';
const classifierFailure = { passed: 0, failed: 1, executed: 1, passedCases: [], errors: [{ name: classifierTarget, code: 'ERR_ASSERTION', assertion: true }] };
assert.equal(classifyRemoval(classifierFailure, classifierTarget), 'KILLED');
assert.equal(classifyRemoval({ ...classifierFailure, errors: [{ name: classifierTarget, code: 'TypeError', assertion: false }] }, classifierTarget), 'CONTROL_ERROR');
assert.equal(classifyRemoval({ ...classifierFailure, errors: [{ name: classifierTarget, code: 'rate_error', assertion: false }] }, classifierTarget), 'CONTROL_ERROR');
assert.equal(classifyRemoval(classifierFailure, 'different target'), 'CONTROL_ERROR');
assert.equal(classifyRemoval({ passed: 1, failed: 0, executed: 1, passedCases: [classifierTarget], errors: [] }, classifierTarget), 'SURVIVED');
assert.equal(classifyRemoval({ passed: 0, failed: 0, executed: 0, passedCases: [], errors: [] }, classifierTarget), 'CONTROL_ERROR');
console.log('RAN 6 control-classifier checks PASS');

let killed = 0; let survived = 0; let controlErrors = 0;
if (process.argv.includes('--mutations') && baseline.failed === 0) {
  for (let i = 0; i < variants.length; i++) {
    let status = 'CONTROL_ERROR';
    try {
      assert(baseline.passedCases.includes(variants[i].targetCase), 'target must pass on original source');
      const modules = copyModules(join(runRoot, `variant_${i}`), variants[i]);
      const fixtureRoot = join(runRoot, `variant_${i}_fixtures`); mkdirSync(fixtureRoot, { mode: 0o700 });
      const outcome = await exercise(modules, fixtureRoot, { concurrency: false, onlyCase: variants[i].targetCase });
      status = classifyRemoval(outcome, variants[i].targetCase);
    } catch { /* Import, patch-anchor and fixture errors never count as kills. */ }
    if (status === 'KILLED') killed += 1;
    else if (status === 'SURVIVED') survived += 1;
    else controlErrors += 1;
    console.log(`${status} ${variants[i].name} [${variants[i].targetCase}]`);
  }
  console.log(`RAN ${killed}/${variants.length} removal controls killed; ${survived} survived; ${controlErrors} CONTROL_ERROR`);
}
process.exitCode = baseline.failed || survived || controlErrors ? 1 : 0;
