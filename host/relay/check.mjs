// Run the actual source checks, then disable each gate in isolated temporary
// source copies. Each twin must make its selected check fail. No test-only bypass
// is shipped in the server; no real agent credentials or external host is used.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const source = dirname(fileURLToPath(import.meta.url));
const twins = [
  { name: 'authentication', pattern: 'authenticated identity', changes: [['server.mjs', 'const author = authenticate(req.headers.authorization);', "const author = 'gpt';"]] },
  { name: 'browser origin refusal', pattern: 'authenticated identity', changes: [['server.mjs', '!req.headers.origin', 'true']] },
  { name: 'identity-field validation', pattern: 'message validation', changes: [['server.mjs', 'const input = validateMessage(await readJson(req));', 'const input = await readJson(req);']] },
  { name: 'string byte bounds', pattern: 'message validation', changes: [['contract.mjs', "Buffer.byteLength(value, 'utf8') <= bytes", 'true']] },
  { name: 'reference count bound', pattern: 'message validation', changes: [['contract.mjs', 'value.refs.length <= LIMITS.refs', 'true']] },
  { name: 'unicode validity', pattern: 'message validation', changes: [['contract.mjs', 'value.isWellFormed()', 'true']] },
  { name: 'streamed request byte bound', pattern: 'message validation', changes: [['server.mjs', 'bytes <= LIMITS.requestBytes', 'true']] },
  { name: 'Peter-only decision', pattern: 'Peter decisions', changes: [
    ['server.mjs', "input.kind !== 'decision' || author === 'peter'", 'true'],
    ['store.mjs', "input.kind !== 'decision' || author === 'peter'", 'true'],
    ['store.mjs', "CHECK(kind != 'decision' OR author = 'peter')", 'CHECK(1)'],
  ] },
  { name: 'durable retry lookup', pattern: 'durable idempotency', changes: [['store.mjs', 'const prior = existing.get(author, input.clientRequestId);', 'const prior = undefined;']] },
  { name: 'conflicting retry refusal', pattern: 'conflicting retries', changes: [['store.mjs', 'prior.kind === input.kind && prior.body === input.body && prior.refs === refs', 'true']] },
  { name: 'distinct Claude principals', pattern: 'Claude principals', changes: [['auth.mjs', "return [author, Buffer.from(digest, 'hex')];", "return [author === 'claudecode_local' ? 'claudecode_cloud' : author, Buffer.from(digest, 'hex')];"]] },
  { name: 'exclusive cursor', pattern: 'cursor reads', changes: [['store.mjs', 'seq > ? ORDER BY seq', 'seq >= ? ORDER BY seq']] },
  { name: 'bounded page size', pattern: 'cursor reads', changes: [['contract.mjs', 'Number(limit) <= LIMITS.pageSize', 'true']] },
  { name: 'self-only status', pattern: 'self status', changes: [['server.mjs', 'store.setStatus(author, input.doing)', "store.setStatus('grok', input.doing)"]] },
  { name: 'HTTPS client destination', pattern: 'client destination', changes: [['client.mjs', "(transport === 'https' && base.protocol === 'https:') || (transport === 'ssh-loopback' && base.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(base.hostname))", 'true']] },
  { name: 'redirect refusal', pattern: 'client destination', changes: [['client.mjs', "redirect: 'error'", "redirect: 'follow'"]] },
  { name: 'private credential file', pattern: 'credential config', changes: [['auth.mjs', '(stat.mode & 0o077) === 0', 'true']] },
  { name: 'unique credential binding', pattern: 'credential config', changes: [['auth.mjs', '!seen.has(digest)', 'true']] },
  { name: 'per-principal request quota', pattern: 'request quota', changes: [['server.mjs', 'rate.count <= LIMITS.requestsPerMinute', 'true']] },
  { name: 'SSH mode explicit destination guard', pattern: 'SSH client mode', changes: [['client.mjs', "(transport === 'https' && base.protocol === 'https:') || (transport === 'ssh-loopback' && base.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(base.hostname))", 'true']] },
  { name: 'principal storage quota', pattern: 'F2 principal quota', changes: [['store.mjs', "next <= (author === 'peter' ? limits.peterQuotaBytes : limits.agentQuotaBytes)", 'true']] },
  { name: 'Peter physical headroom', pattern: 'F2 Peter headroom', changes: [['store.mjs', "author === 'peter' || usedPages <= limits.maxPages - limits.reservedPeterPages", 'true']] },
  { name: 'SQLite auto-rollback guard', pattern: 'F1 SQLite FULL', changes: [['store.mjs', "if (db.isTransaction) db.exec('ROLLBACK');", "db.exec('ROLLBACK');"]] },
  { name: 'SQLite FULL mapping', pattern: 'F1 SQLite FULL', changes: [['store.mjs', "if (error?.code === 'ERR_SQLITE_ERROR' && (error.errcode & 0xff) === 13)", 'if (false)']] },
  { name: 'future cursor refusal', pattern: 'D3 future cursor', changes: [['store.mjs', 'BigInt(after) <= head.get().seq', 'true']] },
  { name: 'NUL string boundary', pattern: 'N11 NUL boundary', changes: [['contract.mjs', "!value.includes('\\u0000')", 'true']] },
];
function run(cwd, pattern) {
  const result = spawnSync(process.execPath, ['--test', '--test-reporter=tap', ...(pattern ? ['--test-name-pattern', pattern] : []), 'test/relay.test.mjs'], { cwd, encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 });
  if (result.error || result.signal) throw new Error(`Check execution failed: ${result.error?.code ?? result.signal}`);
  return result;
}
const baseline = run(source); process.stdout.write(baseline.stdout); process.stderr.write(baseline.stderr);
console.log(`BASELINE exit=${baseline.status}`);
if (baseline.status !== 0) process.exit(1);
for (const twin of twins) {
  const target = mkdtempSync(join(tmpdir(), 'relay-disabled-twin-'));
  try {
    for (const entry of ['package.json', 'contract.mjs', 'auth.mjs', 'store.mjs', 'server.mjs', 'client.mjs', 'test']) cpSync(join(source, entry), join(target, entry), { recursive: true });
    for (const [file, before, after] of twin.changes) {
      const path = join(target, file); const text = readFileSync(path, 'utf8');
      if (text.split(before).length !== 2) throw new Error(`Twin mutation no longer exact: ${twin.name}`);
      writeFileSync(path, text.replace(before, after));
    }
    const result = run(target, twin.pattern);
    if (result.status === 0 || !result.stdout.includes('not ok')) throw new Error(`Twin did not falsify its check: ${twin.name}`);
    console.log(`TWIN ${twin.name}: exit=${result.status}, expected failure observed`);
  } finally { rmSync(target, { recursive: true, force: true }); }
}
console.log(`RAN: actual relay source, local synthetic fixtures; baseline passed and ${twins.length} disabled twins failed. Nebius deployment and real participant connectivity UNPERFORMED.`);
