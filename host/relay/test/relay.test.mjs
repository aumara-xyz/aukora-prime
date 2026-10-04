// Synthetic tokens exercise the actual transport source. They are public fixtures,
// confer no real participant identity, and are never deployed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRelay } from '../server.mjs';
import { createStore } from '../store.mjs';
import { AUTHORS, LIMITS } from '../contract.mjs';
import { createAuthenticator, loadAuthenticator, tokenDigest } from '../auth.mjs';
import { createClient } from '../client.mjs';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';

const tokens = Object.fromEntries(AUTHORS.map(a => [a, `SYNTHETIC_PUBLIC_TEST_ONLY_${a}`.padEnd(64, '_')]));
const config = { version: 1, tokenDigests: Object.fromEntries(AUTHORS.map(a => [a, tokenDigest(tokens[a])])) };
const message = (id = 'one', overrides = {}) => ({ clientRequestId: id, kind: 'chat', body: 'Project-only transport test', refs: ['SOURCE-ONLY'], ...overrides });
async function fixture(t, storeLimits = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'relay-source-check-')); const path = join(dir, 'relay.sqlite');
  let store, server, base;
  const open = async () => {
    store = createStore(path, storeLimits); server = createRelay({ authenticate: createAuthenticator(config), store });
    await new Promise((done, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', done); });
    base = `http://127.0.0.1:${server.address().port}`;
  };
  const close = async () => { if (server?.listening) await new Promise(done => server.close(done)); server?.closeAllConnections(); store?.close(); };
  t.after(async () => { await close(); rmSync(dir, { recursive: true, force: true }); });
  await open();
  return {
    async request(path, { author = 'gpt', method = 'GET', input, headers = {}, raw, streamed = false } = {}) {
      const body = raw ?? (input === undefined ? undefined : JSON.stringify(input));
      const response = await fetch(base + path, {
        method, signal: AbortSignal.timeout(5000),
        headers: { ...(author === null ? {} : { Authorization: `Bearer ${tokens[author]}` }), ...(input === undefined && raw === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
        body: streamed ? new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(body)); controller.close(); } }) : body,
        ...(streamed ? { duplex: 'half' } : {}),
      });
      return { code: response.status, data: await response.json() };
    },
    client: author => createClient({ baseUrl: base, token: tokens[author], transport: 'ssh-loopback' }),
    base: () => base,
    path, store: () => store,
    async restart() { await close(); await open(); },
  };
}

test('authenticated identity: absent and unknown tokens fail', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('/v1/whoami', { author: null })).code, 401);
  assert.equal((await f.request('/v1/whoami', { headers: { Authorization: `Bearer ${'UNKNOWN_PUBLIC_FIXTURE_'.padEnd(64, '_')}` } })).code, 401);
  const me = await f.client('gpt').whoami(); assert.equal(me.author, 'gpt'); assert(!me.scopes.includes('messages:post:decision'));
  assert.equal((await f.request('/v1/messages', { headers: { Origin: 'https://untrusted.invalid' } })).code, 403);
  assert.equal((await f.request('/v1/status', { author: null })).code, 401);
});
test('message validation: identity fields and byte/type bounds are rejected', async t => {
  const f = await fixture(t);
  for (const input of [message('a', { author: 'peter' }), message('b', { kind: 'effect' }), message('c', { body: 'x'.repeat(LIMITS.bodyBytes + 1) }), message('d', { refs: ['x'.repeat(LIMITS.refBytes + 1)] }), message('e', { refs: Array(LIMITS.refs + 1).fill('ref') }), message('f', { body: '\ud800' }), message('g', { body: 42 }), message('h', { createdAt: 1 }), message('i', { body: ' ' })]) {
    assert.equal((await f.request('/v1/messages', { method: 'POST', input })).code, 400);
  }
  assert.equal((await f.request('/v1/messages', { method: 'POST', raw: 'x'.repeat(LIMITS.requestBytes + 1) })).code, 413);
  assert.equal((await f.request('/v1/messages', { method: 'POST', raw: 'x'.repeat(LIMITS.requestBytes + 1), streamed: true })).code, 413);
  assert.equal((await f.request('/v1/messages', { method: 'POST', raw: '{broken' })).code, 400);
  const result = await f.client('gpt').post(message('valid')); assert.equal(result.message.author, 'gpt');
});
test('Peter decisions: every non-Peter principal is refused', async t => {
  const f = await fixture(t);
  for (const author of AUTHORS.filter(a => a !== 'peter')) assert.equal((await f.request('/v1/messages', { author, method: 'POST', input: message(author, { kind: 'decision' }) })).code, 403);
  const result = await f.client('peter').post(message('owner', { kind: 'decision' })); assert.equal(result.message.author, 'peter');
  assert((await f.client('peter').whoami()).scopes.includes('messages:post:decision'));
});
test('durable idempotency: exact retries keep IDs and timestamps across restart', async t => {
  const f = await fixture(t); const first = await f.client('gpt').post(message()); assert.equal(first.replayed, false);
  const replies = await Promise.all(Array.from({ length: 8 }, () => f.client('gpt').post(message())));
  for (const result of replies) { assert.equal(result.replayed, true); assert.deepEqual(result.message, first.message); }
  await f.restart(); const replay = await f.client('gpt').post(message()); assert.deepEqual(replay.message, first.message); assert(replay.replayed);
  assert.equal((await f.client('gpt').read()).messages.length, 1);
});
test('conflicting retries: changed bytes return conflict without replacing data', async t => {
  const f = await fixture(t); await f.client('gpt').post(message());
  for (const input of [message('one', { body: 'Different body' }), message('one', { kind: 'review' }), message('one', { refs: ['different'] })]) {
    assert.equal((await f.request('/v1/messages', { method: 'POST', input })).code, 409);
  }
  assert.equal((await f.client('gpt').read()).messages[0].body, message().body);
});
test('Claude principals: cloud and local keep independent identity, retries, and status', async t => {
  const f = await fixture(t);
  const cloud = await f.client('claudecode_cloud').post(message('same-client-id'));
  const local = await f.client('claudecode_local').post(message('same-client-id'));
  assert.equal(cloud.message.author, 'claudecode_cloud'); assert.equal(local.message.author, 'claudecode_local'); assert.notEqual(cloud.message.id, local.message.id);
  assert.equal((await f.client('claudecode_local').whoami()).author, 'claudecode_local');
  await f.client('claudecode_cloud').setStatus('Cloud source review'); await f.client('claudecode_local').setStatus('Local source review');
  const rows = (await f.client('gpt').status()).status;
  assert.equal(rows.find(r => r.agent === 'claudecode_cloud').doing, 'Cloud source review'); assert.equal(rows.find(r => r.agent === 'claudecode_local').doing, 'Local source review');
});
test('cursor reads: exclusive order, pages, and exact 64-bit cursor parsing', async t => {
  const f = await fixture(t); for (let i = 0; i < 3; i++) await f.client('gpt').post(message(`page-${i}`));
  const one = await f.client('gpt').read('0', 2); assert.equal(one.messages.length, 2); assert(one.hasMore);
  const two = await f.client('gpt').read(one.nextCursor, 2); assert.equal(two.messages.length, 1); assert(!two.hasMore); assert(!one.messages.some(m => m.id === two.messages[0].id));
  const empty = await f.client('gpt').read(two.nextCursor); assert.equal(empty.messages.length, 0); assert.equal(empty.nextCursor, two.nextCursor);
  assert.equal((await f.request('/v1/messages?after=9007199254740993')).code, 409);
  const setup = new DatabaseSync(f.path); setup.prepare("UPDATE sqlite_sequence SET seq = ? WHERE name = 'messages'").run(9007199254740992n); setup.close();
  const highMessage = await f.client('gpt').post(message('wide-sequence')); assert.equal(highMessage.message.cursor, '9007199254740993');
  const high = await f.client('gpt').read('9007199254740993'); assert.equal(high.nextCursor, '9007199254740993'); assert.equal(high.messages.length, 0);
  for (const query of ['after=-1', 'after=01', 'after=1e0', 'after=9223372036854775808', 'limit=101', 'limit=0', 'limit=1.0', 'after=0&after=1', 'author=peter']) assert.equal((await f.request(`/v1/messages?${query}`)).code, 400);
});
test('self status: callers cannot set identity or timestamps and reads do not mark presence', async t => {
  const f = await fixture(t);
  const unknown = (await f.client('gpt').status()).status; assert(unknown.every(r => r.lastSeen === null));
  for (const input of [{ doing: 'Spoof', agent: 'grok' }, { doing: 'Spoof', lastSeen: 1 }, { doing: 'x'.repeat(LIMITS.doingBytes + 1) }]) assert.equal((await f.request('/v1/status', { method: 'PUT', input })).code, 400);
  const result = await f.client('gpt').setStatus('Source transport checks'); assert.equal(result.agent, 'gpt'); assert(Number.isSafeInteger(result.lastSeen));
  const rows = (await f.client('peter').status()).status; assert.equal(rows.find(r => r.agent === 'gpt').doing, 'Source transport checks'); assert.equal(rows.find(r => r.agent === 'grok').lastSeen, null);
  await f.restart(); assert.equal((await f.client('peter').status()).status.find(r => r.agent === 'gpt').doing, result.doing);
});
test('client destination: HTTPS, no URL credentials, and no redirect token forwarding', async t => {
  const token = tokens.gpt;
  assert.throws(() => createClient({ baseUrl: 'http://untrusted.invalid', token }));
  assert.throws(() => createClient({ baseUrl: 'https://user:password@untrusted.invalid', token }));
  assert.throws(() => createClient({ baseUrl: 'https://untrusted.invalid/?token=hidden', token }));
  assert.throws(() => createClient({ baseUrl: 'http://untrusted.invalid', token, transport: 'ssh-loopback' }));
  const http = await import('node:http'); const server = http.createServer((req, res) => {
    if (req.url === '/sink') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"author":"SYNTHETIC"}'); }
    else { res.writeHead(302, { Location: '/sink' }); res.end(); }
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done)); t.after(() => new Promise(done => server.close(done)));
  const client = createClient({ baseUrl: `http://127.0.0.1:${server.address().port}`, token, transport: 'ssh-loopback' }); await assert.rejects(() => client.whoami());
});
test('credential config: private external file and unique principal bindings required', t => {
  const dir = mkdtempSync(join(tmpdir(), 'relay-config-check-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'synthetic-config.json'); writeFileSync(path, JSON.stringify(config), { mode: 0o600 });
  assert.equal(loadAuthenticator(path)(`Bearer ${tokens.gpt}`), 'gpt'); chmodSync(path, 0o644); assert.throws(() => loadAuthenticator(path));
  assert.throws(() => createAuthenticator({ version: 1, tokenDigests: {} }));
  assert.throws(() => createAuthenticator({ version: 1, tokenDigests: { gpt: tokenDigest(tokens.gpt), grok: tokenDigest(tokens.gpt) } }));
  assert.throws(() => loadAuthenticator(new URL('../package.json', import.meta.url).pathname));
});
test('request quota: each authenticated principal has a bounded separate budget', async t => {
  const f = await fixture(t);
  for (let i = 0; i < LIMITS.requestsPerMinute; i++) assert.equal((await f.request('/v1/whoami')).code, 200);
  assert.equal((await f.request('/v1/whoami')).code, 429);
  assert.equal((await f.request('/v1/whoami', { author: 'grok' })).code, 200);
});
test('SSH client mode: explicit loopback-only configuration and real CLI authentication', async t => {
  const f = await fixture(t); const token = tokens.gpt;
  assert.throws(() => createClient({ baseUrl: f.base(), token }));
  assert.throws(() => createClient({ baseUrl: f.base(), token, transport: 'automatic' }));
  assert.throws(() => createClient({ baseUrl: 'https://untrusted.invalid', token, transport: 'ssh-loopback' }));
  assert.throws(() => createClient({ baseUrl: 'http://untrusted.invalid', token, transport: 'ssh-loopback' }));
  assert.throws(() => createClient({ baseUrl: 'http://localhost:18733', token, transport: 'ssh-loopback' }));
  const dir = mkdtempSync(join(tmpdir(), 'relay-cli-check-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const tokenPath = join(dir, 'public-synthetic-token'); writeFileSync(tokenPath, token, { mode: 0o600 });
  async function cli(transport, command, input) {
    return new Promise((done, fail) => {
      const child = spawn(process.execPath, [new URL('../client.mjs', import.meta.url).pathname, command], {
        env: { PATH: process.env.PATH, RELAY_URL: f.base(), RELAY_TOKEN_FILE: tokenPath, ...(transport === undefined ? {} : { RELAY_TRANSPORT: transport }) },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const timer = setTimeout(() => { child.kill(); fail(new Error('CLI check timed out')); }, 10000);
      let stdout = '', stderr = ''; child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
      child.once('error', fail); child.once('close', code => { clearTimeout(timer); done({ code, stdout, stderr }); });
      child.stdin.end(input === undefined ? undefined : JSON.stringify(input));
    });
  }
  assert.equal((await cli(undefined, 'whoami')).code, 1);
  assert.equal((await cli('automatic', 'whoami')).code, 1);
  const me = await cli('ssh-loopback', 'whoami'); assert.equal(me.code, 0); assert.equal(JSON.parse(me.stdout).author, 'gpt'); assert(!me.stdout.includes(token));
  const post = await cli('ssh-loopback', 'post', message('cli')); assert.equal(post.code, 0); assert.equal(JSON.parse(post.stdout).message.author, 'gpt');
  const read = await cli('ssh-loopback', 'read'); assert.equal(read.code, 0); assert.equal(JSON.parse(read.stdout).messages[0].id, JSON.parse(post.stdout).message.id);
  const status = await cli('ssh-loopback', 'set-status', { doing: 'Local CLI source check' }); assert.equal(status.code, 0); assert.equal(JSON.parse(status.stdout).agent, 'gpt');
  chmodSync(tokenPath, 0o644); assert.equal((await cli('ssh-loopback', 'whoami')).code, 1);
});
test('F2 principal quota: refusals, exact retries and status replacement account atomically', async t => {
  const f = await fixture(t, { agentQuotaBytes: 650, peterQuotaBytes: 2000 });
  const input = message('quota-one', { body: 'x' }); const first = await f.client('gpt').post(input);
  for (let i = 0; i < 8; i++) assert.deepEqual((await f.client('gpt').post(input)).message, first.message);
  const denied = await f.request('/v1/messages', { method: 'POST', input: message('quota-two', { body: 'x' }) });
  assert.equal(denied.code, 507); assert.equal(denied.data.error, 'principal_storage_quota');
  assert.equal((await f.request('/v1/messages', { method: 'POST', input: message('quota-one', { body: 'changed' }) })).code, 409);
  assert.equal((await f.request('/v1/status', { method: 'PUT', input: { doing: 'agent status' } })).code, 507);
  assert.equal((await f.client('gpt').read()).messages.length, 1);
  const control = await f.client('peter').post(message('owner-after-quota', { kind: 'decision', body: 'Owner headroom control' })); assert.equal(control.message.kind, 'decision');
  const grok = f.client('grok'); await grok.setStatus('x'.repeat(50)); for (let i = 0; i < 8; i++) await grok.setStatus('x'.repeat(50));
  const statusDenied = await f.request('/v1/status', { author: 'grok', method: 'PUT', input: { doing: 'x'.repeat(200) } }); assert.equal(statusDenied.code, 507);
  assert.equal((await grok.status()).status.find(r => r.agent === 'grok').doing, 'x'.repeat(50));
  await f.restart(); assert.deepEqual((await f.client('gpt').post(input)).message, first.message);
  assert.equal((await f.request('/v1/messages', { method: 'POST', input: message('quota-three', { body: 'x' }) })).code, 507);
});
test('F2 Peter headroom: agent physical growth is refused while owner decisions still fit', async t => {
  const f = await fixture(t, { maxPages: 32, reservedPeterPages: 8 }); let stopped = false;
  for (let i = 0; i < 60; i++) {
    const result = await f.request('/v1/messages', { method: 'POST', input: message(`fill-${i}`, { body: 'x'.repeat(4096) }) });
    if (result.code === 507) { assert.equal(result.data.error, 'peter_headroom_reserved'); stopped = true; break; }
    assert.equal(result.code, 201);
  }
  assert(stopped, 'physical reserve must stop the agent before the database hard cap');
  const inspect = new DatabaseSync(f.path); const used = inspect.prepare('PRAGMA page_count').get().page_count - inspect.prepare('PRAGMA freelist_count').get().freelist_count; inspect.close();
  assert(used <= 24);
  const owner = await f.client('peter').post(message('physical-owner-control', { kind: 'decision', body: 'Owner still has reserved space' })); assert.equal(owner.message.author, 'peter');
});
test('F1 SQLite FULL: native exhaustion returns 507, preserves rows and does not mask other errors', async t => {
  const f = await fixture(t, { maxPages: 16, reservedPeterPages: 4 }); await f.client('peter').post(message('before-full'));
  let full = false;
  for (let i = 0; i < 10; i++) {
    const result = await f.request('/v1/messages', { author: 'peter', method: 'POST', input: message(`native-full-${i}`, { body: 'x'.repeat(16384) }) });
    if (result.code === 507) { assert.equal(result.data.error, 'storage_full'); full = true; break; }
    assert.equal(result.code, 201);
  }
  assert(full, 'actual SQLite page exhaustion must be reached');
  assert((await f.client('peter').read()).messages.some(m => m.body === message().body));
  assert.throws(() => f.store().post('peter', message('constraint-control', { kind: 'unknown' })), error => (error.errcode & 0xff) === 19 && error.status !== 507);
  const control = await f.client('peter').post(message('after-full', { body: 'small control' })); assert.equal(control.message.body, 'small control');
});
test('D3 future cursor: ahead-of-log is 409 and the exact head remains readable', async t => {
  const f = await fixture(t); let last;
  for (let i = 0; i < 3; i++) last = await f.client('gpt').post(message(`cursor-${i}`));
  const ahead = await f.request('/v1/messages?after=1000'); assert.equal(ahead.code, 409); assert.equal(ahead.data.error, 'cursor_ahead_of_log');
  const control = await f.client('gpt').read(last.message.cursor); assert.equal(control.messages.length, 0); assert.equal(control.nextCursor, last.message.cursor);
  assert.equal((await f.client('gpt').read('0')).messages.length, 3);
});
test('N11 NUL boundary: body, refs and status reject zero bytes before SQLite', async t => {
  const f = await fixture(t);
  const body = await f.request('/v1/messages', { method: 'POST', input: message('nul-body', { body: 'before\u0000after' }) });
  assert.equal(body.code, 400); assert.equal(body.data.error, 'invalid_string');
  const refs = await f.request('/v1/messages', { method: 'POST', input: message('nul-ref', { refs: ['before\u0000after'] }) }); assert.equal(refs.code, 400);
  const status = await f.request('/v1/status', { method: 'PUT', input: { doing: 'before\u0000after' } }); assert.equal(status.code, 400);
  assert.equal((await f.client('gpt').read()).messages.length, 0);
  assert.equal((await f.client('gpt').status()).status.find(r => r.agent === 'gpt').lastSeen, null);
  const control = message('nul-body', { body: 'before-after', refs: ['ordinary-ref'] });
  const first = await f.client('gpt').post(control); const replay = await f.client('gpt').post(control);
  assert.equal(first.message.body, control.body); assert.deepEqual(replay.message, first.message); assert(replay.replayed);
  const safeStatus = await f.client('gpt').setStatus('before-after'); assert.equal(safeStatus.doing, 'before-after');
});
test('claude principal: authenticates, posts chat under its server identity, never decisions', async t => {
  const f = await fixture(t);
  const me = await f.client('claude').whoami(); assert.equal(me.author, 'claude'); assert(!me.scopes.includes('messages:post:decision'));
  const posted = await f.client('claude').post(message('claude-hello')); assert.equal(posted.message.author, 'claude');
  const read = await f.client('gpt').read(); assert.equal(read.messages.at(-1).id, posted.message.id); assert.equal(read.messages.at(-1).author, 'claude');
  assert.equal((await f.request('/v1/messages', { author: 'claude', method: 'POST', input: message('claude-decision', { kind: 'decision' }) })).code, 403);
});
test('auma principal: reads and posts plain chat only, under her own server identity', async t => {
  const f = await fixture(t);
  const me = await f.client('auma').whoami(); assert.equal(me.author, 'auma'); assert.deepEqual(me.scopes, ['messages:read', 'messages:post:chat']);
  const posted = await f.client('auma').post(message('auma-hello')); assert.equal(posted.message.author, 'auma');
  const seen = await f.client('grok').read(); assert.equal(seen.messages.at(-1).id, posted.message.id); assert.equal(seen.messages.at(-1).author, 'auma');
  assert.equal((await f.request('/v1/messages', { author: 'auma' })).code, 200);
  for (const kind of ['claim', 'review', 'decision']) assert.equal((await f.request('/v1/messages', { author: 'auma', method: 'POST', input: message(`auma-${kind}`, { kind }) })).code, 403, kind);
  assert.equal((await f.request('/v1/status', { author: 'auma' })).code, 403);
  assert.equal((await f.request('/v1/status', { author: 'auma', method: 'PUT', input: { doing: 'x' } })).code, 403);
  assert.equal((await f.request('/v1/status', { author: 'grok' })).code, 200, 'other agents keep status');
  assert.equal((await f.request('/v1/messages', { author: 'grok', method: 'POST', input: message('grok-claim', { kind: 'claim' }) })).code, 201, 'other agents keep claims');
});
test('auma body cap: her posts are capped at 2000 bytes while other agents keep the general cap', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('/v1/messages', { author: 'auma', method: 'POST', input: message('auma-max', { body: 'a'.repeat(2000) }) })).code, 201);
  assert.equal((await f.request('/v1/messages', { author: 'auma', method: 'POST', input: message('auma-big', { body: 'a'.repeat(2001) }) })).code, 413);
  assert.equal((await f.request('/v1/messages', { author: 'grok', method: 'POST', input: message('grok-big', { body: 'a'.repeat(2001) }) })).code, 201);
  assert.equal((await f.client('grok').read()).messages.filter(m => m.author === 'auma').length, 1);
});
test('auma rate: 12 requests per minute, then 429; other agents are not throttled by her budget', async t => {
  const f = await fixture(t);
  for (let i = 0; i < 12; i += 1) assert.equal((await f.request('/v1/messages', { author: 'auma' })).code, 200, `request ${i + 1}`);
  assert.equal((await f.request('/v1/messages', { author: 'auma' })).code, 429);
  assert.equal((await f.request('/v1/messages', { author: 'auma', method: 'POST', input: message('auma-late') })).code, 429);
  for (let i = 0; i < 13; i += 1) assert.equal((await f.request('/v1/messages', { author: 'grok' })).code, 200);
});
test('tail read: tail=N returns the newest N ascending in one request; bounds and mixing are refused', async t => {
  const f = await fixture(t);
  for (let i = 0; i < 25; i += 1) await f.client('grok').post(message(`m${i}`, { body: `message ${i}` }));
  const r = await f.request('/v1/messages?tail=20', { author: 'auma' }); assert.equal(r.code, 200);
  assert.equal(r.data.messages.length, 20); assert.equal(r.data.messages[0].body, 'message 5'); assert.equal(r.data.messages.at(-1).body, 'message 24');
  assert.equal(r.data.nextCursor, r.data.messages.at(-1).cursor);
  for (const q of ['tail=0', 'tail=21', 'tail=x', 'tail=5&after=1', 'tail=5&limit=5', 'tail=1&tail=2']) assert.equal((await f.request(`/v1/messages?${q}`, { author: 'auma' })).code, 400, q);
});
