// SPDX-License-Identifier: AGPL-3.0-or-later
// Actual combined plugin; invented protected files and injected gate/HTTP only.
// No listening socket, operational key/configuration, cleanup or permission changes.
import fs from 'node:fs'
import path from 'node:path'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { registerHooks } from 'node:module'
import { makeSyntheticPostPolicy } from './synthetic-policy.mjs'

const entryUrl = new URL('../lib/index.mjs', import.meta.url)
const source = fs.readFileSync(entryUrl, 'utf8')
const variants = new Map()
const hooks = registerHooks({ load(url, context, nextLoad) {
  if (variants.has(url)) return { format: 'module', source: variants.get(url), shortCircuit: true }
  return nextLoad(url, context)
} })
const ordinary = 'Synthetic source-only relay progress update.'
const publicKey = 'SYNTHETIC_PUBLIC_JOIN_FIXTURE_ONLY'.padEnd(64, '_')
const messageId = 'c'.repeat(64), intentHash = 'a'.repeat(64), postedHash = 'b'.repeat(64)
const cursor = '9170002'
const witness = (condition, label) => assert(condition, label)
const countZero = (f, label) => {
  for (const key of ['key', 'check', 'take', 'gate', 'fetch']) witness(f.counts[key] === 0, label + ':' + key)
}
const refused = (f, result, code, label) => {
  witness(result?.ok === false && result.state === 'REFUSED', label + ':refused')
  countZero(f, label + ':no-post-effect')
  witness(result.error_code === code, label + ':error-code')
  witness(result.reason === (code === 'UNAVAILABLE' ? 'relay post policy unavailable' : 'relay post refused'), label + ':closed-reason')
  witness(Object.keys(result).sort().join(',') === 'error_code,ok,reason,state', label + ':closed-result')
}
function retainedFile(root, name, bytes, mode = 0o600) {
  const file = path.join(root, name)
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, mode)
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
  return file
}
function fixture(api, options = {}) {
  const policy = makeSyntheticPostPolicy()
  const config = Object.hasOwn(options, 'postPolicy') ? options.postPolicy : policy.config
  options.changePolicy?.(policy)
  const counts = { key: 0, check: 0, take: 0, gate: 0, fetch: 0 }
  const trace = [], sent = [], gateArgs = []
  const tools = api.createRelayTools({ postPolicy: config, gateSocket: '/synthetic-only/gate.sock',
    getKey() { counts.key++; trace.push('key'); options.onKey?.(); return publicKey },
    limiter: { check() { counts.check++; trace.push('rate-check'); options.onCheck?.() },
      take() { counts.take++; trace.push('rate-take'); options.onTake?.() } },
    async gate(_socket, op, args) {
      counts.gate++; trace.push('gate-' + args.phase)
      witness(op === 'relay_record', 'fixture:closed-gate-op')
      gateArgs.push(structuredClone(args))
      if (args.phase === 'intent') {
        options.onIntent?.()
        return options.intent ? options.intent() : { ok: true, seq: 5, hash: intentHash }
      }
      return options.posted ? options.posted() : { ok: true, seq: 9, hash: postedHash }
    },
    async fetchImpl(_url, request) {
      counts.fetch++; trace.push('fetch')
      witness(request.redirect === 'error', 'fixture:no-redirect')
      if (request.method === 'GET') return { ok: true, status: 200, json: async () => ({ messages: [
        { id: 'synthetic-read', cursor: '1', author: 'peter', kind: 'chat', body: 'Synthetic read fixture.', createdAt: 'synthetic' },
      ] }) }
      sent.push(JSON.parse(request.body))
      return { ok: true, status: 201, json: async () => ({ message: { id: messageId, cursor, author: 'auma' } }) }
    },
  })
  const protectedPaths = new Set(policy.config.files.map(file => file.path))
  return { policy, config, counts, trace, sent, gateArgs, tools,
    async post(...incoming) {
      const args = incoming.length ? incoming[0] : { text: ordinary }
      const originalOpen = fs.openSync
      fs.openSync = function (file, ...args) {
        if (protectedPaths.has(file)) trace.push('policy-read')
        return originalOpen.call(fs, file, ...args)
      }
      try {
        const raw = await tools.post.execute(args)
        witness(typeof raw === 'string' && !raw.includes(publicKey), 'fixture:key-never-returned')
        for (const value of policy.protectedValues) witness(!raw.includes(value), 'fixture:protected-value-never-returned')
        for (const file of policy.config.files) witness(!raw.includes(file.path), 'fixture:protected-path-never-returned')
        return JSON.parse(raw)
      } finally { fs.openSync = originalOpen }
    },
  }
}
function unconfirmed(f, result, label) {
  witness(result.ok === true && result.state === 'POSTED_UNRECORDED' && result.anchored === false, label + ':unconfirmed')
  witness(result.id === messageId && result.cursor === cursor, label + ':actual-relay-receipt')
  witness(!Object.hasOwn(result, 'ledger_seq') && !Object.hasOwn(result, 'ledger_hash'), label + ':no-invented-coordinates')
  witness(f.counts.fetch === 1 && f.sent.length === 1 && f.counts.gate === 2, label + ':no-retry')
}
const cases = [
  ['confirmed-receipt-and-preflight-order', async api => {
    const f = fixture(api), result = await f.post()
    witness(result.ok === true && result.state === 'POSTED' && result.anchored === true, 'join:confirmed:posted')
    witness(result.ledger_seq === 9 && result.ledger_hash === postedHash, 'join:confirmed:exact-posted-receipt')
    witness(result.cursor === cursor && String(result.ledger_seq) !== result.cursor, 'join:confirmed:cursor-separate')
    witness(f.trace.join(',') === 'policy-read,policy-read,policy-read,policy-read,rate-check,key,gate-intent,rate-take,fetch,gate-posted', 'join:confirmed:policy-before-effects')
    witness(f.counts.key === 1 && f.sent.length === 1, 'join:confirmed:one-key-one-send')
  }],
  ['protected-categories', async api => {
    for (let index = 0; index < 4; index++) {
      const f = fixture(api), result = await f.post({ text: 'A note includes ' + f.policy.protectedValues[index] + ' and stops.' })
      refused(f, result, 'REFUSED', 'join:protected:category-' + String(index))
    }
  }],
  ['secret-shapes', async api => {
    for (const text of ['d'.repeat(64), 'Bearer invented-fixture-value', 'api_key: invented-fixture-value',
      '-----BEGIN PRIVATE KEY-----\ninvented fixture material\n-----END PRIVATE KEY-----']) {
      const f = fixture(api), result = await f.post({ text })
      refused(f, result, 'REFUSED', 'join:shapes')
    }
  }],
  ['missing-policy-keeps-reader', async api => {
    const f = fixture(api, { postPolicy: undefined })
    refused(f, await f.post(), 'UNAVAILABLE', 'join:missing-policy')
    const read = JSON.parse(await f.tools.read.execute({ count: 1 }))
    witness(read.ok === true && read.messages.length === 1 && read.messages[0].order === true, 'join:missing-policy:reader-available')
    witness(f.counts.key === 1 && f.counts.fetch === 1 && f.counts.gate === 0 && f.counts.check === 0, 'join:missing-policy:reader-unchanged')
  }],
  ['malformed-policy-keeps-reader', async api => {
    const f = fixture(api, { postPolicy: {} })
    refused(f, await f.post(), 'UNAVAILABLE', 'join:malformed-policy')
    const read = JSON.parse(await f.tools.read.execute({}))
    witness(read.ok === true && read.messages.length === 1, 'join:malformed-policy:reader-available')
  }],
  ['missing-protected-file', async api => {
    const f = fixture(api, { changePolicy(p) { p.config.files[0].path = path.join(p.root, 'never-created') } })
    refused(f, await f.post(), 'UNAVAILABLE', 'join:missing-file')
  }],
  ['unreadable-protected-file', async api => {
    const f = fixture(api, { changePolicy(p) { p.config.files[0].path = retainedFile(p.root, 'unreadable', 'invented inaccessible value', 0o000) } })
    refused(f, await f.post(), 'UNAVAILABLE', 'join:unreadable-file')
  }],
  ['malformed-protected-json', async api => {
    const f = fixture(api, { changePolicy(p) {
      p.config.files[0].path = retainedFile(p.root, 'duplicate-json', '{"value":"invented one","value":"invented two"}')
      p.config.files[0].selectors = [{ kind: 'json-pointer', pointer: '/value' }]
    } })
    refused(f, await f.post(), 'UNAVAILABLE', 'join:malformed-file')
  }],
  ['closed-post-arguments', async api => {
    let invoked = 0
    const trap = () => { invoked++; throw new Error('synthetic trap must not run') }
    const accessor = Object.defineProperty({}, 'text', { enumerable: true, get: trap })
    const proxy = new Proxy({ text: ordinary }, { get: trap, getPrototypeOf: trap, ownKeys: trap, getOwnPropertyDescriptor: trap })
    const inputs = [undefined, null, [], () => ordinary, {}, { text: ordinary, extra: true },
      { text: ordinary, [Symbol('synthetic')]: true }, accessor, proxy,
      Object.create({ text: ordinary }), Object.defineProperty({}, 'text', { value: ordinary }),
      { text: new String(ordinary) }, { text: '' }, { text: '\ud800' }, { text: 'invalid\0text' }, { text: 'λ'.repeat(1001) }]
    for (const args of inputs) {
      const f = fixture(api)
      refused(f, await f.post(args), 'REFUSED', 'join:arguments')
    }
    witness(invoked === 0, 'join:arguments:traps-never-called')
  }],
  ['captured-text-survives-caller-mutation', async api => {
    for (const point of ['onCheck', 'onKey', 'onIntent']) {
      const args = { text: ordinary }
      const f = fixture(api, { [point]: () => { args.text = 'Different caller mutation after preflight.' } })
      const result = await f.post(args)
      witness(result.state === 'POSTED', 'join:captured-text:posted')
      witness(f.sent.length === 1 && f.sent[0].body === ordinary, 'join:captured-text:sent-original')
      const expected = createHash('sha256').update(ordinary, 'utf8').digest('hex')
      witness(f.gateArgs.length === 2 && f.gateArgs.every(value => value.body_sha256 === expected), 'join:captured-text:hashed-original')
      witness(f.gateArgs.every(value => value.bytes === Buffer.byteLength(ordinary, 'utf8')), 'join:captured-text:bytes-original')
    }
  }],
  ['captured-policy-survives-caller-mutation', async api => {
    const f = fixture(api)
    f.policy.config.files[0].path = path.join(f.policy.root, 'never-created-after-capture')
    refused(f, await f.post({ text: 'Embedded ' + f.policy.protectedValues[0] + ' fixture.' }), 'REFUSED', 'join:captured-policy')
  }],
  ['lost-posted-acknowledgment', async api => {
    const f = fixture(api, { posted() { throw new Error('synthetic lost acknowledgment after append') } })
    unconfirmed(f, await f.post(), 'join:lost-ack')
  }],
  ['malformed-posted-acknowledgment', async api => {
    for (const posted of [() => ({ ok: true, seq: 9 }), () => ({ ok: true, seq: '9', hash: postedHash }),
      () => ({ ok: true, seq: 9, hash: postedHash, extra: true }), () => ({ ok: false, seq: 9, hash: postedHash }),
      () => Object.defineProperty({ ok: true, seq: 9 }, 'hash', { enumerable: true, get() { throw new Error('synthetic receipt getter') } })]) {
      const f = fixture(api, { posted })
      unconfirmed(f, await f.post(), 'join:malformed-ack')
    }
  }],
  ['intent-receipt-cannot-substitute', async api => {
    const f = fixture(api, { posted: () => ({ ok: true, seq: 5, hash: intentHash }) })
    unconfirmed(f, await f.post(), 'join:stale-ack')
  }],
  ['malformed-intent-prevents-send', async api => {
    const f = fixture(api, { intent: () => ({ ok: true, seq: 5, hash: null }) })
    const result = await f.post()
    witness(result.ok === false && result.state === 'REFUSED', 'join:intent:refused')
    witness(f.sent.length === 0 && f.counts.fetch === 0 && f.counts.take === 0 && f.counts.gate === 1, 'join:intent:no-send')
    witness(!Object.hasOwn(result, 'ledger_seq') && !Object.hasOwn(result, 'ledger_hash'), 'join:intent:no-coordinates')
  }],
]

function replaceExactly(input, before, after) {
  witness(input.split(before).length === 2, 'control:unique-source-anchor')
  return input.replace(before, after)
}
const mutants = [
  ['remove-policy-call', 'protected-categories', input => replaceExactly(input, '        protectedPostPolicy.assertAllowed(text)', '')],
  ['delay-policy-until-after-rate', 'protected-categories', input => replaceExactly(
    replaceExactly(input, '        protectedPostPolicy.assertAllowed(text)', ''), '        limiter.check()', '        limiter.check()\n        protectedPostPolicy.assertAllowed(text)')],
  ['missing-policy-noop-fallback', 'missing-policy-keeps-reader', input => replaceExactly(input,
    'catch { /* posts refuse below */ }', 'catch { protectedPostPolicy = Object.freeze({ assertAllowed() {} }) }')],
  ['scrub-preflight-refusal', 'protected-categories', input => replaceExactly(input,
    "        return JSON.stringify({ ok: false, state: 'REFUSED',\n          reason: error instanceof PostPolicyError ? error.message : 'relay post refused',\n          error_code: error instanceof PostPolicyError ? error.code : 'REFUSED' })", '        return refuse(error)')],
  ['reread-caller-body', 'captured-text-survives-caller-mutation', input => replaceExactly(input,
    'kind: \'chat\', body: text, refs: []', 'kind: \'chat\', body: args.text, refs: []')],
  ['reread-caller-hash', 'captured-text-survives-caller-mutation', input => replaceExactly(input,
    "createHash('sha256').update(text, 'utf8').digest('hex')", "createHash('sha256').update(args.text, 'utf8').digest('hex')")],
  ['accept-stale-posted-sequence', 'intent-receipt-cannot-substitute', input => replaceExactly(input,
    "          if (receipt.seq <= intentReceipt.seq) throw new Error('gate posted receipt must follow the intent')", '')],
  ['allow-extra-receipt-field', 'malformed-posted-acknowledgment', input => replaceExactly(input,
    "keys.length !== 3 || keys.some(key => !['ok', 'seq', 'hash'].includes(key))", 'keys.length < 3')],
]

let phase = 'import', activeCase = null
try {
  const api = await import(entryUrl.href)
  phase = 'baseline'
  const passed = []
  for (const [label, run] of cases) { activeCase = label; await run(api); passed.push(label) }
  phase = 'controls'
  const controls = []
  for (let index = 0; index < mutants.length; index++) {
    const [label, caseName, change] = mutants[index]
    activeCase = label
    // Construction/import exceptions never count as killed guards. Only an
    // original selected baseline assertion, after successful import, qualifies.
    const modified = change(source), url = new URL('?join-control=' + String(index), entryUrl).href
    variants.set(url, modified)
    const mutantApi = await import(url)
    const run = cases.find(([name]) => name === caseName)?.[1]
    witness(typeof run === 'function', 'control:known-baseline-case')
    let failure
    try { await run(mutantApi) } catch (error) { failure = error }
    witness(failure?.name === 'AssertionError' && failure.code === 'ERR_ASSERTION'
      && failure.message.startsWith('join:'), 'control:original-assertion-required')
    controls.push({ id: label, case: caseName, status: 'KILLED', assertion: failure.message })
  }
  console.log(JSON.stringify({ status: 'PASS', scope: 'SOURCE-ONLY', actual_module: 'plugins/aukora-relay-auma/lib/index.mjs',
    baseline_cases: passed, case_count: passed.length, controls, killed_controls: controls.length,
    fixtures: { invented_protected_inputs: true, retained: true, operational_inputs: false, network_calls: false },
    receipt_scope: 'Injected gate acknowledgments; actual signed gate court runs separately.',
    installed_runtime: 'UNPERFORMED' }, null, 2))
} catch (error) {
  console.log(JSON.stringify({ status: 'FAIL', phase, case: activeCase,
    reason: error?.name === 'AssertionError' ? error.message : 'unexpected construction/import/check error',
    error_type: error?.name ?? 'unknown' }))
  process.exitCode = 1
} finally { hooks.deregister() }
