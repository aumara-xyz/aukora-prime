// SPDX-License-Identifier: AGPL-3.0-or-later
// In-process gate pages and software signatures check rehearsal refusals without an installed node.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { EventEmitter } from 'node:events'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { createGate } from '../../../packages/boundary-gate/src/gate.mjs'
import { openDb, keyFingerprint } from '../../../packages/boundary-gate/src/ledger.mjs'
import { themeTarget, THEME_TARGET } from '../../../packages/boundary-gate/src/targets.mjs'
import { verifyReceipt } from '../../../packages/boundary-gate/src/receipts.mjs'
import { createPasskeyEnrollmentCeremony } from '../../../packages/authority/src/passkey-enrollment.mjs'
import { didKeyFromEd25519PublicKey } from '../../../packages/authority/upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import * as driver from './rehearse-passkey.mjs'

const ownerOrigin = 'https://owner.example.test', appOrigin = 'https://app.example.test', rpId = 'owner.example.test'
const hash = value => createHash('sha256').update(value).digest('hex')
const driverUrl = new URL('./rehearse-passkey.mjs', import.meta.url)
const marker = '<meta name="aukora-node-mode" content="rehearsal">'
const pageUrl = new URL('../../../packages/boundary-gate/src/owner-page.mjs', import.meta.url)
const pageSource = fs.readFileSync(pageUrl, 'utf8').replace("mode === 'enroll' && readRehearsalMarker()", "mode === 'enroll' && false")
  .replace(/from\s+(['"])(\.[^'"]+)\1/g, (_match, quote, relative) => 'from ' + quote + new URL(relative, pageUrl).href + quote)
const { createPasskeyOwnerHandler } = await import('data:text/javascript;base64,' + Buffer.from(pageSource).toString('base64'))

function fixture(t, { alter = () => {}, markerPresent = true, proposal = true, signin = true,
  cookie = '__Host-aukora-session=synthetic-session; Path=/; Secure; HttpOnly; SameSite=Strict' } = {}) {
  const home = fs.mkdtempSync(path.join(process.cwd(), '.rehearse-passkey-'))
  const pair = generateKeyPairSync('ed25519'), now = Date.now()
  const key = { priv: pair.privateKey, pub: pair.publicKey, pubPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(), fp: keyFingerprint(pair.publicKey) }
  const f = { home, key, now, calls: [], lines: [], current: Buffer.from('{"accent": "default"}'), writes: 0,
    claim: 'x'.repeat(43), bearer: 'synthetic-private-page-access', joined: false, proposal: null }
  f.setup = { version: 1, kind: 'aukora-gate-passkey-setup/v1', gate: hash(pair.publicKey.export({ format: 'der', type: 'spki' })),
    node: 'c'.repeat(64), origin: ownerOrigin, rp_id: rpId, claim_sha256: hash(f.claim), expires_at_ms: now + 300000,
    binding: { identity: { owner_id: 'software-owner', subject: 'aukora:1:' + 'a'.repeat(64),
      approval_key_did: didKeyFromEd25519PublicKey('b'.repeat(64)), control_digest: 'd'.repeat(64), authorization_epoch: 1 },
      identity_provenance: { kind: 'owner-approved-initial-public-identity/v1', identity_source_sha256: 'e'.repeat(64), approval_reference: 'root-selected-test-binding' },
      passkey_profile: { profile: 'https', origin: ownerOrigin, rp_id: rpId },
      user: { id: Buffer.from('software-owner').toString('base64url'), name: 'Owner', display_name: 'Owner' }, existing_credential_ids: [] } }
  f.open = joined => createGate({ home, key, db: openDb(path.join(home, 'gate.db')),
    owner: { bearer: f.bearer, bearer_expires: now + 3600000, hmacKey: 'f'.repeat(64) },
    readPasskeySetup: () => f.setup, passkeyEnrollmentCeremony: createPasskeyEnrollmentCeremony,
    ...(joined ? { browserJoin: { appOrigin, readBinding: () => ({ subject: f.setup.binding.identity.subject, rootId: 'b'.repeat(64) }) } } : {}),
    targets: { [THEME_TARGET]: themeTarget(home) }, now: () => now, iso: () => new Date(now).toISOString(),
    limits: { maxPerWindow: 100, rejectCooldownMs: 0 },
    store: { read: () => f.current, write: (_target, _sha, bytes) => { f.current = Buffer.from(bytes); f.writes++ } } })
  f.gate = f.open(false)
  t.after(() => { f.gate.close(); fs.rmSync(home, { recursive: true, force: true }) })
  f.raise = () => {
    f.proposal = f.gate.proposeOps.propose({ target: THEME_TARGET, content: '{"accent": "#112233"}',
      claimed_base: hash(f.current), why: 'Passkey protocol rehearsal', session: 'software-rehearsal' })
  }
  async function page(url, options) {
    const req = new EventEmitter(), headers = Object.fromEntries(new Headers(options.headers || {}))
    Object.assign(req, { method: options.method || 'GET', url: url.pathname + url.search,
      headers: { host: url.host, ...headers }, setTimeout() {}, destroy() {} })
    const res = { writeHead(status, fields) { this.status = status; this.headers = fields }, end(body) { this.body = body } }
    const handler = createPasskeyOwnerHandler(f.gate, { origin: ownerOrigin, rpId,
      ...(f.joined ? { appOrigin, node: f.setup.node, gateId: f.setup.gate } : {}) }).handler
    const work = handler(req, res)
    if (req.method !== 'GET') { req.emit('data', Buffer.from(options.body || '')); req.emit('end') }
    await work
    if (url.pathname === '/owner/enroll' && markerPresent) res.body = res.body.replace('<head>', '<head>' + marker)
    return res
  }
  f.fetch = async (input, options = {}) => {
    const url = new URL(input), method = options.method || 'GET'
    const call = { url, method, options, body: options.body && new Headers(options.headers).get('content-type') === 'application/json' ? JSON.parse(options.body) : options.body }
    f.calls.push(call)
    let result
    if (url.origin === ownerOrigin) {
      if (url.pathname === '/owner/cards' && proposal && !f.proposal) f.raise()
      if (url.pathname === '/owner/signin' && signin && !f.joined) {
        f.gate.close(); f.joined = true; f.gate = f.open(true)
      }
      result = await page(url, options)
    } else if (url.origin === appOrigin && url.pathname === '/__aukora/signin' && method === 'POST') {
      const redeemed = await page(new URL('/owner/signin/redeem', ownerOrigin), { method: 'POST',
        headers: { origin: ownerOrigin, 'content-type': 'application/json', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty' },
        body: JSON.stringify({ code: options.body, app_origin: appOrigin }) })
      assert.equal(redeemed.status, 200, 'real owner-browser one-use code exchange')
      const value = JSON.parse(redeemed.body)
      assert.equal(value.ok, true); assert.equal(value.result.app_origin, appOrigin)
      f.redeemed = value.result
      result = { status: 204, headers: { 'set-cookie': cookie }, body: '' }
    } else if (url.origin === appOrigin && url.pathname === '/__aukora/signin' && method === 'GET') {
      result = { status: 200, headers: { 'content-type': 'text/html' }, body: '<!doctype html><script src="/__aukora/signin.js"></script>' }
    } else throw new Error('TEST_UNEXPECTED_ROUTE')
    await alter(call, result, f)
    const response = new Response(result.status === 204 ? null : result.body, { status: result.status, headers: result.headers })
    Object.defineProperty(response, 'url', { value: url.href })
    return response
  }
  f.run = (module = driver, overrides = {}) => module.rehearsePasskey({ ownerOrigin, appOrigin,
    claimLink: ownerOrigin + '/owner/enroll#claim=' + f.claim,
    cardsLink: ownerOrigin + '/owner/cards?bearer=' + f.bearer,
    fetch: f.fetch, log: line => f.lines.push(line), wait: async () => {}, timeoutMs: 10, ...overrides })
  return f
}

test('rehearsal completes real gate enrollment, exact-card approval, refusals and returning sign-in in process', async t => {
  const f = fixture(t)
  assert.equal(await f.run(), true, f.lines.join('\n'))
  assert.equal(f.writes, 1)
  assert.equal(f.current.toString(), '{"accent": "#112233"}')
  assert.equal(f.gate.db.prepare('SELECT claim_state FROM owner_passkey').get().claim_state, 'spent')
  assert.equal(f.gate.db.prepare('SELECT spent FROM owner_browser_codes').get().spent, 1)
  assert.equal(f.redeemed.node, f.setup.node)
  assert.ok(f.lines.length >= 12)
  assert.ok(f.lines.every(line => /^PASS [a-zA-Z0-9 _-]+$/.test(line)))
  assert.doesNotMatch(f.lines.join('\n'), new RegExp(f.claim + '|' + f.bearer + '|synthetic-session'))
  const approvals = f.calls.filter(call => call.url.pathname === '/owner/approve' && call.body.owner_authorization_proof)
  assert.ok(approvals.length >= 5, 'three wrong proofs, approval and replay reach the real gate')
  const rows = f.gate.db.prepare("SELECT detail FROM ledger WHERE event='apply'").all()
  assert.equal(rows.length, 1)
  const { receipt, receipt_sig } = JSON.parse(rows[0].detail)
  assert.equal(verifyReceipt(f.gate.db, receipt, receipt_sig, f.key.pub).ok, true)
  console.log('SOURCE-ONLY passkey rehearsal: real in-process enrollment, approval, receipt, replay/RP/origin/challenge refusals and sign-in; harness cookie simulated')
})

function loaded(source) {
  const rewritten = source.replace(/from\s+(['"])(\.[^'"]+)\1/g, (_match, quote, relative) => 'from ' + quote + new URL(relative, driverUrl).href + quote)
  return import('data:text/javascript;base64,' + Buffer.from(rewritten).toString('base64'))
}
function changedJson(result, change) {
  const value = JSON.parse(result.body); change(value.result, value); result.body = JSON.stringify(value)
}
function changeRoute(route, change, occurrence = 1) {
  return (call, result, f) => {
    if (call.url.pathname === route && f.calls.filter(item => item.url.pathname === route).length === occurrence) change(call, result, f)
  }
}
async function refused(t, module, options, code, label, overrides = {}) {
  const f = fixture(t, options)
  assert.equal(await f.run(module, overrides), false, 'rehearsal must fail')
  assert.equal(f.lines.at(-1), 'FAIL ' + label + ' REHEARSAL_' + code)
  assert.equal(f.lines.includes('PASS ' + label), false, 'failed step must never print PASS')
  return f
}

const protections = [
  ['marker', 'MARKER_REQUIRED', 'enrollment-page', { markerPresent: false }],
  ['page profile', 'PAGE_PROFILE_REFUSED', 'enrollment-page', { alter: changeRoute('/owner/enroll', (_call, res) => { res.body = res.body.replace('data-origin="' + ownerOrigin + '"', 'data-origin="' + appOrigin + '"') }) }],
  ['successful HTTP and envelope', 'REQUEST_REFUSED', 'create', { alter: changeRoute('/owner/enroll/start', (_call, res) => { res.status = 403; changedJson(res, (_value, envelope) => { envelope.ok = false }) }) }],
  ['JSON response', 'RESPONSE_INVALID', 'create', { alter: changeRoute('/owner/enroll/start', (_call, res) => { res.body = 'invalid JSON' }) }],
  ['fresh registration', 'FRESH_ENROLLMENT_REQUIRED', 'create', { alter: changeRoute('/owner/enroll/start', (_call, res) => changedJson(res, value => { value.stage = 'possession' })) }],
  ['ceremony ID', 'ENROLLMENT_ID_MISMATCH', 'create', { alter: changeRoute('/owner/enroll/register', (_call, res) => changedJson(res, value => { value.enrollment_id = 'changed' })) }],
  ['confirmed possession', 'ENROLLMENT_NOT_CONFIRMED', 'possession', { alter: changeRoute('/owner/enroll/finish', (_call, res) => changedJson(res, value => { value.enrolled = false })) }],
  ['exact refusal', 'REFUSAL_NOT_OBSERVED', 'enrollment-closed', { alter: changeRoute('/owner/enroll/start', (_call, res) => { res.status = 200; res.body = JSON.stringify({ ok: true, result: {} }) }, 2) }],
  ['cards page', 'CARDS_PAGE_REFUSED', 'pending-theme', { alter: changeRoute('/owner/cards', (_call, res) => { res.status = 403 }) }],
  ['one proposal', 'ONE_THEME_REQUIRED', 'pending-theme', { alter: changeRoute('/owner/cards', (_call, res) => { res.body = res.body.replace(/(<article data-card[\s\S]*?<\/article>)/, '$1$1') }) }],
  ['theme-only', 'THEME_REQUIRED', 'pending-theme', { alter: changeRoute('/owner/cards', (_call, res) => { res.body = res.body.replace('plugins/auma-theme/theme.json', 'plugins/other/approval.json') }) }],
  ['pending deadline', 'PENDING_TIMEOUT', 'pending-theme', { proposal: false }],
  ['exact card digest', 'CARD_DIGEST_REFUSED', 'wrong-rpid', { alter: changeRoute('/owner/review', (_call, res) => changedJson(res, value => { value.card_text += ' ' })) }],
  ['harmless exact content', 'CARD_CHANGED', 'wrong-rpid', { alter: changeRoute('/owner/review', (_call, res) => changedJson(res, value => {
    const card = JSON.parse(value.card_text); card.content = '{"accent":"#112233"}'; value.card_text = JSON.stringify(card); value.owner_authorization.card_sha256 = hash(value.card_text)
  })) }],
  ['enrolled authorization binding', 'AUTHORIZATION_MISMATCH', 'wrong-rpid', { alter: changeRoute('/owner/review', (_call, res) => changedJson(res, value => { value.owner_authorization.node = 'd'.repeat(64) })) }],
  ['challenge is authorization digest', 'CHALLENGE_DIGEST_REFUSED', 'wrong-rpid', { alter: changeRoute('/owner/review', (_call, res) => changedJson(res, value => { value.authorization_digest = 'd'.repeat(64) })) }],
  ['APPLIED response', 'APPLY_NOT_OBSERVED', 'applied-receipt', { alter: (call, res) => {
    if (call.url.pathname === '/owner/approve' && res.status === 200) changedJson(res, value => { value.applied = false })
  } }],
  ['bound receipt', 'RECEIPT_REQUIRED', 'applied-receipt', { alter: (call, res) => {
    if (call.url.pathname === '/owner/approve' && res.status === 200) changedJson(res, value => { value.receipt_sig = '' })
  } }],
  ['no remaining pending card', 'APPLIED_STILL_PENDING', 'applied-receipt', { alter: changeRoute('/owner/cards', (_call, res, f) => {
    res.body = res.body.replace('</body>', '<article data-id="' + f.proposal.id + '"></article></body>')
  }, 2) }],
  ['sign-in profile', 'SIGNIN_PROFILE_REFUSED', 'signin-page', { alter: changeRoute('/owner/signin', (_call, res) => { res.body = res.body.replace('data-app-origin="' + appOrigin + '"', 'data-app-origin="https://other.example.test"') }) }],
  ['sign-in deadline', 'SIGNIN_TIMEOUT', 'signin-page', { signin: false }],
  ['sign-in statement', 'SIGNIN_STATEMENT_REFUSED', 'signin-proof', { alter: changeRoute('/owner/signin/start', (_call, res) => changedJson(res, value => {
    const statement = JSON.parse(value.statement_text); statement.app_origin = 'https://other.example.test'; value.statement_text = JSON.stringify(statement)
  })) }],
  ['returned code audience', 'SIGNIN_CODE_REFUSED', 'signin-proof', { alter: changeRoute('/owner/signin/finish', (_call, res) => changedJson(res, value => { value.app_origin = 'https://other.example.test' })) }],
  ['app sign-in page', 'APP_SIGNIN_PAGE_REFUSED', 'host-session-cookie', { alter: (call, res) => {
    if (call.url.origin === appOrigin && call.method === 'GET') res.status = 403
  } }],
  ['session exchange status', 'SESSION_EXCHANGE_REFUSED', 'host-session-cookie', { alter: (call, res) => {
    if (call.url.origin === appOrigin && call.method === 'POST') res.status = 200
  } }],
  ['host-only cookie', 'HOST_COOKIE_REQUIRED', 'host-session-cookie', { cookie: 'aukora-session=synthetic-session; Path=/; Secure; HttpOnly; SameSite=Strict' }],
]
for (const [name, code, label, options] of protections) test('rehearsal refuses ' + name + ' before its PASS line', t => refused(t, driver, options, code, label))

test('removing each driver outcome check fails its focused regression', async t => {
  const source = fs.readFileSync(driverUrl, 'utf8')
  let killed = 0
  for (const [name, code, label, options] of protections) await t.test(name, async st => {
    const expression = new RegExp("need\\(([\\s\\S]*?),\\s*'" + code + "'\\)", 'g')
    const matches = [...source.matchAll(expression)]
    assert.equal(matches.length, 1, 'one named mutation anchor: ' + name)
    const anchor = matches[0][0], index = matches[0].index
    const start = source.lastIndexOf('need(', index + anchor.length - 1)
    const end = index + anchor.length
    const mutated = await loaded(source.slice(0, start) + "need(true, '" + code + "')" + source.slice(end))
    await assert.rejects(() => refused(st, mutated, options, code, label), assert.AssertionError, name)
    killed++
  })
  console.log(`SOURCE-ONLY passkey rehearsal outcome mutations: ${killed}/${protections.length} killed`)
})

test('a gate refusal never produces PASS at any positive protocol stage; bypassing the check is caught', async t => {
  const source = fs.readFileSync(driverUrl, 'utf8')
  const anchor = "need(response.status === 200 && body.ok === true && body.result && typeof body.result === 'object', 'REQUEST_REFUSED')"
  assert.equal(source.split(anchor).length, 2)
  const loose = await loaded(source.replace(anchor, ''))
  const cases = [
    ['/owner/enroll/start', 'create'], ['/owner/enroll/register', 'create'], ['/owner/enroll/finish', 'possession'],
    ['/owner/review', 'wrong-rpid'], ['/owner/approve', 'applied-receipt'], ['/owner/signin/start', 'signin-proof'], ['/owner/signin/finish', 'signin-proof'],
  ]
  for (const [route, label] of cases) await t.test(route, async st => {
    const options = { alter: (call, res) => {
      if (call.url.pathname === route && res.status === 200) { res.status = 403; changedJson(res, (_value, envelope) => { envelope.ok = false }) }
    } }
    await refused(st, driver, options, 'REQUEST_REFUSED', label)
    await assert.rejects(() => refused(st, loose, options, 'REQUEST_REFUSED', label), assert.AssertionError)
  })
  console.log(`SOURCE-ONLY passkey rehearsal gate-refusal mutation cases: ${cases.length}/${cases.length} killed`)
})

test('accepted or unrelated-error responses cannot satisfy any negative protocol step', async t => {
  const cases = [
    ['/owner/enroll/start', 2, 'enrollment-closed'], ['/act', 1, 'bearer-refused'], ['/owner/approve', 1, 'bearer-refused'],
    ['/owner/approve', 2, 'wrong-rpid'], ['/owner/approve', 3, 'wrong-origin'], ['/owner/approve', 4, 'wrong-challenge'], ['/owner/approve', 6, 'replay-refused'],
  ]
  for (const [route, occurrence, label] of cases) await t.test(label + ' ' + route, async st => {
    for (const accepted of [true, false]) {
      const alter = changeRoute(route, (_call, res) => {
        res.status = accepted ? 200 : 403
        res.body = JSON.stringify(accepted ? { ok: true, result: {} } : { ok: false, error: 'UNRELATED_GATE_ERROR' })
      }, occurrence)
      await refused(st, driver, { alter }, 'REFUSAL_NOT_OBSERVED', label)
    }
  })
})

test('canonical software-authenticator options are enforced and each guard removal is killed', async () => {
  const source = fs.readFileSync(driverUrl, 'utf8')
  const creation = { rp: { id: rpId }, attestation: 'none', authenticatorSelection: { userVerification: 'required' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }], challenge: Buffer.alloc(32, 1).toString('base64url'), user: { id: 'AQ' } }
  const cases = [
    ['creation profile', "need(publicKey?.rp?.id === rpId && publicKey.attestation === 'none'\n        && publicKey.authenticatorSelection?.userVerification === 'required'\n        && publicKey.pubKeyCredParams?.some(item => item.type === 'public-key' && item.alg === -7), 'CREATION_OPTIONS_REFUSED')",
      auth => auth.registration({ ...creation, attestation: 'direct' }), 'CREATION_OPTIONS_REFUSED'],
    ['base64url alphabet', "need(typeof text === 'string' && /^[A-Za-z0-9_-]+$/.test(text), 'OPTIONS_INVALID')",
      auth => auth.registration({ ...creation, challenge: '' }), 'OPTIONS_INVALID'],
    ['canonical base64url', "need(bytes.toString('base64url') === text, 'OPTIONS_INVALID')",
      auth => auth.registration({ ...creation, challenge: 'AR' }), 'OPTIONS_INVALID'],
    ['assertion credential RP and UV', "need(publicKey?.rpId === rpId && publicKey.userVerification === 'required'\n      && publicKey.allowCredentials?.some(item => item.type === 'public-key' && item.id === credentialId), 'ASSERTION_OPTIONS_REFUSED')",
      auth => auth.assertion({ rpId, userVerification: 'required', allowCredentials: [{ type: 'public-key', id: 'other' }], challenge: creation.challenge }), 'ASSERTION_OPTIONS_REFUSED'],
  ]
  for (const [name, anchor, exercise, code] of cases) {
    const check = module => {
      const auth = module.createSoftwareAuthenticator({ origin: ownerOrigin, rpId })
      assert.throws(() => exercise(auth), { message: 'REHEARSAL_' + code })
    }
    check(driver)
    assert.equal(source.split(anchor).length, 2, 'one mutation anchor: ' + name)
    const mutated = await loaded(source.replace(anchor, ''))
    assert.throws(() => check(mutated), assert.AssertionError, name)
  }
  console.log(`SOURCE-ONLY passkey rehearsal authenticator mutations: ${cases.length}/${cases.length} killed`)
})

test('claim and cards links cannot select another route or carry a noncanonical secret; guard removals are killed', async t => {
  const source = fs.readFileSync(driverUrl, 'utf8')
  const cases = [
    ['closed origin/path/fragment fields', "need(url.origin === expectedOrigin && !url.username && !url.password && url.pathname === path\n    && (fragment ? !url.search : !url.hash) && [...secret.keys()].join(',') === key, 'LINK_INVALID')",
      { claimLink: ownerOrigin + '/owner/enroll/unexpected#claim=' + 'x'.repeat(43) }],
    ['canonical private claim/card secret', "need(fragment ? /^[A-Za-z0-9_-]{43}$/.test(code ?? '') : /^[A-Za-z0-9_-]{16,256}$/.test(code ?? ''), 'LINK_INVALID')",
      { cardsLink: ownerOrigin + '/owner/cards?bearer=short' }],
  ]
  for (const [name, anchor, overrides] of cases) {
    await refused(t, driver, {}, 'LINK_INVALID', 'inputs', overrides)
    assert.equal(source.split(anchor).length, 2, 'one mutation anchor: ' + name)
    const mutated = await loaded(source.replace(anchor, ''))
    await assert.rejects(() => refused(t, mutated, {}, 'LINK_INVALID', 'inputs', overrides), assert.AssertionError)
  }
  for (const claimLink of [ownerOrigin + '/owner/enroll#claim=' + 'x'.repeat(43) + '&extra=1',
    appOrigin + '/owner/enroll#claim=' + 'x'.repeat(43), ownerOrigin + '/owner/enroll?claim=synthetic#claim=' + 'x'.repeat(43)]) {
    const f = await refused(t, driver, {}, 'LINK_INVALID', 'inputs', { claimLink })
    assert.equal(f.calls.length, 0, 'invalid private link is never fetched')
  }
  console.log(`SOURCE-ONLY passkey rehearsal private-link mutations: ${cases.length}/${cases.length} killed`)
})

test('two-origin requests refuse unsafe redirects and oversized responses; guard removals are killed', async () => {
  const source = fs.readFileSync(driverUrl, 'utf8')
  const response = (status = 200, headers = {}, body = 'safe') => new Response(body, { status, headers })
  const cases = [
    ['HTTPS origin', "need(url.protocol === 'https:' && url.origin === value && !url.username && !url.password, 'ORIGIN_INVALID')",
      async module => assert.throws(() => module.checkedFetch('http://owner.example.test', appOrigin, () => response()), { message: 'REHEARSAL_ORIGIN_INVALID' })],
    ['separate origins', "need(ownerOrigin !== appOrigin, 'ORIGINS_NOT_SEPARATED')",
      async module => assert.throws(() => module.checkedFetch(ownerOrigin, ownerOrigin, () => response()), { message: 'REHEARSAL_ORIGINS_NOT_SEPARATED' })],
    ['redirect origin boundary', "need([ownerOrigin, appOrigin].includes(url.origin) && !url.username && !url.password && !url.hash, 'REDIRECT_REFUSED')",
      async module => {
        const calls = [], fetch = async target => { calls.push(target); return calls.length === 1 ? response(302, { location: 'https://other.example.test/' }) : response() }
        await assert.rejects(module.checkedFetch(ownerOrigin, appOrigin, fetch)(ownerOrigin + '/owner/enroll'), { message: 'REHEARSAL_REDIRECT_REFUSED' })
        assert.equal(calls.length, 1, 'foreign origin is never contacted')
      }],
    ['redirected POST', "need(method === 'GET' && response.headers.has('location'), 'REDIRECT_REFUSED')",
      async module => {
        let calls = 0
        const fetch = async () => ++calls === 1 ? response(307, { location: '/elsewhere' }) : response()
        await assert.rejects(module.checkedFetch(ownerOrigin, appOrigin, fetch)(ownerOrigin + '/owner/enroll/start', { method: 'POST', body: 'private' }), { message: 'REHEARSAL_REDIRECT_REFUSED' })
        assert.equal(calls, 1, 'POST proof is never redirected')
      }],
    ['bounded redirects', "need(false, 'REDIRECT_LIMIT')",
      async module => assert.rejects(module.checkedFetch(ownerOrigin, appOrigin, async () => response(302, { location: '/loop' }))(ownerOrigin + '/loop'), { message: 'REHEARSAL_REDIRECT_LIMIT' })],
    ['bounded response', "need(bytes <= 262144, 'RESPONSE_TOO_LARGE')",
      async module => assert.rejects(module.checkedFetch(ownerOrigin, appOrigin, async () => response(200, {}, 'a'.repeat(262145)))(ownerOrigin + '/owner/enroll'), { message: 'REHEARSAL_RESPONSE_TOO_LARGE' })],
  ]
  for (const [name, anchor, check] of cases) {
    await check(driver)
    assert.equal(source.split(anchor).length, 2, 'one mutation anchor: ' + name)
    const mutated = await loaded(source.replace(anchor, ''))
    await assert.rejects(() => check(mutated), assert.AssertionError, name)
  }
  let count = 0
  const fetch = async (target, options) => {
    assert.equal(options.redirect, 'manual'); assert.equal(options.credentials, 'omit'); assert.ok(options.signal)
    return ++count === 1 ? response(302, { location: appOrigin + '/__aukora/signin' }) : response()
  }
  assert.equal((await driver.checkedFetch(ownerOrigin, appOrigin, fetch)(ownerOrigin + '/owner/signin')).status, 200)
  console.log(`SOURCE-ONLY passkey rehearsal transport mutations: ${cases.length}/${cases.length} killed`)
})

test('private links are accepted only through bounded stdin; usage errors print no supplied secret', () => {
  const secret = 'synthetic-secret-do-not-print'
  for (const [args, input] of [[['--claim-link', secret], ''], [[], secret + '\n'], [[], secret.repeat(400)]]) {
    const child = spawnSync(process.execPath, [driverUrl.pathname, '--owner-origin', ownerOrigin, '--app-origin', appOrigin, ...args],
      { cwd: process.cwd(), input, encoding: 'utf8' })
    assert.equal(child.status, 1)
    assert.equal(child.stdout + child.stderr, 'FAIL inputs REHEARSAL_USAGE_REFUSED\n')
    assert.doesNotMatch(child.stdout + child.stderr, new RegExp(secret))
  }
})

test('fetch redirect policy, credential omission, deadline and secret-free failures survive mutation checks', async t => {
  const source = fs.readFileSync(driverUrl, 'utf8')
  for (const [name, anchor, after, check] of [
    ['manual redirects', "redirect: 'manual'", "redirect: 'follow'", options => assert.equal(options.redirect, 'manual')],
    ['no ambient cookies', "credentials: 'omit'", "credentials: 'include'", options => assert.equal(options.credentials, 'omit')],
    ['request deadline', 'signal: AbortSignal.timeout(10000)', 'signal: undefined', options => assert.ok(options.signal)],
  ]) {
    const exercise = module => module.checkedFetch(ownerOrigin, appOrigin, async (_url, options) => {
      check(options); return new Response('safe')
    })(ownerOrigin + '/owner/enroll')
    await exercise(driver)
    assert.equal(source.split(anchor).length, 2, name)
    const mutated = await loaded(source.replace(anchor, after))
    await assert.rejects(() => exercise(mutated), assert.AssertionError, name)
  }
  const exercise = async module => {
    const f = fixture(t), secret = f.claim + f.bearer
    assert.equal(await f.run(module, { fetch: async () => { throw new Error(secret) } }), false)
    assert.equal(f.lines.at(-1), 'FAIL enrollment-page REHEARSAL_REFUSED')
    assert.doesNotMatch(f.lines.join('\n'), new RegExp(secret))
  }
  await exercise(driver)
  const anchor = "(/^REHEARSAL_[A-Z_]+$/.test(error?.message) ? error.message : 'REHEARSAL_REFUSED')"
  assert.equal(source.split(anchor).length, 2)
  const mutated = await loaded(source.replace(anchor, 'error.message'))
  await assert.rejects(() => exercise(mutated), assert.AssertionError)
  console.log('SOURCE-ONLY passkey rehearsal request/output mutations: 4/4 killed')
})

test('private input requires the pinned runtime, byte bound and two lines; guard removals are killed', async () => {
  const source = fs.readFileSync(driverUrl, 'utf8'), two = [Buffer.from('private-claim\nprivate-cards\n')]
  assert.deepEqual(await driver.readPrivateLinks(two), ['private-claim', 'private-cards'])
  const cases = [
    ['runtime version', "need(version === 'v24.11.1', 'NODE_VERSION_REQUIRED')", two, 'v24.11.2', 'NODE_VERSION_REQUIRED'],
    ['stdin bound', "need(Buffer.byteLength(input) + bytes.length <= 8192, 'INPUT_TOO_LARGE')", [Buffer.from('claim\n' + 'x'.repeat(8192))], undefined, 'INPUT_TOO_LARGE'],
    ['closed line count', "need(lines.length === 2, 'TWO_PRIVATE_LINKS_REQUIRED')", [Buffer.from('one-secret-line')], undefined, 'TWO_PRIVATE_LINKS_REQUIRED'],
  ]
  for (const [name, anchor, input, version, code] of cases) {
    const check = module => assert.rejects(module.readPrivateLinks(input, version), { message: 'REHEARSAL_' + code })
    await check(driver)
    assert.equal(source.split(anchor).length, 2, 'one mutation anchor: ' + name)
    const mutated = await loaded(source.replace(anchor, ''))
    await assert.rejects(() => check(mutated), assert.AssertionError, name)
  }
  console.log(`SOURCE-ONLY passkey rehearsal private-input mutations: ${cases.length}/${cases.length} killed`)
})
