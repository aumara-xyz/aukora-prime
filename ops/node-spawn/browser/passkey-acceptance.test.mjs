// SPDX-License-Identifier: AGPL-3.0-or-later
// Software fixtures check acceptance refusals without enrolling an installed owner.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { Readable } from 'node:stream'
import * as authorization from '../../../packages/owner-key/src/authorization.mjs'
import { createPasskeyOwnerHandler } from '../../../packages/boundary-gate/src/owner-page.mjs'
import { passkeyAcceptance, softwareProofChecks } from './passkey-acceptance.mjs'

const url = new URL('./passkey-acceptance.mjs', import.meta.url), source = fs.readFileSync(url, 'utf8')
const hex = bytes => createHash('sha256').update(bytes).digest('hex')
function fixture() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const der = pair.publicKey.export({ type: 'spki', format: 'der' }), jwk = pair.publicKey.export({ format: 'jwk' })
  const binding = { subject: 'aukora:1:' + 'a'.repeat(64), control_digest: 'b'.repeat(64),
    approval_key_did: 'fixture-public-machine', authorization_epoch: 1 }
  const setup = { gate: 'c'.repeat(64), node: 'd'.repeat(64), origin: 'https://owner.example.test', rp_id: 'owner.example.test', binding: { identity: {
    subject: binding.subject, control_digest: binding.control_digest, approval_key_did: binding.approval_key_did, authorization_epoch: binding.authorization_epoch } } }
  const state = { version: 2, kind: 'aukora-owner-state/passkey-v2', owner_subject: binding.subject,
    owner_root_spki_base64: der.toString('base64'), owner_root_id: hex(der), owner_epoch: 1,
    registry_sha256: 'e'.repeat(64), activation_sha256: 'f'.repeat(64), node: setup.node, rp_id: setup.rp_id, origin: setup.origin,
    credential_id: Buffer.from('fixture-credential').toString('base64url'), user_handle: Buffer.from('fixture-owner').toString('base64url'),
    public_key_hex: '04' + Buffer.from(jwk.x, 'base64url').toString('hex') + Buffer.from(jwk.y, 'base64url').toString('hex'), sign_count: 1, backup_eligible: false }
  const responses = {
    '/owner/enroll/start': { status: 403, body: { ok: false, error: 'passkey:enrollment-closed' } },
    '/act': { status: 404, body: { ok: false, error: 'OWNER_PASSKEY_PATH_REFUSED' } },
    '/owner/approve': { status: 403, body: { ok: false, error: 'OWNER_PASSKEY_FIELDS_REFUSED' } },
  }
  const calls = []
  return { setup, row: { claim_state: 'spent', state_text: JSON.stringify(state), setup_text: JSON.stringify(setup) }, binding,
    ownerOrigin: setup.origin, gateId: setup.gate, bearer: 'PRIVATE_FIXTURE_BEARER', authorization, responses, calls,
    post: async (target, body) => { calls.push({ target, body }); return responses[target] } }
}

test('passkey acceptance checks the bound subject, closed enrollment and live bearer refusals without proposing effects', async () => {
  const f = fixture(), before = JSON.stringify(f.row), lines = await passkeyAcceptance(f)
  assert.equal(lines.length, 2)
  assert.match(lines[0], /live enrollment closed; bearer page and proofless bearer approval refused/)
  assert.match(lines[1], /ephemeral state only/)
  assert.doesNotMatch(lines.join('\n'), /PRIVATE_FIXTURE_BEARER|fixture-credential/)
  assert.deepEqual(f.calls.map(call => call.target), ['/owner/enroll/start', '/act', '/owner/approve'])
  assert.equal(JSON.stringify(f.row), before, 'acceptance must not change owner state')
  assert.ok(f.calls.every(call => !Object.hasOwn(call.body, 'owner_authorization_proof')))
})

test('acceptance exercises the actual passkey HTTP handler refusal contract without calling approval', async () => {
  const f = fixture(), invoked = []
  const gate = { startPasskeyEnrollment: () => { invoked.push('closed-enrollment'); throw new Error('passkey:enrollment-closed') },
    ownerOps: { decide_review: () => { throw new Error('approval must never be called') } } }
  const { handler } = createPasskeyOwnerHandler(gate, { origin: f.setup.origin, rpId: f.setup.rp_id })
  f.post = async (target, body) => {
    const req = Readable.from([Buffer.from(JSON.stringify(body))])
    req.method = 'POST'; req.url = target; req.headers = { host: f.setup.rp_id, origin: f.setup.origin,
      'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'content-type': 'application/json' }
    let status, bytes
    await handler(req, { writeHead: value => { status = value }, end: value => { bytes = value } })
    return { status, body: JSON.parse(bytes) }
  }
  assert.equal((await passkeyAcceptance(f)).length, 2)
  assert.deepEqual(invoked, ['closed-enrollment'])
})

const negatives = [
  ['owner hostname exactly', "need(setup.origin === ownerOrigin && setup.rp_id === new URL(ownerOrigin).hostname, 'OWNER_ORIGIN_MISMATCH')", f => { f.ownerOrigin = 'https://sub.owner.example.test' }, 'OWNER_ORIGIN_MISMATCH'],
  ['installed signer', "need(setup.gate === gateId, 'GATE_MISMATCH')", f => { f.gateId = 'e'.repeat(64) }, 'GATE_MISMATCH'],
  ['spent enrollment', "need(row?.claim_state === 'spent' && typeof row.state_text === 'string', 'ENROLLMENT_NOT_CLOSED')", f => { f.row.claim_state = 'reserved' }, 'ENROLLMENT_NOT_CLOSED'],
  ['retained setup', "need(row.setup_text === JSON.stringify(setup), 'SETUP_MISMATCH')", f => { f.row.setup_text = '{}' }, 'SETUP_MISMATCH'],
  ['enrolled node/RP/origin', "need(state.version === 2 && state.node === setup.node && state.rp_id === setup.rp_id && state.origin === setup.origin,\n    'ENROLLMENT_BINDING_MISMATCH')", f => { const state = JSON.parse(f.row.state_text); state.node = 'e'.repeat(64); f.row.state_text = JSON.stringify(state) }, 'ENROLLMENT_BINDING_MISMATCH'],
  ['actual app subject/control/key/epoch', "need(identity.subject === binding.subject && identity.control_digest === binding.control_digest\n    && identity.approval_key_did === binding.approval_key_did && identity.authorization_epoch === binding.authorization_epoch\n    && state.owner_subject === binding.subject, 'APP_BINDING_MISMATCH')", f => { f.binding.control_digest = 'e'.repeat(64) }, 'APP_BINDING_MISMATCH'],
  ['live enrollment closed', "need(closed.status === 403 && closed.body?.ok === false && closed.body.error === 'passkey:enrollment-closed', 'LIVE_ENROLLMENT_NOT_CLOSED')", f => { f.responses['/owner/enroll/start'] = { status: 200, body: { ok: true } } }, 'LIVE_ENROLLMENT_NOT_CLOSED'],
  ['bearer page absent', "need(oldPage.status === 404 && oldPage.body?.ok === false && oldPage.body.error === 'OWNER_PASSKEY_PATH_REFUSED', 'BEARER_PAGE_NOT_REFUSED')", f => { f.responses['/act'] = { status: 200, body: { ok: true } } }, 'BEARER_PAGE_NOT_REFUSED'],
  ['proofless approval refused', "need(withoutProof.status === 403 && withoutProof.body?.ok === false && withoutProof.body.error === 'OWNER_PASSKEY_FIELDS_REFUSED', 'BEARER_APPROVAL_NOT_REFUSED')", f => { f.responses['/owner/approve'] = { status: 200, body: { ok: true } } }, 'BEARER_APPROVAL_NOT_REFUSED'],
]
for (const [name, , change, code] of negatives) test(name + ': acceptance refuses', async () => {
  const f = fixture(); change(f)
  await assert.rejects(passkeyAcceptance(f), { message: 'BROWSER_PASSKEY_' + code })
})

test('acceptance guard removal kills every corresponding negative regression', async () => {
  for (const [name, anchor, change, code] of negatives) {
    assert.equal(source.split(anchor).length, 2, 'mutation preimage: ' + name)
    const mutated = await import('data:text/javascript;base64,' + Buffer.from(source.replace(anchor, '')).toString('base64'))
    const f = fixture(); change(f)
    await assert.rejects(async () => assert.rejects(mutated.passkeyAcceptance(f), { message: 'BROWSER_PASSKEY_' + code }), assert.AssertionError, name)
  }
  console.log(`SOURCE-ONLY browser passkey acceptance mutations: ${negatives.length}/${negatives.length} killed`)
})

test('software probe requires its positive control and each exact refusal; removing those checks fails the regression', async () => {
  const f = fixture()
  const control = { ...authorization, verifyOwnerAuthorization: (...args) => {
    const result = authorization.verifyOwnerAuthorization(...args); return { ...result, status: 'unverified' }
  } }
  const args = { authorization: control, setup: f.setup, subject: f.binding.subject }
  assert.throws(() => softwareProofChecks(args), { message: 'BROWSER_PASSKEY_SOFTWARE_CONTROL_REFUSED' })
  const anchor = "need(control.status === 'verified-owner-authorization', 'SOFTWARE_CONTROL_REFUSED')"
  assert.equal(source.split(anchor).length, 2)
  const removed = await import('data:text/javascript;base64,' + Buffer.from(source.replace(anchor, '')).toString('base64'))
  assert.throws(() => assert.throws(() => removed.softwareProofChecks(args), { message: 'BROWSER_PASSKEY_SOFTWARE_CONTROL_REFUSED' }), assert.AssertionError)
  const refusal = "need(refused === code, 'WRONG_' + name + '_NOT_REFUSED')"
  assert.equal(source.split(refusal).length, 2)
  const withoutRefusal = await import('data:text/javascript;base64,' + Buffer.from(source.replace(refusal, '')).toString('base64'))
  for (const context of ['RP', 'ORIGIN', 'NODE']) {
    const loose = { ...authorization, verifyOwnerAuthorization: (...values) => {
      try { return authorization.verifyOwnerAuthorization(...values) } catch (error) {
        const code = { RP: 'WEBAUTHN_RP_ID_MISMATCH', ORIGIN: 'WEBAUTHN_CHALLENGE_OR_ORIGIN_MISMATCH', NODE: 'owner-authorization:passkey-state-mismatch' }[context]
        if (error.message === code) return { status: 'verified-owner-authorization' }; throw error
      }
    } }
    const attack = { ...args, authorization: loose }, expected = { message: 'BROWSER_PASSKEY_WRONG_' + context + '_NOT_REFUSED' }
    assert.throws(() => softwareProofChecks(attack), expected)
    assert.throws(() => assert.throws(() => withoutRefusal.softwareProofChecks(attack), expected), assert.AssertionError)
  }
  console.log('SOURCE-ONLY browser software-probe acceptance mutations: 4/4 killed')
})

function load(code, base, replacements = {}) {
  const rewritten = code.replace(/from\s+(['"])(\.[^'"]+)\1/g,
    (_match, quote, specifier) => 'from ' + quote + (replacements[specifier] ?? new URL(specifier, base).href) + quote)
  return 'data:text/javascript;base64,' + Buffer.from(rewritten).toString('base64')
}
test('installed-verifier probe has a valid signature control and kills RP/origin/node verifier guard removals', async () => {
  const webauthnUrl = new URL('../../../packages/owner-key/src/webauthn.mjs', import.meta.url)
  const authorizationUrl = new URL('../../../packages/owner-key/src/authorization.mjs', import.meta.url)
  const webauthnSource = fs.readFileSync(webauthnUrl, 'utf8'), authorizationSource = fs.readFileSync(authorizationUrl, 'utf8')
  const f = fixture()
  assert.match(softwareProofChecks({ authorization, setup: f.setup, subject: f.binding.subject }), /PASS/)
  const mutations = [
    ['rpId', webauthnSource, "auth.length !== 37 || !timingSafeEqual(auth.subarray(0, 32), hash(config.rp_id))", 'auth.length !== 37', 'BROWSER_PASSKEY_WRONG_RP_NOT_REFUSED'],
    ['origin', webauthnSource, '!config.origins.includes(client.origin)', 'false', 'BROWSER_PASSKEY_WRONG_ORIGIN_NOT_REFUSED'],
  ]
  for (const [name, before, anchor, replacement, code] of mutations) {
    assert.equal(before.split(anchor).length, 2, 'mutation preimage: ' + name)
    const webauthnData = load(before.replace(anchor, replacement), webauthnUrl)
    const mutated = await import(load(authorizationSource, authorizationUrl, { './webauthn.mjs': webauthnData }))
    assert.throws(() => softwareProofChecks({ authorization: mutated, setup: f.setup, subject: f.binding.subject }), { message: code })
  }
  const nodeState = 'a.node !== state.node || ', nodeExpectation = "for (const field of AUTHORIZATION_V2_FIELDS) if (e[field] !== a[field]) fail('passkey-expectation-mismatch')"
  const challenge = "if (e.authorization_digest !== ownerAuthorizationDigest(a)) fail('passkey-challenge-mismatch')"
  assert.ok(authorizationSource.includes(nodeState) && authorizationSource.includes(nodeExpectation) && authorizationSource.includes(challenge))
  const altered = authorizationSource.replaceAll(nodeState, '').replace(nodeExpectation,
    "for (const field of AUTHORIZATION_V2_FIELDS.filter(field => field !== 'node')) if (e[field] !== a[field]) fail('passkey-expectation-mismatch')").replace(challenge, '')
  const mutated = await import(load(altered, authorizationUrl))
  assert.throws(() => softwareProofChecks({ authorization: mutated, setup: f.setup, subject: f.binding.subject }), { message: 'BROWSER_PASSKEY_WRONG_NODE_NOT_REFUSED' })
  console.log('SOURCE-ONLY installed-verifier software probe mutations: 3/3 killed (node state/expectation/digest guards jointly removed)')
})

test('passkey phase dispatches only after the same container transport readback', t => {
  const dir = fs.mkdtempSync(new URL('./.acceptance-test-', import.meta.url))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const config = { expanded_config: { 'security.privileged': 'false', 'security.nesting': 'false', 'security.idmap.isolated': 'true', 'security.devlxd': 'false' },
    expanded_devices: { root: { type: 'disk' } } }
  for (const [name, target, port] of [['app', '18735', '28735'], ['owner', '17792', '27792'], ['claim', '18736', '28736']]) config.expanded_devices['browser-' + name] = {
    type: 'proxy', bind: 'host', nat: 'false', 'security.uid': '65534', 'security.gid': '65534', connect: 'tcp:127.0.0.1:' + target, listen: 'tcp:127.0.0.1:' + port }
  const configPath = path.join(dir, 'config'), calls = path.join(dir, 'calls')
  fs.writeFileSync(configPath, JSON.stringify(config))
  fs.writeFileSync(path.join(dir, 'lxc'), '#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\ncase "$*" in *" query "*) cat "$CONFIG" ;; *" exec "*) exit 0 ;; *) exit 1 ;; esac\n', { mode: 0o700 })
  const result = spawnSync('bash', [new URL('./acceptance.sh', import.meta.url).pathname, '--name', 'C1', '--phase', 'passkey'], {
    encoding: 'utf8', env: { PATH: dir + ':' + process.env.PATH, CALLS: calls, CONFIG: configPath } })
  assert.equal(result.status, 0, result.stderr)
  assert.match(fs.readFileSync(calls, 'utf8'), /accept --phase passkey/)
})
