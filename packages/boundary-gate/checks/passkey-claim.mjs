// SPDX-License-Identifier: AGPL-3.0-or-later
// Software-authenticator checks cover retained enrollment and fragment-only owner entry.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import vm from 'node:vm'
import { fixture } from '../../../tests/owner-passkey-gate.test.mjs'
import { retainedEnrollment } from '../src/owner-enrollment.mjs'
import { passkeyOwnerScript } from '../src/owner-passkey-script.mjs'
import { canonicalJson } from '../../contracts/src/runtime.mjs'
import * as enrollmentRuntime from '../../authority/src/passkey-enrollment.mjs'
import * as webauthnRuntime from '../../authority/src/webauthn.mjs'

function registration(f) {
  const start = f.gate.startPasskeyEnrollment({ claim_code: f.claim })
  return { start, material: f.auth.registration(start.public_key.challenge) }
}
function resume(f) { f.restart(); return f.gate.startPasskeyEnrollment({ claim_code: f.claim }) }

test('same secret claim restores the original enrollment at both interrupted stages; completion closes it', t => {
  const f = fixture(t), { start, material } = registration(f)
  assert.throws(() => f.gate.startPasskeyEnrollment({ claim_code: f.claim }), /enrollment-closed/)
  f.restart()
  assert.throws(() => f.gate.registerPasskeyEnrollment({ enrollment_id: start.enrollment_id, registration: material }), /ceremony-lost/)
  assert.throws(() => f.gate.startPasskeyEnrollment({ claim_code: 'z'.repeat(43) }), /claim-invalid/)
  const recovered = f.gate.startPasskeyEnrollment({ claim_code: f.claim })
  assert.equal(recovered.enrollment_id, start.enrollment_id)
  assert.deepEqual(recovered.public_key, start.public_key)
  assert.equal(recovered.stage, 'registration')
  const registered = f.gate.registerPasskeyEnrollment({ enrollment_id: start.enrollment_id, registration: material })
  const possessed = resume(f)
  assert.equal(possessed.stage, 'possession')
  assert.equal(possessed.enrollment_id, start.enrollment_id)
  assert.deepEqual(possessed.public_key, registered.public_key)
  assert.throws(() => f.gate.registerPasskeyEnrollment({ enrollment_id: start.enrollment_id, registration: material }), /registration-closed/)
  assert.equal(f.gate.finishPasskeyEnrollment({ enrollment_id: start.enrollment_id, assertion: f.auth.assertion(possessed.public_key.challenge) }).enrolled, true)
  f.restart(); assert.throws(() => f.gate.startPasskeyEnrollment({ claim_code: f.claim }), /enrollment-closed/)
  f.clock = f.setup.expires_at_ms
  assert.throws(() => f.gate.startPasskeyEnrollment({ claim_code: 'z'.repeat(43) }), /enrollment-closed/)
  assert.equal(f.gate.db.prepare("SELECT COUNT(*) AS n FROM ledger WHERE event='owner-passkey-enrolled'").get().n, 1)
})
for (const stage of ['registration', 'possession']) test(`${stage} refusal remains closed after restart`, t => {
  const f = fixture(t), { start, material } = registration(f)
  if (stage === 'registration') assert.throws(() => f.gate.registerPasskeyEnrollment({ enrollment_id: start.enrollment_id,
    registration: f.auth.registration(start.public_key.challenge, { origin: 'https://other.example.test' }) }))
  else {
    const registered = f.gate.registerPasskeyEnrollment({ enrollment_id: start.enrollment_id, registration: material })
    assert.throws(() => f.gate.finishPasskeyEnrollment({ enrollment_id: start.enrollment_id,
      assertion: f.auth.assertion(registered.public_key.challenge, { rp: 'other.example.test' }) }))
  }
  assert.throws(() => resume(f), /enrollment-closed/)
  assert.equal(f.gate.db.prepare('SELECT state_text FROM owner_passkey').get().state_text, null)
})
test('retained request, credential and failed state cannot rewind; expired claim cannot recover', t => {
  const f = fixture(t), { start, material } = registration(f)
  assert.throws(() => f.gate.db.prepare('UPDATE owner_passkey_ceremony SET request_text=?').run('{}'), /ceremony retained/)
  f.gate.registerPasskeyEnrollment({ enrollment_id: start.enrollment_id, registration: material })
  assert.throws(() => f.gate.db.exec('UPDATE owner_passkey_ceremony SET registration_text=NULL'), /ceremony retained/)
  f.gate.db.exec('UPDATE owner_passkey_ceremony SET failed=1')
  assert.throws(() => f.gate.db.exec('UPDATE owner_passkey_ceremony SET failed=0'), /ceremony retained/)
  assert.throws(() => f.gate.db.exec('DELETE FROM owner_passkey_ceremony'), /ceremony retained/)
  f.clock = f.setup.expires_at_ms
  assert.throws(() => resume(f), /claim-expired/)
})
test('retained registration request must match the protected binding', t => {
  const f = fixture(t); registration(f)
  const request = JSON.parse(f.gate.db.prepare('SELECT request_text FROM owner_passkey_ceremony').get().request_text)
  assert.throws(() => retainedEnrollment(request, { ...f.setup.binding, user: { ...f.setup.binding.user, name: 'Other' } }), /ceremony-binding/)
})

function browser({ hash = '#claim=' + 'x'.repeat(43), stored = null, stage = 'registration' } = {}) {
  const elements = Object.fromEntries(['root', 'status', 'claim', 'form'].map(name => [name, { value: '', hidden: false,
    dataset: {}, addEventListener() {} }]))
  elements.root.dataset = { origin: 'https://owner.example.test', rpId: 'owner.example.test', mode: 'enroll' }
  const calls = [], storage = new Map(stored ? [['aukora-owner-passkey-claim:https://owner.example.test', stored]] : [])
  const ids = { '[data-owner-passkey]': elements.root, '#status': elements.status, '#claim-code': elements.claim, '#enroll-form': elements.form }
  const get = { challenge: 'AQ', rpId: elements.root.dataset.rpId, userVerification: 'required', allowCredentials: [{ type: 'public-key', id: 'AQ' }] }
  const create = { rp: { id: get.rpId }, challenge: 'AQ', user: { id: 'AQ' }, attestation: 'none', authenticatorSelection: { userVerification: 'required' } }
  const bytes = Uint8Array.of(1).buffer
  const environment = { isSecureContext: true, PublicKeyCredential: function () {}, btoa, atob,
    document: { querySelector: key => ids[key] }, location: { origin: elements.root.dataset.origin, hash },
    history: { replaceState(_state, _title, url) { calls.push('erase:' + url); environment.location.hash = '' } },
    sessionStorage: { setItem: (key, value) => storage.set(key, value), getItem: key => storage.get(key), removeItem: key => storage.delete(key) },
    navigator: { credentials: {
      async create() { calls.push('create'); return { type: 'public-key', rawId: bytes, response: { clientDataJSON: bytes, attestationObject: bytes }, getClientExtensionResults: () => ({}) } },
      async get() { calls.push('get'); return { type: 'public-key', rawId: bytes, response: { clientDataJSON: bytes, authenticatorData: bytes, signature: bytes } } },
    } },
    async fetch(url, options) {
      const body = JSON.parse(options.body); calls.push(url)
      if (url.endsWith('/start')) assert.equal(body.claim_code, 'x'.repeat(43))
      return { ok: true, json: async () => ({ ok: true, result: url.endsWith('/start') ? { enrollment_id: 'id', stage, public_key: stage === 'possession' ? get : create }
        : url.endsWith('/register') ? { enrollment_id: 'id', public_key: get } : { enrolled: true } }) }
    } }
  return { environment, calls, storage, elements }
}
test('opening one fragment link erases it before requests, creates then proves possession, and clears tab storage', async () => {
  const b = browser(); await passkeyOwnerScript(b.environment)
  assert.deepEqual(b.calls, ['erase:/owner/enroll', '/owner/enroll/start', 'create', '/owner/enroll/register', 'get', '/owner/enroll/finish'])
  assert.equal(b.environment.location.hash, ''); assert.equal(b.storage.size, 0)
  assert.match(b.elements.status.textContent, /Enrollment is closed/)
})
test('tab reload after gate restart resumes retained possession without another creation', async () => {
  const b = browser({ hash: '', stored: 'x'.repeat(43), stage: 'possession' }); await passkeyOwnerScript(b.environment)
  assert.deepEqual(b.calls, ['/owner/enroll/start', 'get', '/owner/enroll/finish']); assert.equal(b.storage.size, 0)
})
test('malformed fragment and unknown recovered stage refuse before an authenticator call', async () => {
  for (const change of [{ hash: '#claim=bad' }, { stage: 'untrusted' }]) {
    const b = browser(change); await passkeyOwnerScript(b.environment)
    assert.equal(b.calls.includes('create'), false); assert.equal(b.calls.includes('get'), false)
    assert.match(b.elements.status.textContent, /REFUSED/)
  }
})

test('retained enrollment and fragment guards fail when removed', async t => {
  const gateUrl = new URL('../src/gate.mjs', import.meta.url), source = fs.readFileSync(gateUrl, 'utf8')
  const mutations = [
    ['completed enrollment closed', "if (row?.state_text || row?.claim_state === 'spent') passkeyRefuse('enrollment-closed')", '', f => {
      f.enroll(); f.clock = f.setup.expires_at_ms; assert.throws(() => f.gate.startPasskeyEnrollment({ claim_code: 'z'.repeat(43) }), /enrollment-closed/)
    }],
    ['request retained', 'JSON.stringify(created.request))', "JSON.stringify({ ...created.request, ceremony_id: 'e'.repeat(64) }))", f => {
      const { start } = registration(f); const recovered = resume(f); assert.equal(recovered.enrollment_id, start.enrollment_id)
    }],
    ['registration retained', "db.prepare('UPDATE owner_passkey_ceremony SET registration_text=? WHERE singleton=1 AND registration_text IS NULL').run(JSON.stringify(args.registration))", '', f => {
      const { start, material } = registration(f); f.gate.registerPasskeyEnrollment({ enrollment_id: start.enrollment_id, registration: material }); assert.equal(resume(f).stage, 'possession')
    }],
    ['request immutable', 'NEW.request_text != OLD.request_text OR ', '', f => {
      registration(f); assert.throws(() => f.gate.db.prepare('UPDATE owner_passkey_ceremony SET request_text=?').run('{}'))
    }],
    ['credential immutable', '(OLD.registration_text IS NOT NULL AND NEW.registration_text IS NOT OLD.registration_text)', '0', f => {
      const { start, material } = registration(f); f.gate.registerPasskeyEnrollment({ enrollment_id: start.enrollment_id, registration: material }); assert.throws(() => f.gate.db.exec('UPDATE owner_passkey_ceremony SET registration_text=NULL'))
    }],
    ['failure monotonic', 'NEW.failed < OLD.failed', '0', f => {
      registration(f); f.gate.db.exec('UPDATE owner_passkey_ceremony SET failed=1'); assert.throws(() => f.gate.db.exec('UPDATE owner_passkey_ceremony SET failed=0'))
    }],
    ['ceremony retained after delete', "CREATE TRIGGER IF NOT EXISTS owner_passkey_ceremony_no_delete BEFORE DELETE ON owner_passkey_ceremony\n      BEGIN SELECT RAISE(ABORT,'owner passkey ceremony retained'); END;", '', f => {
      registration(f); assert.throws(() => f.gate.db.exec('DELETE FROM owner_passkey_ceremony'))
    }],
    ['failed ceremony refused', "if (!retained || retained.failed !== 0) passkeyRefuse('enrollment-closed')", '', f => {
      registration(f); f.gate.db.exec('UPDATE owner_passkey_ceremony SET failed=1'); assert.throws(() => resume(f), /enrollment-closed/)
    }],
    ['registration commit expiry', "if (currentMs() >= selectedPasskeySetup().expires_at_ms) passkeyRefuse('claim-expired-at-registration-commit')", '', f => {
      const { start, material } = registration(f)
      const at = f.clock; let reads = 0
      Object.defineProperty(f, 'clock', { configurable: true, get: () => ++reads === 1 ? at : f.setup.expires_at_ms })
      assert.throws(() => f.gate.registerPasskeyEnrollment({ enrollment_id: start.enrollment_id, registration: material }), /claim-expired-at-registration-commit/)
    }],
    ['failed attempts durable', "if (attempted) db.prepare('UPDATE owner_passkey_ceremony SET failed=1 WHERE singleton=1').run()", '', f => {
      const { start } = registration(f); assert.throws(() => f.gate.registerPasskeyEnrollment({ enrollment_id: start.enrollment_id, registration: f.auth.registration(start.public_key.challenge, { origin: 'https://other.example.test' }) })); assert.throws(() => resume(f), /enrollment-closed/)
    }],
  ]
  for (const [name, before, after, exercise] of mutations) await t.test(name, async st => {
    assert.ok(source.includes(before), name)
    const changed = source.replaceAll(before, after).replace(/from\s+(['"])(\.[^'"]+)\1/g, (_m, q, spec) => 'from ' + q + new URL(spec, gateUrl).href + q)
    const factory = (await import('data:text/javascript;base64,' + Buffer.from(changed + '\n// ' + name).toString('base64'))).createGate
    const f = fixture(st, factory)
    let failed = false
    try { exercise(f) } catch { failed = true }
    assert.equal(failed, true, 'removed protection must fail regression')
  })
  const helper = retainedEnrollment.toString(), helperNames = ['PASSKEY_PILOT_GUARANTEE', 'passkeyRegistrationSigningBytes',
    'passkeyPossessionSigningBytes', 'passkeyRegistrationCandidateDigest', 'passkeyBootstrapEvidenceDigest', 'verifyPasskeyRegistration',
    'webauthnChallenge', 'webauthnOptions', 'verifyWebauthnAssertion', 'canonicalJson', 'modules', 'refuse']
  const runtime = { ...enrollmentRuntime, ...webauthnRuntime, canonicalJson, modules: true,
    refuse: code => { throw new Error('passkey:' + code) } }
  for (const [name, before, exercise] of [
    ['request bound', "if (canonicalJson(request.binding) !== canonicalJson(binding)) refuse('ceremony-binding')", (f, restore, request) => {
      assert.throws(() => restore(request, { ...f.setup.binding, user: { ...f.setup.binding.user, name: 'Other' } }), /ceremony-binding/)
    }],
    ['ceremony expiry', "if (Date.now() >= Date.parse(request.expiry)) refuse('ceremony-expired')", (f, restore, request) => {
      const old = { ...request, issued_at: new Date(Date.now() - 600000).toISOString(), expiry: new Date(Date.now() - 300000).toISOString() }
      assert.throws(() => restore(old, f.setup.binding).resume(), /ceremony-expired/)
    }],
  ]) await t.test(name, st => {
    const f = fixture(st); registration(f)
    const request = JSON.parse(f.gate.db.prepare('SELECT request_text FROM owner_passkey_ceremony').get().request_text)
    assert.ok(helper.includes(before), name)
    const restore = vm.runInThisContext('(function(runtime){const {' + helperNames.join(',') + '}=runtime;return (' + helper.replace(before, '') + ')})')(runtime)
    assert.throws(() => exercise(f, restore, request), assert.AssertionError)
  })
  const script = passkeyOwnerScript.toString()
  for (const [name, before, after, check] of [
    ['fragment erased', "environment.history.replaceState(null, '', '/owner/enroll')", '', b => assert.equal(b.environment.location.hash, '')],
    ['fragment shape', "if (!/^#claim=[A-Za-z0-9_-]{43}$/.test(fragment)) error('OWNER_PASSKEY_CLAIM_LINK_REFUSED')", '', b => assert.equal(b.calls.includes('/owner/enroll/start'), false)],
    ['claim cleared', 'environment.sessionStorage?.removeItem(claimStorageKey)', '', b => assert.equal(b.storage.size, 0)],
    ['stage closed', "if (started.stage !== undefined && started.stage !== 'registration') error('OWNER_PASSKEY_STAGE_REFUSED')", '', b => assert.equal(b.calls.includes('create'), false)],
  ]) await t.test(name, async () => {
    const b = browser(name === 'fragment shape' ? { hash: '#claim=' + 'x'.repeat(43) + 'extra' } : name === 'stage closed' ? { stage: 'untrusted' } : {})
    assert.ok(script.includes(before), name)
    await vm.runInThisContext('(' + script.replaceAll(before, after) + ')')(b.environment)
    assert.throws(() => check(b), assert.AssertionError)
  })
  t.diagnostic('SOURCE-ONLY retained enrollment and claim-link mutations: 16/16 killed')
})
