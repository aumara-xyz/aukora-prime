// SPDX-License-Identifier: AGPL-3.0-or-later
// Software assertions exercise durable browser login and exact subject binding, not device custody.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { createOwnerBrowser } from '../packages/boundary-gate/src/owner-browser.mjs'
import { ownerRootPin } from '../packages/owner-key/src/index.mjs'
import { ownerAuthorizationOwnerState } from '../packages/owner-key/src/authorization.mjs'
import { fixture as passkeyGateFixture } from './owner-passkey-gate.test.mjs'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { verifyReceipt } from '../packages/boundary-gate/src/receipts.mjs'
const hash = bytes => createHash('sha256').update(bytes).digest()
const origin = 'https://owner.example.test', appOrigin = 'https://app.example.test', rp = 'owner.example.test'
const challenge = text => hash(text).toString('base64url')
function fixture(t, factory = createOwnerBrowser) {
  const home = fs.mkdtempSync(path.join(process.cwd(), '.owner-browser-'))
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), jwk = pair.publicKey.export({ format: 'jwk' })
  const spki = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
  const f = { home, clock: 1000000, count: 1, available: true, appOrigin, record: { subject: 'aukora:1:' + 'b'.repeat(64), rootId: 'c'.repeat(64) } }
  f.setup = { gate: 'd'.repeat(64), node: 'e'.repeat(64), origin, rp_id: rp }
  f.state = ownerAuthorizationOwnerState({ version: 2, kind: 'aukora-owner-state/passkey-v2', owner_subject: 'aukora:1:' + 'a'.repeat(64),
    owner_root_spki_base64: spki, owner_root_id: ownerRootPin(spki).owner_root_id, owner_epoch: 1,
    registry_sha256: '1'.repeat(64), activation_sha256: '2'.repeat(64), node: f.setup.node, rp_id: rp, origin,
    credential_id: Buffer.from('software-owner-key').toString('base64url'), user_handle: Buffer.from('software-owner').toString('base64url'),
    public_key_hex: '04' + Buffer.from(jwk.x, 'base64url').toString('hex') + Buffer.from(jwk.y, 'base64url').toString('hex'), sign_count: 1, backup_eligible: false })
  f.assertion = (value, change = {}) => {
    const client = Buffer.from(JSON.stringify({ type: change.type ?? 'webauthn.get', challenge: change.challenge ?? value,
      origin: change.origin ?? origin, crossOrigin: change.crossOrigin ?? false, ...(change.topOrigin ? { topOrigin: change.topOrigin } : {}) }))
    const auth = Buffer.alloc(37); hash(change.rp ?? rp).copy(auth); auth[32] = change.flags ?? 5; auth.writeUInt32BE(change.count ?? ++f.count, 33)
    return { kind: 'passkey', credential_id: change.credential_id ?? f.state.credential_id, user_handle: change.user_handle ?? f.state.user_handle,
      client_data_json: client.toString('base64url'), authenticator_data: auth.toString('base64url'),
      signature: sign('sha256', Buffer.concat([auth, hash(client)]), change.key ?? pair.privateKey).toString('base64url') }
  }
  f.open = () => {
    f.db = new DatabaseSync(path.join(home, 'browser.db'))
    f.db.exec('CREATE TABLE IF NOT EXISTS owner_passkey(singleton INTEGER PRIMARY KEY,sign_count INTEGER NOT NULL,state_text TEXT NOT NULL)')
    f.db.prepare('INSERT OR IGNORE INTO owner_passkey VALUES(1,1,?)').run(JSON.stringify(f.state))
    f.tx = (fn, beforeCommit, refused) => {
      f.db.exec('BEGIN IMMEDIATE'); if (refused) f.db.exec('SAVEPOINT browser_attempt')
      try {
        let result
        try { result = fn(); f.beforeCommit?.(); beforeCommit?.() }
        catch (error) {
          if (!refused) throw error
          f.db.exec('ROLLBACK TO browser_attempt; RELEASE browser_attempt'); result = refused(error)
        }
        f.db.exec('COMMIT'); return result
      } catch (error) { f.db.exec('ROLLBACK'); throw error }
    }
    return factory({ db: f.db, tx: f.tx, setup: () => f.setup, ownerState: () => f.available ? f.state : null,
      readBinding: () => { if (f.recordError) throw new Error('unreadable public binding'); return f.record }, appOrigin: f.appOrigin, now: () => f.clock,
      append: () => { f.onAppend?.() } })
  }
  f.browser = f.open()
  f.restart = () => { f.db.close(); f.browser = f.open() }
  f.finishSignin = start => f.browser.finishSignin({ challenge_id: start.challenge_id, assertion: f.assertion(start.public_key.challenge) })
  f.signin = () => f.finishSignin(f.browser.startSignin({}))
  f.finishBinding = start => f.browser.finishBinding({ challenge_id: start.challenge_id, assertion: f.assertion(start.public_key.challenge) })
  f.bind = () => f.finishBinding(f.browser.startBinding({}))
  f.redeem = code => f.browser.redeemSignin({ code, app_origin: f.appOrigin })
  t.after(() => { f.db.close(); fs.rmSync(home, { recursive: true, force: true }) })
  return f
}
test('returning sign-in is passkey-only; durable challenge and code survive restart and each is spent once', t => {
  const f = fixture(t), start = f.browser.startSignin({}), statement = JSON.parse(start.statement_text)
  assert.equal(statement.gate, f.setup.gate); assert.equal(statement.node, f.setup.node); assert.equal(statement.origin, origin)
  assert.equal(statement.app_origin, appOrigin); assert.equal(statement.nonce, start.challenge_id)
  assert.equal(start.public_key.userVerification, 'required'); assert.equal(start.public_key.challenge, challenge(start.statement_text))
  f.restart(); const login = f.finishSignin(start); assert.equal(login.app_origin, appOrigin)
  assert.equal(f.db.prepare('SELECT sign_count FROM owner_passkey').get().sign_count, 2)
  assert.throws(() => f.finishSignin(start), /challenge-spent/)
  assert.equal(f.db.prepare('SELECT code_sha256 FROM owner_browser_codes').get().code_sha256, hash(login.code).toString('hex'))
  f.restart(); assert.equal(f.redeem(login.code).node, f.setup.node); assert.throws(() => f.redeem(login.code), /code-spent/)
})
test('without enrolled credential sign-in refuses, and browser inputs cannot choose authority', t => {
  const f = fixture(t); f.available = false; assert.throws(() => f.browser.startSignin({}), /owner-not-enrolled/)
  f.available = true
  assert.throws(() => f.browser.startSignin({ node: 'f'.repeat(64) }), /request-shape/)
  assert.throws(() => f.browser.startBinding({ subject: f.record.subject }), /request-shape/)
  const start = f.browser.startSignin({})
  assert.throws(() => f.browser.finishSignin({ challenge_id: start.challenge_id, assertion: f.assertion(start.public_key.challenge), subject: f.record.subject }), /request-shape/)
  assert.throws(() => f.finishSignin(start), /challenge-spent/)
  assert.throws(() => f.browser.redeemSignin({ code: 'x'.repeat(43), app_origin: appOrigin, node: f.setup.node }), /request-shape/)
})
for (const [name, change, refusal] of [
  ['wrong challenge', { challenge: 'wrong' }, /CHALLENGE_OR_ORIGIN/], ['wrong origin', { origin: appOrigin }, /CHALLENGE_OR_ORIGIN/],
  ['wrong RP', { rp: 'other.example.test' }, /RP_ID/], ['wrong key', { key: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey }, /SIGNATURE_INVALID/],
  ['wrong credential', { credential_id: Buffer.from('stranger-key').toString('base64url') }, /CREDENTIAL_NOT_PINNED/],
  ['wrong user', { user_handle: Buffer.from('stranger').toString('base64url') }, /USER_HANDLE/], ['wrong type', { type: 'webauthn.create' }, /CHALLENGE_OR_ORIGIN/],
  ['cross origin', { crossOrigin: true }, /CHALLENGE_OR_ORIGIN/], ['top origin', { topOrigin: appOrigin }, /CHALLENGE_OR_ORIGIN/],
  ['no UV', { flags: 1 }, /UP_UV/], ['no UP', { flags: 4 }, /UP_UV/], ['backup eligibility changed', { flags: 13 }, /BACKUP_ELIGIBILITY/],
  ['counter replay', { count: 1 }, /COUNTER_REPLAYED/],
]) test(`sign-in ${name} refuses and spends the durable challenge`, t => {
  const f = fixture(t), start = f.browser.startSignin({})
  assert.throws(() => f.browser.finishSignin({ challenge_id: start.challenge_id, assertion: f.assertion(start.public_key.challenge, change) }), refusal)
  assert.equal(f.db.prepare('SELECT sign_count FROM owner_passkey').get().sign_count, 1)
  f.restart(); assert.throws(() => f.finishSignin(start), /challenge-spent/); assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM owner_browser_codes').get().n, 0)
})
test('expired/backdated challenge, failed final clock, wrong kind and missing nonce refuse', t => {
  for (const attack of ['expired', 'backdated', 'commit', 'kind', 'missing']) {
    const f = fixture(t), start = f.browser.startSignin({})
    if (attack === 'expired') f.clock = start.expires_at_ms
    if (attack === 'backdated') f.clock--
    if (attack === 'commit') f.beforeCommit = () => { f.clock = start.expires_at_ms }
    if (attack === 'kind') assert.throws(() => f.finishBinding(start), /challenge-spent/)
    else if (attack === 'missing') assert.throws(() => f.finishSignin({ ...start, challenge_id: '0'.repeat(64) }), /challenge-spent/)
    else assert.throws(() => f.finishSignin(start), /challenge-expired|expired-at-commit/)
    if (attack !== 'missing') assert.equal(f.db.prepare('SELECT spent FROM owner_browser_challenges WHERE challenge_id=?').get(start.challenge_id).spent, 1)
    assert.equal(f.db.prepare('SELECT sign_count FROM owner_passkey').get().sign_count, 1)
  }
})
test('code refuses wrong app, expiry, backdate and final commit expiry; every attempted valid code stays spent', t => {
  for (const attack of ['app', 'expiry', 'backdate', 'commit']) {
    const f = fixture(t), login = f.signin()
    if (attack === 'expiry') f.clock = login.expires_at_ms
    if (attack === 'backdate') f.clock--
    if (attack === 'commit') f.beforeCommit = () => { f.clock = login.expires_at_ms }
    assert.throws(() => f.browser.redeemSignin({ code: login.code, app_origin: attack === 'app' ? 'https://other.example.test' : appOrigin }), /app-origin-mismatch|code-expired|expired-at-commit/)
    f.beforeCommit = undefined; f.clock = 1000000
    f.restart(); assert.throws(() => f.redeem(login.code), /code-spent/)
  }
})
test('exact verified binding subject/node is signed, retained and selected for approvals after restart', t => {
  const f = fixture(t); assert.throws(() => f.browser.boundOwnerState(f.state), /binding-required/)
  const start = f.browser.startBinding({}), statement = JSON.parse(start.statement_text)
  assert.equal(statement.subject, f.record.subject); assert.equal(statement.rootId, f.record.rootId); assert.equal(statement.node, f.setup.node)
  assert.equal(f.finishBinding(start).bound, true); assert.throws(() => f.browser.startBinding({}), /already-bound/)
  f.clock = start.expires_at_ms + 1; f.restart()
  const state = f.browser.boundOwnerState(f.state)
  assert.equal(state.owner_subject, f.record.subject); assert.equal(state.owner_root_id, f.state.owner_root_id)
  assert.notEqual(state.registry_sha256, f.state.registry_sha256); assert.notEqual(state.activation_sha256, f.state.activation_sha256)
  assert.equal(f.signin().app_origin, appOrigin)
  assert.throws(() => f.browser.boundOwnerState({ ...f.state, owner_subject: f.record.subject }), /owner-state-changed/)
})
test('binding refuses stale subject/root, unreadable records, assertion substitution and concurrent second binding', t => {
  for (const attack of ['subject', 'root', 'unreadable', 'signature', 'race']) {
    const f = fixture(t), start = f.browser.startBinding({})
    if (attack === 'subject') f.record.subject = 'aukora:1:' + 'f'.repeat(64)
    if (attack === 'root') f.record.rootId = 'f'.repeat(64)
    if (attack === 'unreadable') f.recordError = true
    if (attack === 'race') f.finishBinding(f.browser.startBinding({}))
    if (attack === 'signature') assert.throws(() => f.browser.finishBinding({ challenge_id: start.challenge_id, assertion: f.assertion(start.public_key.challenge, { challenge: 'wrong' }) }), /CHALLENGE_OR_ORIGIN/)
    else assert.throws(() => f.finishBinding(start), /binding-mismatch|binding-record-unavailable|already-bound/)
    assert.equal(f.db.prepare('SELECT spent FROM owner_browser_challenges WHERE challenge_id=?').get(start.challenge_id).spent, 1)
  }
})
test('after binding, mismatched public subject/root refuses sign-in, code exchange and owner verification', t => {
  for (const field of ['subject', 'rootId']) {
    const f = fixture(t); f.bind(); const login = f.signin(), start = f.browser.startSignin({})
    f.record[field] = field === 'subject' ? 'aukora:1:' + 'f'.repeat(64) : 'f'.repeat(64)
    assert.throws(() => f.browser.boundOwnerState(f.state), /binding-mismatch/)
    assert.throws(() => f.browser.startSignin({}), /binding-mismatch/)
    assert.throws(() => f.finishSignin(start), /binding-mismatch/)
    assert.throws(() => f.redeem(login.code), /binding-mismatch/)
  }
})
test('node/RP/origin/application config cannot drift; owner node mismatches and missing counters refuse', t => {
  const f = fixture(t)
  for (const [key, value] of [['node', 'f'.repeat(64)], ['origin', appOrigin], ['rp_id', 'other.example.test'], ['gate', 'f'.repeat(64)]]) {
    const previous = f.setup[key]; f.setup[key] = value; assert.throws(() => f.browser.startSignin({}), /config-changed|origins-not-separated/); f.setup[key] = previous
  }
  const previous = f.state; f.state = { ...f.state, node: 'f'.repeat(64) }; assert.throws(() => f.browser.startSignin({}), /credential-binding/); f.state = previous
  f.db.prepare('DELETE FROM owner_passkey').run(); assert.throws(() => f.browser.startSignin({}), /counter-unavailable/)
  assert.throws(() => createOwnerBrowser({ db: f.db, tx: f.tx, setup: () => f.setup, appOrigin: 'http://app.example.test' }), /app-origin/)
  assert.throws(() => createOwnerBrowser({ db: f.db, tx: f.tx, setup: () => f.setup, appOrigin: 'https://app.example.test/path' }), /app-origin/)
  assert.throws(() => createOwnerBrowser({ db: f.db, tx: f.tx, setup: () => f.setup, appOrigin: origin }), /origins-not-separated/)
})
test('durable bounded issuance and retained config/challenge/code/binding rows reject reopening or removal', t => {
  const f = fixture(t), login = f.signin(); f.bind()
  for (const table of ['owner_browser_config', 'owner_browser_challenges', 'owner_browser_codes', 'owner_browser_binding']) assert.throws(() => f.db.exec('DELETE FROM ' + table), /retained/)
  assert.throws(() => f.db.exec('UPDATE owner_browser_config SET config_text=\'{}\''), /retained/)
  assert.throws(() => f.db.exec('UPDATE owner_browser_challenges SET spent=0'), /retained/)
  f.redeem(login.code); assert.throws(() => f.db.exec('UPDATE owner_browser_codes SET spent=0'), /retained/)
  assert.throws(() => f.db.exec('UPDATE owner_browser_binding SET assertion_text=\'{}\''), /retained/)
  for (let n = 2; n < 32; n++) f.browser.startSignin({})
  f.restart(); assert.throws(() => f.browser.startSignin({}), /challenge-limit/)
})


test('expired challenge/code cleanup bounds retained rows without reviving old proofs', t => {
  const f = fixture(t), start = f.browser.startSignin({}), login = f.finishSignin(start)
  f.clock = login.expires_at_ms; f.browser.startSignin({})
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM owner_browser_challenges').get().n, 1)
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM owner_browser_codes').get().n, 0)
  f.restart(); assert.throws(() => f.finishSignin(start), /challenge-spent/); assert.throws(() => f.redeem(login.code), /code-spent/)
})

// Mutants remove guards in memory; all scratch state remains in this clone.
test('browser join guard removals fail their focused regressions', async t => {
  const url = new URL('../packages/boundary-gate/src/owner-browser.mjs', import.meta.url), source = fs.readFileSync(url, 'utf8')
  const mutants = [
    ['enrollment required', "const { config, text } = configuration(), raw = ownerState()\n    if (!raw) refuse('owner-not-enrolled')", "const { config, text } = configuration(), raw = ownerState() ?? JSON.parse(db.prepare('SELECT state_text FROM owner_passkey WHERE singleton=1').get().state_text)", f => { f.available = false; assert.throws(() => f.browser.startSignin({}), /owner-not-enrolled/) }],
    ['closed browser authority', "if (!exact(args, [])) refuse('request-shape')", '', f => assert.throws(() => f.browser.startSignin({ node: 'f'.repeat(64) }), /request-shape/)],
    ['configured app origin', "if (url.protocol !== 'https:' || url.origin !== appOrigin) refuse('app-origin')", '', (f, factory) => { f.db.exec('DROP TRIGGER owner_browser_config_delete; DELETE FROM owner_browser_config'); assert.throws(() => factory({ db: f.db, tx: f.tx, setup: () => f.setup, appOrigin: 'http://app.example.test' }), /app-origin/) }],
    ['separate owner origin', "if (selected.origin === appOrigin) refuse('origins-not-separated')", '', (f, factory) => { f.db.exec('DROP TRIGGER owner_browser_config_delete; DELETE FROM owner_browser_config'); assert.throws(() => factory({ db: f.db, tx: f.tx, setup: () => f.setup, appOrigin: origin }), /origins-not-separated/) }],
    ['durable config pin', "if (retained && retained.config_text !== text) refuse('config-changed')", '', f => { f.setup.gate = 'f'.repeat(64); assert.throws(() => f.browser.startSignin({}), /config-changed/) }],
    ['credential node binding', "if (state.version !== 2 || state.node !== config.node || state.origin !== config.origin || state.rp_id !== config.rp_id) refuse('credential-binding')", '', f => { f.state = { ...f.state, node: 'f'.repeat(64) }; assert.throws(() => f.browser.startSignin({}), /credential-binding/) }],
    ['bounded challenge issuance', "if (db.prepare('SELECT COUNT(*) AS n FROM owner_browser_challenges WHERE issued_at_ms>?').get(at - LIFE_MS).n >= 32) refuse('challenge-limit')", '', f => { for (let n = 0; n < 32; n++) f.browser.startSignin({}); assert.throws(() => f.browser.startSignin({}), /challenge-limit/) }],
    ['challenge lifetime', "if (at < row.issued_at_ms || at >= row.expires_at_ms) refuse('challenge-expired')", '', f => { const start = f.browser.startSignin({}); f.clock = start.expires_at_ms; f.beforeCommit = () => { f.clock = 1000000 }; assert.throws(() => f.finishSignin(start), /challenge-expired/) }],
    ['failed assertion burns nonce', "if (challenge_id !== null) db.prepare('UPDATE owner_browser_challenges SET spent=1 WHERE challenge_id=? AND spent=0').run(challenge_id)", '', f => { const start = f.browser.startSignin({}); assert.throws(() => f.browser.finishSignin({ challenge_id: start.challenge_id, assertion: f.assertion(start.public_key.challenge, { challenge: 'wrong' }) })); f.restart(); assert.throws(() => f.finishSignin(start), /challenge-spent/) }],
    ['durable shared counter', "const updated = db.prepare('UPDATE owner_passkey SET sign_count=? WHERE singleton=1 AND sign_count=?').run(verified.sign_count, current.counter)", 'const updated = { changes: 1 }', f => { f.signin(); f.restart(); assert.equal(f.db.prepare('SELECT sign_count FROM owner_passkey').get().sign_count, 2) }],
    ['counter compare and set', "if (updated.changes !== 1) refuse('counter-conflict')", '', f => { f.db.exec("CREATE TRIGGER ignore_counter BEFORE UPDATE ON owner_passkey BEGIN SELECT RAISE(IGNORE); END"); assert.throws(() => f.signin(), /counter-conflict/) }],
    ['signin commit lifetime', "if (clock() < acceptedStatement.issued_at_ms || clock() >= acceptedStatement.expires_at_ms) refuse('expired-at-commit')", '', f => { const start = f.browser.startSignin({}); f.beforeCommit = () => { f.clock = start.expires_at_ms }; assert.throws(() => f.finishSignin(start), /expired-at-commit/) }],
    ['trusted exact subject', "if (statement.subject !== projection.subject || statement.rootId !== projection.rootId) refuse('binding-mismatch')", '', f => { f.bind(); f.record.subject = 'aukora:1:' + 'f'.repeat(64); assert.throws(() => f.browser.boundOwnerState(f.state), /binding-mismatch/) }],
    ['trusted binding is required', "if (!row) { if (required) refuse('binding-required'); return null }", 'if (!row) return { row: { statement_text: "{}", assertion_text: "{}" }, statement: { subject: current.state.owner_subject } }', f => assert.throws(() => f.browser.boundOwnerState(f.state), /binding-required/)],
    ['retained binding evidence', "verifyWebauthnAssertion({ material: JSON.parse(row.assertion_text), config: current.webauthn, ownerId: current.state.owner_root_id,\n      challenge: webauthnChallenge(Buffer.from(row.statement_text)), checkCounter: false })", '', f => { f.bind(); f.db.exec('DROP TRIGGER owner_browser_binding_update'); const row = f.db.prepare('SELECT assertion_text FROM owner_browser_binding').get(), assertion = JSON.parse(row.assertion_text); assertion.signature = Buffer.alloc(70).toString('base64url'); f.db.prepare('UPDATE owner_browser_binding SET assertion_text=?').run(JSON.stringify(assertion)); assert.throws(() => f.browser.boundOwnerState(f.state), /SIGNATURE_INVALID/) }],
    ['broker app authority', "if (args.app_origin !== current.config.app_origin) refuse('app-origin-mismatch')", '', f => { const login = f.signin(); assert.throws(() => f.browser.redeemSignin({ code: login.code, app_origin: 'https://other.example.test' }), /app-origin-mismatch/) }],
    ['short-lived code', "if (at < row.issued_at_ms || at >= row.expires_at_ms) refuse('code-expired')", '', f => { const login = f.signin(); f.clock = login.expires_at_ms; f.beforeCommit = () => { f.clock = 1000000 }; assert.throws(() => f.redeem(login.code), /code-expired/) }],
    ['failed redemption burns code', "db.prepare('UPDATE owner_browser_codes SET spent=1 WHERE code_sha256=? AND spent=0').run(hash(args.code))\n      return { refused_error: error }", 'return { refused_error: error }', f => { const login = f.signin(); assert.throws(() => f.browser.redeemSignin({ code: login.code, app_origin: origin })); f.restart(); assert.throws(() => f.redeem(login.code), /code-spent/) }],
    ['code commit lifetime', "if (clock() >= acceptedExpiry) refuse('expired-at-commit')", '', f => { const login = f.signin(); f.beforeCommit = () => { f.clock = login.expires_at_ms }; assert.throws(() => f.redeem(login.code), /expired-at-commit/) }],

    ['one-use signin nonce', "if (!row || row.kind !== kind || row.spent !== 0) refuse('challenge-spent')", "if (!row || row.kind !== kind) refuse('challenge-spent')", f => { const start = f.browser.startSignin({}); f.finishSignin(start); f.restart(); assert.throws(() => f.finishSignin(start), /challenge-spent/) }],
    ['one-use app exchange code', "if (!row || row.spent !== 0) refuse('code-spent')", "if (!row) refuse('code-spent')", f => { const login = f.signin(); f.redeem(login.code); f.restart(); assert.throws(() => f.redeem(login.code), /code-spent/) }],
    ['signin verifier invocation', "const verified = verifyWebauthnAssertion({ material: args.assertion, config: current.webauthn, ownerId: current.state.owner_root_id,\n        challenge: webauthnChallenge(Buffer.from(row.statement_text)), counter: current.counter })", 'const verified = { sign_count: current.counter + 1 }', f => { const start = f.browser.startSignin({}); assert.throws(() => f.browser.finishSignin({ challenge_id: start.challenge_id, assertion: f.assertion(start.public_key.challenge, { key: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey }) }), /SIGNATURE_INVALID/) }],
    ['statement node identity', "Object.keys(current.config).some(field => statement[field] !== current.config[field])", 'false', f => { const start = f.browser.startSignin({}), statement = JSON.parse(start.statement_text); statement.node = 'f'.repeat(64); const text = JSON.stringify(statement); f.db.exec('DROP TRIGGER owner_browser_challenge_update'); f.db.prepare('UPDATE owner_browser_challenges SET statement_text=? WHERE challenge_id=?').run(text, start.challenge_id); assert.throws(() => f.browser.finishSignin({ challenge_id: start.challenge_id, assertion: f.assertion(challenge(text)) }), /statement-mismatch/) }],
    ['statement row nonce', "if (statement.nonce !== challenge_id || statement.issued_at_ms !== row.issued_at_ms || statement.expires_at_ms !== row.expires_at_ms) refuse('statement-row-mismatch')", '', f => { const start = f.browser.startSignin({}), statement = JSON.parse(start.statement_text); statement.nonce = 'f'.repeat(64); const text = JSON.stringify(statement); f.db.exec('DROP TRIGGER owner_browser_challenge_update'); f.db.prepare('UPDATE owner_browser_challenges SET statement_text=? WHERE challenge_id=?').run(text, start.challenge_id); assert.throws(() => f.browser.finishSignin({ challenge_id: start.challenge_id, assertion: f.assertion(challenge(text)) }), /statement-row-mismatch/) }],
    ['trusted record shape', "if (!exact(projection, ['subject', 'rootId']) || typeof projection.subject !== 'string'\n      || !/^aukora:1:[0-9a-f]{64}$/u.test(projection.subject) || !id(projection.rootId)) refuse('binding-record-unavailable')", '', f => { f.record = { subject: 'browser-unverified', rootId: 'c'.repeat(64) }; assert.throws(() => f.browser.startBinding({}), /binding-record-unavailable/) }],
    ['new challenge commit lifetime', "if (clock() >= statement.expires_at_ms) refuse('expired-at-commit')", '', f => { f.beforeCommit = () => { f.clock += 60000 }; assert.throws(() => f.browser.startSignin({}), /expired-at-commit/) }],
    ['owner state commit pin', "if (JSON.stringify(current.state) !== acceptedState) refuse('owner-state-changed')", '', f => { const start = f.browser.startSignin({}); f.beforeCommit = () => { f.state = { ...f.state, owner_epoch: 2 } }; assert.throws(() => f.finishSignin(start), /owner-state-changed/) }],
    ['verification uses enrolled state', "if (JSON.stringify(ownerAuthorizationOwnerState(rawState)) !== JSON.stringify(current.state)) refuse('owner-state-changed')", '', f => { f.bind(); assert.throws(() => f.browser.boundOwnerState({ ...f.state, owner_epoch: 2 }), /owner-state-changed/) }],
    ['post-binding signin subject check', "if (kind === 'signin') verifyRetainedBinding(current)", '', f => { f.bind(); f.record.subject = 'aukora:1:' + 'f'.repeat(64); assert.throws(() => f.browser.startSignin({}), /binding-mismatch/) }],
    ['protected code state', "CREATE TRIGGER IF NOT EXISTS owner_browser_code_delete BEFORE DELETE ON owner_browser_codes\n      WHEN OLD.expires_at_ms>owner_browser_clock() BEGIN SELECT RAISE(ABORT,'browser code retained'); END;", '', f => { f.signin(); assert.throws(() => f.db.exec('DELETE FROM owner_browser_codes'), /retained/) }],
    ['protected binding state', "CREATE TRIGGER IF NOT EXISTS owner_browser_binding_update BEFORE UPDATE ON owner_browser_binding BEGIN SELECT RAISE(ABORT,'browser binding retained'); END;", '', f => { f.bind(); assert.throws(() => f.db.exec("UPDATE owner_browser_binding SET assertion_text='{}'"), /retained/) }],
    ['protected challenge state', "CREATE TRIGGER IF NOT EXISTS owner_browser_challenge_delete BEFORE DELETE ON owner_browser_challenges\n      WHEN OLD.expires_at_ms>owner_browser_clock() BEGIN SELECT RAISE(ABORT,'browser challenge retained'); END;", '', f => { f.browser.startSignin({}); assert.throws(() => f.db.exec('DELETE FROM owner_browser_challenges'), /retained/) }],
  ]
  let killed = 0
  for (const [name, before, after, exercise] of mutants) await t.test(name, async st => {
    assert.ok(source.includes(before), 'mutation preimage ' + name)
    let modified = source.replace(before, after)
    if (name === 'one-use signin nonce') modified = modified.replaceAll('SET spent=1 WHERE challenge_id=? AND spent=0', 'SET spent=1 WHERE challenge_id=?')
    if (name === 'one-use app exchange code') modified = modified.replaceAll('SET spent=1 WHERE code_sha256=? AND spent=0', 'SET spent=1 WHERE code_sha256=?')
    modified = modified.replace(/from\s+(['"])(\.[^'"]+)\1/g, (_m, q, relative) => 'from ' + q + new URL(relative, url).href + q)
    const factory = (await import('data:text/javascript;base64,' + Buffer.from(modified + '\n// ' + name).toString('base64'))).createOwnerBrowser
    const f = fixture(st, factory)
    assert.throws(() => exercise(f, factory), assert.AssertionError, 'removed guard must fail behavior assertion'); killed++
  })
  t.diagnostic(`SOURCE-ONLY owner browser join guard mutations: ${killed}/${mutants.length} killed`)
})

function joinedGateFixture(t, factory = createGate) {
  const record = { subject: 'aukora:1:' + '7'.repeat(64), rootId: '8'.repeat(64) }, join = { enabled: true }
  const f = passkeyGateFixture(t, options => {
    try { return factory({ ...options, ...(join.enabled ? { browserJoin: { appOrigin, readBinding: () => record } } : {}) }) }
    catch (error) { options.db.close(); throw error }
  })
  f.record = record; f.join = join
  f.bindOwner = () => { const start = f.gate.ownerBrowser.startBinding({}); return f.gate.ownerBrowser.finishBinding({ challenge_id: start.challenge_id, assertion: f.auth.assertion(start.public_key.challenge) }) }
  return f
}
test('gate effect requires the final subject signature and its receipt verifies after cold restart', t => {
  const f = joinedGateFixture(t); f.enroll()
  assert.throws(() => f.review(), /binding-required/); assert.equal(f.writes, 0)
  const proposal = f.gate.db.prepare("SELECT id FROM proposals WHERE state='pending'").get()
  assert.equal(f.bindOwner().subject, f.record.subject); f.restart()
  const review = f.gate.ownerOps.review({ id: proposal.id })
  assert.equal(review.owner_authorization.owner_subject, f.record.subject)
  const result = f.decide(review, f.proof(review)); assert.equal(result.applied, true); assert.equal(f.writes, 1)
  assert.equal(verifyReceipt(f.gate.db, result.receipt, result.receipt_sig, f.key.pub).ok, true)
  f.restart(); assert.equal(verifyReceipt(f.gate.db, result.receipt, result.receipt_sig, f.key.pub).ok, true)
  f.record.subject = 'aukora:1:' + '9'.repeat(64)
  assert.throws(() => f.gate.ownerBrowser.startSignin({}), /binding-mismatch/)
  f.content = '{"accent": "#224466"}'
  assert.throws(() => f.review(), /binding-mismatch/); assert.equal(f.writes, 1)
})
test('losing browser join configuration after selecting it cannot bypass final binding, even before enrollment', t => {
  for (const enroll of [false, true]) {
    const f = joinedGateFixture(t); if (enroll) f.enroll()
    f.join.enabled = false; assert.throws(() => f.restart(), /browser-join-required/); assert.equal(f.writes, 0)
  }
})
test('gate final-binding integration removals fail their focused regressions', async t => {
  const url = new URL('../packages/boundary-gate/src/gate.mjs', import.meta.url), source = fs.readFileSync(url, 'utf8')
  const mutants = [
    ['final signature for gate approvals', 'return ownerBrowser ? ownerBrowser.boundOwnerState(state) : state', 'return state', f => { f.enroll(); assert.throws(() => f.review(), /binding-required/); assert.equal(f.writes, 0) }],
    ['retained browser mode', `if (!ownerBrowser && db.prepare("SELECT 1 FROM sqlite_master WHERE name='owner_browser_config'").get()
    && db.prepare('SELECT 1 FROM owner_browser_config LIMIT 1').get()) passkeyRefuse('browser-join-required')`, '', f => { f.enroll(); f.join.enabled = false; assert.throws(() => f.restart(), /browser-join-required/) }],
  ]
  let killed = 0
  for (const [name, before, after, exercise] of mutants) await t.test(name, async st => {
    assert.ok(source.includes(before), 'mutation preimage ' + name)
    const modified = source.replace(before, after).replace(/from\s+(['"])(\.[^'"]+)\1/g, (_m, q, relative) => 'from ' + q + new URL(relative, url).href + q)
    const factory = (await import('data:text/javascript;base64,' + Buffer.from(modified + '\n// ' + name).toString('base64'))).createGate
    const f = joinedGateFixture(st, factory)
    assert.throws(() => exercise(f), assert.AssertionError, 'removed integration guard must fail behavior assertion'); killed++
  })
  t.diagnostic(`SOURCE-ONLY owner browser gate integration mutations: ${killed}/${mutants.length} killed`)
})
