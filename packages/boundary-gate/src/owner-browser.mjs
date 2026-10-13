// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser sign-in and final subject binding require one-use node-bound enrolled-passkey assertions.
import { createHash, randomBytes } from 'node:crypto'
import { ownerAuthorizationOwnerState } from '../../owner-key/src/authorization.mjs'
import { prepareWebauthnConfig, verifyWebauthnAssertion, webauthnOptions } from '../../owner-key/src/webauthn.mjs'

const hash = value => createHash('sha256').update(value).digest('hex')
const webauthnChallenge = bytes => Buffer.from(hash(bytes), 'hex').toString('base64url')
const refuse = code => { throw Object.assign(new Error('owner-browser:' + code), { code: 'owner-browser:' + code }) }
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field))
const id = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
const LIFE_MS = 60000

export function createOwnerBrowser({ db, tx, setup, ownerState, readBinding, appOrigin, now = Date.now, append } = {}) {
  let url
  try { url = new URL(appOrigin) } catch { refuse('app-origin') }
  if (url.protocol !== 'https:' || url.origin !== appOrigin) refuse('app-origin')
  db.function('owner_browser_clock', clock)
  db.exec(`CREATE TABLE IF NOT EXISTS owner_browser_config(singleton INTEGER PRIMARY KEY CHECK(singleton=1), config_text TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS owner_browser_challenges(challenge_id TEXT PRIMARY KEY, kind TEXT NOT NULL,
      statement_text TEXT NOT NULL, issued_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, spent INTEGER NOT NULL CHECK(spent IN (0,1)));
    CREATE TABLE IF NOT EXISTS owner_browser_codes(code_sha256 TEXT PRIMARY KEY, config_text TEXT NOT NULL,
      issued_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, spent INTEGER NOT NULL CHECK(spent IN (0,1)));
    CREATE TABLE IF NOT EXISTS owner_browser_binding(singleton INTEGER PRIMARY KEY CHECK(singleton=1), statement_text TEXT NOT NULL, assertion_text TEXT NOT NULL);
    CREATE TRIGGER IF NOT EXISTS owner_browser_config_update BEFORE UPDATE ON owner_browser_config BEGIN SELECT RAISE(ABORT,'browser config retained'); END;
    CREATE TRIGGER IF NOT EXISTS owner_browser_config_delete BEFORE DELETE ON owner_browser_config BEGIN SELECT RAISE(ABORT,'browser config retained'); END;
    CREATE TRIGGER IF NOT EXISTS owner_browser_challenge_update BEFORE UPDATE ON owner_browser_challenges
      WHEN NEW.challenge_id!=OLD.challenge_id OR NEW.kind!=OLD.kind OR NEW.statement_text!=OLD.statement_text
        OR NEW.issued_at_ms!=OLD.issued_at_ms OR NEW.expires_at_ms!=OLD.expires_at_ms OR NEW.spent<OLD.spent
      BEGIN SELECT RAISE(ABORT,'browser challenge retained'); END;
    CREATE TRIGGER IF NOT EXISTS owner_browser_challenge_delete BEFORE DELETE ON owner_browser_challenges
      WHEN OLD.expires_at_ms>owner_browser_clock() BEGIN SELECT RAISE(ABORT,'browser challenge retained'); END;
    CREATE TRIGGER IF NOT EXISTS owner_browser_code_update BEFORE UPDATE ON owner_browser_codes
      WHEN NEW.code_sha256!=OLD.code_sha256 OR NEW.config_text!=OLD.config_text OR NEW.issued_at_ms!=OLD.issued_at_ms
        OR NEW.expires_at_ms!=OLD.expires_at_ms OR NEW.spent<OLD.spent
      BEGIN SELECT RAISE(ABORT,'browser code retained'); END;
    CREATE TRIGGER IF NOT EXISTS owner_browser_code_delete BEFORE DELETE ON owner_browser_codes
      WHEN OLD.expires_at_ms>owner_browser_clock() BEGIN SELECT RAISE(ABORT,'browser code retained'); END;
    CREATE TRIGGER IF NOT EXISTS owner_browser_binding_update BEFORE UPDATE ON owner_browser_binding BEGIN SELECT RAISE(ABORT,'browser binding retained'); END;
    CREATE TRIGGER IF NOT EXISTS owner_browser_binding_delete BEFORE DELETE ON owner_browser_binding BEGIN SELECT RAISE(ABORT,'browser binding retained'); END;`)
  function configuration() {
    const selected = setup()
    if (selected.origin === appOrigin) refuse('origins-not-separated')
    const config = { gate: selected.gate, node: selected.node, origin: selected.origin, rp_id: selected.rp_id, app_origin: appOrigin }
    const text = JSON.stringify(config), retained = db.prepare('SELECT config_text FROM owner_browser_config WHERE singleton=1').get()
    if (retained && retained.config_text !== text) refuse('config-changed')
    return { config, text }
  }
  tx(() => { const { text } = configuration(); db.prepare('INSERT OR IGNORE INTO owner_browser_config VALUES(1,?)').run(text) })
  function enrolled() {
    const { config, text } = configuration(), raw = ownerState()
    if (!raw) refuse('owner-not-enrolled')
    const state = ownerAuthorizationOwnerState(raw)
    if (state.version !== 2 || state.node !== config.node || state.origin !== config.origin || state.rp_id !== config.rp_id) refuse('credential-binding')
    const counter = db.prepare('SELECT sign_count FROM owner_passkey WHERE singleton=1').get()?.sign_count
    if (!Number.isSafeInteger(counter)) refuse('counter-unavailable')
    const webauthn = prepareWebauthnConfig({ rp_id: config.rp_id, origins: [config.origin], credentials: [{ owner_id: state.owner_root_id,
      credential_id: state.credential_id, public_key_hex: state.public_key_hex, user_handle: state.user_handle,
      sign_count: counter, backup_eligible: state.backup_eligible }] })
    return { config, text, state, counter, webauthn }
  }
  function bindingRecord() {
    let projection
    try { projection = readBinding?.() } catch { refuse('binding-record-unavailable') }
    if (!exact(projection, ['subject', 'rootId']) || typeof projection.subject !== 'string'
      || !/^aukora:1:[0-9a-f]{64}$/u.test(projection.subject) || !id(projection.rootId)) refuse('binding-record-unavailable')
    return projection
  }
  function clock() {
    const at = now()
    if (!Number.isSafeInteger(at) || at < 0 || at > Number.MAX_SAFE_INTEGER - LIFE_MS) refuse('clock')
    return at
  }
  function statementIdentity(statement, kind, current) {
    const fields = ['version', 'kind', 'gate', 'node', 'origin', 'rp_id', 'app_origin', 'credential_id', 'passkey_root_id', 'nonce', 'issued_at_ms', 'expires_at_ms']
    if (kind === 'binding') fields.push('subject', 'rootId')
    if (!exact(statement, fields) || statement.version !== 1 || statement.kind !== 'aukora-owner-browser-' + kind + '/v1'
      || !id(statement.nonce) || !Number.isSafeInteger(statement.issued_at_ms) || statement.issued_at_ms < 0
      || statement.expires_at_ms !== statement.issued_at_ms + LIFE_MS
      || Object.keys(current.config).some(field => statement[field] !== current.config[field])
      || statement.credential_id !== current.state.credential_id || statement.passkey_root_id !== current.state.owner_root_id) refuse('statement-mismatch')
    if (kind === 'binding') {
      const projection = bindingRecord()
      if (statement.subject !== projection.subject || statement.rootId !== projection.rootId) refuse('binding-mismatch')
    }
  }
  function start(args, kind) {
    if (!exact(args, [])) refuse('request-shape')
    let statement, challenge_id
    tx(() => {
      const current = enrolled(), at = clock()
      if (kind === 'signin') verifyRetainedBinding(current)
      db.prepare('DELETE FROM owner_browser_challenges WHERE expires_at_ms<=?').run(at)
      db.prepare('DELETE FROM owner_browser_codes WHERE expires_at_ms<=?').run(at)
      if (db.prepare('SELECT COUNT(*) AS n FROM owner_browser_challenges WHERE issued_at_ms>?').get(at - LIFE_MS).n >= 32) refuse('challenge-limit')
      if (kind === 'binding' && db.prepare('SELECT 1 FROM owner_browser_binding WHERE singleton=1').get()) refuse('already-bound')
      const projection = kind === 'binding' ? bindingRecord() : undefined
      challenge_id = randomBytes(32).toString('hex')
      statement = { version: 1, kind: 'aukora-owner-browser-' + kind + '/v1', ...current.config,
        credential_id: current.state.credential_id, passkey_root_id: current.state.owner_root_id,
        nonce: challenge_id, issued_at_ms: at, expires_at_ms: at + LIFE_MS, ...(projection ?? {}) }
      const statement_text = JSON.stringify(statement)
      db.prepare('INSERT INTO owner_browser_challenges VALUES(?,?,?,?,?,0)').run(challenge_id, kind, statement_text, at, at + LIFE_MS)
    }, () => { statementIdentity(statement, kind, enrolled()); if (clock() >= statement.expires_at_ms) refuse('expired-at-commit') })
    const current = enrolled(), statement_text = JSON.stringify(statement)
    return { challenge_id, statement_text, expires_at_ms: statement.expires_at_ms,
      public_key: webauthnOptions(current.webauthn, current.state.owner_root_id, webauthnChallenge(Buffer.from(statement_text))),
      ...(kind === 'binding' ? { subject: statement.subject, node: statement.node } : {}) }
  }
  function finish(args, kind) {
    const challenge_id = typeof args?.challenge_id === 'string' && id(args.challenge_id) ? args.challenge_id : null
    let acceptedStatement, acceptedState
    const result = tx(() => {
      if (!exact(args, ['challenge_id', 'assertion']) || challenge_id === null) refuse('request-shape')
      const row = db.prepare('SELECT * FROM owner_browser_challenges WHERE challenge_id=?').get(challenge_id)
      if (!row || row.kind !== kind || row.spent !== 0) refuse('challenge-spent')
      const at = clock()
      if (at < row.issued_at_ms || at >= row.expires_at_ms) refuse('challenge-expired')
      const statement = JSON.parse(row.statement_text), current = enrolled()
      if (statement.nonce !== challenge_id || statement.issued_at_ms !== row.issued_at_ms || statement.expires_at_ms !== row.expires_at_ms) refuse('statement-row-mismatch')
      statementIdentity(statement, kind, current)
      if (kind === 'signin') verifyRetainedBinding(current)
      const verified = verifyWebauthnAssertion({ material: args.assertion, config: current.webauthn, ownerId: current.state.owner_root_id,
        challenge: webauthnChallenge(Buffer.from(row.statement_text)), counter: current.counter })
      const spent = db.prepare('UPDATE owner_browser_challenges SET spent=1 WHERE challenge_id=? AND spent=0').run(challenge_id)
      if (spent.changes !== 1) refuse('challenge-spent')
      const updated = db.prepare('UPDATE owner_passkey SET sign_count=? WHERE singleton=1 AND sign_count=?').run(verified.sign_count, current.counter)
      if (updated.changes !== 1) refuse('counter-conflict')
      acceptedStatement = statement; acceptedState = JSON.stringify(current.state)
      if (kind === 'binding') {
        if (db.prepare('SELECT 1 FROM owner_browser_binding WHERE singleton=1').get()) refuse('already-bound')
        db.prepare('INSERT INTO owner_browser_binding VALUES(1,?,?)').run(row.statement_text, JSON.stringify(args.assertion))
        append?.('owner-browser-bound', { detail: { statement_text: row.statement_text, assertion: args.assertion } })
        return { bound: true, subject: statement.subject, node: statement.node }
      }
      const code = randomBytes(32).toString('base64url'), issued = clock()
      db.prepare('INSERT INTO owner_browser_codes VALUES(?,?,?,?,0)').run(hash(code), current.text, issued, issued + LIFE_MS)
      return { code, expires_at_ms: issued + LIFE_MS, app_origin: current.config.app_origin }
    }, () => {
      const current = enrolled()
      statementIdentity(acceptedStatement, kind, current)
      if (kind === 'signin') verifyRetainedBinding(current)
      if (JSON.stringify(current.state) !== acceptedState) refuse('owner-state-changed')
      if (clock() < acceptedStatement.issued_at_ms || clock() >= acceptedStatement.expires_at_ms) refuse('expired-at-commit')
    }, error => {
      if (challenge_id !== null) db.prepare('UPDATE owner_browser_challenges SET spent=1 WHERE challenge_id=? AND spent=0').run(challenge_id)
      return { refused_error: error }
    })
    if (result.refused_error) throw result.refused_error
    return result
  }
  function verifyRetainedBinding(current, required = false) {
    const row = db.prepare('SELECT * FROM owner_browser_binding WHERE singleton=1').get()
    if (!row) { if (required) refuse('binding-required'); return null }
    const statement = JSON.parse(row.statement_text)
    statementIdentity(statement, 'binding', current)
    verifyWebauthnAssertion({ material: JSON.parse(row.assertion_text), config: current.webauthn, ownerId: current.state.owner_root_id,
      challenge: webauthnChallenge(Buffer.from(row.statement_text)), checkCounter: false })
    return { row, statement }
  }
  function redeemSignin(args) {
    if (!exact(args, ['code', 'app_origin']) || typeof args.code !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(args.code)) refuse('request-shape')
    let acceptedExpiry
    const result = tx(() => {
      const current = enrolled()
      verifyRetainedBinding(current)
      if (args.app_origin !== current.config.app_origin) refuse('app-origin-mismatch')
      const row = db.prepare('SELECT * FROM owner_browser_codes WHERE code_sha256=?').get(hash(args.code)), at = clock()
      if (!row || row.spent !== 0) refuse('code-spent')
      if (row.config_text !== current.text) refuse('code-binding')
      if (at < row.issued_at_ms || at >= row.expires_at_ms) refuse('code-expired')
      const spent = db.prepare('UPDATE owner_browser_codes SET spent=1 WHERE code_sha256=? AND spent=0').run(hash(args.code))
      if (spent.changes !== 1) refuse('code-spent')
      acceptedExpiry = row.expires_at_ms
      return { ...current.config, expires_at_ms: row.expires_at_ms }
    }, () => { verifyRetainedBinding(enrolled()); if (clock() >= acceptedExpiry) refuse('expired-at-commit') }, error => {
      db.prepare('UPDATE owner_browser_codes SET spent=1 WHERE code_sha256=? AND spent=0').run(hash(args.code))
      return { refused_error: error }
    })
    if (result.refused_error) throw result.refused_error
    return result
  }
  function boundOwnerState(rawState) {
    const current = enrolled(), { row, statement } = verifyRetainedBinding(current, true)
    if (JSON.stringify(ownerAuthorizationOwnerState(rawState)) !== JSON.stringify(current.state)) refuse('owner-state-changed')
    return ownerAuthorizationOwnerState({ ...current.state, owner_subject: statement.subject,
      registry_sha256: hash(row.statement_text), activation_sha256: hash(row.statement_text + '\n' + row.assertion_text) })
  }
  return { startSignin: args => start(args, 'signin'), finishSignin: args => finish(args, 'signin'), redeemSignin,
    startBinding: args => start(args, 'binding'), finishBinding: args => finish(args, 'binding'), boundOwnerState }
}
