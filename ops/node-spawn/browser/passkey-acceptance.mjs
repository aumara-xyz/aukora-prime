// SPDX-License-Identifier: AGPL-3.0-or-later
// Enrollment and bearer refusals are live; software proof checks use only ephemeral public state.
import fs from 'node:fs'
import http from 'node:http'
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import { pathToFileURL } from 'node:url'

const hash = bytes => createHash('sha256').update(bytes).digest()
const hex = bytes => hash(bytes).toString('hex')
const need = (condition, code) => { if (!condition) throw new Error('BROWSER_PASSKEY_' + code) }

export function softwareProofChecks({ authorization, setup, subject, now = Date.now() }) {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const der = pair.publicKey.export({ type: 'spki', format: 'der' }), jwk = pair.publicKey.export({ format: 'jwk' })
  const state = { version: 2, kind: 'aukora-owner-state/passkey-v2', owner_subject: subject,
    owner_root_spki_base64: der.toString('base64'), owner_root_id: hex(der), owner_epoch: 1,
    registry_sha256: hex('software-registry'), activation_sha256: hex('software-activation'),
    node: setup.node, rp_id: setup.rp_id, origin: setup.origin,
    credential_id: Buffer.from('acceptance-software-credential').toString('base64url'),
    user_handle: Buffer.from('acceptance-software-owner').toString('base64url'),
    public_key_hex: '04' + Buffer.from(jwk.x, 'base64url').toString('hex') + Buffer.from(jwk.y, 'base64url').toString('hex'),
    sign_count: 0, backup_eligible: false }
  const base = authorization.ownerAuthorization({ version: 2, kind: 'aukora-owner-authorization/v2', operation: 'change',
    proposal_id: randomUUID(), target: 'plugins/owner-note/note.md', before_sha256: hex('before'), after_sha256: hex('after'),
    gate: setup.gate, challenge: hex('acceptance-challenge'), issued_at_ms: now, expires_at_ms: now + 60000,
    owner_subject: subject, owner_root_id: state.owner_root_id, owner_epoch: 1, node: setup.node, card_sha256: hex('software-card') })
  const expectations = { owner_state: state, authorization_digest: authorization.ownerAuthorizationDigest(base), ...base }
  function proof(change = {}) {
    const value = { ...base, ...(change.node ? { node: change.node } : {}) }
    const client = Buffer.from(JSON.stringify({ type: 'webauthn.get',
      challenge: Buffer.from(authorization.ownerAuthorizationDigest(value), 'hex').toString('base64url'),
      origin: change.origin ?? setup.origin, crossOrigin: false }))
    const auth = Buffer.alloc(37); hash(change.rp ?? setup.rp_id).copy(auth); auth[32] = 5; auth.writeUInt32BE(1, 33)
    return { version: 2, algorithm: 'webauthn-es256-sha256', authorization: value,
      assertion: { kind: 'passkey', credential_id: state.credential_id, client_data_json: client.toString('base64url'),
        authenticator_data: auth.toString('base64url'), signature: sign('sha256', Buffer.concat([auth, hash(client)]), pair.privateKey).toString('base64url'),
        user_handle: state.user_handle } }
  }
  const control = authorization.verifyOwnerAuthorization(proof(), expectations, now)
  need(control.status === 'verified-owner-authorization', 'SOFTWARE_CONTROL_REFUSED')
  for (const [name, change, code] of [
    ['RP', { rp: 'wrong.' + setup.rp_id }, 'WEBAUTHN_RP_ID_MISMATCH'],
    ['ORIGIN', { origin: 'https://wrong.' + setup.rp_id }, 'WEBAUTHN_CHALLENGE_OR_ORIGIN_MISMATCH'],
    ['NODE', { node: hex('wrong-node:' + setup.node) }, 'owner-authorization:passkey-state-mismatch'],
  ]) {
    let refused
    try { authorization.verifyOwnerAuthorization(proof(change), expectations, now) } catch (error) { refused = error.message }
    need(refused === code, 'WRONG_' + name + '_NOT_REFUSED')
  }
  return 'PASS | installed verifier refuses software-signed wrong rpId/origin/node (ephemeral state only)'
}

export async function passkeyAcceptance({ setup, row, binding, ownerOrigin, gateId, bearer, post, authorization }) {
  need(setup.origin === ownerOrigin && setup.rp_id === new URL(ownerOrigin).hostname, 'OWNER_ORIGIN_MISMATCH')
  need(setup.gate === gateId, 'GATE_MISMATCH')
  need(row?.claim_state === 'spent' && typeof row.state_text === 'string', 'ENROLLMENT_NOT_CLOSED')
  need(row.setup_text === JSON.stringify(setup), 'SETUP_MISMATCH')
  const state = authorization.ownerAuthorizationOwnerState(JSON.parse(row.state_text))
  need(state.version === 2 && state.node === setup.node && state.rp_id === setup.rp_id && state.origin === setup.origin,
    'ENROLLMENT_BINDING_MISMATCH')
  const identity = setup.binding.identity
  need(identity.subject === binding.subject && identity.control_digest === binding.control_digest
    && identity.approval_key_did === binding.approval_key_did && identity.authorization_epoch === binding.authorization_epoch
    && state.owner_subject === binding.subject, 'APP_BINDING_MISMATCH')
  const closed = await post('/owner/enroll/start', { claim_code: 'x'.repeat(43) })
  need(closed.status === 403 && closed.body?.ok === false && closed.body.error === 'passkey:enrollment-closed', 'LIVE_ENROLLMENT_NOT_CLOSED')
  const oldPage = await post('/act', { k: bearer, a: 'approve-step1', id: 'acceptance-refusal-only' })
  need(oldPage.status === 404 && oldPage.body?.ok === false && oldPage.body.error === 'OWNER_PASSKEY_PATH_REFUSED', 'BEARER_PAGE_NOT_REFUSED')
  const withoutProof = await post('/owner/approve', { bearer, id: 'acceptance-refusal-only',
    base_sha: hex('before'), new_sha: hex('after'), review_challenge: hex('acceptance') })
  need(withoutProof.status === 403 && withoutProof.body?.ok === false && withoutProof.body.error === 'OWNER_PASSKEY_FIELDS_REFUSED', 'BEARER_APPROVAL_NOT_REFUSED')
  return ['PASS | live enrollment closed; bearer page and proofless bearer approval refused',
    softwareProofChecks({ authorization, setup, subject: state.owner_subject })]
}

function ownerPost(origin) {
  return (target, body) => new Promise((resolve, reject) => {
    const bytes = Buffer.from(JSON.stringify(body)), request = http.request({ hostname: '127.0.0.1', port: 17792,
      method: 'POST', path: target, headers: { Host: new URL(origin).host, Origin: origin,
        'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty',
        'Content-Type': 'application/json', 'Content-Length': bytes.length } }, response => {
      let length = 0, chunks = []
      response.on('data', chunk => { length += chunk.length; if (length > 65536) request.destroy(new Error('BROWSER_PASSKEY_RESPONSE_TOO_LARGE')); else chunks.push(chunk) })
      response.on('error', reject)
      response.on('end', () => { try { resolve({ status: response.statusCode, body: JSON.parse(Buffer.concat(chunks)) }) }
        catch { reject(new Error('BROWSER_PASSKEY_RESPONSE_INVALID')) } })
    })
    request.setTimeout(5000, () => request.destroy(new Error('BROWSER_PASSKEY_REQUEST_TIMEOUT')))
    request.on('error', reject); request.end(bytes)
  })
}

async function main() {
  need(process.argv.length === 2 && process.getuid?.() === 0 && process.version === 'v24.11.1', 'USAGE')
  const authorization = await import('/opt/owner-key/src/authorization.mjs')
  const { passkeySetupReader } = await import('/opt/aukora-boundary-gate/src/owner-state.mjs')
  const { readCurrentBinding } = await import('/opt/aukora-boundary-gate/src/browser-passkey-claim.mjs')
  const setup = passkeySetupReader('/etc/aukora-boundary-gate/passkey-setup.json')()
  const db = new DatabaseSync('/home/aukora-gate/gate.db', { readOnly: true })
  let row
  try { row = db.prepare('SELECT setup_text,claim_state,state_text FROM owner_passkey WHERE singleton=1').get() } finally { db.close() }
  const pub = createPublicKey(fs.readFileSync('/run/aukora-gate/receipt-ed25519.pub'))
  const bearer = JSON.parse(fs.readFileSync('/home/aukora-gate/owner-secret.json')).bearer
  const ownerOrigin = fs.readFileSync('/etc/aukora/owner-public-origin', 'utf8').trim()
  for (const line of await passkeyAcceptance({ setup, row, binding: await readCurrentBinding(), ownerOrigin,
    gateId: hex(pub.export({ type: 'spki', format: 'der' })), bearer, post: ownerPost(ownerOrigin), authorization })) console.log(line)
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main().catch(error => {
  console.error('REFUSED ' + (/^BROWSER_PASSKEY_[A-Z_]+$/.test(error.message) ? error.message : 'BROWSER_PASSKEY_ACCEPTANCE_REFUSED'))
  process.exitCode = 1
})
