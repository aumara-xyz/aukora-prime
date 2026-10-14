#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Software enrollment and approval run only on a marked rehearsal node and two exact HTTPS origins.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import { parseArgs } from 'node:util'
import { pathToFileURL } from 'node:url'
import { ownerAuthorizationDigest, ownerAuthorizationProofDigest } from '../../../packages/owner-key/src/authorization.mjs'

const hash = value => createHash('sha256').update(value).digest()
const hex = value => hash(value).toString('hex')
const need = (condition, code) => { if (!condition) throw new Error('REHEARSAL_' + code) }
const decode = text => {
  need(typeof text === 'string' && /^[A-Za-z0-9_-]+$/.test(text), 'OPTIONS_INVALID')
  const bytes = Buffer.from(text, 'base64url')
  need(bytes.toString('base64url') === text, 'OPTIONS_INVALID')
  return bytes
}
const unescape = text => text.replace(/&(amp|lt|gt|quot|#39);/g, (_, name) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" }[name]))
const attribute = (html, name) => unescape(html.match(new RegExp('\\b' + name + '="([^"<>]*)"'))?.[1] ?? '')
function origin(value) {
  let url
  try { url = new URL(value) } catch { need(false, 'ORIGIN_INVALID') }
  need(url.protocol === 'https:' && url.origin === value && !url.username && !url.password, 'ORIGIN_INVALID')
  return url
}
function link(value, expectedOrigin, path, key, fragment = false) {
  let url
  try { url = new URL(value) } catch { need(false, 'LINK_INVALID') }
  const secret = (fragment ? new URLSearchParams(url.hash.slice(1)) : url.searchParams)
  need(url.origin === expectedOrigin && !url.username && !url.password && url.pathname === path
    && (fragment ? !url.search : !url.hash) && [...secret.keys()].join(',') === key, 'LINK_INVALID')
  const code = secret.get(key)
  need(fragment ? /^[A-Za-z0-9_-]{43}$/.test(code ?? '') : /^[A-Za-z0-9_-]{16,256}$/.test(code ?? ''), 'LINK_INVALID')
  return code
}

// Manual redirects cannot leave the selected origins or carry a POST to another route.
export function checkedFetch(ownerOrigin, appOrigin, fetchImpl) {
  origin(ownerOrigin); origin(appOrigin)
  need(ownerOrigin !== appOrigin, 'ORIGINS_NOT_SEPARATED')
  return async function request(target, options = {}) {
    let url = new URL(target), method = options.method ?? 'GET'
    for (let count = 0; count < 6; count++) {
      need([ownerOrigin, appOrigin].includes(url.origin) && !url.username && !url.password && !url.hash, 'REDIRECT_REFUSED')
      const response = await fetchImpl(url.href, { ...options, method, redirect: 'manual', credentials: 'omit',
        signal: AbortSignal.timeout(10000) })
      if (![301, 302, 303, 307, 308].includes(response.status)) {
        let text = '', bytes = 0
        for await (const chunk of response.body ?? []) {
          bytes += chunk.length; need(bytes <= 262144, 'RESPONSE_TOO_LARGE')
          text += Buffer.from(chunk).toString('utf8')
        }
        return { status: response.status, headers: response.headers, text }
      }
      need(method === 'GET' && response.headers.has('location'), 'REDIRECT_REFUSED')
      await response.body?.cancel()
      url = new URL(response.headers.get('location'), url)
    }
    need(false, 'REDIRECT_LIMIT')
  }
}

function cbor(value) {
  const head = (major, size) => size < 24 ? Buffer.from([major * 32 + size]) : size < 256
    ? Buffer.from([major * 32 + 24, size]) : Buffer.from([major * 32 + 25, size >>> 8, size & 255])
  if (Number.isInteger(value)) return value >= 0 ? head(0, value) : head(1, -1 - value)
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value])
  if (typeof value === 'string') return Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)])
  return Buffer.concat([head(5, value.size), ...[...value].flatMap(([key, item]) => [cbor(key), cbor(item)])])
}

export function createSoftwareAuthenticator({ origin: ownerOrigin, rpId }) {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), jwk = pair.publicKey.export({ format: 'jwk' })
  const id = randomBytes(32), credentialId = id.toString('base64url')
  let count = 0, user
  function options(publicKey) {
    need(publicKey?.rpId === rpId && publicKey.userVerification === 'required'
      && publicKey.allowCredentials?.some(item => item.type === 'public-key' && item.id === credentialId), 'ASSERTION_OPTIONS_REFUSED')
    decode(publicKey.challenge)
  }
  return {
    registration(publicKey) {
      need(publicKey?.rp?.id === rpId && publicKey.attestation === 'none'
        && publicKey.authenticatorSelection?.userVerification === 'required'
        && publicKey.pubKeyCredParams?.some(item => item.type === 'public-key' && item.alg === -7), 'CREATION_OPTIONS_REFUSED')
      decode(publicKey.challenge); user = decode(publicKey.user?.id).toString('base64url')
      const auth = Buffer.alloc(55); hash(rpId).copy(auth); auth[32] = 0x45; auth.writeUInt16BE(id.length, 53)
      const key = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]))
      const client = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: publicKey.challenge, origin: ownerOrigin, crossOrigin: false }))
      return { kind: 'passkey-registration', type: 'public-key', id: credentialId, raw_id: credentialId,
        client_data_json: client.toString('base64url'), client_extension_results: {},
        attestation_object: cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', Buffer.concat([auth, id, key])]])).toString('base64url') }
    },
    assertion(publicKey, change = {}) {
      options(publicKey)
      const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: change.challenge ?? publicKey.challenge,
        origin: change.origin ?? ownerOrigin, crossOrigin: false }))
      const auth = Buffer.alloc(37); hash(change.rpId ?? rpId).copy(auth); auth[32] = 5; auth.writeUInt32BE(++count, 33)
      return { kind: 'passkey', credential_id: credentialId, user_handle: user,
        client_data_json: client.toString('base64url'), authenticator_data: auth.toString('base64url'),
        signature: sign('sha256', Buffer.concat([auth, hash(client)]), pair.privateKey).toString('base64url') }
    }, options,
  }
}

export async function rehearsePasskey({ ownerOrigin, appOrigin, claimLink, cardsLink, fetch: fetchImpl = globalThis.fetch,
  log = console.log, wait = ms => new Promise(resolve => setTimeout(resolve, ms)), timeoutMs = 300000 }) {
  let label = 'inputs'
  const step = async (name, run) => { label = name; const result = await run(); log('PASS ' + name); return result }
  try {
    const owner = origin(ownerOrigin); origin(appOrigin)
    const claim = link(claimLink, ownerOrigin, '/owner/enroll', 'claim', true)
    const bearer = link(cardsLink, ownerOrigin, '/owner/cards', 'bearer')
    const request = checkedFetch(ownerOrigin, appOrigin, fetchImpl)
    const navigation = { headers: { 'Sec-Fetch-Site': 'none', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' } }
    const get = path => request(ownerOrigin + path, navigation)
    const post = (path, body) => request(ownerOrigin + path, { method: 'POST', headers: { Origin: ownerOrigin,
      'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty', 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
    function json(response) { try { return JSON.parse(response.text) } catch { need(false, 'RESPONSE_INVALID') } }
    function success(response) {
      const body = json(response)
      need(response.status === 200 && body.ok === true && body.result && typeof body.result === 'object', 'REQUEST_REFUSED')
      return body.result
    }
    function refusal(response, status, code) {
      const body = json(response)
      need(response.status === status && body.ok === false && body.error === code, 'REFUSAL_NOT_OBSERVED')
    }
    const profile = await step('enrollment-page', async () => {
      const page = await get('/owner/enroll')
      need(page.status === 200 && /<meta name="aukora-node-mode" content="rehearsal">/.test(page.text), 'MARKER_REQUIRED')
      need(attribute(page.text, 'data-mode') === 'enroll' && attribute(page.text, 'data-origin') === ownerOrigin
        && attribute(page.text, 'data-rp-id') === owner.hostname, 'PAGE_PROFILE_REFUSED')
      return { origin: ownerOrigin, rpId: owner.hostname }
    })
    const auth = createSoftwareAuthenticator(profile)
    const registered = await step('create', async () => {
      const started = success(await post('/owner/enroll/start', { claim_code: claim }))
      need(started.stage === undefined || started.stage === 'registration', 'FRESH_ENROLLMENT_REQUIRED')
      const result = success(await post('/owner/enroll/register', { enrollment_id: started.enrollment_id,
        registration: auth.registration(started.public_key) }))
      need(result.enrollment_id === started.enrollment_id, 'ENROLLMENT_ID_MISMATCH')
      return result
    })
    const enrolled = await step('possession', async () => {
      const result = success(await post('/owner/enroll/finish', { enrollment_id: registered.enrollment_id, assertion: auth.assertion(registered.public_key) }))
      need(result.enrolled === true && /^[a-f0-9]{64}$/.test(result.node), 'ENROLLMENT_NOT_CONFIRMED')
      return result
    })
    await step('enrollment-closed', async () => refusal(await post('/owner/enroll/start', { claim_code: claim }), 403, 'passkey:enrollment-closed'))
    await step('bearer-refused', async () => {
      refusal(await post('/act', { k: bearer, a: 'approve-step1', id: 'rehearsal' }), 404, 'OWNER_PASSKEY_PATH_REFUSED')
      refusal(await post('/owner/approve', { bearer, id: 'rehearsal', base_sha: hex('before'), new_sha: hex('after'), review_challenge: hex('review') }), 403, 'OWNER_PASSKEY_FIELDS_REFUSED')
    })
    const card = await step('pending-theme', async () => {
      const end = Date.now() + timeoutMs
      do {
        const page = await get('/owner/cards?bearer=' + encodeURIComponent(bearer))
        need(page.status === 200 && attribute(page.text, 'data-mode') === 'cards', 'CARDS_PAGE_REFUSED')
        const cards = [...page.text.matchAll(/<article data-card data-id="([^"<>]+)">[\s\S]*?<pre data-card-text>([\s\S]*?)<\/pre>/g)]
        if (cards.length) {
          need(cards.length === 1, 'ONE_THEME_REQUIRED')
          const value = JSON.parse(unescape(cards[0][2]))
          need(value.id === unescape(cards[0][1]) && value.target === 'plugins/auma-theme/theme.json' && value.kind === 'change', 'THEME_REQUIRED')
          return value
        }
        await wait(1000)
      } while (Date.now() < end)
      need(false, 'PENDING_TIMEOUT')
    })
    async function review() {
      const r = success(await post('/owner/review', { bearer, id: card.id })), a = r.owner_authorization
      need(typeof r.card_text === 'string' && a?.version === 2 && hex(r.card_text) === a.card_sha256, 'CARD_DIGEST_REFUSED')
      const exact = JSON.parse(r.card_text)
      need(exact.id === card.id && exact.target === card.target && exact.base_sha === card.base_sha && exact.new_sha === card.new_sha
        && exact.kind === 'change' && exact.displayable === true && /^\{"accent": "(?:default|#[0-9A-F]{6})"\}$/.test(exact.content)
        && hex(exact.content) === exact.new_sha, 'CARD_CHANGED')
      need(a.node === enrolled.node && a.owner_subject === enrolled.owner_subject && a.proposal_id === exact.id && a.target === exact.target
        && a.before_sha256 === exact.base_sha && a.after_sha256 === exact.new_sha && a.operation === exact.kind && a.challenge === r.review_challenge,
      'AUTHORIZATION_MISMATCH')
      need(r.authorization_digest === ownerAuthorizationDigest(a)
        && r.public_key?.challenge === Buffer.from(r.authorization_digest, 'hex').toString('base64url'), 'CHALLENGE_DIGEST_REFUSED')
      auth.options(r.public_key)
      return r
    }
    function approval(r, change = {}) {
      return { bearer, id: r.id, base_sha: r.base_sha, new_sha: r.new_sha, review_challenge: r.review_challenge,
        owner_authorization_proof: { version: 2, algorithm: 'webauthn-es256-sha256', authorization: r.owner_authorization,
          assertion: auth.assertion(r.public_key, change) } }
    }
    // Fresh reviews exercise each cryptographic check before the card is consumed.
    for (const [name, change, code] of [['wrong-rpid', { rpId: 'wrong.' + profile.rpId }, 'WEBAUTHN_RP_ID_MISMATCH'],
      ['wrong-origin', { origin: 'https://wrong.' + profile.rpId }, 'WEBAUTHN_CHALLENGE_OR_ORIGIN_MISMATCH'],
      ['wrong-challenge', { challenge: randomBytes(32).toString('base64url') }, 'WEBAUTHN_CHALLENGE_OR_ORIGIN_MISMATCH']]) {
      await step(name, async () => refusal(await post('/owner/approve', approval(await review(), change)), 403, code))
    }
    const submitted = await step('applied-receipt', async () => {
      const r = await review(), body = approval(r), result = success(await post('/owner/approve', body)), receipt = result.receipt
      need(result.applied === true && result.state === 'applied', 'APPLY_NOT_OBSERVED')
      need(receipt?.v === 3 && receipt.proposal === r.id && receipt.target === card.target
        && receipt.base_sha === r.base_sha && receipt.new_sha === r.new_sha && receipt.gate_pubkey_sha256 === r.owner_authorization.gate
        && receipt.owner_authorization?.authorization_id === r.authorization_digest
        && receipt.owner_authorization?.proof_sha256 === ownerAuthorizationProofDigest(body.owner_authorization_proof)
        && typeof result.receipt_sig === 'string' && Buffer.from(result.receipt_sig, 'base64').length === 64
        && Number.isSafeInteger(result.ledger_seq) && result.ledger_seq > 0, 'RECEIPT_REQUIRED')
      const page = await get('/owner/cards?bearer=' + encodeURIComponent(bearer))
      need(page.status === 200 && !page.text.includes('data-id="' + card.id + '"'), 'APPLIED_STILL_PENDING')
      return body
    })
    await step('replay-refused', async () => refusal(await post('/owner/approve', submitted), 403, 'OWNER_PASSKEY_REFUSED'))
    const signin = await step('signin-page', async () => {
      const end = Date.now() + timeoutMs
      do {
        const page = await get('/owner/signin')
        if (page.status === 200) {
          need(attribute(page.text, 'data-mode') === 'signin' && attribute(page.text, 'data-origin') === ownerOrigin
            && attribute(page.text, 'data-rp-id') === profile.rpId && attribute(page.text, 'data-app-origin') === appOrigin
            && attribute(page.text, 'data-node') === enrolled.node, 'SIGNIN_PROFILE_REFUSED')
          return { gate: attribute(page.text, 'data-gate') }
        }
        refusal(page, 403, 'OWNER_BROWSER_JOIN_REQUIRED'); await wait(1000)
      } while (Date.now() < end)
      need(false, 'SIGNIN_TIMEOUT')
    })
    const code = await step('signin-proof', async () => {
      const started = success(await post('/owner/signin/start', {})), statement = JSON.parse(started.statement_text)
      need(statement.version === 1 && statement.kind === 'aukora-owner-browser-signin/v1' && statement.origin === ownerOrigin
        && statement.rp_id === profile.rpId && statement.app_origin === appOrigin && statement.node === enrolled.node
        && statement.gate === signin.gate && statement.nonce === started.challenge_id
        && hash(started.statement_text).toString('base64url') === started.public_key?.challenge, 'SIGNIN_STATEMENT_REFUSED')
      const result = success(await post('/owner/signin/finish', { challenge_id: started.challenge_id, assertion: auth.assertion(started.public_key) }))
      need(result.app_origin === appOrigin && /^[A-Za-z0-9_-]{43}$/.test(result.code ?? ''), 'SIGNIN_CODE_REFUSED')
      return result.code
    })
    await step('host-session-cookie', async () => {
      const page = await request(appOrigin + '/__aukora/signin', navigation)
      need(page.status === 200, 'APP_SIGNIN_PAGE_REFUSED')
      const response = await request(appOrigin + '/__aukora/signin', { method: 'POST', headers: { Origin: appOrigin,
        'Content-Type': 'text/plain', 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty' }, body: code })
      const cookies = response.headers.getSetCookie()
      need(response.status === 204 && cookies.length === 1, 'SESSION_EXCHANGE_REFUSED')
      const cookie = cookies[0]
      need(/^__Host-[A-Za-z0-9_-]+=[^;\s]+;/.test(cookie) && /; Path=\/(?:;|$)/i.test(cookie)
        && /; Secure(?:;|$)/i.test(cookie) && /; HttpOnly(?:;|$)/i.test(cookie) && /; SameSite=Strict(?:;|$)/i.test(cookie)
        && !/;\s*Domain=/i.test(cookie), 'HOST_COOKIE_REQUIRED')
    })
    return true
  } catch (error) {
    log('FAIL ' + label + ' ' + (/^REHEARSAL_[A-Z_]+$/.test(error?.message) ? error.message : 'REHEARSAL_REFUSED'))
    return false
  }
}

export async function readPrivateLinks(stdin, version = process.version) {
  need(version === 'v24.11.1', 'NODE_VERSION_REQUIRED')
  let input = ''
  for await (const bytes of stdin) { need(Buffer.byteLength(input) + bytes.length <= 8192, 'INPUT_TOO_LARGE'); input += bytes.toString('utf8') }
  const lines = input.trim().split(/\r?\n/)
  need(lines.length === 2, 'TWO_PRIVATE_LINKS_REQUIRED')
  return lines
}
async function main() {
  const { values } = parseArgs({ options: { 'owner-origin': { type: 'string' }, 'app-origin': { type: 'string' } }, strict: true, allowPositionals: false })
  origin(values['owner-origin']); origin(values['app-origin'])
  const lines = await readPrivateLinks(process.stdin)
  const ok = await rehearsePasskey({ ownerOrigin: values['owner-origin'], appOrigin: values['app-origin'], claimLink: lines[0], cardsLink: lines[1] })
  if (!ok) process.exitCode = 1
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main().catch(() => {
  console.error('FAIL inputs REHEARSAL_USAGE_REFUSED'); process.exitCode = 1
})
