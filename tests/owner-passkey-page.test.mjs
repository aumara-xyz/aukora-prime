import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { createHash, webcrypto } from 'node:crypto'
import fs from 'node:fs'
import vm from 'node:vm'
import { createPasskeyOwnerHandler } from '../packages/boundary-gate/src/owner-page.mjs'
import { bearerOk } from '../packages/boundary-gate/src/secrets.mjs'
import { OWNER_PASSKEY_SCRIPT, passkeyOwnerScript } from '../packages/boundary-gate/src/owner-passkey-script.mjs'

const origin = 'https://owner.example.test', rpId = 'owner.example.test', bearer = 'synthetic-owner-bearer'
const sourceUrl = new URL('../packages/boundary-gate/src/owner-page.mjs', import.meta.url)
const hash = value => createHash('sha256').update(value).digest('hex')
function fakeGate() {
  const calls = []
  const record = operation => args => { calls.push({ operation, args }); return operation === 'pending' ? { pending: [{ id: 'card-1', content: '<script>model</script>' }] } : { applied: true } }
  return { calls, owner: { bearer, bearer_expires: 2000 }, now: () => 1000,
    ownerOps: { pending: record('pending'), review: record('review'), decide_review: record('decide_review') },
    startPasskeyEnrollment: record('start'), registerPasskeyEnrollment: record('register'), finishPasskeyEnrollment: record('finish') }
}
async function request(handler, { method = 'POST', url = '/owner/enroll/start', body = { claim_code: 'synthetic-claim' }, headers = {}, chunks, timeout = false } = {}) {
  const req = new EventEmitter()
  req.method = method; req.url = url
  req.headers = { host: rpId, origin, 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': method === 'GET' ? 'navigate' : 'cors',
    'sec-fetch-dest': method === 'GET' ? 'document' : '', 'content-type': 'application/json', ...headers }
  req.setTimeout = (ms, callback) => { if (callback) req.timeout = callback }
  req.destroy = () => { req.destroyed = true }
  const response = { writeHead(status, headers) { this.status = status; this.headers = headers }, end(body) { this.body = body } }
  const work = handler(req, response)
  if (timeout) req.timeout?.()
  else {
    for (const chunk of chunks || [JSON.stringify(body)]) req.emit('data', Buffer.from(chunk))
    req.emit('end')
  }
  await work
  return { ...response, destroyed: req.destroyed === true }
}

test('gate passkey page isolates HTTPS origin, static script and exact card rendering', async () => {
  const gate = fakeGate(), { handler } = createPasskeyOwnerHandler(gate, { origin, rpId })
  const page = await request(handler, { method: 'GET', url: '/owner/cards?bearer=' + bearer })
  assert.equal(page.status, 200)
  assert.equal(page.headers['x-frame-options'], 'DENY')
  assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/)
  assert.match(page.headers['content-security-policy'], /base-uri 'none'/)
  assert.doesNotMatch(page.headers['content-security-policy'], /unsafe-inline|unsafe-eval/)
  const scriptHash = createHash('sha256').update(OWNER_PASSKEY_SCRIPT).digest('base64')
  assert.match(page.headers['content-security-policy'], new RegExp("script-src 'sha256-" + scriptHash.replace(/[+]/g, '\\+') + "'"))
  assert.ok(page.body.includes(`integrity="sha256-${scriptHash}"`))
  assert.equal((page.body.match(/<script/g) || []).length, 1)
  assert.match(page.body, /<script defer src="\/owner\/passkey\.js" integrity="sha256-[^\"]+"><\/script>/)
  assert.match(page.body, /&lt;script&gt;model&lt;\/script&gt;/)
  const script = await request(handler, { method: 'GET', url: '/owner/passkey.js', headers: { 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'script' } })
  assert.equal(script.status, 200); assert.equal(script.body, OWNER_PASSKEY_SCRIPT)
  assert.equal(script.headers['x-content-type-options'], 'nosniff')
  assert.equal(page.headers['cache-control'], 'no-store'); assert.equal(page.headers['referrer-policy'], 'no-referrer')
})
test('owner page requires canonical HTTPS origin and an isolated DNS RP', () => {
  for (const options of [{ origin: 'http://owner.example.test', rpId }, { origin, rpId: 'example.test' }, { origin: 'https://127.0.0.1', rpId: '127.0.0.1' }]) {
    assert.throws(() => createPasskeyOwnerHandler(fakeGate(), options), /OWNER_PASSKEY_ORIGIN_REQUIRED/)
  }
})

const wireRefusals = [
  ['host', { headers: { host: 'evil.example.test', 'x-forwarded-host': rpId } }],
  ['origin', { headers: { origin: 'http://owner.example.test' } }],
  ['fetch metadata', { headers: { 'sec-fetch-site': 'cross-site' } }],
  ['fetch mode', { headers: { 'sec-fetch-mode': 'navigate' } }],
  ['fetch destination', { headers: { 'sec-fetch-dest': 'iframe' } }],
  ['content type', { headers: { 'content-type': 'text/plain' } }],
  ['exact fields', { body: { claim_code: 'synthetic', owner: true } }],
  ['body bound', { chunks: [JSON.stringify({ claim_code: 'x'.repeat(65536) })] }, 413],
  ['body timeout', { timeout: true }],
  ['UTF-8', { chunks: [Buffer.concat([Buffer.from('{"claim_code":"'), Buffer.from([0xff]), Buffer.from('"}')])] }],
  ['absolute URL', { url: origin + '/owner/enroll/start' }],
  ['query', { url: '/owner/enroll/start?claim=synthetic' }],
  ['GET fetch metadata', { method: 'GET', url: '/owner/enroll', headers: { 'sec-fetch-site': 'cross-site' } }],
  ['script query', { method: 'GET', url: '/owner/passkey.js?bearer=synthetic', headers: { 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'script' } }],
]
for (const [name, input, status = 403] of wireRefusals) test('owner page refuses ' + name + ' before gate authority', async () => {
  const gate = fakeGate(), { handler } = createPasskeyOwnerHandler(gate, { origin, rpId })
  const result = await request(handler, input)
  assert.equal(result.status, status); assert.equal(gate.calls.length, 0)
})
test('owner page requires bearer and proof fields, never a cookie alone', async () => {
  const gate = fakeGate(), { handler } = createPasskeyOwnerHandler(gate, { origin, rpId })
  for (const input of [
    { method: 'GET', url: '/owner/cards?bearer=wrong', headers: { cookie: 'owner=synthetic' } },
    { url: '/owner/review', body: { bearer: 'wrong', id: 'card-1' } },
    { url: '/owner/approve', body: { bearer, id: 'card-1', base_sha: 'a', new_sha: 'b', review_challenge: 'c' } },
  ]) assert.ok((await request(handler, input)).status >= 400)
  assert.equal(gate.calls.length, 0)
  const result = await request(handler, { url: '/owner/approve', body: { bearer, id: 'card-1', base_sha: 'a', new_sha: 'b', review_challenge: 'c', owner_authorization_proof: { version: 2 } } })
  assert.equal(result.status, 200)
  assert.deepEqual(gate.calls[0], { operation: 'decide_review', args: { id: 'card-1', base_sha: 'a', new_sha: 'b', review_challenge: 'c', owner_authorization_proof: { version: 2 }, outcome: 'allowed-once' } })
})
test('owner page enrollment forwards only the three closed ceremony stages', async () => {
  const gate = fakeGate(), { handler } = createPasskeyOwnerHandler(gate, { origin, rpId })
  for (const [url, body] of [
    ['/owner/enroll/start', { claim_code: 'synthetic' }],
    ['/owner/enroll/register', { enrollment_id: 'ceremony', registration: {} }],
    ['/owner/enroll/finish', { enrollment_id: 'ceremony', assertion: {} }],
  ]) assert.equal((await request(handler, { url, body })).status, 200)
  assert.deepEqual(gate.calls.map(call => call.operation), ['start', 'register', 'finish'])
})

function element(dataset = {}) {
  return { dataset, hidden: false, disabled: false, textContent: '', value: '', listeners: {},
    addEventListener(name, callback) { this.listeners[name] = callback },
    async fire(name = 'click') { return (this.listeners[name] || (name === 'click' ? this.onclick : null))?.({ preventDefault() {} }) } }
}
function browser({ mode = 'cards', alterReview = () => {}, secure = true, credentialId = 'AQ', creation = {}, browserOrigin = origin,
  assertionType = 'public-key', registrationType = 'public-key', extensionResults = {} } = {}) {
  const status = element(), root = element({ origin, rpId, mode }), claim = element(), form = element(), token = element()
  claim.value = 'synthetic-claim'; token.value = bearer
  const text = element(), authorization = element(), reviewButton = element(), approveButton = element(), card = element({ id: 'card-1' })
  approveButton.hidden = true
  const cardElements = { '[data-card-text]': text, '[data-authorization]': authorization, '[data-review]': reviewButton, '[data-approve]': approveButton }
  card.querySelector = selector => cardElements[selector]
  const elements = { '[data-owner-passkey]': root, '#status': status, '#claim-code': claim, '#enroll-form': form, '#owner-bearer': token }
  const publicKey = { challenge: Buffer.from('a'.repeat(64), 'hex').toString('base64url'), rpId, userVerification: 'required', allowCredentials: [{ type: 'public-key', id: 'AQ' }] }
  const card_text = '{"node":"c1","content":"<script>model</script>"}'
  const review = { id: 'card-1', card_text, authorization_digest: 'a'.repeat(64), base_sha: 'b', new_sha: 'c', review_challenge: 'd',
    owner_authorization: { version: 2, card_sha256: hash(card_text), node: 'c1' }, public_key: publicKey }
  alterReview(review)
  const calls = [], credentials = []
  const bytes = (...values) => Uint8Array.from(values).buffer
  const assertion = { type: assertionType, rawId: Buffer.from(credentialId, 'base64url'),
    response: { clientDataJSON: bytes(2), authenticatorData: bytes(3), signature: bytes(4), userHandle: null } }
  const environment = { document: { querySelector: selector => elements[selector], querySelectorAll: () => [card] },
    location: { origin: browserOrigin }, isSecureContext: secure, PublicKeyCredential: function () {}, btoa, atob, crypto: webcrypto,
    history: { replaceState(...args) { calls.push({ path: 'history', args }) } },
    navigator: { credentials: {
      async get(options) { credentials.push({ operation: 'get', options }); return assertion },
      async create(options) { credentials.push({ operation: 'create', options }); return { type: registrationType, rawId: bytes(1), response: { clientDataJSON: bytes(2), attestationObject: bytes(3) }, getClientExtensionResults: () => extensionResults } },
    } },
    async fetch(path, options) {
      calls.push({ path, options, body: JSON.parse(options.body) })
      const result = path === '/owner/review' ? review
        : path === '/owner/enroll/start' ? { enrollment_id: 'ceremony', public_key: { rp: { id: rpId }, challenge: publicKey.challenge, user: { id: 'AQ' }, attestation: 'none', authenticatorSelection: { userVerification: 'required' }, ...creation } }
          : path === '/owner/enroll/register' ? { enrollment_id: 'ceremony', public_key: publicKey } : { applied: true }
      return { ok: true, json: async () => ({ ok: true, result }) }
    } }
  return { environment, status, calls, credentials, text, authorization, reviewButton, approveButton, form, claim }
}
test('static owner script reviews exact bytes then asks the device and sends explicit WebAuthn proof', async () => {
  const b = browser()
  vm.runInNewContext(OWNER_PASSKEY_SCRIPT, { ...b.environment, URL, TextEncoder, Uint8Array, ArrayBuffer })
  await b.reviewButton.fire()
  assert.equal(b.credentials.length, 0)
  assert.equal(b.text.textContent, '{"node":"c1","content":"<script>model</script>"}')
  assert.equal(b.approveButton.hidden, false)
  await b.approveButton.fire()
  assert.equal(b.credentials.length, 1)
  assert.equal(b.credentials[0].options.publicKey.userVerification, 'required')
  const approval = b.calls.find(call => call.path === '/owner/approve')
  assert.deepEqual(JSON.parse(JSON.stringify(approval.body.owner_authorization_proof)), { version: 2, algorithm: 'webauthn-es256-sha256',
    authorization: { version: 2, card_sha256: hash(b.text.textContent), node: 'c1' },
    assertion: { kind: 'passkey', credential_id: 'AQ', client_data_json: 'Ag', authenticator_data: 'Aw', signature: 'BA', user_handle: null } })
  assert.equal(approval.options.credentials, 'omit'); assert.equal(approval.options.redirect, 'error')
  assert.equal(b.approveButton.hidden, true)
})
test('owner script creates then asserts possession before enrollment success', async () => {
  const b = browser({ mode: 'enroll' }); passkeyOwnerScript(b.environment)
  await b.form.fire('submit')
  assert.deepEqual(b.credentials.map(call => call.operation), ['create', 'get'])
  assert.deepEqual(b.calls.map(call => call.path), ['/owner/enroll/start', '/owner/enroll/register', '/owner/enroll/finish'])
  assert.equal(b.claim.value, ''); assert.equal(b.form.hidden, true)
  assert.equal(b.calls[1].body.registration.kind, 'passkey-registration')
  assert.equal(b.calls[2].body.assertion.kind, 'passkey')
})
const browserRefusals = [
  ['secure context', { secure: false }],
  ['exact browser origin', { browserOrigin: 'https://evil.example.test' }],
  ['authorization version', { alterReview: review => { review.owner_authorization.version = 1 } }],
  ['card digest', { alterReview: review => { review.card_text += ' ' } }],
  ['challenge digest', { alterReview: review => { review.public_key.challenge = 'AQ' } }],
  ['RP option', { alterReview: review => { review.public_key.rpId = 'evil.example.test' } }],
  ['required UV option', { alterReview: review => { review.public_key.userVerification = 'preferred' } }],
  ['credential inventory', { credentialId: 'Ag' }],
  ['assertion type', { assertionType: 'password' }],
  ['creation RP', { mode: 'enroll', creation: { rp: { id: 'evil.example.test' } } }],
  ['creation UV', { mode: 'enroll', creation: { authenticatorSelection: { userVerification: 'preferred' } } }],
  ['attestation policy', { mode: 'enroll', creation: { attestation: 'direct' } }],
  ['canonical options', { mode: 'enroll', creation: { challenge: 'AR' } }],
  ['registration type', { mode: 'enroll', registrationType: 'password' }],
  ['registration extensions', { mode: 'enroll', extensionResults: { appid: true } }],
]
async function refusesBrowser(run, settings) {
  const b = browser(settings); run(b.environment)
  if (settings.mode === 'enroll') await b.form.fire('submit')
  else { await b.reviewButton.fire(); await b.approveButton.fire() }
  assert.equal(b.calls.some(call => ['/owner/approve', '/owner/enroll/finish'].includes(call.path)), false)
  assert.match(b.status.textContent, /REFUSED|INVALID|CANCELLED/)
}
for (const [name, settings] of browserRefusals) test('owner browser refuses ' + name, () => refusesBrowser(passkeyOwnerScript, settings))

test('owner page source guard mutations are killed by the refusal regressions', async () => {
  const source = fs.readFileSync(sourceUrl, 'utf8').replace(/from '(\.\/[^']+)'/g, (_, relative) => `from '${new URL(relative, sourceUrl).href}'`)
  const mutations = [
    ['host', "if (req.headers.host !== configured.host) fail('OWNER_PASSKEY_HOST_REFUSED')", ''],
    ['origin', "if (req.headers.origin !== origin) fail('OWNER_PASSKEY_ORIGIN_REFUSED')", ''],
    ['fetch metadata', "req.headers['sec-fetch-site'] !== 'same-origin' || !['cors', 'same-origin'].includes(req.headers['sec-fetch-mode']) || !['', 'empty'].includes(req.headers['sec-fetch-dest'])", 'false'],
    ['fetch mode', "!['cors', 'same-origin'].includes(req.headers['sec-fetch-mode']) ||", ''],
    ['fetch destination', "|| !['', 'empty'].includes(req.headers['sec-fetch-dest'])", ''],
    ['content type', "if (req.headers['content-type'] !== 'application/json') fail('OWNER_PASSKEY_CONTENT_TYPE_REFUSED')", ''],
    ['exact fields', "if (!closed(body, enroll[url.pathname])) fail('OWNER_PASSKEY_FIELDS_REFUSED')", ''],
    ['body bound', 'bytes > 65536', 'bytes > 655360'],
    ['body timeout', "() => stop(new Error('OWNER_PASSKEY_BODY_TIMEOUT'))", '() => stop(null, {claim_code:"synthetic"})'],
    ['UTF-8', "new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))", "new TextDecoder('utf-8').decode(Buffer.concat(chunks))"],
    ['absolute URL', "!req.url.startsWith('/') ||", ''],
    ['query', "if (url.search) fail('OWNER_PASSKEY_PATH_REFUSED')\n      const body", 'const body'],
    ['GET fetch metadata', "(!['same-origin', 'none'].includes(req.headers['sec-fetch-site']) && !publicNavigation) ||", ''],
    ['script query', "if (url.search) fail('OWNER_PASSKEY_PATH_REFUSED')\n          return send", 'return send'],
  ]
  for (const [name, before, after] of mutations) {
    assert.ok(source.includes(before), name)
    const mutated = await import('data:text/javascript;base64,' + Buffer.from(source.replace(before, after)).toString('base64'))
    const gate = fakeGate(), { handler } = mutated.createPasskeyOwnerHandler(gate, { origin, rpId })
    const scenario = wireRefusals.find(([label]) => label === name)[1]
    const response = await request(handler, scenario)
    assert.throws(() => { assert.ok(response.status >= 400); assert.equal(gate.calls.length, 0) }, { name: 'AssertionError' }, name)
  }
  console.log(`SOURCE-ONLY owner passkey HTTP guard mutations: ${mutations.length}/${mutations.length} killed`)
})
test('owner page configuration, bearer and CSP mutations are killed', async () => {
  const source = fs.readFileSync(sourceUrl, 'utf8').replace(/from '(\.\/[^']+)'/g, (_, relative) => `from '${new URL(relative, sourceUrl).href}'`)
  const configurations = [
    ["configured.protocol !== 'https:' ||", '', { origin: 'http://owner.example.test', rpId }],
    ['configured.hostname !== rpId ||', '', { origin, rpId: 'example.test' }],
    ['/^\\d+(?:\\.\\d+){3}$/.test(rpId)', 'false', { origin: 'https://127.0.0.1', rpId: '127.0.0.1' }],
  ]
  for (const [before, after, options] of configurations) {
    assert.ok(source.includes(before))
    const mutated = await import('data:text/javascript;base64,' + Buffer.from(source.replace(before, after)).toString('base64'))
    assert.throws(() => assert.throws(() => mutated.createPasskeyOwnerHandler(fakeGate(), options), /OWNER_PASSKEY_ORIGIN_REQUIRED/), { name: 'AssertionError' })
  }
  const protections = [
    ["'x-frame-options': 'DENY'", "'x-frame-options': 'SAMEORIGIN'", response => assert.equal(response.headers['x-frame-options'], 'DENY')],
    ["frame-ancestors 'none'", "frame-ancestors 'self'", response => assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/)],
    ["script-src 'sha256-${scriptHash}'", "script-src 'self'", response => assert.match(response.headers['content-security-policy'], /script-src 'sha256-/)],
    ["style-src 'sha256-${hash(css)}'", "style-src 'unsafe-inline'", response => assert.doesNotMatch(response.headers['content-security-policy'], /unsafe-inline/)],
    ["if (!bearerOk(gate.owner, bearer, gate.now))", 'if (false)', response => assert.equal(response.status, 401)],
  ]
  for (const [before, after, check] of protections) {
    assert.ok(source.includes(before))
    const mutated = await import('data:text/javascript;base64,' + Buffer.from(source.replaceAll(before, after)).toString('base64'))
    const { handler } = mutated.createPasskeyOwnerHandler(fakeGate(), { origin, rpId })
    const response = await request(handler, { method: 'GET', url: '/owner/cards?bearer=' + (before.includes('bearerOk') ? 'wrong' : bearer) })
    assert.throws(() => check(response), { name: 'AssertionError' })
  }
  console.log('SOURCE-ONLY owner passkey profile, bearer and CSP mutations: 8/8 killed')
})
test('owner page total body deadline survives active input; deleting the timer is killed', async () => {
  async function check(source) {
    const timers = []
    const scheduled = (callback, delay) => { const timer = { callback, delay, cleared: false, unref() {} }; timers.push(timer); return timer }
    const clear = timer => { if (timer) timer.cleared = true }
    const compiled = vm.runInThisContext('(function(createHash,bearerOk,esc,OWNER_PASSKEY_SCRIPT,setTimeout,clearTimeout){return (' + source + ')})')
    const gate = fakeGate(), factory = compiled(createHash, bearerOk, value => value, OWNER_PASSKEY_SCRIPT, scheduled, clear)
    const { handler } = factory(gate, { origin, rpId }), req = new EventEmitter()
    Object.assign(req, { method: 'POST', url: '/owner/enroll/start', headers: { host: rpId, origin, 'sec-fetch-site': 'same-origin',
      'sec-fetch-mode': 'cors', 'sec-fetch-dest': '', 'content-type': 'application/json' }, setTimeout() {}, destroy() {} })
    const response = { writeHead(status) { this.status = status }, end() {} }
    const work = handler(req, response)
    req.emit('data', Buffer.from('{"claim_code":"synthetic"}'))
    for (const timer of timers) if (!timer.cleared) { assert.equal(timer.delay, 10000); timer.callback() }
    req.emit('end')
    await work
    assert.equal(response.status, 403); assert.equal(gate.calls.length, 0)
  }
  const source = createPasskeyOwnerHandler.toString()
  await check(source)
  const guard = 'timer = setTimeout(timedOut, 10000); timer.unref?.()'
  assert.ok(source.includes(guard))
  await assert.rejects(check(source.replace(guard, '')), { name: 'AssertionError' })
  console.log('SOURCE-ONLY owner passkey total body deadline mutation: 1/1 killed')
})
test('owner script source guard mutations are killed by the refusal regressions', async () => {
  const source = passkeyOwnerScript.toString()
  const mutations = [
    ['secure context', 'environment.isSecureContext !== true ||', ''],
    ['exact browser origin', 'location.origin !== profile.origin ||', ''],
    ['authorization version', 'authorization?.version !== 2 ||', ''],
    ['card digest', "if (hex !== authorization.card_sha256) error('OWNER_PASSKEY_CARD_DIGEST_REFUSED')", ''],
    ['challenge digest', "if (options?.challenge !== encode(challenge)) error('OWNER_PASSKEY_CHALLENGE_REFUSED')", ''],
    ['RP option', 'publicKey.rpId !== profile.rpId ||', ''],
    ['required UV option', "publicKey.userVerification !== 'required' ||", ''],
    ['credential inventory', "if (!options.allowCredentials.some(allowed => allowed.id === credential_id)) error('OWNER_PASSKEY_CREDENTIAL_REFUSED')", ''],
    ['assertion type', "credential?.type !== 'public-key' ||", ''],
    ['creation RP', 'publicKey.rp?.id !== profile.rpId ||', ''],
    ['creation UV', "publicKey.authenticatorSelection?.userVerification !== 'required'", 'false'],
    ['attestation policy', "publicKey.attestation !== 'none' ||", ''],
    ['canonical options', "if (encode(bytes) !== value) error('OWNER_PASSKEY_OPTIONS_INVALID')", ''],
    ['registration type', "credential?.type !== 'public-key' || !credential.response) error('OWNER_PASSKEY_REGISTRATION_CANCELLED')", "!credential.response) error('OWNER_PASSKEY_REGISTRATION_CANCELLED')"],
    ['registration extensions', "if (Object.keys(extensions).length !== 0) error('OWNER_PASSKEY_REGISTRATION_EXTENSIONS_REFUSED')", ''],
  ]
  for (const [name, before, after] of mutations) {
    assert.ok(source.includes(before), name)
    const mutated = vm.runInThisContext('(' + source.replace(before, after) + ')')
    await assert.rejects(refusesBrowser(mutated, browserRefusals.find(([label]) => label === name)[1]), { name: 'AssertionError' }, name)
  }
  console.log(`SOURCE-ONLY owner passkey browser guard mutations: ${mutations.length}/${mutations.length} killed`)
})
