// SPDX-License-Identifier: AGPL-3.0-or-later
// Native presentation completion does not clear the desktop's private-pixel latch.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createPublicKey } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const file = fileURLToPath(import.meta.url)
const root = fileURLToPath(new URL('..', import.meta.url))
const caseAt = process.argv.indexOf('--case')
const scenario = caseAt < 0 ? null : process.argv[caseAt + 1]
const outcome = caseAt < 0 ? null : process.argv[caseAt + 2]
const mutant = process.env.DESKTOP_OWNER_PRIVACY_MUTANT
const mutations = {
  binding: ['owner-key-bridge.mjs',
    "privateSurface('owner', () => presentOwnerAction(Object.freeze({ wire, preview: ownerKeyPreview(request) })))",
    'presentOwnerAction(Object.freeze({ wire, preview: ownerKeyPreview(request) }))'],
  authorization: ['owner-key-bridge.mjs',
    "privateSurface('owner', () => presentOwnerAction(Object.freeze({ kind: 'owner-authorization', wire,\n          preview: ownerAuthorizationPreview(authorization) })))",
    "presentOwnerAction(Object.freeze({ kind: 'owner-authorization', wire,\n          preview: ownerAuthorizationPreview(authorization) }))"],
  touchid: ['aumlok-presence.mjs',
    "privateSurface('touchid', () => run(['sign', digest, oneLine(operation?.kind, 64) || 'operation',\n              oneLine(operation?.reason, 160) || `digest ${digest.slice(0, 16)}`], timeout))",
    "run(['sign', digest, oneLine(operation?.kind, 64) || 'operation',\n              oneLine(operation?.reason, 160) || `digest ${digest.slice(0, 16)}`], timeout)"],
  'native-owner': ['eye.mjs', "const owner = paintOwner ?? (kind === 'lane' ? surface : null)",
    'const owner = paintOwner ?? surface'],
}

if (mutant !== undefined) {
  assert.ok(scenario !== null && Object.hasOwn(mutations, mutant), 'known child-only mutation')
  const [basename, before, after] = mutations[mutant]
  registerHooks({ load(url, context, next) {
    const result = next(url, context)
    if (!url.endsWith(`/apps/aukora-desktop/${basename}`)) return result
    const source = typeof result.source === 'string' ? result.source : Buffer.from(result.source).toString('utf8')
    assert.equal(source.split(before).length, 2, 'one actual production wrapper must be removed')
    return { ...result, source: source.replace(before, after) }
  } })
}

async function runCase() {
  assert.ok(Object.hasOwn(mutations, scenario) && ['cancelled', 'rejected', 'forged'].includes(outcome))
  const { createPrivateSurfaceFence, getPrivateSurfaceState } = await import('../apps/aukora-desktop/eye.mjs')
  if (scenario === 'native-owner') {
    for (const kind of ['owner', 'touchid']) {
      const fence = createPrivateSurfaceFence(), reply = new EventEmitter()
      reply.isDestroyed = () => true
      fence.privateSurface(kind, () => reply)
      reply.emit('closed')
      assert.equal(fence.getPrivateSurfaceState().code, 'eye.approval-open',
        'native return object must not witness window destruction')
    }
    return
  }
  assert.equal(getPrivateSurfaceState().code, null, 'each producer starts in a fresh process')
  let finish, fail, inside
  const present = () => {
    inside = getPrivateSurfaceState()
    return new Promise((resolve, reject) => { finish = resolve; fail = reject })
  }
  let pending, cleanup = () => {}
  if (scenario === 'touchid') {
    const base = join(root, '.runtime')
    mkdirSync(base, { recursive: true, mode: 0o700 })
    const support = mkdtempSync(join(base, 'desktop-owner-privacy-'))
    cleanup = () => rmSync(support, { recursive: true, force: true })
    const directory = join(support, 'state/home/aumlok-presence')
    mkdirSync(directory, { recursive: true, mode: 0o700 })
    // RFC6979 A.2.5 public point only; the helper and biometric UI are synthetic.
    const publicKey = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
      x: Buffer.from('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6', 'hex').toString('base64url'),
      y: Buffer.from('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299', 'hex').toString('base64url') } })
    writeFileSync(join(directory, 'presence-public.pem'), publicKey.export({ format: 'pem', type: 'spki' }), { mode: 0o600 })
    const platform = Object.getOwnPropertyDescriptor(process, 'platform')
    Object.defineProperty(process, 'platform', { ...platform, value: 'darwin' })
    const { createDesktopPresence } = await import('../apps/aukora-desktop/aumlok-presence.mjs')
    pending = createDesktopPresence(support, { run: present }).sign(Buffer.from('synthetic approval'), 500,
      { kind: 'synthetic', reason: 'synthetic owner question' })
    const remove = cleanup
    cleanup = () => { Object.defineProperty(process, 'platform', platform); remove() }
  } else {
    const { createOwnerKeyBridge, createOwnerAuthorizationBridge } = await import('../apps/aukora-desktop/owner-key-bridge.mjs')
    const common = { owner_subject: `aukora:1:${'1'.repeat(64)}`, owner_root_id: '2'.repeat(64) }
    pending = scenario === 'binding'
      ? createOwnerKeyBridge({ expectations: {}, presentOwnerAction: present }).requestBinding({ ...common,
        version: 1, action: 'bind-scoped-nostr', audience: 'aukora:aura', scope: 'owner-recipient',
        request_id: '3'.repeat(64), nonce: '4'.repeat(64), scoped_nostr_pubkey_hex: '5'.repeat(64),
        previous_binding_digest: null, previous_nostr_pubkey_hex: null, epoch: 1, issued_at: 100, expires_at: 200 })
      : createOwnerAuthorizationBridge({ expectations: {}, presentOwnerAction: present }).requestAuthorization({ ...common,
        version: 1, kind: 'aukora-owner-authorization/v1', operation: 'change',
        proposal_id: '01234567-89ab-4cde-8123-456789abcdef', target: 'plugins/auma-theme/theme.json',
        before_sha256: 'a'.repeat(64), after_sha256: 'b'.repeat(64), gate: 'c'.repeat(64), challenge: 'd'.repeat(64),
        issued_at_ms: 100000, expires_at_ms: 200000, owner_epoch: 1 })
  }
  try {
    assert.equal(typeof finish, 'function', 'the actual native producer must run')
    assert.equal(inside.code, 'eye.approval-open', 'private surface must latch before native presentation')
    assert.equal(inside.generation, 1n)
    if (outcome === 'rejected') fail(new Error('synthetic native failure'))
    else finish(scenario === 'touchid' ? { stdout: '' } : { status: 'cancelled' })
    await pending
    assert.equal(getPrivateSurfaceState().code, 'eye.approval-open', 'settlement must not claim native pixels disappeared')
    assert.equal(getPrivateSurfaceState().generation, inside.generation)
  } finally { cleanup() }
}

if (scenario !== null) {
  const umask = process.umask(0o002)
  try { await runCase() } finally { process.umask(umask) }
} else {
  const run = (kind, result, mutation) => spawnSync(process.execPath, [file, '--case', kind, result], {
    cwd: root, encoding: 'utf8', timeout: 10000,
    env: { ...process.env, ...(mutation === undefined ? {} : { DESKTOP_OWNER_PRIVACY_MUTANT: mutation }) },
  })
  for (const kind of ['binding', 'authorization', 'touchid']) for (const result of ['cancelled', 'rejected']) {
    test(`${kind} stays private after native ${result}`, () => {
      const child = run(kind, result)
      assert.equal(child.status, 0, `${child.stdout}${child.stderr}`)
    })
  }
  test('native return objects cannot forge a window destruction witness', () => {
    const child = run('native-owner', 'forged')
    assert.equal(child.status, 0, `${child.stdout}${child.stderr}`)
  })
  test('removing each production presentation latch fails the same sequence', () => {
    for (const kind of Object.keys(mutations)) {
      const child = run(kind, kind === 'native-owner' ? 'forged' : 'cancelled', kind)
      assert.equal(child.status, 1, `${child.stdout}${child.stderr}`)
      assert.match(child.stderr, kind === 'native-owner'
        ? /native return object must not witness window destruction/u
        : /private surface must latch before native presentation/u)
    }
    console.log('PASS desktop owner privacy mutations: 4/4 killed (synthetic native callbacks, umask 002)')
  })
}
