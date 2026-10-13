// SPDX-License-Identifier: AGPL-3.0-or-later
// Public voice upgrades retain harness admission and exact browser-origin checks.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { spawnSync } from 'node:child_process'
import vm from 'node:vm'

if (vm.SourceTextModule === undefined) {
  const again = spawnSync(process.execPath, ['--experimental-vm-modules', ...process.execArgv, ...process.argv.slice(1)], { stdio: 'inherit' })
  process.exit(again.status ?? 1)
}

const sourceUrl = new URL('../plugins/aukora-face/apps/src/auma-live/voice.ts', import.meta.url)
const source = readFileSync(sourceUrl, 'utf8')
const publicHost = 'c1.example.test'
const publicOrigin = `https://${publicHost}`

async function load(input = source) {
  const context = vm.createContext({ URL, Buffer, console })
  const module = new vm.SourceTextModule(stripTypeScriptTypes(input, { mode: 'transform' }), {
    context, identifier: sourceUrl.href,
  })
  await module.link(specifier => {
    const exports = specifier === 'ws'
      ? { default: class {}, WebSocketServer: class {} }
      : specifier === './voice-sidecar.ts'
        ? { VoiceSidecarSupervisor: class {}, voiceEnvironment() {}, voiceLogger() {}, VOICE_LOG_PREFIX: 'voice' }
        : undefined
    assert.ok(exports, `unexpected import: ${specifier}`)
    return new vm.SyntheticModule(Object.keys(exports), function () {
      for (const [name, value] of Object.entries(exports)) this.setExport(name, value)
    }, { context })
  })
  await module.evaluate()
  return module.namespace.voiceUpgradeRefusal
}

function request({ host = publicHost, origin = publicOrigin, cookie = 'dsh-auth=valid', remoteAddress = '127.0.0.1' } = {}) {
  return { headers: { host, ...(origin === null ? {} : { origin }), ...(cookie === null ? {} : { cookie }) }, socket: { remoteAddress } }
}

function harness(req) {
  if (req.headers.host !== publicHost && !req.headers.host?.startsWith('127.0.0.1:')) return 403
  if (req.headers.cookie !== 'dsh-auth=valid') return 401
  if (req.headers.origin !== undefined) {
    const expected = req.headers.host === publicHost ? publicOrigin : `http://${req.headers.host}`
    if (req.headers.origin !== expected) return 403
  }
  return undefined
}

async function verdicts(input = source) {
  const guard = await load(input)
  return {
    public: guard(request(), harness),
    wrongHost: guard(request({ host: 'other.example.test', origin: 'https://other.example.test' }), harness),
    crossSite: guard(request({ origin: 'https://other.example.test' }), harness),
    crossSiteAfterAdmission: guard(request({ origin: 'https://other.example.test' }), () => undefined),
    missingCookie: guard(request({ cookie: null }), harness),
    direct: guard(request({ remoteAddress: '203.0.113.7' }), harness),
    missingPublicOrigin: guard(request({ origin: null }), harness),
    insecurePublicOrigin: guard(request({ origin: `http://${publicHost}` }), () => undefined),
    loopback: guard(request({ host: '127.0.0.1:18735', origin: null }), harness),
    loopbackOrigin: guard(request({ host: '127.0.0.1:18735', origin: 'http://127.0.0.1:18735' }), harness),
  }
}

function check(rows) {
  assert.equal(rows.public, undefined)
  assert.equal(`${rows.wrongHost?.status}:${rows.wrongHost?.code}`, '403:voice-harness-refused')
  assert.equal(`${rows.crossSite?.status}:${rows.crossSite?.code}`, '403:voice-harness-refused')
  assert.equal(`${rows.crossSiteAfterAdmission?.status}:${rows.crossSiteAfterAdmission?.code}`, '403:voice-carrier-refused')
  assert.equal(`${rows.missingCookie?.status}:${rows.missingCookie?.code}`, '401:voice-auth-required')
  assert.equal(`${rows.direct?.status}:${rows.direct?.code}`, '403:voice-carrier-refused')
  assert.equal(`${rows.missingPublicOrigin?.status}:${rows.missingPublicOrigin?.code}`, '403:voice-carrier-refused')
  assert.equal(`${rows.insecurePublicOrigin?.status}:${rows.insecurePublicOrigin?.code}`, '403:voice-carrier-refused')
  assert.equal(rows.loopback, undefined)
  assert.equal(rows.loopbackOrigin, undefined)
}

test('admitted public voice and loopback development work; other authority paths refuse', async () => {
  check(await verdicts())
})

test('voice authority mutations are killed', async t => {
  const mutations = [
    ['harness admission', 'if (rejection !== undefined) {', 'if (false) {'],
    ['loopback carrier', 'if (!isLoopbackAddress(req.socket.remoteAddress)) {', 'if (false) {'],
    ['public Origin required', "return loopback ? undefined : { status: 403, code: 'voice-carrier-refused' }", 'return undefined'],
    ['exact same origin', "if (!protocolAccepted || parsed.origin !== origin || parsed.host !== authority) {", 'if (!protocolAccepted) {'],
    ['public HTTPS', ": parsed.protocol === 'https:'", ': true'],
  ]
  let killed = 0
  for (const [label, before, after] of mutations) {
    assert.ok(source.includes(before), `mutation anchor missing: ${label}`)
    const rows = await verdicts(source.replace(before, after))
    assert.throws(() => check(rows), assert.AssertionError, `surviving mutant: ${label}`)
    killed++
    t.diagnostic(`killed ${label}`)
  }
  console.log(`MUTATION public-voice-authority: ${killed}/${mutations.length} killed`)
})
