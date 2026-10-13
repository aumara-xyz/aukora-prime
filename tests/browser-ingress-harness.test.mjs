// SPDX-License-Identifier: AGPL-3.0-or-later
// In-memory pinned-harness trust and public-browser cookie checks; no listener or browser.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'

const root = fileURLToPath(new URL('../', import.meta.url))
const archive = join(root, 'vendor/dsh-source.tar.gz')
const patchFile = 'patches/public-browser-secure-cookie.patch.json'
const pin = JSON.parse(readFileSync(join(root, 'upstream-dsh.json'), 'utf8'))
const patchBytes = readFileSync(join(root, patchFile))
const patch = JSON.parse(patchBytes)
const sha256 = value => createHash('sha256').update(value).digest('hex')
const listing = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }).trim().split('\n')

function pinnedSource(relative) {
  const entry = listing.find(name => name.endsWith('/' + relative))
  assert.ok(entry, `pinned source missing ${relative}`)
  return execFileSync('tar', ['-xOf', archive, entry], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 })
}

function applyPatch(relative, source, omit = -1) {
  let result = source
  for (const [index, edit] of patch.edits.entries()) {
    if (edit.path !== relative || index === omit) continue
    assert.equal(result.split(edit.find).length - 1, edit.occurrences ?? 1, `exact patch edit ${index}`)
    result = result.replaceAll(edit.find, edit.replace)
  }
  return result
}

function loadTrust(source) {
  const javascript = stripTypeScriptTypes(source
    .replace(/^import .*$/gmu, '')
    .replaceAll('export function ', 'function '))
  const isLoopbackHostname = hostname => hostname === 'localhost' || hostname === '[::1]'
    || /^127(?:\.\d{1,3}){3}$/u.test(hostname)
  return vm.runInNewContext(`${javascript}\n;({ assertTrustedAuthority, isTrustedApiRequest })`,
    { URL, Headers, isLoopbackHostname })
}

function sessionCookie(source) {
  const declaration = source.match(/function sessionCookie\([^]*?^\}/mu)?.[0]
  assert.ok(declaration, 'patched sessionCookie declaration')
  const javascript = stripTypeScriptTypes(declaration)
  const isLoopbackHostname = hostname => hostname === 'localhost' || hostname === '[::1]'
    || /^127(?:\.\d{1,3}){3}$/u.test(hostname)
  return vm.runInNewContext(`${javascript}\n;sessionCookie`, { URL, Date, String, isLoopbackHostname })
}

test('pinned harness public authority accepts same-origin API and refuses hostile HTTP and WebSocket facts', t => {
  assert.equal(sha256(readFileSync(archive)), pin.archiveSha256)
  const trust = loadTrust(pinnedSource('packages/client/connection/src/api-request-trust.ts'))
  const publicHost = 'node.example.test'
  const request = headers => ({ headers })
  assert.equal(trust.isTrustedApiRequest(request({ host: publicHost, origin: `https://${publicHost}` }), [publicHost]), true,
    'matching public Host and Origin reaches authenticated API handling')
  assert.equal(trust.isTrustedApiRequest(request({ host: 'wrong.example.test', origin: 'https://wrong.example.test' }), [publicHost]), false,
    'wrong Host is refused')
  assert.equal(trust.isTrustedApiRequest(request({ host: publicHost, origin: `https://${publicHost}`, 'sec-fetch-site': 'cross-site' }), [publicHost]), false,
    'cross-site Fetch is refused')
  assert.equal(trust.isTrustedApiRequest(request({ host: publicHost, origin: 'https://wrong.example.test',
    connection: 'Upgrade', upgrade: 'websocket' }), [publicHost]), false,
  'the WebSocket upgrade route uses this same request rejection and refuses cross-origin Origin')
  t.diagnostic('PASS pinned harness trust probe: public API accepted; wrong Host, cross-site Fetch and cross-origin WebSocket refused')
})

test('pinned patch marks public authority cookies Secure and its removal fails the behavior', t => {
  const declaration = pin.localPatches.find(entry => entry.file === patchFile)
  assert.equal(declaration?.sha256, sha256(patchBytes))
  assert.equal(declaration?.reason, patch.reason)
  const relative = 'packages/client/connection/src/browser-auth.ts'
  const pristine = pinnedSource(relative)
  const patched = applyPatch(relative, pristine)
  for (const expectation of patch.expectAfterApply.filter(row => row.path === relative)) {
    assert.ok(patched.includes(expectation.contains), expectation.contains)
  }
  const cookie = sessionCookie(patched)
  const publicCookie = cookie('node.example.test', 'dsh-auth-fixture', 'value', 2_000, 1)
  const loopbackCookie = cookie('127.0.0.1:18735', 'dsh-auth-fixture', 'value', 2_000, 1)
  assert.match(publicCookie, /; Secure$/u)
  assert.match(publicCookie, /; HttpOnly; SameSite=Strict; Secure$/u)
  assert.doesNotMatch(loopbackCookie, /; Secure/u)

  const guard = "const secure = isLoopbackHostname(hostname) ? '' : '; Secure'"
  assert.equal(patched.split(guard).length, 2)
  const mutant = sessionCookie(patched.replace(guard, "const secure = ''"))
  assert.throws(() => assert.match(mutant('node.example.test', 'n', 'v', 2_000, 1), /; Secure$/u), assert.AssertionError)

  const pristineDeclaration = pristine.match(/function sessionCookie\([^]*?^\}/mu)?.[0]
  assert.ok(pristineDeclaration)
  const pristineCookie = vm.runInNewContext(`${stripTypeScriptTypes(pristineDeclaration)}\n;sessionCookie`, { Date, String })
  assert.throws(() => assert.match(pristineCookie('n', 'v', 2_000, 1), /; Secure$/u), assert.AssertionError,
    'removing the patch restores the insecure public cookie')
  t.diagnostic('MUTATION public Secure-cookie guard: 2/2 killed (guard removal and full patch removal)')
})
