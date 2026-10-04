/**
 * L3 memory on Linux (2026-10-04): the owner identity, the door's authentication and the file fence around both.
 *
 * Fails if: Linux accepts the placeholder subject or a mismatched one; the overlay reader takes another plugin's
 * subject; the Viking door answers without its Bearer credential; the credential reader accepts a shared file;
 * or Auma's file tools can read the owner config or the OpenViking home. No real identity or key is used.
 */
import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { resolveMemoryIdentity, readKiraDeploymentOverlay, UNLINKED_MEMORY_SUBJECT } from '../plugins/aukora-kira/lib/memory-identity.mjs'
import { createVikingDoor } from '../plugins/aukora-kira/lib/viking-door.mjs'
import { readDoorCredential } from '../scripts/kira/viking-auth.mjs'
import { readSettings } from '../plugins/aukora-action-gate/lib/index.mjs'
import { createPolicy } from '../plugins/aukora-action-gate/lib/policy.mjs'

let n = 0
const ok = (cond, label) => { assert.ok(cond, label); n++ }
const throwsCode = (fn, code, label) => {
  let caught
  try { fn() } catch (error) { caught = error }
  ok(caught !== undefined && String(caught.code ?? caught.message).includes(code), `${label}: expected ${code}, got ${caught?.code ?? caught?.message ?? 'no error'}`)
}

const SUBJECT = `aukora:1:${'ab'.repeat(32)}`
const OTHER = `aukora:1:${'cd'.repeat(32)}`
const overlay = (subject, stateDir = '/srv/state/home/kira-memory') => `- id: aukora-board\n  config:\n    memoryOwner:\n      subject: ${OTHER}\n- id: aukora-kira\n  config:\n    retrieval: lexical\n    memoryOwner:\n      stateDir: ${stateDir}\n      subject: ${subject}\n      permittedPrivacy: [local]\n`
const reader = text => () => text
const missing = () => { const e = new Error('nope'); e.code = 'ENOENT'; throw e }
const linux = { platform: 'linux', env: {} }

// ── IDENTITY ────────────────────────────────────────────────────────────────────────────────────────────────
throwsCode(() => resolveMemoryIdentity({ ...linux, stateDir: '/srv/k', subject: UNLINKED_MEMORY_SUBJECT, installed: true, allowLegacyPlaceholder: true, readText: missing }),
  'memory.identity:field-missing', 'linux placeholder with no overlay')
throwsCode(() => resolveMemoryIdentity({ ...linux, stateDir: '/srv/k', subject: UNLINKED_MEMORY_SUBJECT, allowLegacyPlaceholder: true }),
  'memory.identity:field-missing', 'linux placeholder with no state root')
const resolved = resolveMemoryIdentity({ ...linux, supportRoot: '/srv/state', subject: UNLINKED_MEMORY_SUBJECT, stateDir: '/srv/state/home/kira-memory', allowLegacyPlaceholder: true, readText: reader(overlay(SUBJECT)) })
ok(resolved.subject === SUBJECT && resolved.stateDir === '/srv/state/home/kira-memory', 'overlay supplies the real subject over the placeholder')
throwsCode(() => resolveMemoryIdentity({ ...linux, supportRoot: '/srv/state', subject: OTHER, stateDir: '/srv/state/home/kira-memory', readText: reader(overlay(SUBJECT)) }),
  'memory.identity:field-mismatch', 'explicit subject disagreeing with the overlay')
throwsCode(() => resolveMemoryIdentity({ ...linux, supportRoot: '/srv/state', stateDir: '/elsewhere', subject: SUBJECT, readText: reader(overlay(SUBJECT)) }),
  'memory.identity:field-mismatch', 'explicit stateDir disagreeing with the overlay')
throwsCode(() => resolveMemoryIdentity({ ...linux, supportRoot: '/srv/state', stateDir: '/srv/state/home/kira-memory', readText: reader(overlay('aumlok:subject:owner')) }),
  'memory.identity:field-invalid', 'overlay carrying the placeholder')
throwsCode(() => resolveMemoryIdentity({ ...linux, stateDir: '/srv/k', subject: 'owner' }), 'memory.identity:field-invalid', 'non-canonical subject')
ok(readKiraDeploymentOverlay(overlay(SUBJECT)).subject === SUBJECT, "overlay reader takes aukora-kira's subject, not another row's")

// ── CREDENTIAL FILE ─────────────────────────────────────────────────────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), 'aukora-l3-'))
const keyFile = join(dir, 'viking-door.key')
writeFileSync(keyFile, 'fixture-door-token-0123456789\n', { mode: 0o600 })
ok(readDoorCredential(keyFile) === 'fixture-door-token-0123456789', 'private credential file is read')
chmodSync(keyFile, 0o644)
throwsCode(() => readDoorCredential(keyFile), 'viking.door:credential-file-unsafe', 'shared credential file refused')
throwsCode(() => readDoorCredential('relative.key'), 'viking.door:credential-file-missing', 'relative credential path refused')

// ── DOOR AUTHENTICATION ─────────────────────────────────────────────────────────────────────────────────────
let calls = 0
const memory = {
  recall: async () => { calls++; return { notes: [], method: 'lexical-bm25-bigram', semantic: { available: false } } },
  remember: async () => { calls++; return { remembered: 1, ids: ['x'] } },
  retry: async () => {},
}
throwsCode(() => createVikingDoor({ memory, port: 0 }), 'viking.door:credential-missing', 'door refuses to start without a credential')
const door = createVikingDoor({ memory, authToken: 'fixture-door-token-0123456789', port: 0 })
const { port } = await door.listen()
const ask = headers => fetch(`http://127.0.0.1:${port}/recall`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-aukora-memory-version': '2', ...headers }, body: JSON.stringify({ q: 'sister' }) })
ok((await ask({})).status === 401, 'no Bearer: 401')
ok((await ask({ authorization: 'Bearer wrong-token' })).status === 401, 'wrong Bearer: 401')
ok(calls === 0, 'memory untouched by unauthenticated requests')
ok((await ask({ authorization: 'Bearer fixture-door-token-0123456789' })).status === 200, 'right Bearer: 200')
ok(calls === 1, 'memory reached only after authentication')
await door.close()

// ── THE FILE FENCE AROUND L3 ────────────────────────────────────────────────────────────────────────────────
const state = join(dir, 'genesis', 'state'); const dshHome = join(state, 'home'); const workspace = join(state, 'workspace')
for (const d of [workspace, join(dshHome, 'aura-actions')]) mkdirSync(d, { recursive: true })
for (const confineReads of [true, false]) {
  const policy = createPolicy(readSettings({ auraDir: join(dshHome, 'aura-actions'), dshHome, home: dir, releaseRoots: [], defaultWorkspace: workspace, confineReads }))
  for (const [path, rule] of [
    [join(state, 'kira-deployment-overlay.patch.yml'), 'host-secret:kira-owner-config'],
    [join(dshHome, 'openviking', 'aukora-bridge.json'), 'host-secret:openviking-home'],
    [join(dshHome, 'openviking', 'ov.conf'), 'host-secret:openviking-home'],
    [join(dshHome, 'openviking', 'root.key'), 'key-material:openviking-root-key'],
    ['/var/lib/aukora-host/openviking/data/x', 'host-secret:openviking-home'],
    [join(dir, 'viking-door.key'), 'host-secret:viking-door-key'],
  ]) {
    for (const tool of ['read', 'write']) {
      const v = policy.judge({ tool, args: { file_path: path }, workspace })
      ok(v.decision === 'deny' && v.rule === rule, `${tool} ${path} (confineReads=${confineReads}): expected ${rule}, got ${v.decision} ${v.rule}`)
    }
  }
}
console.log(`aukora-l3-memory-linux: ${n}/${n} PASS`)
