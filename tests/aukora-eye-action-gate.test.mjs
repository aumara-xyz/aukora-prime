// SPDX-License-Identifier: AGPL-3.0-or-later
// The action gate refuses app capture before the eye tool can return private pixels.
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import test from 'node:test'
import { createGuard, readSettings } from '../plugins/aukora-action-gate/lib/index.mjs'
import { decideCall } from '../plugins/aukora-action-gate/lib/kernel.mjs'
import * as eye from '../plugins/aukora-eye/lib/index.js'

const policyUrl = new URL('../plugins/aukora-action-gate/lib/policy.mjs', import.meta.url)
const mutant = process.env.EYE_ACTION_GATE_MUTANT
assert.ok(mutant === undefined || ['overlay-entry', 'default-entry', 'overlay-family', 'default-family'].includes(mutant), 'known mutation only')
let source = readFileSync(policyUrl, 'utf8')
if (mutant === 'default-entry' || mutant === 'default-family') {
  const marker = 'export const DEFAULT_ALLOW_TOOLS = Object.freeze([\n'
  const name = mutant === 'default-entry' ? 'aukora_see' : 'aukora_see*'
  const changed = source.replace(marker, `${marker}  '${name}',\n`)
  assert.notEqual(changed, source, 'default capture permission mutation applied')
  source = changed.replace(/from (['"])(\.[^'"]+)\1/gu,
    (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, policyUrl).href)}`)
}
const { createPolicy } = await import(mutant === 'default-entry' || mutant === 'default-family'
  ? `data:text/javascript;base64,${Buffer.from(source).toString('base64')}` : policyUrl.href)
let overlay = readFileSync(new URL('../overlays/action-gate.patch.yml', import.meta.url), 'utf8')
if (mutant === 'overlay-entry' || mutant === 'overlay-family') {
  const marker = '        allowTools:\n'
  const name = mutant === 'overlay-entry' ? 'aukora_see' : 'aukora_see*'
  const changed = overlay.replace(marker, `${marker}          - ${name}\n`)
  assert.notEqual(changed, overlay, 'overlay capture permission mutation applied')
  overlay = changed
}
const allowTools = overlay.split('        allowTools:\n')[1].split('        repoRoots:')[0]
  .split('\n').flatMap(line => /^          - (\S+)$/u.exec(line)?.slice(1) ?? [])

function fixture(t) {
  const base = fileURLToPath(new URL('../.runtime/', import.meta.url))
  mkdirSync(base, { recursive: true })
  const root = mkdtempSync(join(base, 'eye-action-gate-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const workspace = join(root, 'workspace')
  mkdirSync(workspace)
  const settings = readSettings({
    home: root, supportRoot: join(root, 'support'), dshHome: join(root, 'state', 'home'),
    auraDir: join(root, 'aura'), repoRoots: [], releaseRoots: [], extraWritableRoots: [],
    networkAllow: [], allowLoopback: false, defaultWorkspace: workspace,
  })
  return { root, workspace, settings }
}

test('fallback policy refuses the eye tool and action aliases through the kernel', t => {
  const { workspace, settings } = fixture(t)
  const policy = createPolicy(settings)
  for (const tool of [eye.SEE_TOOL_NAME, 'aukora_see_click', 'aukora_eye_act', 'aukora_see_upload']) {
    const call = { tool, args: { scale: 1 }, workspace }
    assert.equal(policy.judge(call).rule, 'authority:tool-not-approved', tool)
    assert.equal(decideCall(policy.classify(call), 'a'.repeat(64)).decision, 'deny', tool)
  }
})

test('deployed allow-list refuses the exact eye name and writes a denial receipt', t => {
  const { root, workspace, settings } = fixture(t)
  const guard = createGuard({ settings: { ...settings, allowTools } })
  const exec = { name: eye.SEE_TOOL_NAME, arguments: { scale: 1 }, agent: { id: 'synthetic-agent', session: { header: { cwd: workspace } } } }
  assert.match(guard(exec), /authority:tool-not-approved/u)
  const receipt = JSON.parse(readFileSync(join(root, 'aura', 'aura.jsonl'), 'utf8').trim())
  assert.equal(receipt.tool, 'aukora_see')
  assert.equal(receipt.decision, 'deny')
  assert.equal(receipt.kernelCode, 'policy_no_match')
  assert.match(guard({ ...exec, name: 'aukora_see_click' }), /authority:tool-not-approved/u)
})

test('the mounted eye is refused before fetching pixels or saving an image attachment', async t => {
  const { root, workspace, settings } = fixture(t)
  let tool, captures = 0, attachments = 0
  eye.apply({ inject: (_names, mount) => mount({
    get: () => ({ saveImage: async () => { attachments++; return { attachmentId: 'synthetic-image' } } }),
    tools: { register: value => { tool = value } },
  }) }, { stateDir: join(root, 'captures') })
  assert.deepEqual(Object.keys(tool.parameters).sort(), ['height', 'note', 'scale', 'width', 'x', 'y'])
  const previous = { AUKORA_EYE_URL: process.env.AUKORA_EYE_URL, AUKORA_EYE_TOKEN: process.env.AUKORA_EYE_TOKEN }
  Object.assign(process.env, { AUKORA_EYE_URL: 'http://127.0.0.1:12345', AUKORA_EYE_TOKEN: 'synthetic-token' })
  t.after(() => { for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value } })
  t.mock.method(globalThis, 'fetch', async () => { captures++; throw new Error('capture body must not run') })
  const exec = { name: tool.name, arguments: { scale: 1 }, agent: { id: 'synthetic-agent', session: { id: 'synthetic-session', header: { cwd: workspace } } } }
  const refusal = createGuard({ settings: { ...settings, allowTools }, definitionOf: () => tool })(exec)
  if (refusal === undefined) await tool.execute(exec.arguments, exec)
  assert.match(refusal, /authority:tool-not-approved/u)
  assert.equal(captures, 0)
  assert.equal(attachments, 0)
})
