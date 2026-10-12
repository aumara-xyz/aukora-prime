// SPDX-License-Identifier: AGPL-3.0-or-later
// The exact eye tool passes the deployed guard and preserves the desktop capture fences.
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import http from 'node:http'
import { syncBuiltinESMExports } from 'node:module'
import { Readable } from 'node:stream'
import test from 'node:test'
import { createGuard, readSettings } from '../plugins/aukora-action-gate/lib/index.mjs'
import { decideCall } from '../plugins/aukora-action-gate/lib/kernel.mjs'
import * as eye from '../plugins/aukora-eye/lib/index.js'
import { installEyeDoor } from '../apps/aukora-desktop/eye.mjs'

const policyUrl = new URL('../plugins/aukora-action-gate/lib/policy.mjs', import.meta.url)
const mutant = process.env.EYE_ACTION_GATE_MUTANT
assert.ok(mutant === undefined || ['overlay-entry', 'default-entry', 'overlay-family', 'default-family', 'draw-recheck'].includes(mutant), 'known mutation only')
let source = readFileSync(policyUrl, 'utf8')
if (mutant === 'default-entry' || mutant === 'default-family') {
  const changed = source.replace("  'aukora_see',\n", mutant === 'default-entry' ? '' : "  'aukora_see*',\n")
  assert.notEqual(changed, source, 'default entry mutation applied')
  source = changed.replace(/from (['"])(\.[^'"]+)\1/gu,
    (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, policyUrl).href)}`)
}
const { createPolicy } = await import(mutant === 'default-entry' || mutant === 'default-family'
  ? `data:text/javascript;base64,${Buffer.from(source).toString('base64')}` : policyUrl.href)
let receive = installEyeDoor
if (mutant === 'draw-recheck') {
  const source = readFileSync(new URL('../apps/aukora-desktop/eye.mjs', import.meta.url), 'utf8')
  const block = '      if (isDrawPending()) {\n        say(`eye: refused ${EYE_REFUSE.BIND_SURFACE_OPEN}`)\n        return refuse(res, 423, EYE_REFUSE.BIND_SURFACE_OPEN)\n      }\n'
  const changed = source.replace(block, '')
  assert.notEqual(changed, source, 'post-capture draw fence mutation applied')
  receive = (await import(`data:text/javascript;base64,${Buffer.from(changed).toString('base64')}`)).installEyeDoor
}
let overlay = readFileSync(new URL('../overlays/action-gate.patch.yml', import.meta.url), 'utf8')
if (mutant === 'overlay-entry' || mutant === 'overlay-family') {
  const changed = overlay.replace('          - aukora_see\n', mutant === 'overlay-entry' ? '' : '          - aukora_see*\n')
  assert.notEqual(changed, overlay, 'overlay entry mutation applied')
  overlay = changed
}
const allowTools = overlay.split('        allowTools:\n')[1].split('        repoRoots:')[0]
  .split('\n').flatMap(line => /^          - (\S+)$/u.exec(line)?.slice(1) ?? [])
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==', 'base64')

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

test('fallback policy allows the exact eye tool through the kernel, without approving action aliases', t => {
  const { workspace, settings } = fixture(t)
  const policy = createPolicy(settings)
  const call = { tool: eye.SEE_TOOL_NAME, args: { scale: 1 }, workspace }
  assert.equal(decideCall(policy.classify(call), 'a'.repeat(64)).decision, 'allow')
  for (const tool of ['aukora_see_click', 'aukora_eye_act', 'aukora_see_upload']) {
    assert.equal(policy.judge({ ...call, tool }).rule, 'authority:tool-not-approved', tool)
  }
})

test('deployed allow-list permits only the exact eye name and writes an allow receipt', t => {
  const { root, workspace, settings } = fixture(t)
  const guard = createGuard({ settings: { ...settings, allowTools } })
  const exec = { name: eye.SEE_TOOL_NAME, arguments: { scale: 1 }, agent: { id: 'synthetic-agent', session: { header: { cwd: workspace } } } }
  assert.equal(guard(exec), undefined, 'the deployed allow-list must reach the tool body')
  const receipt = JSON.parse(readFileSync(join(root, 'aura', 'aura.jsonl'), 'utf8').trim())
  assert.equal(receipt.tool, 'aukora_see')
  assert.equal(receipt.kernelCode, 'allowed')
  assert.match(guard({ ...exec, name: 'aukora_see_click' }), /authority:tool-not-approved/u)
})

test('the mounted eye uses the allowed capture route and commits its image attachment', async t => {
  const { root, workspace, settings } = fixture(t)
  let tool, captures = 0
  const attachments = { saveImage: async ({ data, name }) => ({ attachmentId: 'synthetic-image', bytes: data.length, width: 1, height: 1, name }) }
  eye.apply({ inject: (_names, mount) => mount({ get: () => attachments, tools: { register: value => { tool = value } } }) }, { stateDir: join(root, 'captures') })
  assert.deepEqual(Object.keys(tool.parameters).sort(), ['height', 'note', 'scale', 'width', 'x', 'y'])
  const previous = { AUKORA_EYE_URL: process.env.AUKORA_EYE_URL, AUKORA_EYE_TOKEN: process.env.AUKORA_EYE_TOKEN }
  Object.assign(process.env, { AUKORA_EYE_URL: 'http://127.0.0.1:12345', AUKORA_EYE_TOKEN: 'synthetic-token' })
  t.after(() => { for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value } })
  t.mock.method(globalThis, 'fetch', async (url, request) => {
    assert.equal(url, 'http://127.0.0.1:12345/eye/capture')
    assert.equal(request.method, 'POST')
    assert.deepEqual(JSON.parse(request.body), { scale: 1 })
    captures++
    return new Response(png, { status: 200, headers: { 'content-type': 'image/png' } })
  })
  const exec = { name: tool.name, arguments: { scale: 1 }, agent: { id: 'synthetic-agent', session: { id: 'synthetic-session', header: { cwd: workspace } } } }
  assert.equal(createGuard({ settings: { ...settings, allowTools }, definitionOf: () => tool })(exec), undefined)
  const result = await tool.execute(exec.arguments, exec)
  assert.equal(result.image.attachmentId, 'synthetic-image')
  assert.deepEqual(readFileSync(result.stored.path), png)
  assert.equal(captures, 1)
})

test('desktop receiver drops pixels when a bind draw starts during capture', async t => {
  let handler, draw = false, captures = 0
  // Only the transport is replaced; the receiver's actual handler and refusal paths run.
  t.mock.method(http, 'createServer', callback => {
    handler = callback
    return { once() {}, listen: (_port, _host, ready) => ready(), address: () => ({ port: 12345 }), close: ready => ready() }
  })
  syncBuiltinESMExports()
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports() })
  const door = await receive({
    getWindow: () => ({ webContents: { capturePage: async () => {
      captures++; draw = true
      return { getSize: () => ({ width: 1, height: 1 }), toPNG: () => png }
    } } }),
    isDrawPending: () => draw,
  })
  t.after(() => door.dispose())
  const req = Readable.from([Buffer.from('{}')])
  Object.assign(req, { method: 'POST', url: '/eye/capture', headers: { host: '127.0.0.1:12345', authorization: `Bearer ${door.token}` } })
  const response = await new Promise(resolve => {
    let status, headers
    handler(req, { headersSent: false, writeHead: (code, fields) => { status = code; headers = fields }, end: body => resolve({ status, headers, body }) })
  })
  assert.equal(captures, 1, 'the draw began after the early fence')
  assert.equal(response.status, 423)
  assert.equal(response.headers['content-type'], 'application/json')
  assert.equal(JSON.parse(response.body).code, 'eye.bind-surface-open')
})

test('mounted eye passes the deployed guard and reaches the desktop capture receiver', async t => {
  const { root, workspace, settings } = fixture(t)
  let approval = false, draw = false, captures = 0
  let door
  try {
    door = await installEyeDoor({
      getWindow: () => ({ webContents: { capturePage: async () => {
        captures++
        return { getSize: () => ({ width: 1, height: 1 }), toPNG: () => png }
      } } }),
      isApprovalOpen: () => approval, isDrawPending: () => draw,
    })
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.skip(`UNPERFORMED: loopback listen refused by sandbox (${error.code})`)
      return
    }
    throw error
  }
  t.after(() => door.dispose())
  let tool
  const attachments = { saveImage: async ({ data, name }) => ({ attachmentId: 'synthetic-image', bytes: data.length, width: 1, height: 1, name }) }
  eye.apply({ inject: (_names, mount) => mount({ get: () => attachments, tools: { register: value => { tool = value } } }) }, { stateDir: join(root, 'captures') })
  assert.equal(tool.name, 'aukora_see')
  assert.deepEqual(Object.keys(tool.parameters).sort(), ['height', 'note', 'scale', 'width', 'x', 'y'])
  const guard = createGuard({ settings: { ...settings, allowTools }, definitionOf: () => tool })
  const exec = { name: tool.name, arguments: { scale: 1 }, agent: { id: 'synthetic-agent', session: { id: 'synthetic-session', header: { cwd: workspace } } } }
  const previous = Object.fromEntries(Object.keys(door.env).map(key => [key, process.env[key]]))
  Object.assign(process.env, door.env)
  t.after(() => { for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value } })
  assert.equal(guard(exec), undefined, 'the deployed allow-list must reach the tool body')
  const result = await tool.execute(exec.arguments, exec)
  assert.equal(result.image.attachmentId, 'synthetic-image')
  assert.equal(captures, 1)
  for (const [kind, code] of [['approval', 'eye.approval-open'], ['draw', 'eye.bind-surface-open']]) {
    approval = kind === 'approval'; draw = kind === 'draw'
    await assert.rejects(tool.execute(exec.arguments, exec), error => error.code === code)
    assert.equal(captures, 1, `${kind} surface is never captured`)
  }
  approval = false; draw = false
  const rejected = await fetch(`${door.url}/eye/capture`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer synthetic-wrong-token' }, body: '{}' })
  assert.equal(rejected.status, 401)
  assert.equal((await rejected.json()).code, 'eye.unauthorized')
  assert.equal(captures, 1, 'wrong token never captures')
  const receipt = readFileSync(join(root, 'aura', 'aura.jsonl'), 'utf8')
  assert.equal(JSON.parse(receipt.trim()).kernelCode, 'allowed')
})
