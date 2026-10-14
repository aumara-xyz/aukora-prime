// SPDX-License-Identifier: AGPL-3.0-or-later
// The browser's compatibility reader exposes only a bounded public head and no provider.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { readAuraSnapshot } from '../plugins/aukora-face/settings/src/aura/snapshot-reader.ts'

const materializer = new URL('../scripts/materialize-aukora-release.py', import.meta.url)
const extracted = spawnSync('python3', ['-c', `import ast,json,sys
tree=ast.parse(open(sys.argv[1]).read())
names=('BROWSER_AURA_READER_ENTRY','BROWSER_AURA_READER_SOURCE')
print(json.dumps({n.targets[0].id:ast.literal_eval(n.value) for n in tree.body
 if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in names}))`, materializer.pathname], { encoding: 'utf8' })
assert.equal(extracted.status, 0, extracted.stderr)
const { BROWSER_AURA_READER_ENTRY: entry, BROWSER_AURA_READER_SOURCE: source } = JSON.parse(extracted.stdout)
assert.equal(entry, 'plugins/aukora-buzz-door/lib/index.mjs')
const head = '11'.repeat(32)
const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const scratch = mkdtempSync(new URL('.browser-aura-reader-', import.meta.url))
const file = join(scratch, 'gate.json')
const url = text => `data:text/javascript;base64,${Buffer.from(text).toString('base64')}`
const local = text => text.replace("'/var/lib/aukora-aura/head/gate.json'", JSON.stringify(file))
const read = module => module.gateCall('/run/aukora-gate/gate.sock', 'log', { limit: 1 }, 3000)

async function checks(text) {
  const module = await import(url(local(text)))
  assert.deepEqual(Object.keys(module), ['gateCall'])
  rmSync(file, { force: true })
  writeFileSync(file, JSON.stringify({ ok: true, entries: 5, head, detail: 'PRIVATE_DETAIL' }))
  assert.deepEqual(await read(module), { verify: { ok: true, entries: 5, head } })
  const array = []; array.limit = 1
  const callable = () => {}; callable.limit = 1
  for (const args of [array, callable, null, 'wrong', {}, { limit: 2 }, { limit: 1, target: 'private' }]) {
    await assert.rejects(() => module.gateCall('/run/aukora-gate/gate.sock', 'log', args), error => error.code === 'aura-head:read-only')
  }
  await assert.rejects(() => module.gateCall('/fixture/gate.sock', 'log', { limit: 1 }))
  for (const op of ['propose', 'aura_note', 'verify', 'selfcheck']) {
    await assert.rejects(() => module.gateCall('/run/aukora-gate/gate.sock', op, { limit: 1 }))
  }
  writeFileSync(file, JSON.stringify({ ok: true, entries: 0, head: 'GENESIS' }))
  assert.deepEqual(await read(module), { verify: { ok: true, entries: 0, head: 'GENESIS' } })
  for (const value of [null, {}, { ok: false, entries: 5, head }, { ok: true, entries: -1, head },
    { ok: true, entries: 1.5, head }, { ok: true, entries: Number.MAX_SAFE_INTEGER + 1, head },
    { ok: true, entries: 0, head }, { ok: true, entries: 5, head: 'GENESIS' },
    { ok: true, entries: 5, head: null }, { ok: true, entries: 5, head: [head] },
    { ok: true, entries: 5, head: head + '\n' },
    { ok: true, entries: 5, head: 'AA'.repeat(32) }, { ok: true, entries: 5, head: 'bad' }]) {
    writeFileSync(file, JSON.stringify(value))
    await assert.rejects(() => read(module), error => error.code === 'aura-head:head-invalid')
  }
  writeFileSync(file, JSON.stringify({ ok: true, entries: 5, head }) + ' '.repeat(4096))
  await assert.rejects(() => read(module))
  const target = join(scratch, 'target.json')
  writeFileSync(target, JSON.stringify({ ok: true, entries: 5, head }))
  rmSync(file); symlinkSync(target, file)
  await assert.rejects(() => read(module))
  rmSync(file)
  await assert.rejects(() => read(module))
}

async function growth(text) {
  const body = JSON.stringify({ ok: true, entries: 5, head })
  const stub = `let closed=false
  const open=async()=>{let at=0; const body=Buffer.from(${JSON.stringify(body)}); return {
    async stat(){return {isFile:()=>true,size:body.length-1}},
    async read(bytes,offset,length){const count=Math.min(length,body.length-at);body.copy(bytes,offset,at,at+count);at+=count;return {bytesRead:count}},
    async close(){closed=true}
  }}
  export const wasClosed=()=>closed`
  assert.ok(text.includes("import { open } from 'node:fs/promises'"))
  const module = await import(url(text.replace("import { open } from 'node:fs/promises'", stub)))
  await assert.rejects(() => read(module))
  assert.equal(module.wasClosed(), true)
}

async function regular(text) {
  const stub = `const open=async()=>{let done=false; const body=Buffer.from(${JSON.stringify(JSON.stringify({ ok: true, entries: 5, head }))});return {
    async stat(){return {isFile:()=>false,size:body.length}},
    async read(bytes,offset,length){if(done)return {bytesRead:0};done=true;body.copy(bytes,offset);return {bytesRead:body.length}},
    async close(){}
  }}`
  const module = await import(url(text.replace("import { open } from 'node:fs/promises'", stub)))
  await assert.rejects(() => read(module))
}

async function fifo(text) {
  rmSync(file, { force: true })
  const made = spawnSync('mkfifo', [file], { encoding: 'utf8' })
  assert.equal(made.status, 0, made.stderr)
  const script = `const m=await import(${JSON.stringify(url(local(text)))}); try {await m.gateCall('/run/aukora-gate/gate.sock','log',{limit:1});process.exitCode=2} catch {}`
  const result = await new Promise(resolve => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'ignore', 'ignore'] })
    let timeout = false
    const timer = setTimeout(() => { timeout = true; child.kill('SIGKILL') }, 1200)
    child.on('close', status => { clearTimeout(timer); resolve({ status, timeout }) })
  })
  rmSync(file)
  assert.equal(result.timeout, false)
  assert.equal(result.status, 0)
}

try {
  await checks(source)
  await growth(source)
  await regular(source)
  await fifo(source)
  const build = join(scratch, '.dsh-build'); mkdirSync(build)
  const record = JSON.stringify({ kind: 'genesis-artifact-record', formatVersion: 1 })
  writeFileSync(join(build, 'genesis-artifacts.json'), record)
  writeFileSync(join(build, 'aukora-release.json'), JSON.stringify({ record: { sha256: digest(record) } }))
  const carried = join(scratch, entry); mkdirSync(join(scratch, 'plugins/aukora-buzz-door/lib'), { recursive: true })
  writeFileSync(carried, local(source))
  writeFileSync(file, JSON.stringify({ ok: true, entries: 5, head }))
  const snapshot = await readAuraSnapshot(scratch, '/run/aukora-gate/gate.sock',
    () => ({ head: null, entries: 0, absence: 'kira-ledger-missing' }))
  assert.deepEqual(snapshot.sources, [{ name: 'gate-ledger', head, entries: 5, absence: null },
    { name: 'kira-chain', head: null, entries: 0, absence: 'kira-ledger-missing', browserMemory: null },
    { name: 'code-chain', head: digest(record), entries: 1, absence: null }])
  console.log('PASS browser Aura reader: fixed read-only operation, bounded public summary, explicit empty Kira, code head')
  const mutations = [
    ["socket !== '/run/aukora-gate/gate.sock'", 'false'], ["op !== 'log'", 'false'],
    ['args === null', 'false'], ["typeof args !== 'object'", 'false'], ['Array.isArray(args)', 'false'],
    ['Object.keys(args).length !== 1', 'false'], ['args.limit !== 1', 'false'],
    ['FS.O_NOFOLLOW', '0'], ['stat.size > 4096', 'false'],
    ['value?.ok !== true', 'false'], ['!Number.isSafeInteger(value.entries)', 'false'],
    ['value.entries < 0', 'false'], ["value.head !== 'GENESIS'", 'false'],
    ["typeof value.head !== 'string'", 'false'],
    ['!/^[0-9a-f]{64}$/.test(value.head)', 'false'],
    ['return { verify: { ok: true, entries: value.entries, head: value.head } }', 'return { verify: value }'],
    ['if (offset !== stat.size)', 'if (false)', growth],
    ['await handle.close()', 'undefined', growth], ['FS.O_NONBLOCK', '0', fifo],
    ['!stat.isFile()', 'false', regular],
  ]
  let killed = 0
  for (const [before, after, run = checks] of mutations) {
    assert.ok(source.includes(before), `missing mutation seam: ${before}`)
    let caught = false
    try { await run(source.replace(before, after)) }
    catch (error) { if (error.code !== 'ERR_ASSERTION') throw error; caught = true; killed += 1 }
    assert.equal(caught, true, `mutation survived: ${before}`)
  }
  assert.equal(killed, mutations.length)
  console.log(`PASS browser Aura reader mutation controls: ${killed}/${mutations.length} killed`)
} finally { rmSync(scratch, { recursive: true, force: true }) }
