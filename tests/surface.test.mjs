// The committed surface follows default composition, policy, custody and pinned upstream sources.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join, resolve } from 'node:path'
import vm from 'node:vm'
import { createHash } from 'node:crypto'
import { inventory, renderSurface, checkPage, verifyUpstream, upstreamRows } from '../scripts/audit/surface.mjs'
import { root, source, generated, rows } from './helpers/release-composition.mjs'

const page = readFileSync(join(root, 'docs/SURFACE.md'), 'utf8')
const pin = JSON.parse(readFileSync(join(root, 'upstream-dsh.json')))
const fail = code => { throw Object.assign(new Error(code), { code }) }

test('surface is current without a harness and names every active mount, allowed tool, unit and custody anchor', t => {
  const result = inventory({ archive: false })
  checkPage(page, renderSurface({ archive: false }))
  assert.equal(result.plugins.length, 148)
  assert.equal(result.session.length, 24)
  assert.equal(result.tools.length, 55)
  for (const row of [...result.plugins, ...result.session]) assert.ok(page.includes(`\`${row.id}\``), row.id)
  for (const tool of result.tools) assert.ok(page.includes(`\`${tool}\``), tool)
  for (const unit of result.units) assert.ok(page.includes(unit.file), unit.file)
  for (const path of Object.values(result.custody)) assert.ok(page.includes(path), path)
  for (const match of page.matchAll(/\]\((\.\.\/[^)]+)\)/gu)) assert.ok(existsSync(resolve(root, 'docs', match[1])), match[1])
  const mounts = rows(generated(undefined, { includeUpstream: false }).patches['aukora-composition.patch.yml'], 'default')
  assert.ok(mounts.some(row => row.id === 'aukora-buzz-door'))
  assert.ok(!result.plugins.some(row => row.id === 'aukora-relay-auma' || row.id === 'aukora-core-read-deny'))
  assert.ok(!result.tools.some(tool => /^relay_/u.test(tool)))
  t.diagnostic(`surface: PASS (${result.plugins.length} host/client plugins; ${result.session.length} session plugins; ${result.tools.length} tool names/families)`)
})

test('stale page and source composition mutations cannot keep the committed page green', t => {
  const control = check => assert.throws(() => check(page.replace('aukora-buzz-door', 'removed-door'), page), { code: 'surface:stale' })
  control(checkPage)
  const guard = 'if (actual !== expected)'
  assert.equal(checkPage.toString().split(guard).length, 2)
  const mutant = vm.runInNewContext(`(${checkPage.toString().replace(guard, 'if (false)')})`, { fail })
  assert.throws(() => control(mutant), { code: 'ERR_ASSERTION' })
  const name = '    - id: aukora-buzz-door\\n'
  assert.ok(source.includes(name))
  const changed = source.replace(name, '    - id: surface-new-door\\n')
  assert.throws(() => checkPage(page, renderSurface({ materializer: changed, archive: false })), { code: 'surface:stale' })
  t.diagnostic('MUTATION CAUGHT stale-page guard removal and materializer mount change')
})

test('upstream revision drift requires snapshot review even without an archive; guard removals fail controls', t => {
  const body = verifyUpstream.toString()
  const snapshot = { commit: pin.commit, archiveSha256: pin.archiveSha256 }
  const guard = 'if (pin.commit !== upstream.commit || pin.archiveSha256 !== upstream.archiveSha256)'
  assert.equal(body.split(guard).length, 2)
  for (const field of ['commit', 'archiveSha256']) {
    const control = verify => assert.throws(() => verify({ ...pin, [field]: 'changed' }, false), { code: 'surface:upstream-review-required' })
    control(verifyUpstream)
    const mutant = vm.runInNewContext(`(${body.replace(guard, 'if (false)')})`, { upstream: snapshot, join, root, fail })
    assert.throws(() => control(mutant), { code: 'ERR_ASSERTION' })
  }
  t.diagnostic('MUTATION CAUGHT upstream revision/hash guard removal (2 controls)')
})

test('archive source hashes and the reviewed row snapshot agree; removals fail their controls', t => {
  verifyUpstream(pin)
  const text = "- insert:\n    - id: fixture\n      name: '@deepseek-ai/fixture'\n      disabled: false\n"
  const hash = value => createHash('sha256').update(value).digest('hex')
  const snapshot = { commit: pin.commit, archiveSha256: pin.archiveSha256,
    files: { fixture: { sha256: hash(text), rows: upstreamRows(text) } } }
  const dependencies = { upstream: snapshot, root, join, existsSync: () => true, fail, hash, upstreamRows,
    execFileSync: () => JSON.stringify({ fixture: text }) }
  const body = verifyUpstream.toString()
  for (const [guard, mutate, reason] of [
    ['if (hash(actual[file]) !== item.sha256)', state => { state.files.fixture.sha256 = 'changed' }, 'surface:upstream-snapshot-drift'],
    ['if (JSON.stringify(upstreamRows(actual[file])) !== JSON.stringify(item.rows))', state => { state.files.fixture.rows[0].name = 'changed' }, 'surface:upstream-rows-drift'],
  ]) {
    assert.equal(body.split(guard).length, 2)
    const changed = structuredClone(snapshot)
    mutate(changed)
    const control = verify => assert.throws(() => verify(pin, 'fixture-archive'), { code: reason })
    control(vm.runInNewContext(`(${body})`, { ...dependencies, upstream: changed }))
    const mutant = vm.runInNewContext(`(${body.replace(guard, 'if (false)')})`, { ...dependencies, upstream: changed })
    assert.throws(() => control(mutant), { code: 'ERR_ASSERTION' })
  }
  assert.deepEqual(upstreamRows("- id: hmr\n  name: hmr\n  disabled: true\n- id: shell\n  name: shell\n  disabled: !!js process.platform === 'win32'\n"),
    [{ id: 'hmr', name: 'hmr', disabled: true }, { id: 'shell', name: 'shell', disabled: false }])
  assert.throws(() => upstreamRows('- id: fixture\n  disabled: !!js arbitrary()\n'), { code: 'surface:upstream-disabled-unreadable' })
  const disabledGuard = "else fail('surface:upstream-disabled-unreadable')"
  assert.equal(upstreamRows.toString().split(disabledGuard).length, 2)
  const disabledControl = parse => assert.throws(() => parse('- id: fixture\n  disabled: !!js arbitrary()\n'), { code: 'surface:upstream-disabled-unreadable' })
  const disabledMutant = vm.runInNewContext(`(${upstreamRows.toString().replace(disabledGuard, 'else {}')})`, { fail })
  assert.throws(() => disabledControl(disabledMutant), { code: 'ERR_ASSERTION' })
  t.diagnostic('MUTATION CAUGHT archive source hash and snapshot row guard removal (2 controls)')
  t.diagnostic('MUTATION CAUGHT unsupported disabled-expression refusal removal')
})

test('an archive with matching source rows still needs the pinned archive hash; removal fails its control', t => {
  const parent = join(root, '.scratch')
  mkdirSync(parent, { recursive: true, mode: 0o700 })
  const directory = mkdtempSync(join(parent, 'surface-archive-')), archive = join(directory, 'source.tar.gz')
  const text = '- id: fixture\n  name: fixture\n'
  const hash = value => createHash('sha256').update(value).digest('hex')
  const snapshot = { ...pin, files: { fixture: { sha256: hash(text), rows: upstreamRows(text) } } }
  try {
    execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', `
import io,sys,tarfile
data=sys.argv[2].encode()
with tarfile.open(sys.argv[1],'w:gz') as tar:
    entry=tarfile.TarInfo('root/fixture'); entry.size=len(data); tar.addfile(entry,io.BytesIO(data))
`, archive, text], { timeout: 5000 })
    const dependencies = { upstream: snapshot, root, join, existsSync, execFileSync, fail, hash, upstreamRows }
    const body = verifyUpstream.toString()
    const control = verify => assert.throws(() => verify(pin, archive), error => String(error.stderr).includes('surface:archive-pin'))
    control(vm.runInNewContext(`(${body})`, dependencies))
    const guard = "if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected['archiveSha256']:"
    assert.equal(body.split(guard).length, 2)
    const mutant = vm.runInNewContext(`(${body.replace(guard, 'if False:')})`, dependencies)
    assert.throws(() => control(mutant), { code: 'ERR_ASSERTION' })
    t.diagnostic('MUTATION CAUGHT archive hash guard removal')
  } finally { rmSync(directory, { recursive: true, force: true }) }
})
