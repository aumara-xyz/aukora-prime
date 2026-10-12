// The installed acceptance driver cannot replace live HOME state or escape its explicit scratch HOME.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = fileURLToPath(new URL('../', import.meta.url))
const driver = path.join(root, 'plugins/aukora-buzz-door/checks/installed-accept.mjs')
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(root, '.buzz-installed-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const home = path.join(dir, 'home'), scratch = path.join(dir, 'scratch'), release = path.join(dir, 'release')
  for (const name of [home, scratch]) fs.mkdirSync(name)
  const write = (file, data) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, data) }
  write(path.join(release, 'plugins/aukora-buzz-door/lib/index.mjs'), `
export const RELAY_HTTP = 'http://fixture.invalid'
export const httpAuthHeader = () => 'fixture'
export function apply(ctx, config) { console.log('ROW ' + JSON.stringify({ home: process.env.HOME, config })); process.exit(0) }
`)
  write(path.join(release, 'plugins/aukora-nostr/lib/event.mjs'), `
export const randomSecretKey = () => 'a'.repeat(64)
export const publicKeyOf = () => 'b'.repeat(64)
export const signEvent = event => ({ ...event, id: 'c'.repeat(64) })
`)
  const preload = path.join(dir, 'preload.mjs')
  write(preload, `globalThis.fetch = async () => ({ status: 200, json: async () => ({ accepted: true }) })`)
  const configDir = base => path.join(base, '.config/aukora-buzz')
  const run = (...args) => spawnSync(process.execPath, ['--import', preload, driver, release, ...args], {
    env: { ...process.env, HOME: home }, encoding: 'utf8', timeout: 5000,
  })
  return { dir, home, scratch, release, preload, write, configDir, run }
}
function refused(result, code) {
  assert.equal(result.status, 1, result.stderr + result.stdout)
  assert.match(result.stderr, new RegExp(`REFUSED ${code}\\b`, 'u'))
  assert.doesNotMatch(result.stdout, /PLUGIN|ROW/u, 'refusal must precede imports and relay calls')
}

test('acceptance requires explicit scratch HOME even when live HOME is empty', t => {
  const f = fixture(t)
  refused(f.run(), 'SCRATCH_HOME_REQUIRED')
  assert.deepEqual(fs.readdirSync(f.home), [])
})

for (const name of ['door.json', 'auma.key']) test(`acceptance refuses existing live ${name} without scratch`, t => {
  const f = fixture(t), file = path.join(f.configDir(f.home), name)
  f.write(file, 'live fixture')
  refused(f.run(), 'LIVE_HOME_STATE_EXISTS')
  assert.equal(fs.readFileSync(file, 'utf8'), 'live fixture')
})

test('scratch HOME cannot be live HOME, its alias, or inside the live door directory', t => {
  const f = fixture(t), alias = path.join(f.dir, 'alias'), nested = path.join(f.configDir(f.home), 'nested')
  fs.symlinkSync(f.home, alias)
  fs.mkdirSync(nested, { recursive: true })
  for (const candidate of [f.home, alias, nested]) refused(f.run('--scratch-home', candidate), 'LIVE_HOME_FORBIDDEN')
})

test('scratch HOME must be an existing absolute directory', t => {
  const f = fixture(t)
  const file = path.join(f.dir, 'file'); f.write(file, 'fixture')
  for (const candidate of [path.relative(process.cwd(), f.scratch), path.join(f.dir, 'missing'), file]) refused(f.run('--scratch-home', candidate), 'SCRATCH_HOME_NOT_DIRECTORY')
})

test('scratch HOME cannot alias the live door directory through the live config path', t => {
  const f = fixture(t), config = path.join(f.dir, 'config')
  fs.mkdirSync(path.join(config, 'aukora-buzz'), { recursive: true })
  fs.symlinkSync(config, path.join(f.home, '.config'))
  refused(f.run('--scratch-home', path.join(config, 'aukora-buzz')), 'LIVE_HOME_FORBIDDEN')
})

for (const parent of ['.config', '.config/aukora-buzz']) test(`scratch ${parent} cannot redirect writes through a symlink`, t => {
  const f = fixture(t), destination = path.join(f.home, parent), link = path.join(f.scratch, parent)
  fs.mkdirSync(destination, { recursive: true }); fs.mkdirSync(path.dirname(link), { recursive: true })
  fs.symlinkSync(destination, link)
  refused(f.run('--scratch-home', f.scratch), 'SCRATCH_CONFIG_PATH_UNSAFE')
  assert.deepEqual(fs.readdirSync(destination), [])
})

for (const name of ['door.json', 'auma.key']) test(`scratch ${name} must not replace existing state, including dangling symlinks`, t => {
  const f = fixture(t), file = path.join(f.configDir(f.scratch), name)
  f.write(file, 'scratch fixture')
  refused(f.run('--scratch-home', f.scratch), 'SCRATCH_HOME_STATE_EXISTS')
  assert.equal(fs.readFileSync(file, 'utf8'), 'scratch fixture')
  fs.unlinkSync(file); fs.symlinkSync(path.join(f.dir, 'absent'), file)
  refused(f.run('--scratch-home', f.scratch), 'SCRATCH_HOME_STATE_EXISTS')
})

for (const name of ['door.json', 'auma.key']) test(`exclusive creation preserves ${name} appearing after preflight`, t => {
  const f = fixture(t)
  const insertion = `import fs from 'node:fs'; import path from 'node:path';
const insert = () => {
  const file = path.join(process.env.HOME, '.config/aukora-buzz/${name}')
  fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, 'intervening fixture')
}`
  if (name === 'auma.key') fs.appendFileSync(path.join(f.release, 'plugins/aukora-nostr/lib/event.mjs'), insertion + '\ninsert()\n')
  else f.write(f.preload, insertion + `\nglobalThis.fetch = async () => { insert(); return { status: 200, json: async () => ({ accepted: true }) } }`)
  const result = f.run('--scratch-home', f.scratch)
  assert.equal(result.status, 1, result.stdout + result.stderr)
  assert.match(result.stderr, /REFUSED SCRATCH_HOME_STATE_EXISTS/u)
  assert.equal(fs.readFileSync(path.join(f.configDir(f.scratch), name), 'utf8'), 'intervening fixture')
})

test('explicit scratch supplies HOME and every row path while live state stays unchanged', t => {
  const f = fixture(t)
  for (const name of ['door.json', 'auma.key']) f.write(path.join(f.configDir(f.home), name), 'live fixture')
  const result = f.run('--scratch-home', f.scratch)
  assert.equal(result.status, 0, result.stderr + result.stdout)
  const row = JSON.parse(result.stdout.split('\n').find(line => line.startsWith('ROW ')).slice(4))
  assert.equal(row.home, fs.realpathSync(f.scratch))
  assert.deepEqual(row.config, {
    keyFile: path.join(row.home, '.config/aukora-buzz/auma.key'),
    configFile: path.join(row.home, '.config/aukora-buzz/door.json'),
    gateSocket: '/run/aukora-gate/gate.sock', workspaceRoots: [path.join(row.home, 'workspaces')],
  })
  for (const name of ['door.json', 'auma.key']) {
    assert.ok(fs.existsSync(path.join(f.configDir(f.scratch), name)))
    assert.equal(fs.readFileSync(path.join(f.configDir(f.home), name), 'utf8'), 'live fixture')
  }
})
