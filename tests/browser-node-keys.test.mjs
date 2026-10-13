// Generate real disposable gate keys and refuse reuse, public modes and epoch replacement.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { spawnSync } from 'node:child_process'
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const source = fs.readFileSync(new URL('../ops/node-spawn/browser/keys.mjs', import.meta.url), 'utf8')
const names = ['owner-secret.json', 'receipt-ed25519.pem', 'signer-epochs.json']
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const guard = "if (fs.existsSync(`${home}/${name}`)) throw Error('BROWSER_GATE_KEYS_EXIST')"

function fixture(t) {
  const home = fs.mkdtempSync(join(root, '.browser-keys-'))
  fs.chmodSync(home, 0o700)
  t.after(() => fs.rmSync(home, { recursive: true, force: true }))
  return home
}
function execute(home, input = source, prefix = '', suffix = '') {
  const mapped = input.replace("const home = '/home/aukora-gate'", `const home = ${JSON.stringify(home)}`)
    .replaceAll("'/opt/aukora-boundary-gate/src/secrets.mjs'", JSON.stringify(new URL('../packages/boundary-gate/src/secrets.mjs', import.meta.url).href))
    .replaceAll("'/opt/aukora-boundary-gate/src/ledger.mjs'", JSON.stringify(new URL('../packages/boundary-gate/src/ledger.mjs', import.meta.url).href))
  assert.equal(mapped.includes('/home/aukora-gate'), false)
  return spawnSync(process.execPath, ['--input-type=module'], {
    input: prefix + '\n' + mapped + '\n' + suffix, cwd: root, encoding: 'utf8', timeout: 10000,
    env: { PATH: process.env.PATH, HOME: home },
  })
}
function successful(result) {
  assert.equal(result.status, 0, 'disposable key generation refused')
  assert.equal(Buffer.byteLength(result.stdout), 0, 'key generation printed output')
}
function snapshot(home) {
  return Object.fromEntries(fs.readdirSync(home).sort().map(name => [name, hash(fs.readFileSync(join(home, name)))]))
}
function privateModes(home) {
  for (const name of names) assert.equal(fs.statSync(join(home, name)).mode & 0o777, 0o600, name)
}
function mutate(before, after) {
  assert.equal(source.split(before).length, 2, 'exact key mutation anchor required')
  return source.replace(before, after)
}

test('fresh gate secret, real Ed25519 key and public signer epoch agree and stay private and silent', t => {
  const a = fixture(t), b = fixture(t)
  const first = execute(a), second = execute(b)
  successful(first); successful(second)
  for (const home of [a, b]) {
    assert.deepEqual(fs.readdirSync(home).sort(), [...names].sort())
    privateModes(home)
    const secret = JSON.parse(fs.readFileSync(join(home, names[0])))
    assert.match(secret.hmacKey, /^[a-f0-9]{64}$/u)
    assert.match(secret.bearer, /^[A-Za-z0-9_-]{43}$/u)
    const pem = fs.readFileSync(join(home, names[1]))
    const privateKey = createPrivateKey(pem), publicKey = createPublicKey(privateKey)
    assert.equal(privateKey.asymmetricKeyType, 'ed25519')
    const message = Buffer.from('disposable fresh gate receipt')
    assert.equal(verify(null, message, publicKey, sign(null, message, privateKey)), true)
    const digest = hash(publicKey.export({ type: 'spki', format: 'der' }))
    assert.deepEqual(JSON.parse(fs.readFileSync(join(home, names[2]))), { version: 1,
      kind: 'aukora-signer-epochs/v1', epochs: [{ epoch: 1, gate_pubkey_sha256: digest }] })
    for (const value of [secret.hmacKey, secret.bearer, pem.toString()]) {
      assert.ok(!(first.stdout + first.stderr + second.stdout + second.stderr).includes(value), 'secret escaped child output')
    }
  }
  const before = snapshot(a), after = snapshot(b)
  for (const name of names) assert.ok(before[name] !== after[name], `${name}: fresh nodes reused bytes`)
})

test('each partial pre-existing key set refuses before creating or changing any key', t => {
  const mutant = mutate(guard, '')
  for (const selected of names) {
    const home = fixture(t)
    successful(execute(home))
    for (const name of names) if (name !== selected) fs.unlinkSync(join(home, name))
    const before = snapshot(home), result = execute(home)
    assert.equal(result.status, 1)
    assert.match(result.stderr, /BROWSER_GATE_KEYS_EXIST/u)
    assert.deepEqual(snapshot(home), before, 'partial set changed during refusal')
    const removed = execute(home, mutant)
    assert.ok(removed.status !== 1 || !removed.stderr.includes('BROWSER_GATE_KEYS_EXIST'), 'existing-key guard mutation survived')
    assert.notDeepEqual(snapshot(home), before, 'mutation fixture did not reveal reuse or partial creation')
  }
  t.diagnostic('MUTATION browser key reuse refusal: 3/3 killed (secret, receipt key, epoch partial sets)')
})

test('private umask and explicit epoch mode each protect real files against permissive ambient modes', t => {
  const probe = "fs.writeFileSync(`${home}/ambient-mode-probe`, 'public fixture text')"
  const baseline = fixture(t), lostMask = fixture(t)
  successful(execute(baseline, source, 'process.umask(0)', probe))
  assert.equal(fs.statSync(join(baseline, 'ambient-mode-probe')).mode & 0o777, 0o600)
  successful(execute(lostMask, mutate('process.umask(0o077)', ''), 'process.umask(0)', probe))
  assert.throws(() => assert.equal(fs.statSync(join(lostMask, 'ambient-mode-probe')).mode & 0o777, 0o600), { code: 'ERR_ASSERTION' })
  const resetBeforeEpoch = "const originalWrite = fs.writeFileSync; fs.writeFileSync = (file, ...args) => { if (String(file).endsWith('/signer-epochs.json')) process.umask(0); return originalWrite(file, ...args) }"
  const explicit = fixture(t), lostMode = fixture(t)
  successful(execute(explicit, source, resetBeforeEpoch))
  privateModes(explicit)
  successful(execute(lostMode, mutate('{ mode: 0o600, flag:', '{ flag:'), resetBeforeEpoch))
  assert.throws(() => privateModes(lostMode), { code: 'ERR_ASSERTION' })
  t.diagnostic('MUTATION browser key private modes: 2/2 killed (umask, explicit epoch mode); key helpers retain their own 0600 modes')
})

test('exclusive epoch write refuses a file appearing after the initial existence check', t => {
  const race = `const originalExists = fs.existsSync; fs.existsSync = file => {
    if (String(file).endsWith('/signer-epochs.json')) { fs.writeFileSync(file, 'pre-existing epoch fixture', { mode: 0o600 }); return false }
    return originalExists(file)
  }`
  const baseline = fixture(t), mutant = fixture(t)
  const result = execute(baseline, source, race)
  assert.equal(result.status, 1); assert.match(result.stderr, /EEXIST/u)
  assert.equal(fs.readFileSync(join(baseline, names[2]), 'utf8'), 'pre-existing epoch fixture')
  successful(execute(mutant, mutate("flag: 'wx'", "flag: 'w'"), race))
  assert.throws(() => assert.equal(fs.readFileSync(join(mutant, names[2]), 'utf8'), 'pre-existing epoch fixture'), { code: 'ERR_ASSERTION' })
  t.diagnostic('MUTATION browser epoch exclusive write: 1/1 killed; real file race fixture')
})

test('output check catches an added secret log without printing the captured secret', t => {
  const result = execute(fixture(t), source, '', "console.log(fs.readFileSync(`${home}/owner-secret.json`, 'utf8'))")
  assert.equal(result.status, 0)
  assert.throws(() => successful(result), { code: 'ERR_ASSERTION' })
  t.diagnostic('NEGATIVE CONTROL browser key output: added secret log detected; captured output withheld')
})
