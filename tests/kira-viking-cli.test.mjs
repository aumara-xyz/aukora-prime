#!/usr/bin/env node
/** The Viking CLI selects one authenticated loopback door and accepts only its documented success statuses. */
import assert from 'node:assert/strict'
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = mkdtempSync(join(tmpdir(), 'kira-viking-cli-'))
const production = fileURLToPath(new URL('../scripts/kira/viking-cli.mjs', import.meta.url))
const credential = join(root, 'door.key'), token = 'synthetic-door-token'
writeFileSync(credential, token + '\n', { mode: 0o600 }); chmodSync(credential, 0o600)
const preload = join(root, 'fetch.mjs')
writeFileSync(preload, `
globalThis.fetch = async (url, options) => {
  const parsed = new URL(url)
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1') throw new Error('non-loopback request')
  if (parsed.port !== process.env.EXPECTED_PORT) throw new Error('wrong door port')
  if (options.headers.authorization !== 'Bearer synthetic-door-token') throw new Error('wrong credential')
  return Response.json({ remembered: 1, ids: ['rem:synthetic'], index: { pending: 0 } }, { status: Number(process.env.FIXTURE_STATUS) })
}
`)

const run = (entry, { port, status }) => {
  const env = { ...process.env, ROOM_ME: 'CLAUDE', AUKORA_VIKING_DOOR_KEY_FILE: credential,
    EXPECTED_PORT: port ?? '8766', FIXTURE_STATUS: String(status) }
  if (port === undefined) delete env.AUKORA_VIKING_DOOR_PORT
  else env.AUKORA_VIKING_DOOR_PORT = port
  return spawnSync(process.execPath, ['--import', preload, entry, 'remember', 'Waiting on Peter: choose the signer.'], { encoding: 'utf8', env })
}

const suite = entry => {
  for (const fixture of [{ port: undefined, status: 200 }, { port: '18766', status: 201 }]) {
    const result = run(entry, fixture)
    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, new RegExp(`door ${fixture.port ?? '8766'}\\.`))
    assert.ok(!(result.stdout + result.stderr).includes(token))
  }
  const extraSuccess = run(entry, { port: '18766', status: 202 })
  assert.notEqual(extraSuccess.status, 0)
  assert.match(extraSuccess.stderr, /HTTP 202/u)
  for (const port of ['0', '65536', '8766@198.51.100.1']) {
    const refused = run(entry, { port, status: 201 })
    assert.notEqual(refused.status, 0)
    assert.match(refused.stderr, /viking\.cli:invalid-door-port/u)
    assert.ok(!(refused.stdout + refused.stderr).includes(token))
  }
}

try {
  const candidateAt = process.argv.indexOf('--candidate')
  if (candidateAt >= 0) suite(process.argv[candidateAt + 1])
  else {
    suite(production)
    const auth = pathToFileURL(fileURLToPath(new URL('../scripts/kira/viking-auth.mjs', import.meta.url))).href
    const source = readFileSync(production, 'utf8').replace("'./viking-auth.mjs'", JSON.stringify(auth))
    const mutants = [
      ['door-port', 'const port = doorPort(process.env.AUKORA_VIKING_DOOR_PORT)', 'const port = 8766'],
      ['success-status', 'if (![200, 201].includes(response.status))', 'if (!response.ok)'],
      ['loopback-injection', "const doorPort = value => {\n  if (value === undefined) return 8766\n  if (!/^[1-9][0-9]{0,4}$/u.test(value) || Number(value) > 65535) throw new Error('viking.cli:invalid-door-port')\n  return Number(value)\n}", 'const doorPort = value => Number(value ?? 8766)'],
    ]
    for (const [name, before, after] of mutants) {
      assert.equal(source.split(before).length, 2, `${name} mutation target`)
      const mutant = join(root, `${name}.mjs`)
      writeFileSync(mutant, source.replace(before, after))
      const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--candidate', mutant], { encoding: 'utf8' })
      assert.notEqual(result.status, 0, `${name} mutation survived`)
      console.log(`kira-viking-cli mutation ${name}: CAUGHT`)
    }
    console.log('kira-viking-cli: 3 groups passed, 0 failed (mocked fetch; no listener)')
  }
} finally { rmSync(root, { recursive: true, force: true }) }
