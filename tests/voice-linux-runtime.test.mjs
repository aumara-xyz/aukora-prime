// SPDX-License-Identifier: AGPL-3.0-or-later
// Offline voice installation seals complete pinned inputs for the unprivileged service.
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const root = new URL('../', import.meta.url)
const voice = new URL('../plugins/aukora-face/apps/vendor/auma-live/source/voice/', import.meta.url)
const installerPath = new URL('install.py', voice)
const installer = readFileSync(installerPath, 'utf8')
const launcher = readFileSync(new URL('launch.py', voice), 'utf8')
const readme = readFileSync(new URL('README.md', voice), 'utf8')
const materializer = readFileSync(new URL('scripts/materialize-aukora-release.py', root), 'utf8')
const wheels = JSON.parse(readFileSync(new URL('wheels.lock.json', voice), 'utf8'))
const models = JSON.parse(readFileSync(new URL('models.lock.json', voice), 'utf8'))

test('the staged inventory, commands, pins, and disabled composition agree', () => {
  assert.equal(wheels.wheels.length, 54)
  assert.equal(models.files.length, 6)
  assert.equal(wheels.bootstrap.size, 1_815_170)
  assert.equal(wheels.wheels.reduce((sum, row) => sum + row.size, 0), 153_282_561)
  assert.equal(models.files.reduce((sum, row) => sum + row.size, 0), 198_666_263)
  for (const row of [wheels.bootstrap, ...wheels.wheels, ...models.files]) {
    assert.match(row.sha256, /^[a-f0-9]{64}$/u)
    assert.ok(Number.isSafeInteger(row.size) && row.size > 0)
  }
  assert.ok(!installer.includes('urllib') && !installer.includes('https://') && !installer.includes('http://'))
  assert.ok(installer.includes("'--no-index'"))
  assert.ok(installer.includes("artifact_path(artifacts, 'bootstrap', bootstrap)"))
  assert.ok(installer.includes("artifact_path(artifacts, 'wheels', row)"))
  assert.ok(installer.includes("artifact_path(artifacts, 'models', row)"))
  assert.ok(installer.includes("PIN_DIRECTORY / 'python.sha256'"))
  assert.ok(launcher.includes('PYTHON_PIN_PATH'))
  assert.match(readme, /install \\\n  --artifacts \/var\/lib\/aukora-voice-inputs/u)
  assert.match(readme, / status \\\n  --runtime \/opt\/aukora-voice\/runtime/u)
  assert.ok(materializer.includes("voiceEnabled: false"))
  assert.ok(materializer.includes("voiceAutoStart: false"))
  assert.ok(materializer.includes("VOICE_RUNTIME_DIRECTORY = '/opt/aukora-voice/runtime'"))
})

function modeFixture(input) {
  const scratch = mkdtempSync(join(tmpdir(), 'aukora-voice-modes-'))
  const module = join(scratch, 'install.py')
  writeFileSync(module, input)
  writeFileSync(join(scratch, 'launch.py'), launcher)
  const runtime = join(scratch, 'runtime')
  mkdirSync(join(runtime, '.venv/bin'), { recursive: true })
  writeFileSync(join(runtime, 'sidecar.py'), 'fixture')
  writeFileSync(join(runtime, '.venv/bin/python'), 'fixture', { mode: 0o755 })
  const program = String.raw`
import importlib.util, os, pathlib, sys
sys.path.insert(0,str(pathlib.Path(sys.argv[1]).parent))
spec=importlib.util.spec_from_file_location('voice_install', sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(sys.argv[2]);uid=os.getuid();gid=os.getgid()
module.seal_modes(root,gid,uid);module.check_runtime_access(root,gid,uid)
print(oct(root.stat().st_mode & 0o777),oct((root/'sidecar.py').stat().st_mode & 0o777),oct((root/'.venv/bin/python').stat().st_mode & 0o777))
`
  const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', program, module, runtime], {
    encoding: 'utf8', env: { PATH: '/usr/bin:/bin', PYTHONDONTWRITEBYTECODE: '1' },
  })
  rmSync(scratch, { recursive: true, force: true })
  return result
}

test('runtime custody is traversable but not writable by the service group', () => {
  const result = modeFixture(installer)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim(), '0o750 0o640 0o750')
})

test('offline, mode, pin, and disabled-default mutations are killed', t => {
  const checks = [
    ['network index', installer, "'--no-index'", "'--index-url', 'https://example.invalid/simple'", input => assert.ok(!input.includes('https://'))],
    ['environment pin', installer, "PIN_DIRECTORY / 'environment.sha256'", "PIN_DIRECTORY / 'environment.changed'", input => assert.ok(input.includes("PIN_DIRECTORY / 'environment.sha256'"))],
    ['python pin', installer, "PIN_DIRECTORY / 'python.sha256'", "PIN_DIRECTORY / 'python.changed'", input => assert.ok(input.includes("PIN_DIRECTORY / 'python.sha256'"))],
    ['voice disabled', materializer, '"        voiceEnabled: false\\n"', '"        voiceEnabled: true\\n"', input => assert.ok(input.includes('voiceEnabled: false'))],
    ['voice autostart disabled', materializer, '"        voiceAutoStart: false\\n"', '"        voiceAutoStart: true\\n"', input => assert.ok(input.includes('voiceAutoStart: false'))],
  ]
  let killed = 0
  for (const [label, input, before, after, check] of checks) {
    assert.ok(input.includes(before), `mutation anchor missing: ${label}`)
    assert.throws(() => check(input.replace(before, after)), assert.AssertionError, `surviving mutant: ${label}`)
    killed++
    t.diagnostic(`killed ${label}`)
  }
  for (const [label, before, after] of [
    ['directory mode', 'path.chmod(0o750)', 'path.chmod(0o770)'],
    ['file mode', 'path.chmod(0o750 if executable else 0o640)', 'path.chmod(0o750 if executable else 0o660)'],
  ]) {
    assert.ok(installer.includes(before), `mutation anchor missing: ${label}`)
    const result = modeFixture(installer.replace(before, after))
    assert.notEqual(result.status, 0, `surviving mutant: ${label}`)
    killed++
    t.diagnostic(`killed ${label}`)
  }
  console.log(`MUTATION linux-voice-runtime: ${killed}/${checks.length + 2} killed`)
})
