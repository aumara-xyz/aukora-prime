// SPDX-License-Identifier: AGPL-3.0-or-later
// Optional voice installation failures never escape the sidecar start boundary.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import vm from 'node:vm'

if (vm.SourceTextModule === undefined) {
  const again = spawnSync(process.execPath, ['--experimental-vm-modules', ...process.execArgv, ...process.argv.slice(1)], { stdio: 'inherit' })
  process.exit(again.status ?? 1)
}

const sourceUrl = new URL('../plugins/aukora-face/apps/src/auma-live/voice-sidecar.ts', import.meta.url)
const source = readFileSync(sourceUrl, 'utf8')
const voiceRoot = '/synthetic/package/vendor/auma-live/voice'
const runtimeRoot = '/synthetic/installed-voice'
const pinPath = '/etc/aukora/auma-live-voice/environment.sha256'
const launcher = join(voiceRoot, '..', 'source', 'voice', 'launch.py')
const executable = join(runtimeRoot, '.venv', 'bin', 'python')
const models = join(runtimeRoot, 'models')
const sidecar = join(voiceRoot, 'sidecar.py')
const baseline = 'e1efa562c2cc2e35521a5c9c9b9939921001ff8ca9708a13ef15ace68cc2ccd7'
const environmentPin = 'a'.repeat(64)
const unavailableMessage = 'voice not installed on this node'

function metadata(kind, mode = kind === 'directory' ? 0o700 : 0o644, uid = 0) {
  return { mode, uid, isFile: () => kind === 'file', isDirectory: () => kind === 'directory' }
}

async function fixture(options = {}, input = source) {
  const files = new Map([
    [runtimeRoot, metadata('directory')], [models, metadata('directory')],
    [join(runtimeRoot, '.venv'), metadata('directory')], [executable, metadata('file', 0o755)],
    [launcher, metadata('file')], [pinPath, metadata('file')], [sidecar, metadata('file')],
    [join(runtimeRoot, 'sidecar.py'), metadata('file')],
    ['/usr/bin/python3', metadata('file', 0o755)],
  ])
  for (const path of options.absent ?? []) files.delete(path)
  for (const [path, value] of options.metadata ?? []) files.set(path, value)
  const missing = path => Object.assign(new Error('synthetic missing file'), { code: 'ENOENT', path })
  const reads = [], calls = [], warnings = [], infos = []
  let resolveDone, rejectDone
  const done = new Promise((resolve, reject) => { resolveDone = resolve; rejectDone = reject })
  let rejectionConsumers = 0
  const then = done.then.bind(done)
  done.then = (fulfilled, rejected) => {
    if (typeof rejected === 'function') rejectionConsumers++
    return then(fulfilled, rejected)
  }
  let terminations = 0
  const pipe = { setEncoding() { if (options.pipeError) throw new Error('synthetic pipe setup failure') }, on() {} }
  const handle = { stdout: pipe, stderr: pipe, done, terminate() { terminations++ }, waitForExit: async () => {} }
  const syntheticFs = {
    existsSync(path) { return files.has(path) },
    lstatSync(path) { reads.push(['stat', path]); if (!files.has(path)) throw missing(path); return files.get(path) },
    readFileSync(path) {
      reads.push(['read', path])
      if (!files.has(path)) throw missing(path)
      return path === pinPath ? options.pin ?? environmentPin : Buffer.from('synthetic interpreter bytes')
    },
  }
  const context = vm.createContext({ process: { platform: options.platform ?? 'linux', env: {} }, console, Buffer })
  const module = new vm.SourceTextModule(stripTypeScriptTypes(input, { mode: 'transform' }), {
    context, identifier: sourceUrl.href,
  })
  await module.link(specifier => {
    const exports = specifier === 'node:fs' ? syntheticFs : specifier === 'node:crypto' ? {
      createHash(algorithm) {
        assert.equal(algorithm, 'sha256')
        return { update() { return this }, digest(encoding) { assert.equal(encoding, 'hex'); return options.hash ?? baseline } }
      },
    } : specifier === 'node:path' ? { join } : specifier === '../vendor-paths.ts' ? { AUMA_LIVE_VOICE_ROOT: voiceRoot } : undefined
    assert.ok(exports, `unexpected sidecar import: ${specifier}`)
    return new vm.SyntheticModule(Object.keys(exports), function () {
      for (const [name, value] of Object.entries(exports)) this.setExport(name, value)
    }, { context })
  })
  await module.evaluate()
  const supervisor = new module.namespace.VoiceSidecarSupervisor({
    port: 1937, autoStart: options.autoStart ?? true, runtimeDirectory: runtimeRoot,
  }, {
    exists: syntheticFs.existsSync,
    logger: { info: value => infos.push(String(value)), warn: value => warnings.push(String(value)) },
    subprocess: { spawn(settings) {
      calls.push(settings)
      if (options.spawnError) throw new Error('synthetic spawn failure')
      return handle
    } },
  })
  return { supervisor, reads, calls, warnings, infos, files, get terminations() { return terminations },
    get rejectionConsumers() { return rejectionConsumers },
    async exit(outcome = { exitCode: 1 }) { resolveDone(outcome); await Promise.resolve(); await Promise.resolve() },
    async reject() { rejectDone(new Error('synthetic child failure')); await Promise.resolve(); await Promise.resolve() },
  }
}

async function refused(options, input = source, { spawned = false } = {}) {
  const runtime = await fixture(options, input)
  assert.doesNotThrow(() => runtime.supervisor.start())
  assert.equal(runtime.calls.length, spawned ? 1 : 0)
  const status = runtime.supervisor.status()
  assert.equal(status.available, false)
  assert.equal(status.message, unavailableMessage)
  assert.match(status.code, /^voice-[a-z-]+$/u)
  if (options.code) assert.equal(status.code, options.code)
  assert.equal(runtime.warnings.length, 1)
  assert.ok(runtime.warnings[0].includes(status.code), 'one warning names the unavailable stage')
  runtime.supervisor.start()
  assert.equal(runtime.warnings.length, 1, 'repeated start does not repeat the installation warning')
  assert.equal(runtime.calls.length, spawned ? 2 : 0, 'repeated refusal remains contained')
  return runtime
}

const missingCases = [
  ['Linux pin', { absent: [pinPath], code: 'voice-pin-unavailable' }],
  ['Linux runtime', { absent: [runtimeRoot], code: 'voice-runtime-unavailable' }],
  ['Linux venv', { absent: [executable], code: 'voice-venv-unavailable' }],
  ['Linux models', { absent: [models], code: 'voice-models-unavailable' }],
  ['Linux launcher', { absent: [launcher], code: 'voice-launcher-unavailable' }],
  ['Linux OS interpreter', { absent: ['/usr/bin/python3'], code: 'voice-interpreter-invalid' }],
  ['macOS runtime', { platform: 'darwin', absent: [runtimeRoot], code: 'voice-runtime-unavailable' }],
  ['macOS venv', { platform: 'darwin', absent: [executable], code: 'voice-venv-unavailable' }],
  ['macOS models', { platform: 'darwin', absent: [models], code: 'voice-models-unavailable' }],
  ['macOS script', { platform: 'darwin', absent: [sidecar], code: 'voice-source-unavailable' }],
  ['Linux runtime script', { absent: [join(runtimeRoot, 'sidecar.py')], code: 'voice-source-unavailable' }],
]

test('missing optional installation components disable voice with one named warning', async () => {
  for (const [label, options] of missingCases) {
    try { await refused(options) } catch (cause) { throw new Error(`${label}: ${cause.message}`, { cause }) }
  }
})

const integrityCases = [
  ['OS interpreter digest', { hash: '0'.repeat(64) }, `baselineHash !== '${baseline}'`],
  ['runtime is directory', { metadata: [[runtimeRoot, metadata('file', 0o600)]] }, '!root.isDirectory()'],
  ['runtime is private', { metadata: [[runtimeRoot, metadata('directory', 0o775)]] }, '(root.mode & 0o077) !== 0'],
  ['launcher is regular file', { metadata: [[launcher, metadata('symlink')]] }, '!launcherMetadata.isFile()'],
  ['launcher is root owned', { metadata: [[launcher, metadata('file', 0o644, 1)]] }, 'launcherMetadata.uid !== 0'],
  ['launcher is immutable to service', { metadata: [[launcher, metadata('file', 0o664)]] }, '(launcherMetadata.mode & 0o022) !== 0'],
  ['pin is regular file', { metadata: [[pinPath, metadata('symlink')]] }, '!pin.isFile()'],
  ['pin is root owned', { metadata: [[pinPath, metadata('file', 0o644, 1)]] }, 'pin.uid !== 0'],
  ['pin is immutable to service', { metadata: [[pinPath, metadata('file', 0o664)]] }, '(pin.mode & 0o022) !== 0'],
  ['pin has exact digest syntax', { pin: 'invalid pin' }, '!/^[a-f0-9]{64}$/.test(expected)'],
]

test('every existing Linux integrity check still refuses before spawn', async () => {
  for (const [label, options] of integrityCases) {
    try { await refused(options) } catch (cause) { throw new Error(`${label}: ${cause.message}`, { cause }) }
  }
})

test('spawn failure is caught and named once', async () => {
  await refused({ spawnError: true }, source, { spawned: true })
})

async function partialHandleIsTerminated(input = source) {
  const runtime = await refused({ pipeError: true }, input, { spawned: true })
  assert.equal(runtime.terminations, 2, 'each acquired handle is terminated if startup fails after spawn')
  return runtime
}

test('a partial subprocess startup is terminated at the caught boundary', async () => {
  await partialHandleIsTerminated()
})

async function partialCompletionIsConsumed(input = source) {
  const runtime = await partialHandleIsTerminated(input)
  assert.equal(runtime.rejectionConsumers, 2, 'partial startup consumes each terminated handle completion rejection')
  await runtime.reject()
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(runtime.supervisor.status().available, false)
  assert.equal(runtime.warnings.length, 1)
}

test('a rejected completion after partial startup is consumed', async () => {
  await partialCompletionIsConsumed()
})

test('valid Linux and macOS launch use the existing interpreter and script paths', async () => {
  for (const platform of ['linux', 'darwin']) {
    const runtime = await fixture({ platform })
    runtime.supervisor.start()
    assert.equal(runtime.calls.length, 1)
    assert.deepEqual(Array.from(runtime.calls[0].argv), platform === 'linux'
      ? ['/usr/bin/python3', '-I', '-B', launcher, runtimeRoot, environmentPin] : [executable, sidecar])
    assert.equal(runtime.calls[0].cwd, voiceRoot)
    assert.equal(runtime.calls[0].env.AUKORA_VOICE_MODELS_DIR, models)
    assert.equal(runtime.calls[0].env.HF_HUB_OFFLINE, '1')
    assert.equal(runtime.calls[0].env.TRANSFORMERS_OFFLINE, '1')
    assert.equal(runtime.supervisor.status().available, true)
    runtime.supervisor.start()
    assert.equal(runtime.calls.length, 1)
    await runtime.exit()
    assert.equal(runtime.supervisor.status().available, false, 'a launcher or sidecar exit disables voice')
  }
})

test('a failed subprocess completion disables voice with a sanitized warning', async () => {
  const runtime = await fixture()
  runtime.supervisor.start()
  await runtime.reject()
  assert.equal(runtime.supervisor.status().available, false)
  assert.equal(runtime.supervisor.status().code, 'voice-sidecar-failed')
  assert.equal(runtime.warnings.length, 1)
  assert.ok(!runtime.warnings[0].includes('synthetic child failure'))
})

test('unmanaged voice reports unknown installation state without host reads', async () => {
  const runtime = await fixture({ autoStart: false })
  runtime.supervisor.start()
  assert.equal(runtime.supervisor.status().available, null)
  assert.equal(runtime.calls.length, 0)
  assert.equal(runtime.reads.length, 0)
})

test('removing any Linux integrity guard is detected by the executable fixture', async () => {
  let killed = 0
  for (const [label, options, before] of integrityCases) {
    assert.ok(source.includes(before), `integrity mutation anchor: ${label}`)
    await assert.rejects(refused(options, source.replace(before, 'false')), assert.AssertionError, `surviving mutant: ${label}`)
    killed++
  }
  console.log(`MUTATION voice-sidecar-integrity: ${killed}/${integrityCases.length} killed`)
})

test('removing the caught startup boundary or optional component probes is detected', async () => {
  const mutants = [
    ['startup catch', '    } catch {\n      const handle = this.handle', '    } finally {\n      const handle = this.handle', { absent: [pinPath] }],
    ['venv existence', 'if (!this.exists(join(runtimeDirectory, relative)))', 'if (false)', { absent: [executable] }],
    ['models existence', 'if (!this.exists(join(runtimeDirectory, relative)))', 'if (false)', { absent: [models] }],
    ['source existence', "if (!this.exists(process.platform === 'linux' ? join(runtimeDirectory, 'sidecar.py') : argv[1]!))", 'if (false)', { absent: [join(runtimeRoot, 'sidecar.py')] }],
    ['one warning', 'if (this.warned) return', 'if (false) return', { absent: [pinPath] }],
  ]
  for (const [label, before, after, options] of mutants) {
    assert.ok(source.includes(before), `optional voice mutation anchor: ${label}`)
    await assert.rejects(refused(options, source.replace(before, after)), assert.AssertionError, `surviving mutant: ${label}`)
  }
  const cleanup = '        handle?.terminate()'
  assert.ok(source.includes(cleanup), 'partial handle cleanup mutation anchor')
  await assert.rejects(partialHandleIsTerminated(source.replace(cleanup, '        undefined')), assert.AssertionError)
  const consume = 'void handle?.done.catch(() => {})'
  assert.ok(source.includes(consume), 'partial completion consumer mutation anchor')
  await assert.rejects(partialCompletionIsConsumed(source.replace(consume, 'void undefined')), assert.AssertionError)
  console.log(`MUTATION voice-sidecar-optional: ${mutants.length + 2}/${mutants.length + 2} killed`)
})
