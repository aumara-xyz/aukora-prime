// Release mounts obey Cordis injection declarations with optional host files absent.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs, { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { isBuiltin, registerHooks, syncBuiltinESMExports } from 'node:module'
import os from 'node:os'
import childProcess from 'node:child_process'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import vm from 'node:vm'
import { generated, root, rows, sourcePath } from './helpers/release-composition.mjs'
import { normalizedPlugin, requiredInject, strictContext } from './helpers/release-context.mjs'

const missingHarness = reason => Object.assign(new Error(`UNPERFORMED: ${reason}`), { code: 'RELEASE_HARNESS_ABSENT' })
const inTree = (path, base) => path === resolve(base) || path.startsWith(`${resolve(base)}/`)
let home, built

function declaredPackage(name, parentURL) {
  const file = fileURL(parentURL ?? '')
  if (!file || !inTree(file, root)) return false
  for (let directory = dirname(file); inTree(directory, root); directory = dirname(directory)) {
    const manifest = join(directory, 'package.json')
    if (!existsSync(manifest)) continue
    const pkg = JSON.parse(readFileSync(manifest, 'utf8'))
    if (['dependencies', 'peerDependencies', 'devDependencies'].some(key => Object.hasOwn(pkg[key] ?? {}, name))) return true
  }
  return false
}

// Node selects package formats and conditional exports from the release's dependency tree.
function releaseResolver(nextResolve, packages) {
  return (specifier, context) => {
    const parentURL = context.parentURL
    if (isBuiltin(specifier)) return nextResolve(specifier, context)
    const file = specifier.startsWith('file:') ? fileURLToPath(specifier)
      : specifier.startsWith('.') ? fileURLToPath(new URL(specifier, context.parentURL))
        : specifier.startsWith('/') ? specifier : undefined
    if (file) {
      const path = relative(root, file)
      if (!existsSync(file) && inTree(file, root) && /^(?:packages|apps)\//u.test(path)) {
        if (!built) throw missingHarness(`built pinned harness required for ${path}`)
        return nextResolve(pathToFileURL(join(built, path)).href, context)
      }
      return nextResolve(specifier, context)
    }
    // Harness-internal imports retain their own installed dependency versions.
    if ((built && parentURL?.startsWith(pathToFileURL(`${built}/`).href))
      || parentURL?.startsWith(pathToFileURL(join(root, 'vendor/authority/deps/')).href)) return nextResolve(specifier, context)
    const name = specifier.split('/').slice(0, specifier.startsWith('@') ? 2 : 1).join('/')
    const directory = packages.get(name)
    if (Array.isArray(directory)) throw Object.assign(new Error(`release-load:dependency-ambiguous: ${name}: ${directory.length} installed versions`),
      { code: 'RELEASE_DEPENDENCY_AMBIGUOUS' })
    if (directory) {
      const pkg = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'))
      if (pkg.exports) return nextResolve(specifier, { ...context, parentURL: pathToFileURL(join(directory, 'package.json')).href })
      const suffix = specifier.slice(name.length + 1)
      return nextResolve(pathToFileURL(join(directory, suffix || pkg.main || 'index.js')).href, context)
    }
    let originalError
    if (!built) {
      try { return nextResolve(specifier, context) }
      catch (error) {
        if (error.code !== 'ERR_MODULE_NOT_FOUND' && error.code !== 'MODULE_NOT_FOUND') throw error
        originalError = error
      }
    }
    // The committed authority closure is available even without a harness build.
    try { return nextResolve(specifier, { ...context, parentURL: pathToFileURL(join(root, 'vendor/authority/deps/package.json')).href }) }
    catch (error) {
      if (error.code !== 'ERR_MODULE_NOT_FOUND' && error.code !== 'MODULE_NOT_FOUND') throw error
      if (!built) {
        if (declaredPackage(name, parentURL)) throw missingHarness(`built pinned harness dependency required: ${specifier}`)
        throw originalError ?? error
      }
      throw Object.assign(new Error(`release-load:dependency-unresolved: ${specifier}`), { code: 'RELEASE_DEPENDENCY_UNRESOLVED' })
    }
  }
}

function releasePackages() {
  const packages = new Map()
  if (!built) return packages
  const add = directory => {
    const manifest = join(directory, 'package.json')
    if (existsSync(manifest)) {
      const name = JSON.parse(readFileSync(manifest, 'utf8')).name
      if (!packages.has(name)) packages.set(name, directory)
    }
  }
  for (const base of ['node_modules', 'vendor', 'packages']) {
    for (const entry of readdirSync(join(built, base), { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue
      const directory = join(built, base, entry.name)
      add(directory)
      if (entry.isDirectory()) for (const child of readdirSync(directory, { withFileTypes: true })) {
        if (child.isDirectory() || child.isSymbolicLink()) add(join(directory, child.name))
      }
    }
  }
  // As in materialization, a dependency found only in pnpm's store must be unambiguous.
  const store = join(built, 'node_modules/.pnpm')
  const candidates = new Map()
  for (const entry of readdirSync(store).filter(name => !name.startsWith('.') && name.includes('@'))) {
    const name = entry.slice(0, entry.indexOf('@', 1)).replace('+', '/')
    const directory = join(store, entry, 'node_modules', name)
    if (!existsSync(join(directory, 'package.json')) || packages.has(name)) continue
    candidates.set(name, [...(candidates.get(name) ?? []), directory])
  }
  for (const [name, directories] of candidates) {
    packages.set(name, directories.length === 1 ? directories[0] : directories)
  }
  return packages
}

function absentHostFiles(namespace, promises = false) {
  const result = { ...namespace }
  const visible = value => {
    if (typeof value === 'number') return true
    const path = value instanceof URL ? fileURLToPath(value) : resolve(home, String(value))
    // The voice plugin checks the actual OS interpreter's pin before optional provisioning.
    if (path === '/usr/bin/python3') return true
    return [root, home, built].filter(Boolean).some(base => inTree(path, base))
  }
  for (const name of ['access', 'exists', 'lstat', 'stat', 'readFile', 'readdir', 'readlink', 'realpath', 'open']) {
    for (const key of promises ? [name] : [name, `${name}Sync`]) {
      if (typeof namespace[key] !== 'function') continue
      result[key] = (path, ...args) => {
        if (visible(path)) return namespace[key](path, ...args)
        if (key === 'existsSync') return false
        const error = Object.assign(new Error(`ENOENT: optional host file absent: ${String(path)}`), { code: 'ENOENT', path: String(path) })
        if (promises) return Promise.reject(error)
        const callback = args.at(-1)
        if (typeof callback === 'function') { callback(key === 'exists' ? false : error); return }
        throw error
      }
    }
  }
  if (namespace.promises) result.promises = absentHostFiles(namespace.promises, true)
  return result
}

function installFixture(replacement) {
  process.chdir(home)
  os.homedir = () => home
  const { promises, ...files } = absentHostFiles({ ...fs, promises: { ...fs.promises } })
  for (const [name, value] of Object.entries(files)) if (value !== fs[name]) fs[name] = value
  for (const [name, value] of Object.entries(promises)) if (value !== fs.promises[name]) fs.promises[name] = value
  const unavailable = () => { throw new Error('release-load:child-process-unavailable') }
  for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) childProcess[name] = unavailable
  childProcess.execFile = (...args) => {
    const callback = args.at(-1)
    if (typeof callback !== 'function') return unavailable()
    setImmediate(() => callback(Object.assign(new Error('optional executable absent'), { code: 'ENOENT' }), '', ''))
  }
  globalThis.fetch = () => Promise.reject(new Error('release-load:network-refused'))
  for (const method of ['log', 'info', 'warn', 'error', 'debug']) console[method] = () => {}
  syncBuiltinESMExports()
  const packages = releasePackages()
  registerHooks({
    resolve(specifier, context, nextResolve) { return releaseResolver(nextResolve, packages)(specifier, context) },
    load(url, context, nextLoad) {
      if (replacement && replacement.path === fileURL(url)) return { format: 'module', source: replacement.code, shortCircuit: true }
      return nextLoad(url, context)
    },
  })
}

function fileURL(url) {
  return url.startsWith('file:') ? fileURLToPath(url) : undefined
}

function services() {
  const noop = () => () => {}
  return {
    goals: { get() {}, resume() {} }, agents: { roots: () => [], get() {} },
    tools: { register: noop, guard: noop, intercept: noop, list: () => [] },
    webServer: { host: '127.0.0.1', register: noop, registerUpgrade: noop, use: noop, get: noop, post: noop,
      router: { get: noop, post: noop, all: noop } },
    connection: { register: noop, registerMethod: noop, registerEvent: noop, broadcast() {} },
    credentials: { get() {} }, sessions: { list: () => [], get() {} },
    subprocess: { register: noop }, subagents: { registerProvider: noop },
  }
}

async function applyRow(row, replacement) {
  const path = sourcePath(row.name)
  installFixture(replacement)
  const plugin = normalizedPlugin(await import(pathToFileURL(path).href))
  const recorder = strictContext(plugin.inject, services(), { runPlugins: row.id === 'aukora-seatbelt' })
  try {
    let config = row.config
    if (plugin.Config?.['~standard']) {
      const result = await plugin.Config['~standard'].validate(config)
      assert.equal(result.issues, undefined, `${row.id}: release config rejected`)
      config = result.value
    }
    if (row.id === 'aukora-seatbelt') {
      if (!built) throw missingHarness('seatbelt provider requires the built pinned harness')
      // Its default provider path is relocated to the same package in the harness build.
      if (config.providerModule === undefined) config = { ...config, providerModule: join(built, 'packages/sandbox/sandbox-local/lib/index.js') }
    }
    if (typeof plugin === 'function') {
      if (/^class\s/u.test(Function.prototype.toString.call(plugin))) new plugin(recorder.ctx, config)
      else await plugin(recorder.ctx, config)
    } else await plugin.apply(recorder.ctx, config)
    await recorder.drain()
    assert.deepEqual(recorder.refusals, [], `${row.id}: undeclared service access was swallowed`)
  } finally {
    await recorder.dispose()
  }
}

if (process.argv.includes('--release-row')) {
  const input = JSON.parse(readFileSync(0, 'utf8'))
  ;({ home, built } = input)
  let result
  try { await applyRow(input.row, input.replacement); result = { status: 'PASS' } }
  catch (error) {
    error = error?.errors?.[0] ?? error
    result = { status: error?.code === 'RELEASE_HARNESS_ABSENT' ? 'UNPERFORMED' : 'FAIL', code: error?.code, message: error?.message ?? String(error) }
  }
  process.stdout.write(JSON.stringify(result))
  process.exit(result.status === 'PASS' ? 0 : result.status === 'UNPERFORMED' ? 2 : 1)
}

home = mkdtempSync(join(root, '.release-load-'))
// Required host configuration, not an optional file: on Linux Kira refuses to run memory for nobody, so a node
// always has an owner deployment overlay. The test supplies a synthetic one (the subject is random, not a person).
fs.mkdirSync(join(home, 'support'), { recursive: true, mode: 0o700 })
fs.writeFileSync(join(home, 'support', 'kira-deployment-overlay.patch.yml'), ['- id: aukora-kira', '  config:', '    retrieval: lexical',
  '    memoryOwner:', `      stateDir: ${join(home, 'kira-memory')}`, `      subject: aukora:1:${'5a'.repeat(32)}`, '      permittedPrivacy: [local]', ''].join('\n'), { mode: 0o600 })
built = process.argv.includes('--without-harness') ? undefined
  : [process.env.AUKORA_DSH_BUILD, join(root, 'vendor/dsh')].filter(Boolean)
    .map(path => resolve(path)).find(path => existsSync(join(path, 'vendor/cordis/lib/index.js')))
const fixture = generated(undefined, { home, includeUpstream: false, withLegacyRelay: process.argv.includes('--with-legacy-relay') })
const merged = new Map()
for (const row of rows(fixture.patches['aukora-composition.patch.yml'], 'aukora-composition.patch.yml', { home, cwd: home })) {
  merged.set(row.id, { ...merged.get(row.id), ...row })
}
const mounts = [...merged.values()].filter(row => row.name && row.disabled !== true)

// Each row gets native module loading in a fresh process without host state or credentials.
async function exercise(row, replacement) {
  const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--release-row'], {
    cwd: root, input: JSON.stringify({ home, built, row, replacement }), encoding: 'utf8', timeout: 5000,
    env: { HOME: home, DSH_HOME: home, AUKORA_SUPPORT_ROOT: join(home, 'support') },
  })
  assert.equal(child.error, undefined, `${row.id}: row process did not finish`)
  assert.equal(child.signal, null, `${row.id}: row process signalled`)
  let result
  try { result = JSON.parse(child.stdout) }
  catch { throw new Error(`release-load:invalid-row-result: ${row.id}: ${child.stderr}`) }
  assert.equal(child.status, result.status === 'PASS' ? 0 : result.status === 'UNPERFORMED' ? 2 : 1)
  if (result.status !== 'PASS') throw Object.assign(new Error(result.message), { code: result.code })
}

test.after(() => rmSync(home, { recursive: true, force: true }))
let passed = 0, failed = 0, unperformed = 0
for (const row of mounts) test(`${row.label}: ${row.id} loads with release config and no optional host files`, async t => {
  try { await exercise(row); passed++ }
  catch (error) {
    if (error.code !== 'RELEASE_HARNESS_ABSENT') { failed++; throw error }
    unperformed++
    t.diagnostic(error.message)
    t.skip(error.message)
  }
})

test('release goal state is wired and strict load kills missing inject, load, apply and module mutants', async t => {
  const row = mounts.find(row => row.id === 'aukora-goal-resume')
  assert.equal(row.config.stateDir, join(home, 'goal-resume-state'))
  const path = sourcePath(row.name), original = readFileSync(path, 'utf8')
  const declaration = "export const inject = ['goals', 'agents'];"
  assert.equal(original.split(declaration).length, 2)
  await assert.rejects(exercise(row, { path, code: original.replace(declaration, 'export const inject = [];') }),
    /undeclared service access was swallowed/u)
  await assert.rejects(exercise(row, { path, code: original.replace('logger = ctx.logger;', 'logger = ctx.log;') }),
    /undeclared service access was swallowed/u)
  const entry = 'export function apply(ctx, config = {}) {'
  assert.equal(original.split(entry).length, 2)
  await assert.rejects(exercise(row, { path, code: original.replace(entry, `${entry}\n  throw new Error('release-apply-mutant');`) }),
    /release-apply-mutant/u)
  await assert.rejects(exercise(row, { path, code: `throw new Error('release-import-mutant');\n${original}` }),
    /release-import-mutant/u)
  await assert.rejects(exercise({ ...row, name: './plugins/aukora-goal-resume/lib/missing-module.mjs' }),
    { code: 'ERR_MODULE_NOT_FOUND' })
  await assert.rejects(exercise(row, { path, code: `import 'release-load-deliberately-missing-package';\n${original}` }),
    error => error.code !== 'RELEASE_HARNESS_ABSENT' && /release-load-deliberately-missing-package/u.test(error.message))
  if (built) {
    const seatbelt = mounts.find(row => row.id === 'aukora-seatbelt')
    if (seatbelt) await assert.rejects(exercise({ ...seatbelt, config: { ...seatbelt.config, providerModule: join(home, 'missing-provider.mjs') } }),
      /stock sandbox provider was not found/u)
  }
  await exercise(row, { path, code: `
    import assert from 'assert/strict';
    import { fileURLToPath } from 'url';
    import fs from 'fs';
    import { homedir } from 'os';
    export function apply() {
      assert.equal(fileURLToPath(import.meta.url), ${JSON.stringify(path)});
      assert.equal(homedir(), ${JSON.stringify(home)});
      assert.equal(fs.existsSync('/etc/aukora/auma-live-voice/environment.sha256'), false);
    }
  ` })
  t.diagnostic('native bare builtins: url, fs, os PASS')
  t.diagnostic('MUTATION CAUGHT missing inject, undeclared logger, throwing apply, throwing load, missing module, missing package')
})
test('release resolver preserves builtins and refuses ambiguous installed dependencies; removals fail controls', t => {
  const context = { parentURL: import.meta.url }
  const delegate = (specifier, parent) => ({ specifier, parent })
  const builtinControl = factory => assert.deepEqual(factory(delegate, new Map())('url', context), { specifier: 'url', parent: context })
  const ambiguousControl = factory => assert.throws(() => factory(delegate, new Map([['zod', ['/one', '/two']]]))('zod', context),
    { code: 'RELEASE_DEPENDENCY_AMBIGUOUS' })
  builtinControl(releaseResolver)
  ambiguousControl(releaseResolver)
  const text = releaseResolver.toString()
  for (const [guard, control] of [
    ['if (isBuiltin(specifier))', builtinControl],
    ['if (Array.isArray(directory))', ambiguousControl],
  ]) {
    assert.equal(text.split(guard).length, 2)
    const replacement = guard.includes('isBuiltin')
      ? "if (isBuiltin(specifier)) return nextResolve(pathToFileURL(resolve(root, specifier)).href, context); if (false)"
      : 'if (false)'
    const mutant = vm.runInNewContext(`(${text.replace(guard, replacement)})`, {
      isBuiltin, fileURLToPath, pathToFileURL, existsSync, readFileSync, relative, root, inTree, built, join, missingHarness, declaredPackage,
      resolve,
    })
    assert.throws(() => control(mutant), { code: 'ERR_ASSERTION' })
    t.diagnostic(`MUTATION CAUGHT ${guard}`)
  }
})
test('recorder enforces service reads, inherited injection, optional scopes and immediate effects', async t => {
  const selected = { inject: { needed: {} }, apply() {} }
  assert.equal(normalizedPlugin({ default: { __esModule: true, default: selected } }), selected)
  assert.deepEqual(requiredInject(selected), ['needed'])
  const recorder = strictContext(selected.inject, { needed: {}, child: {} })
  assert.equal(recorder.ctx.needed, recorder.ctx.get('needed'))
  assert.equal(recorder.ctx.get('missing'), undefined)
  assert.throws(() => recorder.ctx.log?.info(), /cannot get property "log" without inject/u)
  let nested = false, absent = false, setup = false, stopped = false
  recorder.ctx.inject(['child'], child => { assert.equal(child.needed, recorder.ctx.needed); nested = true })
  recorder.ctx.inject(['missing'], () => { absent = true })
  recorder.ctx.effect(async () => { setup = true; return () => { stopped = true } })
  recorder.ctx.logger.info('core logger')
  assert.equal(setup, true)
  await recorder.drain()
  assert.equal(nested, true)
  assert.equal(absent, false)
  await recorder.dispose()
  assert.equal(stopped, true)
  const helper = readFileSync(new URL('./helpers/release-context.mjs', import.meta.url), 'utf8')
  const guard = 'if (owned.has(key) || declared.has(key)) return store.get(key)'
  assert.equal(helper.split(guard).length, 2)
  const mutant = await import(`data:text/javascript;base64,${Buffer.from(helper.replace(guard, 'return store.get(key)')).toString('base64')}`)
  const control = context => assert.throws(() => context.ctx.log, /cannot get property "log" without inject/u)
  control(strictContext([]))
  assert.throws(() => control(mutant.strictContext([])), { code: 'ERR_ASSERTION' })
  t.diagnostic('MUTATION CAUGHT undeclared-service guard removal')
})
test('optional host file fixture hides existing files outside the release and state roots', t => {
  const control = factory => {
    const files = factory({ existsSync: () => true, readFileSync: () => 'host file' })
    assert.equal(files.existsSync(join(home, 'optional')), true)
    assert.equal(files.readFileSync('/usr/bin/python3'), 'host file')
    assert.equal(files.existsSync('/opt/aukora/optional-host-file'), false)
    assert.throws(() => files.readFileSync('/opt/aukora/optional-host-file'), { code: 'ENOENT' })
  }
  control(absentHostFiles)
  const source = absentHostFiles.toString(), guard = 'if (visible(path))'
  assert.equal(source.split(guard).length, 2)
  const mutant = vm.runInNewContext(`(${source.replace(guard, 'if (true)')})`, { root, home, built, resolve, URL, fileURLToPath, inTree })
  assert.throws(() => control(mutant), { code: 'ERR_ASSERTION' })
  t.diagnostic('MUTATION CAUGHT absent-host-files guard removal')
})
test.after(() => {
  console.log(`release-plugins-load: ${passed} rows PASS; ${failed} FAIL; ${unperformed} UNPERFORMED; native ${process.platform} load/apply only`)
  if (unperformed) console.log(`UNPERFORMED: ${unperformed} release rows require unavailable harness dependencies`)
})
