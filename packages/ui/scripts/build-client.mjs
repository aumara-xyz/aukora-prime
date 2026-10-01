import { readFile, writeFile, mkdir, readdir, lstat, mkdtemp, cp, realpath, symlink, glob } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { dirname, resolve, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { faces } from '../adapters/mount-plan.mjs'

// Prime's already materialized pinned third-party harness is the sole build input.
// The source tree and frozen face bytes are never written; all compilation happens in a fresh overlay.
const ui = resolve(fileURLToPath(new URL('../', import.meta.url)))
const entries = [
  ...faces.map(face => ({ ...face, folder: `aukora-face-${face.face}` })),
  { face: 'prime-authority', folder: 'aukora-prime-authority', id: '@aukora/prime-authority-ui', directory: new URL('../prime-authority/', import.meta.url) },
]
const repo = resolve(ui, '../..')
const args = process.argv.slice(2)
const flags = {}
for (let i = 0; i < args.length; i += 2) {
  if (!['--dsh', '--output', '--work', '--only'].includes(args[i]) || !args[i + 1]) throw new Error('usage: build-client.mjs --dsh <pinned-Prime-harness> [--output <empty-dir>] [--work <owned-dir>] [--only prime-authority]')
  flags[args[i]] = args[i + 1]
}
if (!flags['--dsh']) throw new Error('ui-build:pinned-harness-required')
if (flags['--only'] && flags['--only'] !== 'prime-authority') throw new Error('ui-build:unknown-selection')
const selected = flags['--only'] ? entries.filter(entry => entry.face === flags['--only']) : entries
const dshInput = resolve(flags['--dsh'])
if ((await lstat(dshInput)).isSymbolicLink()) throw new Error('ui-build:symlinked-harness-refused')
const dsh = await realpath(dshInput)
const workRoot = resolve(flags['--work'] ?? join(repo, '.runtime'))
const output = resolve(flags['--output'] ?? join(repo, '.runtime/client-dist'))
for (const path of [workRoot, output]) {
  if (path === dsh || path.startsWith(dsh + sep) || dsh.startsWith(path + sep) ||
      path === ui || ui.startsWith(path + sep) || path.startsWith(join(ui, 'faces') + sep)) {
    throw new Error('ui-build:overlapping-input-output-refused')
  }
}
const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const compatibility = JSON.parse(await readFile(join(ui, 'compatibility.json'), 'utf8'))
const receiptPath = join(dsh, '.dsh-build/pinned-harness-build.json')
const receiptBytes = await readFile(receiptPath)
const receipt = JSON.parse(receiptBytes)
const upstream = receipt.inputs?.upstream
for (const [key, expected] of Object.entries({
  commit: compatibility.dsh.commit, archiveSha256: compatibility.dsh.archiveSha256,
  lockfileSha256: compatibility.dsh.lockfileSha256, packageManager: compatibility.dsh.packageManager,
})) if (upstream?.[key] !== expected) throw new Error(`ui-build:harness-pin-mismatch:${key}`)
const patchPins = compatibility.dsh.localPatches.map(p => p.file + ':' + p.sha256).sort()
if (JSON.stringify((receipt.inputs.localPatches ?? []).map(p => p.file + ':' + p.sha256).sort()) !== JSON.stringify(patchPins)) {
  throw new Error('ui-build:harness-patch-mismatch')
}
const lockBefore = digest(await readFile(join(dsh, 'pnpm-lock.yaml')))
if (lockBefore !== compatibility.dsh.lockfileSha256) throw new Error('ui-build:source-lock-mismatch')
await mkdir(workRoot, { recursive: true })
const work = await mkdtemp(join(workRoot, 'ui-build-'))
const overlay = join(work, 'dsh')
await mkdir(dirname(output), { recursive: true })
await mkdir(output, { recursive: true })
if ((await readdir(output)).length) throw new Error('ui-build:output-must-be-empty')

function run(command, argv, cwd, label) {
  return new Promise((accept, reject) => {
    const process = spawn(command, argv, { cwd, env: {
      ...globalThis.process.env, CI: 'true', LEFTHOOK: '0', NODE_ENV: 'production',
    }, stdio: ['ignore', 'pipe', 'pipe'] })
    let tail = ''
    for (const stream of [process.stdout, process.stderr]) stream.on('data', part => {
      tail = (tail + part.toString()).slice(-8000)
    })
    process.on('error', reject)
    process.on('exit', code => code === 0 ? accept(tail) : reject(new Error(`${label}:exit-${code}\n${tail}`)))
  })
}
console.log(`UI build overlay ${work}`)
if (globalThis.process.platform === 'darwin') await run('/bin/cp', ['-Rc', dsh, overlay], work, 'ui-build:clone')
else await cp(dsh, overlay, { recursive: true, preserveTimestamps: true, verbatimSymlinks: true })
for (const face of entries) {
  const target = join(overlay, 'packages/client', face.folder)
  await cp(fileURLToPath(face.directory), target, { recursive: true })
  // An overlay-only adapter invokes the original upstream preset with host output disabled.
  await writeFile(join(target, '.prime-client.config.ts'),
    `import { clientBundle } from '../tsdown.client.ts'\nexport default clientBundle(${JSON.stringify(face.id)}, [], { hostPhase: true })\n`)
}
const pnpmVersion = (await run('pnpm', ['--version'], overlay, 'ui-build:pnpm-version')).trim()
if ('pnpm@' + pnpmVersion !== compatibility.dsh.packageManager) throw new Error('ui-build:package-manager-mismatch')
console.log('UI build linking existing pinned workspace dependencies, without install')
const workspace = new Map()
for await (const metadataPath of glob(['packages/*/*/package.json', 'vendor/*/package.json'], { cwd: overlay })) {
  const path = join(overlay, metadataPath)
  const metadata = JSON.parse(await readFile(path, 'utf8'))
  workspace.set(metadata.name, dirname(path))
}
const dependencies = {}
for (const face of entries) {
  const directory = join(overlay, 'packages/client', face.folder)
  const metadata = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'))
  const declared = { ...metadata.dependencies, ...metadata.peerDependencies, ...metadata.devDependencies }
  for (const name of Object.keys(declared)) {
    let target = workspace.get(name)
    if (!target) {
      for (const prefix of ['node_modules', 'node_modules/.pnpm/node_modules']) {
        try { target = await realpath(join(overlay, prefix, name)); break } catch { /* Try the next pinned module seat. */ }
      }
    }
    // Test-only donor declarations do not participate in a client-only compilation.
    if (!target && name.startsWith('@testing-library/')) continue
    if (!target || !target.startsWith(overlay + sep)) throw new Error(`ui-build:dependency-not-in-pinned-closure:${name}`)
    const dependency = JSON.parse(await readFile(join(target, 'package.json'), 'utf8'))
    const expected = compatibility.resolved_build_dependencies?.[name]
    if (expected && dependency.version !== expected) throw new Error(`ui-build:dependency-version-mismatch:${name}`)
    dependencies[name] = dependency.version
    const link = join(directory, 'node_modules', name)
    await mkdir(dirname(link), { recursive: true })
    await symlink(relative(dirname(link), target), link, 'dir')
  }
}
const targets = []
for (const face of selected) {
  const directory = join(overlay, 'packages/client', face.folder)
  const config = (await readdir(directory)).includes('tsconfig.client.json') ? 'tsconfig.client.json' : 'tsconfig.json'
  targets.push(join(directory, config))
}
console.log('UI build type-checking exact face sources')
await run('node', ['--max-old-space-size=3072', join(overlay, 'node_modules/typescript/bin/tsc'), '-b', ...targets], overlay, 'ui-build:client-typecheck')
const authorityDirectory = join(overlay, 'packages/client/aukora-prime-authority')
await cp(join(authorityDirectory, 'src/client/controller.mjs'), join(authorityDirectory, 'lib/types/client/controller.mjs'))
await mkdir(join(authorityDirectory, 'adapters'))
for (const adapter of ['transport.mjs', 'passkey.mjs']) await cp(join(ui, 'adapters', adapter), join(authorityDirectory, 'adapters', adapter))
const artifacts = []
for (const face of selected) {
  console.log(`UI build bundling ${face.face}`)
  const directory = join(overlay, 'packages/client', face.folder)
  await run(join(overlay, 'node_modules/.bin/tsdown'), ['--config', '.prime-client.config.ts', '--env.DSH_BUILD_FACE', 'client'], directory, `ui-build:bundle:${face.face}`)
  const original = await readFile(join(directory, 'lib/client.js'), 'utf8')
  // Same inert home-path normalization as the donor build, applied only to generated bytes.
  const code = original.replace(/\/Users\/[^\s\n]*?\/\.runtime\/[^\s\n]*?\/packages\//g, 'packages/')
  const destination = join(output, face.face)
  await mkdir(destination)
  await writeFile(join(destination, 'client.js'), code)
  const hasMap = (await readdir(join(directory, 'lib'))).includes('client.js.map')
  if (hasMap) await cp(join(directory, 'lib/client.js.map'), join(destination, 'client.js.map'))
  const metadata = await readFile(join(directory, 'package.json'))
  await writeFile(join(destination, 'package.json'), metadata)
  if (face.face === 'prime-authority') await cp(join(directory, 'lib/index.js'), join(destination, 'index.js'))
  artifacts.push({ face: face.face, id: face.id, path: relative(output, join(destination, 'client.js')),
    bytes: Buffer.byteLength(code), sha256: digest(Buffer.from(code)) })
  if (hasMap) {
    const map = await readFile(join(destination, 'client.js.map'))
    artifacts.push({ face: face.face, id: face.id, path: relative(output, join(destination, 'client.js.map')),
      bytes: map.length, sha256: digest(map) })
  }
}
if (digest(await readFile(receiptPath)) !== digest(receiptBytes) || digest(await readFile(join(dsh, 'pnpm-lock.yaml'))) !== lockBefore) {
  throw new Error('ui-build:input-harness-changed')
}
await writeFile(join(output, 'build.json'), JSON.stringify({ version: 1, source_commit: compatibility.dsh.commit,
  harness_receipt_sha256: digest(receiptBytes), source_lock_sha256: lockBefore,
  overlay_lock_sha256: digest(await readFile(join(overlay, 'pnpm-lock.yaml'))), dependency_versions: dependencies,
  mode: 'client-only', legacy_hosts_mounted: false, artifacts }, null, 2) + '\n')
console.log(JSON.stringify({ result: 'PASS', output, faces: selected.filter(entry => entry.face !== 'prime-authority').length,
  separate_plugins: selected.filter(entry => entry.face === 'prime-authority').length, source_faces_changed: false,
  harness_lock_changed: false, runtime_parity: 'UNPERFORMED: browser boot required' }))
