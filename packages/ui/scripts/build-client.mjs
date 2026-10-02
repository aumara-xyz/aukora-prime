import { readFile, writeFile, mkdir, readdir, lstat, mkdtemp, cp, realpath, symlink, glob, rm } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { dirname, resolve, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { faces } from '../adapters/mount-plan.mjs'
import { snapshotOwnerSources, snapshotOwnerBuildInputs, inputDigest, createOwnerReceipt,
  verifyStableHarness, discoverPinnedWorkspace, compilerCommand, validateBuildDirectories, HARNESS_IDENTITY_PATH, OWNER_CONFIG } from './verify-owner-build.mjs'
import {publishOwnerTypeSources} from './publish-owner-types.mjs'

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
  if (!['--dsh', '--prime-root', '--output', '--work', '--only'].includes(args[i]) || !args[i + 1]) throw new Error('usage: build-client.mjs --dsh <original-pinned-Prime-harness> --prime-root <same-Prime-root> [--output <empty-dir>] [--work <owned-dir>] [--only prime-authority]')
  flags[args[i]] = args[i + 1]
}
if (!flags['--dsh']) throw new Error('ui-build:pinned-harness-required')
if (flags['--only'] && flags['--only'] !== 'prime-authority') throw new Error('ui-build:unknown-selection')
const selected = flags['--only'] ? entries.filter(entry => entry.face === flags['--only']) : entries
const dshInput = resolve(flags['--dsh'])
if ((await lstat(dshInput)).isSymbolicLink()) throw new Error('ui-build:symlinked-harness-refused')
const dsh = await realpath(dshInput)
const primeRoot = resolve(flags['--prime-root'] ?? repo)
const { work:workRoot, output } = await validateBuildDirectories({ uiRoot:ui, dsh,
  work:flags['--work'] ?? join(repo,'.runtime'), output:flags['--output'] ?? join(repo,'.runtime/client-dist') })
const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const compatibility = JSON.parse(await readFile(join(ui, 'compatibility.json'), 'utf8'))
// Verify the successful, original pure harness before creating or populating an
// overlay. The UI overlay is never passed off as a pristine harness.
const verifiedHarness = await verifyStableHarness({ dsh, primeRoot, compatibility })
await run('python3', [join(primeRoot,'scripts/build-dsh.py'),'--verify-built','--root',primeRoot,'--source',dsh], primeRoot, 'ui-build:original-harness')
const originalWorkspace = await discoverPinnedWorkspace(dsh)
for (const directory of originalWorkspace.values()) {
  const path = relative(dsh, join(directory,'package.json')).split(sep).join('/')
  const bytes = await readFile(join(directory,'package.json'))
  const pin = verifiedHarness.document.identity.compilerInputs.find(entry => entry.path === path)
  if (pin?.bytes !== bytes.length || pin.sha256 !== digest(bytes)) throw new Error(`ui-build:workspace-not-in-verified-harness:${path}`)
}
const receiptPath = join(dsh, '.dsh-build/pinned-harness-build.json')
const receiptBytes = await readFile(receiptPath)
const receipt = JSON.parse(receiptBytes)
const upstream = receipt.inputs?.upstream
for (const [key, expected] of Object.entries({
  commit: compatibility.dsh.commit, archiveSha256: compatibility.dsh.archiveSha256,
  lockfileSha256: compatibility.dsh.lockfileSha256, packageManager: compatibility.dsh.packageManager,
})) if (upstream?.[key] !== expected) throw new Error(`ui-build:harness-pin-mismatch:${key}`)
if (verifiedHarness.document.identity.upstream.cordisVersion !== compatibility.dsh.cordisVersion) throw new Error('ui-build:harness-pin-mismatch:cordisVersion')
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
    face.face === 'prime-authority' ? OWNER_CONFIG :
      `import { clientBundle } from '../tsdown.client.ts'\nexport default clientBundle(${JSON.stringify(face.id)}, [], { hostPhase: true })\n`)
}
console.log('UI build linking existing pinned workspace dependencies, without install')
const workspace = new Map([...originalWorkspace].map(([name,directory]) => [name,join(overlay,relative(dsh,directory))]))
for (const face of entries) {
  const directory = join(overlay,'packages/client',face.folder)
  const metadata = JSON.parse(await readFile(join(directory,'package.json'),'utf8'))
  if (metadata.name !== face.id || workspace.has(metadata.name)) throw new Error(`ui-build:owned-package-identity-collision:${face.face}`)
  workspace.set(metadata.name, await realpath(directory))
}
if (!(await readFile(join(overlay,HARNESS_IDENTITY_PATH))).equals(await readFile(join(dsh,HARNESS_IDENTITY_PATH)))) throw new Error('ui-build:copied-harness-identity-mismatch')
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
    if (target) target = await realpath(target)
    if (!target || !target.startsWith(overlay + sep)) throw new Error(`ui-build:dependency-not-in-pinned-closure:${name}`)
    const dependency = JSON.parse(await readFile(join(target, 'package.json'), 'utf8'))
    if (dependency.name !== name) throw new Error(`ui-build:dependency-name-mismatch:${name}`)
    const expected = compatibility.resolved_build_dependencies?.[name]
    if (expected && dependency.version !== expected) throw new Error(`ui-build:dependency-version-mismatch:${name}`)
    dependencies[name] = dependency.version
    const link = join(directory, 'node_modules', name)
    await mkdir(dirname(link), { recursive: true })
    await symlink(relative(dirname(link), target), link, 'dir')
  }
}
const targets = []
const authorityDirectory = join(overlay, 'packages/client/aukora-prime-authority')
const ownerLib=await lstat(join(authorityDirectory,'lib'))
if(!ownerLib.isDirectory()||ownerLib.isSymbolicLink())throw new Error('ui-build:unsupported-owner-lib-seat')
// Fresh owner outputs must come from this compilation, not a copied incremental cache.
await rm(join(authorityDirectory, 'lib/types'), { recursive: true, force: true })
await rm(join(authorityDirectory, 'lib/tsconfig.client.tsbuildinfo'), { force: true })
const adapterSeats = [join(authorityDirectory, 'adapters'), join(overlay, 'packages/client/adapters')]
for (const seat of adapterSeats) {
  await rm(seat, { recursive: true, force: true })
  await mkdir(seat, { recursive: true })
  for (const adapter of (await readdir(join(ui, 'adapters'))).filter(path => path.endsWith('.mjs') || path.endsWith('.d.mts'))) {
    await cp(join(ui, 'adapters', adapter), join(seat, adapter))
  }
}
const ownerSourceRoots = { uiRoot: ui, ownerRoot: authorityDirectory,
  adapterRoot: join(authorityDirectory, 'adapters'), layoutRoot: join(overlay, 'packages/client/aukora-face-layout') }
const sourceBefore = await snapshotOwnerSources(ownerSourceRoots)
if (inputDigest(sourceBefore) !== inputDigest(await snapshotOwnerSources({ uiRoot: ui }))) throw new Error('ui-build:overlay-source-mismatch')
if (inputDigest(sourceBefore) !== inputDigest(await snapshotOwnerSources({ ...ownerSourceRoots, adapterRoot: adapterSeats[1] }))) throw new Error('ui-build:typecheck-adapter-seat-mismatch')
const buildBefore = await snapshotOwnerBuildInputs({ ownerRoot: authorityDirectory, dsh: overlay, harnessIdentity:verifiedHarness.binding })
for (const face of selected) {
  const directory = join(overlay, 'packages/client', face.folder)
  const config = (await readdir(directory)).includes('tsconfig.client.json') ? 'tsconfig.client.json' : 'tsconfig.json'
  targets.push(join(directory, config))
}
console.log('UI build type-checking exact face sources')
await run(globalThis.process.execPath, ['--max-old-space-size=3072', await compilerCommand(overlay,'typescript'), '-b', ...targets], overlay, 'ui-build:client-typecheck')
await publishOwnerTypeSources({sourceClient:join(authorityDirectory,'src/client'),
  adapterRoot:adapterSeats[0],typeRoot:join(authorityDirectory,'lib/types')})
const artifacts = []
const ownerOutputs = []
for (const face of selected) {
  console.log(`UI build bundling ${face.face}`)
  const directory = join(overlay, 'packages/client', face.folder)
  await run(globalThis.process.execPath, [await compilerCommand(overlay,'tsdown'), '--config', '.prime-client.config.ts', '--env.DSH_BUILD_FACE', 'client'], directory, `ui-build:bundle:${face.face}`)
  const original = await readFile(join(directory, 'lib/client.js'), 'utf8')
  // These unmapped virtual-module region comments contain the physical build
  // seat. Retain their owned source provenance without publishing account paths.
  const cssRegions = new Map(face.face === 'prime-authority'
    ? ['OwnerSurface.module.css', 'PrimeProviderEditor.module.css'].map(name => [
      `//#region \\0dsh-css:${join(directory, 'src/client', name)}.mjs`,
      `//#region \\0dsh-css:packages/ui/prime-authority/src/client/${name}.mjs`,
    ]) : [])
  const generated = original.replace(/^([\t ]*)(\/\/#region [^\r\n]+)(\r?)$/gm,
    (line, indentation, comment, ending) => cssRegions.has(comment) ? indentation + cssRegions.get(comment) + ending : line)
  // Same inert home-path normalization as the donor build, applied only to generated bytes.
  const code = generated.replace(/\/Users\/[^\s\n]*?\/\.runtime\/[^\s\n]*?\/packages\//g, 'packages/')
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
  if (face.face === 'prime-authority') ownerOutputs.push({ path: 'prime-authority/lib/client.js',
    output_path: 'prime-authority/client.js', bytes: Buffer.byteLength(code), sha256: digest(Buffer.from(code)) })
  if (hasMap) {
    const map = await readFile(join(destination, 'client.js.map'))
    artifacts.push({ face: face.face, id: face.id, path: relative(output, join(destination, 'client.js.map')),
      bytes: map.length, sha256: digest(map) })
    if (face.face === 'prime-authority') ownerOutputs.push({ path: 'prime-authority/lib/client.js.map',
      output_path: 'prime-authority/client.js.map', bytes: map.length, sha256: digest(map) })
  }
  if (face.face === 'prime-authority') {
    const host = await readFile(join(destination, 'index.js'))
    ownerOutputs.push({ path: 'prime-authority/lib/index.js', output_path: 'prime-authority/index.js', bytes: host.length, sha256: digest(host) })
    for await (const typePath of glob('**/*', { cwd: join(directory, 'lib/types') })) {
      const metadata = await lstat(join(directory, 'lib/types', typePath))
      if (metadata.isSymbolicLink()) throw new Error(`ui-build:symlinked-owner-output:${typePath}`)
      if (!metadata.isFile()) continue
      const type = await readFile(join(directory, 'lib/types', typePath))
      await mkdir(dirname(join(destination, 'types', typePath)), { recursive: true })
      await writeFile(join(destination, 'types', typePath), type)
      const path = typePath.split(sep).join('/')
      ownerOutputs.push({ path: `prime-authority/lib/types/${path}`, output_path: `prime-authority/types/${path}`, bytes: type.length, sha256: digest(type) })
    }
  }
}
const originalAfter = await verifyStableHarness({ dsh, primeRoot, compatibility })
if (inputDigest(originalAfter.binding) !== inputDigest(verifiedHarness.binding) || digest(await readFile(join(dsh, 'pnpm-lock.yaml'))) !== lockBefore ||
    !(await readFile(join(overlay,HARNESS_IDENTITY_PATH))).equals(await readFile(join(dsh,HARNESS_IDENTITY_PATH)))) {
  throw new Error('ui-build:input-harness-changed')
}
const sourceAfter = await snapshotOwnerSources(ownerSourceRoots)
if (inputDigest(sourceAfter) !== inputDigest(await snapshotOwnerSources({ uiRoot: ui }))) throw new Error('ui-build:source-changed-during-compilation')
if (inputDigest(sourceAfter) !== inputDigest(await snapshotOwnerSources({ ...ownerSourceRoots, adapterRoot: adapterSeats[1] }))) throw new Error('ui-build:typecheck-adapter-seat-changed')
const buildAfter = await snapshotOwnerBuildInputs({ ownerRoot: authorityDirectory, dsh: overlay, harnessIdentity:originalAfter.binding })
const ownerBuild = createOwnerReceipt({ sourceBefore, sourceAfter, buildBefore, buildAfter,
  outputs: ownerOutputs.sort((a, b) => a.path.localeCompare(b.path, 'en')) })
await writeFile(join(output, 'build.json'), JSON.stringify({ version: 3, source_commit: compatibility.dsh.commit,
  source_commit_attribution: 'pinned-dsh-upstream; not Prime/UI source proof', upstream_commit: compatibility.dsh.commit,
  provenance:{harness_build_receipt:{path:'.dsh-build/pinned-harness-build.json',bytes:receiptBytes.length,sha256:digest(receiptBytes)}}, source_lock_sha256: lockBefore,
  overlay_lock_sha256: digest(await readFile(join(overlay, 'pnpm-lock.yaml'))), dependency_versions: dependencies,
  mode: 'client-only', legacy_hosts_mounted: false, artifacts, owner_build: ownerBuild }, null, 2) + '\n')
console.log(JSON.stringify({ result: 'PASS', output, faces: selected.filter(entry => entry.face !== 'prime-authority').length,
  separate_plugins: selected.filter(entry => entry.face === 'prime-authority').length, source_faces_changed: false,
  harness_lock_changed: false, runtime_parity: 'UNPERFORMED: browser boot required' }))
