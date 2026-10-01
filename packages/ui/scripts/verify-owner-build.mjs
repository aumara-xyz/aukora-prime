import assert from 'node:assert/strict'
import { readFile, readdir, lstat, stat, realpath } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { resolve, join, relative, dirname, basename, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const OWNER_ID = '@aukora/prime-authority-ui'
export const OWNER_CONFIG = `import { clientBundle } from '../tsdown.client.ts'\nexport default clientBundle(${JSON.stringify(OWNER_ID)}, [], { hostPhase: true })\n`
export const PINNED_BUILD_PATHS = Object.freeze([
  'pnpm-lock.yaml',
  'tsconfig.base.json', 'tsconfig.base.client.json',
  'packages/client/tsdown.client.ts',
  'packages/client/modules/src/client/manifest.ts',
  'packages/client/web/src/platform.ts',
  'scripts/client-build-environment.ts', 'scripts/bundle-input-isolation.ts',
])
export const HARNESS_IDENTITY_PATH = '.dsh-build/pinned-harness-identity.json'
export const HARNESS_IDENTITY_ALGORITHM = 'aukora-prime:pinned-harness-identity:v1'
// Independent seats/versions from the frozen DSH archive/lock and owned Layout.
// Receipt-authored routes never choose the files that this verifier reads.
export const OWNER_DEPENDENCY_IDENTITIES = Object.freeze({
  declared_dependencies: [
    ['@aukora/face-layout','workspace:^','0.1.1-rc.2','prime-ui','faces/layout/package.json'],
    ['@deepseek-ai/cordis','workspace:^','4.0.2','pinned-harness','vendor/cordis/package.json'],
    ['@deepseek-ai/dsh-client-locale','workspace:^','0.1.6-alpha.1','pinned-harness','packages/client/locale/package.json'],
    ['@deepseek-ai/dsh-client-ui-renderer','workspace:^','0.1.6-alpha.1','pinned-harness','packages/client/ui-renderer/package.json'],
    ['@deepseek-ai/dsh-client-ui-slots','workspace:^','0.1.6-alpha.1','pinned-harness','packages/client/ui-slots/package.json'],
    ['@types/react','~18.3.1','18.3.31','pinned-harness','node_modules/.pnpm/@types+react@18.3.31/node_modules/@types/react/package.json'],
    ['react','^18.2.0','18.3.1','pinned-harness','node_modules/.pnpm/react@18.3.1/node_modules/react/package.json'],
  ],
  build_dependencies: [
    ['typescript',null,'6.0.3','pinned-harness','node_modules/.pnpm/typescript@6.0.3/node_modules/typescript/package.json'],
    ['tsdown',null,'0.22.2','pinned-harness','node_modules/.pnpm/tsdown@0.22.2_oxc-resolver@11.20.0_publint@0.3.21_tsx@4.22.4_typescript@6.0.3/node_modules/tsdown/package.json'],
    ['lightningcss',null,'1.32.0','pinned-harness','node_modules/.pnpm/lightningcss@1.32.0/node_modules/lightningcss/package.json'],
  ],
})
for (const group of Object.values(OWNER_DEPENDENCY_IDENTITIES)) {
  for (const identity of group) Object.freeze(identity)
  Object.freeze(group)
}
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const sorted = records => records.sort((a, b) => a.path.localeCompare(b.path, 'en'))
export const inputDigest = value => sha(Buffer.from(JSON.stringify(value)))
const fail = reason => { throw new Error(`ui-owner-build:${reason}`) }
const closed = (value, fields, reason) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== [...fields].sort().join(',')) fail(reason)
}
function pathName(path) {
  if (typeof path !== 'string' || !path || /[\u0000-\u001f\u007f\\]/u.test(path) || path.startsWith('/') ||
      path.split('/').some(part => !part || part === '.' || part === '..')) fail('noncanonical-input-path')
  return path
}
async function rootPath(root) {
  const resolved = resolve(root)
  if ((await lstat(resolved)).isSymbolicLink()) fail('symlink-root')
  return realpath(resolved)
}
async function regularPath(root, path) {
  root = await rootPath(root); pathName(path)
  let actual = root
  const parts = path.split('/')
  for (const [index, part] of parts.entries()) {
    actual = join(actual, part)
    const stat = await lstat(actual)
    if (stat.isSymbolicLink() || (index === parts.length - 1 ? !stat.isFile() : !stat.isDirectory())) fail(`nonregular-input:${path}`)
  }
  return actual
}
async function destinationPath(path) {
  let existing = resolve(path)
  const tail = []
  while (true) {
    try { await lstat(existing); break }
    catch (error) { if (error.code !== 'ENOENT') throw error; tail.unshift(basename(existing)); existing = dirname(existing) }
  }
  if (!(await stat(existing)).isDirectory()) fail('build-destination-parent-not-directory')
  return resolve(await realpath(existing), ...tail)
}
export async function validateBuildDirectories({ uiRoot, dsh, work, output }) {
  uiRoot = await rootPath(uiRoot); dsh = await rootPath(dsh)
  work = await destinationPath(work); output = await destinationPath(output)
  for (const path of [work, output]) {
    if ([uiRoot,dsh].some(input => path === input || path.startsWith(input + sep) || input.startsWith(path + sep))) fail('overlapping-build-destination')
  }
  if (work === output || work.startsWith(output + sep)) fail('overlapping-work-output')
  return { work, output }
}
function harnessBinding(value) {
  closed(value, ['path','algorithm','sha256'], 'harness-identity-binding-shape')
  if (value.path !== HARNESS_IDENTITY_PATH || value.algorithm !== HARNESS_IDENTITY_ALGORITHM ||
      typeof value.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.sha256)) fail('harness-identity-binding-invalid')
  return value
}

// This checks the original successful harness, never an augmented UI overlay.
// The verifier lives in the same Prime source root after lane integration.
export async function verifyStableHarness({ dsh, primeRoot, compatibility }) {
  if (!primeRoot) fail('prime-root-verifier-required')
  dsh = await rootPath(dsh); primeRoot = await rootPath(primeRoot)
  const module = await regularPath(primeRoot, 'scripts/lib/artifact-integrity.mjs')
  const verifier = await import(pathToFileURL(module).href)
  if (verifier.HARNESS_IDENTITY_PATH !== HARNESS_IDENTITY_PATH || verifier.HARNESS_IDENTITY_ALGORITHM !== HARNESS_IDENTITY_ALGORITHM ||
      typeof verifier.verifyHarnessIdentity !== 'function') fail('harness-verifier-interface-mismatch')
  const document = verifier.verifyHarnessIdentity({ root: primeRoot, source: dsh })
  if (!compatibility?.dsh) fail('harness-compatibility-required')
  for (const key of ['commit','archiveSha256','lockfileSha256','packageManager','cordisVersion']) {
    if (document.identity.upstream[key] !== compatibility.dsh[key]) fail(`harness-pin-mismatch:${key}`)
  }
  const patches = value => value.map(entry => [entry.file,entry.sha256]).sort((a,b) => a[0].localeCompare(b[0],'en'))
  assert.deepEqual(patches(document.identity.localPatches), patches(compatibility.dsh.localPatches), 'ui-owner-build:harness-patch-mismatch')
  const binding = harnessBinding({ path: HARNESS_IDENTITY_PATH, algorithm: document.algorithm, sha256: document.sha256 })
  return { document, binding }
}

async function record(path, actual) {
  if ((await lstat(actual)).isSymbolicLink() || !(await lstat(actual)).isFile()) fail(`symlink-input:${path}`)
  const bytes = await readFile(actual)
  return { path, bytes: bytes.length, sha256: sha(bytes) }
}
async function files(root, prefix = '') {
  const found = []
  for (const entry of (await readdir(join(root, prefix), { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isSymbolicLink()) fail(`symlink-input:${path}`)
    if (entry.isDirectory()) found.push(...await files(root, path))
    else if (entry.isFile()) found.push(path)
    else fail(`unsupported-input:${path}`)
  }
  return found
}

// Paths in the receipt are relative to packages/ui. The alternate roots bind
// the files actually copied into the build overlay to the same source paths.
export async function snapshotOwnerSources({ uiRoot, ownerRoot = join(uiRoot, 'prime-authority'), adapterRoot = join(uiRoot, 'adapters'), layoutRoot = join(uiRoot, 'faces/layout') }) {
  const inputs = []
  for (const path of await files(join(ownerRoot, 'src'))) inputs.push(await record(`prime-authority/src/${path}`, join(ownerRoot, 'src', path)))
  for (const path of ['package.json', 'tsconfig.client.json']) inputs.push(await record(`prime-authority/${path}`, join(ownerRoot, path)))
  for (const path of (await files(adapterRoot)).filter(path => !path.includes('/') && (path.endsWith('.mjs') || path.endsWith('.d.mts')))) inputs.push(await record(`adapters/${path}`, join(adapterRoot, path)))
  for (const path of ['scripts/build-client.mjs', 'scripts/verify-owner-build.mjs', 'compatibility.json', 'baseline-manifest.json']) inputs.push(await record(path, join(uiRoot, path)))
  try { inputs.push(await record('docs/capture-review-provenance.json', join(uiRoot, 'docs/capture-review-provenance.json'))) } catch (error) { if (error.code !== 'ENOENT') throw error }
  for (const path of await files(join(layoutRoot, 'src'))) inputs.push(await record(`faces/layout/src/${path}`, join(layoutRoot, 'src', path)))
  for (const path of ['package.json', 'tsconfig.json', 'lib/client.js']) inputs.push(await record(`faces/layout/${path}`, join(layoutRoot, path)))
  return sorted(inputs)
}

export function validateDependencyRecords(inputs) {
  for (const [group, expected] of Object.entries(OWNER_DEPENDENCY_IDENTITIES)) {
    const entries = inputs?.[group]
    if (!Array.isArray(entries) || entries.length !== expected.length) fail('dependency-set-mismatch')
    for (const [index, [name, declared, version, origin, path]] of expected.entries()) {
      const entry = entries[index]
      closed(entry, ['name','declared','version','origin','path','bytes','sha256'], `dependency-record-shape:${name}`)
      if (entry.name !== name || entry.declared !== declared || entry.version !== version || entry.origin !== origin || entry.path !== path ||
          !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(entry.sha256)) fail(`dependency-identity-mismatch:${name}`)
    }
  }
}
async function moduleSeat(root, name, expectedDirectory, owner = false) {
  const candidates = owner ? [join(root,'node_modules',name)] : [join(root,'node_modules',name),join(root,'node_modules/.pnpm/node_modules',name)]
  for (const candidate of candidates) {
    try { await lstat(candidate) } catch (error) { if (error.code === 'ENOENT') continue; throw error }
    if (await realpath(candidate) !== expectedDirectory) fail(`dependency-canonical-seat-mismatch:${name}`)
    return
  }
  fail(`dependency-module-seat-missing:${name}`)
}
async function expectedMetadata(root, expected) {
  const [name, declared, version, origin, path] = expected
  const actual = await regularPath(root, path), bytes = await readFile(actual), metadata = JSON.parse(bytes)
  if (metadata.name !== name) fail(`dependency-name-mismatch:${name}`)
  if (metadata.version !== version) fail(`dependency-version-mismatch:${name}`)
  return { name, declared, version, origin, path, bytes: bytes.length, sha256: sha(bytes) }
}
export async function verifyDependencyMetadata({ uiRoot, dsh, inputs }) {
  validateDependencyRecords(inputs)
  dsh = await rootPath(dsh); uiRoot = await rootPath(uiRoot)
  for (const [group, expected] of Object.entries(OWNER_DEPENDENCY_IDENTITIES)) {
    for (const [index, identity] of expected.entries()) {
      const [, , , origin, path] = identity, root = origin === 'prime-ui' ? uiRoot : dsh
      assert.deepEqual(await expectedMetadata(root, identity), inputs[group][index], `ui-owner-build:pinned-dependency-mismatch:${identity[0]}`)
      if (path.startsWith('node_modules/')) await moduleSeat(dsh, identity[0], dirname(await regularPath(dsh, path)))
    }
  }
}
export async function discoverPinnedWorkspace(dsh) {
  dsh = await rootPath(dsh)
  // These package-manager hooks/configs are absent from the exact pinned archive.
  for (const path of ['.npmrc','.pnpmfile.cjs','pnpmfile.cjs','.yarnrc','.yarnrc.yml','.pnp.cjs']) {
    try { await lstat(join(dsh,path)) } catch (error) { if (error.code === 'ENOENT') continue; throw error }
    fail(`unexpected-build-configuration:${path}`)
  }
  const packages = new Map()
  const directories = async path => {
    const entries = await readdir(join(dsh,path), { withFileTypes:true })
    for (const entry of entries) if (entry.isSymbolicLink()) {
      const location = join(dsh,path,entry.name)
      if ((await stat(location)).isDirectory() || !(await realpath(location)).startsWith(dsh + sep)) fail(`workspace-directory-symlink:${path}/${entry.name}`)
    }
    return entries.filter(entry => entry.isDirectory()).map(entry => `${path}/${entry.name}`).sort()
  }
  const seats = [...await directories('vendor')]
  for (const group of await directories('packages')) seats.push(...await directories(group))
  for (const seat of seats) {
    const path = `${seat}/package.json`
    try { await lstat(join(dsh,path)) } catch (error) { if (error.code === 'ENOENT') continue; throw error }
    const actual = await regularPath(dsh, path), metadata = JSON.parse(await readFile(actual, 'utf8'))
    if (typeof metadata.name !== 'string' || !metadata.name || typeof metadata.version !== 'string' || !metadata.version) fail(`workspace-metadata-invalid:${path}`)
    if (packages.has(metadata.name)) fail(`duplicate-workspace-package:${metadata.name}`)
    packages.set(metadata.name, dirname(actual))
  }
  return packages
}
export async function compilerCommand(dsh, name) {
  const identity = OWNER_DEPENDENCY_IDENTITIES.build_dependencies.find(entry => entry[0] === name)
  if (!identity || !['typescript','tsdown'].includes(name)) fail('unknown-compiler')
  dsh = await rootPath(dsh)
  const actual = await regularPath(dsh, identity[4])
  await expectedMetadata(dsh, identity)
  await moduleSeat(dsh, name, dirname(actual))
  const metadata = JSON.parse(await readFile(actual, 'utf8')), command = name === 'typescript' ? 'tsc' : name
  const bin = typeof metadata.bin === 'string' ? metadata.bin : metadata.bin?.[command]
  const fixedBin = name === 'typescript' ? 'bin/tsc' : 'dist/run.mjs'
  if (bin !== './' + fixedBin) fail(`compiler-bin-seat-mismatch:${name}`)
  const path = relative(dsh, join(dirname(actual), fixedBin)).split(sep).join('/')
  return regularPath(dsh, path)
}

export async function snapshotOwnerBuildInputs({ ownerRoot, dsh, harnessIdentity }) {
  dsh = await rootPath(dsh)
  harnessBinding(harnessIdentity)
  const metadata = JSON.parse(await readFile(join(ownerRoot, 'package.json'), 'utf8'))
  const declared = { ...metadata.dependencies, ...metadata.peerDependencies, ...metadata.devDependencies }
  assert.deepEqual(Object.keys(declared).sort().map(name => [name,declared[name]]), OWNER_DEPENDENCY_IDENTITIES.declared_dependencies.map(entry => entry.slice(0,2)), 'ui-owner-build:declared-dependency-mismatch')
  const dependencies = []
  for (const identity of OWNER_DEPENDENCY_IDENTITIES.declared_dependencies) {
    const [name, , , origin, path] = identity
    const actual = origin === 'prime-ui' ? await regularPath(dsh, 'packages/client/aukora-face-layout/package.json') : await regularPath(dsh, path)
    await moduleSeat(ownerRoot, name, dirname(actual), true)
    const bytes = await readFile(actual), metadata = JSON.parse(bytes)
    if (metadata.name !== name || metadata.version !== identity[2]) fail(`dependency-identity-mismatch:${name}`)
    dependencies.push({ name, declared:identity[1], version:identity[2], origin, path, bytes:bytes.length, sha256:sha(bytes) })
  }
  const tools = []
  for (const identity of OWNER_DEPENDENCY_IDENTITIES.build_dependencies) {
    const item = await expectedMetadata(dsh, identity)
    await moduleSeat(dsh, identity[0], dirname(await regularPath(dsh, identity[4])))
    tools.push(item)
  }
  const pinned = []
  for (const path of PINNED_BUILD_PATHS) pinned.push(await record(path, await regularPath(dsh, path)))
  const generated = await record('packages/client/aukora-prime-authority/.prime-client.config.ts', join(ownerRoot, '.prime-client.config.ts'))
  if (generated.bytes !== Buffer.byteLength(OWNER_CONFIG) || generated.sha256 !== sha(Buffer.from(OWNER_CONFIG))) fail('generated-config-mismatch')
  return { harness_identity:harnessIdentity, pinned: sorted(pinned), generated, declared_dependencies: dependencies, build_dependencies: tools }
}

export function createOwnerReceipt({ sourceBefore, sourceAfter, buildBefore, buildAfter, outputs }) {
  assert.deepEqual(sourceAfter, sourceBefore, 'ui-owner-build:source-changed-during-compilation')
  assert.deepEqual(buildAfter, buildBefore, 'ui-owner-build:build-input-changed-during-compilation')
  return { version: 2, package_id: OWNER_ID, source_inputs: sourceBefore,
    source_inputs_before_sha256: inputDigest(sourceBefore), source_inputs_after_sha256: inputDigest(sourceAfter),
    build_inputs: buildBefore, build_inputs_before_sha256: inputDigest(buildBefore), build_inputs_after_sha256: inputDigest(buildAfter),
    output_artifacts: outputs }
}

export async function publishedOwnerOutputs(uiRoot) {
  const paths = ['prime-authority/lib/client.js', 'prime-authority/lib/client.js.map', 'prime-authority/lib/index.js']
  for (const path of await files(join(uiRoot, 'prime-authority/lib/types'))) {
    paths.push(`prime-authority/lib/types/${path}`)
  }
  for (const path of ['prime-authority/lib/types/client/index.d.ts', 'prime-authority/lib/types/client/controller.d.mts', 'prime-authority/lib/types/client/controller.mjs']) {
    if (!paths.includes(path)) fail(`missing-published-type:${path}`)
  }
  return Promise.all(paths.sort((a, b) => a.localeCompare(b, 'en')).map(path => record(path, join(uiRoot, path))))
}

export async function verifyOwnerBuild({ uiRoot, receiptPath = join(uiRoot, 'prime-authority/lib/build.json'), dsh, primeRoot }) {
  const receipt = JSON.parse(await readFile(receiptPath, 'utf8'))
  const owner = receipt.owner_build
  if (receipt.version !== 3 || owner?.version !== 2 || owner.package_id !== OWNER_ID) fail('missing-stable-owner-receipt')
  const compatibility = JSON.parse(await readFile(join(uiRoot, 'compatibility.json'), 'utf8'))
  if (receipt.upstream_commit !== compatibility.dsh.commit || receipt.source_commit !== receipt.upstream_commit || receipt.source_commit_attribution !== 'pinned-dsh-upstream; not Prime/UI source proof') fail('upstream-attribution-mismatch')
  const sources = await snapshotOwnerSources({ uiRoot })
  assert.deepEqual(owner.source_inputs, sources, 'ui-owner-build:source-input-mismatch')
  if (owner.source_inputs_before_sha256 !== inputDigest(sources) || owner.source_inputs_after_sha256 !== inputDigest(sources)) fail('source-binding-mismatch')
  if (owner.build_inputs_before_sha256 !== inputDigest(owner.build_inputs) || owner.build_inputs_after_sha256 !== inputDigest(owner.build_inputs)) fail('build-binding-mismatch')
  closed(owner.build_inputs, ['harness_identity','pinned','generated','declared_dependencies','build_dependencies'], 'build-input-shape')
  harnessBinding(owner.build_inputs.harness_identity)
  closed(receipt.provenance, ['harness_build_receipt'], 'provenance-shape')
  const historical = receipt.provenance.harness_build_receipt
  closed(historical, ['path','bytes','sha256'], 'provenance-receipt-shape')
  if (historical.path !== '.dsh-build/pinned-harness-build.json' || !Number.isSafeInteger(historical.bytes) || historical.bytes < 0 ||
      typeof historical.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(historical.sha256)) fail('provenance-receipt-invalid')
  const generated = owner.build_inputs.generated
  if (generated?.path !== 'packages/client/aukora-prime-authority/.prime-client.config.ts' || generated.bytes !== Buffer.byteLength(OWNER_CONFIG) || generated.sha256 !== sha(Buffer.from(OWNER_CONFIG))) fail('generated-config-mismatch')
  assert.deepEqual(owner.build_inputs.pinned.map(item => item.path), [...PINNED_BUILD_PATHS].sort((a, b) => a.localeCompare(b, 'en')), 'ui-owner-build:pinned-build-closure-mismatch')
  const metadata = JSON.parse(await readFile(join(uiRoot, 'prime-authority/package.json'), 'utf8'))
  const declared = { ...metadata.dependencies, ...metadata.peerDependencies, ...metadata.devDependencies }
  assert.deepEqual(owner.build_inputs.declared_dependencies.map(item => [item.name, item.declared]), Object.keys(declared).sort().map(name => [name, declared[name]]), 'ui-owner-build:declared-dependency-mismatch')
  assert.deepEqual(owner.build_inputs.build_dependencies.map(item => item.name), ['typescript', 'tsdown', 'lightningcss'], 'ui-owner-build:build-dependency-mismatch')
  validateDependencyRecords(owner.build_inputs)
  if (dsh) {
    const verified = await verifyStableHarness({ dsh, primeRoot, compatibility })
    assert.deepEqual(owner.build_inputs.harness_identity, verified.binding, 'ui-owner-build:harness-identity-mismatch')
    for (const item of owner.build_inputs.pinned) assert.deepEqual(await record(item.path, await regularPath(dsh,item.path)), item, `ui-owner-build:pinned-input-mismatch:${item.path}`)
    await verifyDependencyMetadata({ uiRoot, dsh, inputs:owner.build_inputs })
  }
  const outputs = await publishedOwnerOutputs(uiRoot)
  assert.deepEqual(owner.output_artifacts, outputs.map(item => ({ ...item,
    output_path: item.path.replace('prime-authority/lib/', 'prime-authority/') })), 'ui-owner-build:output-artifact-mismatch')
  for (const extension of ['mjs', 'd.mts']) {
    const source = sources.find(item => item.path === `prime-authority/src/client/controller.${extension}`)
    const output = outputs.find(item => item.path === `prime-authority/lib/types/client/controller.${extension}`)
    if (source?.bytes !== output?.bytes || source?.sha256 !== output?.sha256) fail(`copied-controller-mismatch:${extension}`)
  }
  for (const item of owner.output_artifacts.filter(item => /\/client\.js(?:\.map)?$/.test(item.path))) {
    const compiled = receipt.artifacts?.find(artifact => artifact.id === OWNER_ID && artifact.path === item.output_path)
    if (compiled?.bytes !== item.bytes || compiled.sha256 !== item.sha256) fail(`artifact-table-mismatch:${item.path}`)
  }
  const client = await readFile(join(uiRoot, 'prime-authority/lib/client.js'), 'utf8')
  if (!client.includes(`id: "${OWNER_ID}"`) || !client.includes('window.__ModuleLoader__.load(')) fail('native-descriptor-mismatch')
  return { result: 'PASS', source_inputs: sources.length, output_artifacts: outputs.length,
    upstream_commit: receipt.upstream_commit, owner_client_sha256: outputs.find(item => item.path === 'prime-authority/lib/client.js').sha256,
    source_output_binding: 'MATCH', pinned_build_inputs: dsh ? 'MATCH' : 'RECORDED; not rechecked without --dsh',
    served_bytes: 'UNPERFORMED: H must verify the guarded HTTP bytes and loaded descriptor' }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const flags = {}
  for (let i = 2; i < process.argv.length; i += 2) {
    if (!['--ui', '--receipt', '--dsh','--prime-root'].includes(process.argv[i]) || !process.argv[i + 1]) fail('usage: --ui <packages/ui> [--receipt <build.json>] [--dsh <original-pinned-harness> --prime-root <same-Prime-root>]')
    flags[process.argv[i]] = resolve(process.argv[i + 1])
  }
  const uiRoot = flags['--ui'] ?? fileURLToPath(new URL('../', import.meta.url))
  console.log(JSON.stringify(await verifyOwnerBuild({ uiRoot, receiptPath: flags['--receipt'], dsh: flags['--dsh'], primeRoot:flags['--prime-root'] })))
}
