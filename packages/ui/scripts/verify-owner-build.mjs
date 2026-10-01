import assert from 'node:assert/strict'
import { readFile, readdir, lstat, realpath } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { resolve, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

export const OWNER_ID = '@aukora/prime-authority-ui'
export const OWNER_CONFIG = `import { clientBundle } from '../tsdown.client.ts'\nexport default clientBundle(${JSON.stringify(OWNER_ID)}, [], { hostPhase: true })\n`
export const PINNED_BUILD_PATHS = Object.freeze([
  '.dsh-build/pinned-harness-build.json', 'pnpm-lock.yaml',
  'tsconfig.base.json', 'tsconfig.base.client.json',
  'packages/client/tsdown.client.ts',
  'packages/client/modules/src/client/manifest.ts',
  'packages/client/web/src/platform.ts',
  'scripts/client-build-environment.ts', 'scripts/bundle-input-isolation.ts',
])
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const sorted = records => records.sort((a, b) => a.path.localeCompare(b.path, 'en'))
export const inputDigest = value => sha(Buffer.from(JSON.stringify(value)))
const fail = reason => { throw new Error(`ui-owner-build:${reason}`) }

async function record(path, actual) {
  if ((await lstat(actual)).isSymbolicLink()) fail(`symlink-input:${path}`)
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

async function dependency(name, declared, ownerRoot, dsh) {
  let directory
  for (const candidate of [join(ownerRoot, 'node_modules', name), join(dsh, 'node_modules', name), join(dsh, 'node_modules/.pnpm/node_modules', name)]) {
    try { directory = await realpath(candidate); break } catch { /* Existing pinned seats only. */ }
  }
  if (!directory || !directory.startsWith(dsh + sep)) fail(`dependency-outside-pinned-overlay:${name}`)
  const path = name === '@aukora/face-layout' ? 'faces/layout/package.json' : relative(dsh, join(directory, 'package.json')).split(sep).join('/')
  const bytes = await readFile(join(directory, 'package.json'))
  const metadata = JSON.parse(bytes)
  if (metadata.name !== name) fail(`dependency-name-mismatch:${name}`)
  return { name, declared, version: metadata.version, origin: name === '@aukora/face-layout' ? 'prime-ui' : 'pinned-harness', path, bytes: bytes.length, sha256: sha(bytes) }
}

export async function snapshotOwnerBuildInputs({ ownerRoot, dsh }) {
  const metadata = JSON.parse(await readFile(join(ownerRoot, 'package.json'), 'utf8'))
  const declared = { ...metadata.dependencies, ...metadata.peerDependencies, ...metadata.devDependencies }
  const dependencies = []
  for (const name of Object.keys(declared).sort()) dependencies.push(await dependency(name, declared[name], ownerRoot, dsh))
  const tools = []
  for (const name of ['typescript', 'tsdown', 'lightningcss']) tools.push(await dependency(name, null, ownerRoot, dsh))
  const pinned = []
  for (const path of PINNED_BUILD_PATHS) pinned.push(await record(path, join(dsh, path)))
  const generated = await record('packages/client/aukora-prime-authority/.prime-client.config.ts', join(ownerRoot, '.prime-client.config.ts'))
  if (generated.bytes !== Buffer.byteLength(OWNER_CONFIG) || generated.sha256 !== sha(Buffer.from(OWNER_CONFIG))) fail('generated-config-mismatch')
  return { pinned: sorted(pinned), generated, declared_dependencies: dependencies, build_dependencies: tools }
}

export function createOwnerReceipt({ sourceBefore, sourceAfter, buildBefore, buildAfter, outputs }) {
  assert.deepEqual(sourceAfter, sourceBefore, 'ui-owner-build:source-changed-during-compilation')
  assert.deepEqual(buildAfter, buildBefore, 'ui-owner-build:build-input-changed-during-compilation')
  return { version: 1, package_id: OWNER_ID, source_inputs: sourceBefore,
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

export async function verifyOwnerBuild({ uiRoot, receiptPath = join(uiRoot, 'prime-authority/lib/build.json'), dsh }) {
  const receipt = JSON.parse(await readFile(receiptPath, 'utf8'))
  const owner = receipt.owner_build
  if (receipt.version !== 2 || owner?.version !== 1 || owner.package_id !== OWNER_ID) fail('missing-owner-receipt')
  const compatibility = JSON.parse(await readFile(join(uiRoot, 'compatibility.json'), 'utf8'))
  if (receipt.upstream_commit !== compatibility.dsh.commit || receipt.source_commit !== receipt.upstream_commit || receipt.source_commit_attribution !== 'pinned-dsh-upstream; not Prime/UI source proof') fail('upstream-attribution-mismatch')
  const sources = await snapshotOwnerSources({ uiRoot })
  assert.deepEqual(owner.source_inputs, sources, 'ui-owner-build:source-input-mismatch')
  if (owner.source_inputs_before_sha256 !== inputDigest(sources) || owner.source_inputs_after_sha256 !== inputDigest(sources)) fail('source-binding-mismatch')
  if (owner.build_inputs_before_sha256 !== inputDigest(owner.build_inputs) || owner.build_inputs_after_sha256 !== inputDigest(owner.build_inputs)) fail('build-binding-mismatch')
  const generated = owner.build_inputs.generated
  if (generated?.path !== 'packages/client/aukora-prime-authority/.prime-client.config.ts' || generated.bytes !== Buffer.byteLength(OWNER_CONFIG) || generated.sha256 !== sha(Buffer.from(OWNER_CONFIG))) fail('generated-config-mismatch')
  assert.deepEqual(owner.build_inputs.pinned.map(item => item.path), [...PINNED_BUILD_PATHS].sort((a, b) => a.localeCompare(b, 'en')), 'ui-owner-build:pinned-build-closure-mismatch')
  const metadata = JSON.parse(await readFile(join(uiRoot, 'prime-authority/package.json'), 'utf8'))
  const declared = { ...metadata.dependencies, ...metadata.peerDependencies, ...metadata.devDependencies }
  assert.deepEqual(owner.build_inputs.declared_dependencies.map(item => [item.name, item.declared]), Object.keys(declared).sort().map(name => [name, declared[name]]), 'ui-owner-build:declared-dependency-mismatch')
  assert.deepEqual(owner.build_inputs.build_dependencies.map(item => item.name), ['typescript', 'tsdown', 'lightningcss'], 'ui-owner-build:build-dependency-mismatch')
  if (dsh) {
    for (const item of owner.build_inputs.pinned) assert.deepEqual(await record(item.path, join(dsh, item.path)), item, `ui-owner-build:pinned-input-mismatch:${item.path}`)
    for (const item of [...owner.build_inputs.declared_dependencies, ...owner.build_inputs.build_dependencies]) {
      const actual = item.origin === 'prime-ui' ? join(uiRoot, item.path) : join(dsh, item.path)
      const bytes = await readFile(actual)
      if (bytes.length !== item.bytes || sha(bytes) !== item.sha256 || JSON.parse(bytes).version !== item.version) fail(`pinned-dependency-mismatch:${item.name}`)
    }
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
    if (!['--ui', '--receipt', '--dsh'].includes(process.argv[i]) || !process.argv[i + 1]) fail('usage: --ui <packages/ui> [--receipt <build.json>] [--dsh <pinned-harness>]')
    flags[process.argv[i]] = resolve(process.argv[i + 1])
  }
  const uiRoot = flags['--ui'] ?? fileURLToPath(new URL('../', import.meta.url))
  console.log(JSON.stringify(await verifyOwnerBuild({ uiRoot, receiptPath: flags['--receipt'], dsh: flags['--dsh'] })))
}
