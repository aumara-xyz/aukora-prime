import assert from 'node:assert/strict'
import { readFile, writeFile, mkdir, mkdtemp, cp, rm } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { snapshotOwnerSources, publishedOwnerOutputs, verifyOwnerBuild } from './verify-owner-build.mjs'

// Mutate disposable copies of the genuine compiler receipt and its bound files.
// Never synthesize/repair release evidence, compile, mount, or contact services.
const ui = fileURLToPath(new URL('../', import.meta.url))
const work = fileURLToPath(new URL('../../../.runtime/', import.meta.url))
await mkdir(work, { recursive: true })
const fixture = await mkdtemp(join(work, 'owner-receipt-check-'))
const root = join(fixture, 'ui')
const source = await snapshotOwnerSources({ uiRoot: ui })
const receiptPath = join(root, 'prime-authority/lib/build.json')
try {
  for (const item of source) {
    await mkdir(dirname(join(root, item.path)), { recursive: true })
    await cp(join(ui, item.path), join(root, item.path))
  }
  await cp(join(ui, 'prime-authority/lib'), join(root, 'prime-authority/lib'), { recursive: true })
  const outputs = await publishedOwnerOutputs(root)
  const receipt = JSON.parse(await readFile(receiptPath, 'utf8'))
  const save = value => writeFile(receiptPath, JSON.stringify(value))
  await save(receipt)
  assert.equal((await verifyOwnerBuild({ uiRoot: root })).result, 'PASS')
  let killed = 0
  for (const path of ['prime-authority/src/client/OwnerSurface.tsx', 'scripts/build-client.mjs', 'prime-authority/lib/client.js', 'prime-authority/lib/types/client/index.d.ts']) {
    const original = await readFile(join(root, path))
    await writeFile(join(root, path), Buffer.concat([original, Buffer.from('\n// altered verifier fixture\n')]))
    await assert.rejects(verifyOwnerBuild({ uiRoot: root }), /source-input-mismatch|output-artifact-mismatch/)
    await writeFile(join(root, path), original)
    killed++
  }
  const bundlePath = join(root, 'prime-authority/lib/client.js')
  const bundle = await readFile(bundlePath)
  await rm(bundlePath)
  await assert.rejects(verifyOwnerBuild({ uiRoot: root }), /ENOENT/)
  await writeFile(bundlePath, bundle)
  killed++
  await rm(receiptPath)
  await assert.rejects(verifyOwnerBuild({ uiRoot: root }), /ENOENT/)
  await save(receipt)
  killed++
  const missingSource = structuredClone(receipt)
  missingSource.owner_build.source_inputs = missingSource.owner_build.source_inputs.filter(item => item.path !== 'prime-authority/src/client/OwnerSurface.tsx')
  await save(missingSource)
  await assert.rejects(verifyOwnerBuild({ uiRoot: root }), /source-input-mismatch/)
  killed++
  await save({ ...receipt, source_commit_attribution: 'Prime source' })
  await assert.rejects(verifyOwnerBuild({ uiRoot: root }), /upstream-attribution-mismatch/)
  killed++
  await save(receipt)
  assert.equal((await verifyOwnerBuild({ uiRoot: root })).result, 'PASS')
  console.log(JSON.stringify({ result: 'PASS', fixture: 'genuine compiler receipt/files in disposable copies; no runtime claim', killed_mutations: killed,
    cases: ['owner source', 'recipe', 'client bundle', 'published type', 'missing bundle', 'missing receipt', 'omitted source', 'false source attribution'],
    source_inputs: source.length, output_artifacts: outputs.length, live_effects: false }))
} finally {
  await rm(fixture, { recursive: true, force: true })
}
