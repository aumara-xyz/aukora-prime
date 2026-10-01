import { readFile, lstat } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { resolve, sep } from 'node:path'
import { faces } from '../adapters/mount-plan.mjs'
import { baselineFileRecords } from '../../../harness/release-integrity.mjs'

const root = resolve(fileURLToPath(new URL('../', import.meta.url)))
const manifest = JSON.parse(await readFile(new URL('../baseline-manifest.json', import.meta.url), 'utf8'))
let bytes = 0
for (const item of baselineFileRecords(manifest)) {
  const path = resolve(root, item.path)
  if (!path.startsWith(root + sep) && path !== root) throw new Error(`baseline:path-escape:${item.path}`)
  const stat = await lstat(path)
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`baseline:not-owned-file:${item.path}`)
  const body = await readFile(path)
  if (body.length !== item.bytes || createHash('sha256').update(body).digest('hex') !== item.sha256) {
    throw new Error(`baseline:changed:${item.path}`)
  }
  bytes += body.length
}
for (const face of faces) {
  const bundle = await readFile(face.clientBundle, 'utf8')
  if (!bundle.includes('window.__ModuleLoader__.load(') || !bundle.includes(`id: "${face.id}"`)) {
    throw new Error(`baseline:module-loader-binding:${face.face}`)
  }
  if (face.mountDonorHost) throw new Error(`baseline:legacy-host-mount:${face.face}`)
}
console.log(JSON.stringify({
  result: 'PASS', donor: manifest.commit, faces: faces.length,
  files: manifest.files.length, bytes, source_asset_diff: manifest.source_adaptations?.length ?? 0,
  exact_donor_files: manifest.files.length - (manifest.source_adaptations?.length ?? 0),
  source_adaptations: manifest.source_adaptations?.length ?? 0, served_asset_diff: 0,
  build_qualification: 'historical donor bundles and input records; no new compilation',
  runtime_parity: 'UNPERFORMED: pinned harness and browser composition required',
}))
