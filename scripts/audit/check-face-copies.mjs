#!/usr/bin/env node
import { readFileSync, readdirSync, lstatSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const manifest = JSON.parse(readFileSync(resolve(root, 'evidence/face-copies.json'), 'utf8'))
function files(dir, prefix = '') {
  return readdirSync(dir).sort().flatMap(name => {
    const path = resolve(dir, name), rel = prefix + name, info = lstatSync(path)
    if (info.isSymbolicLink()) throw new Error('face copy symlink refused: ' + rel)
    return info.isDirectory() ? files(path, rel + '/') : [rel]
  })
}
// Invariant: listed copies remain byte-identical. Threat: parallel face edits
// drift silently. Reason: compare complete bytes and membership, never regenerate
// immutable donor snapshots or change a build/runtime mount to make this pass.
const found = files(resolve(root, manifest.copies)).sort()
const expected = manifest.files
const failures = []
if (JSON.stringify(found) !== JSON.stringify(expected)) failures.push('copy membership differs from reviewed manifest')
for (const path of expected) {
  try {
    if (!readFileSync(resolve(root, manifest.canonical, path)).equals(readFileSync(resolve(root, manifest.copies, path)))) failures.push(path)
  } catch { failures.push('missing regular face file: ' + path) }
}
console.log(JSON.stringify({ schema: 'aukora-face-copies/v1', canonical: manifest.canonical, copies: manifest.copies, compared: expected.length,
  status: failures.length ? 'FAIL' : 'PASS', failures, limit: 'Source bytes only; frozen NEXT build inputs and generated bundles remain preserved.' }, null, 2))
process.exitCode = failures.length ? 1 : 0
