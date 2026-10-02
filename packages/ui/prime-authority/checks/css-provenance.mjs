// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'

// Source-output regression only: no host, browser or runtime qualification.
const [oldPath, newPath, ...extra] = process.argv.slice(2)
assert.ok(oldPath && newPath && extra.length === 0,
  'usage: node css-provenance.mjs <same-build-raw-client.js> <normalized-client.js>')
const [oldBytes, newBytes, oldMapBytes, newMapBytes] = await Promise.all([
  readFile(oldPath), readFile(newPath), readFile(`${oldPath}.map`), readFile(`${newPath}.map`),
])
const oldCode = oldBytes.toString('utf8'), newCode = newBytes.toString('utf8')
assert.ok(oldBytes.equals(Buffer.from(oldCode)) && newBytes.equals(Buffer.from(newCode)),
  'client bytes must round-trip through UTF-8')
const oldLines = oldCode.split('\n'), newLines = newCode.split('\n')
assert.equal(newLines.length, oldLines.length, 'generated line count changed')
assert.ok(oldMapBytes.equals(newMapBytes), 'source map bytes changed')
const map = JSON.parse(newMapBytes.toString('utf8'))
assert.equal(map.version, 3, 'unexpected source map version')
assert.equal(typeof map.mappings, 'string', 'missing source map mappings')
const mappingLines = map.mappings.split(';')
const names = new Set(['OwnerSurface.module.css.mjs', 'PrimeProviderEditor.module.css.mjs'])
const seen = new Set(), changedLines = []
const region = /^([ \t]*)\/\/#region \\0dsh-css:(.*)$/
const ownerSourcePrefix = '/packages/client/aukora-prime-authority/src/client/'
for (let index = 0; index < oldLines.length; index++) {
  const match = region.exec(oldLines[index])
  const name = match?.[2].slice(match[2].lastIndexOf('/') + 1)
  if (match && names.has(name)) {
    assert.ok(match[2].startsWith('/') && match[2].endsWith(`${ownerSourcePrefix}${name}`),
      'old CSS provenance must name the physical owner source')
    assert.ok(!seen.has(name), 'duplicate owner CSS provenance comment')
    seen.add(name)
    assert.equal(newLines[index],
      `${match[1]}//#region \\0dsh-css:packages/ui/prime-authority/src/client/${name}`,
      'owner CSS provenance did not become its exact relative source path')
    assert.equal(mappingLines[index], '', 'changed comment line has source map segments')
    changedLines.push(index + 1)
  } else {
    assert.ok(newLines[index] === oldLines[index],
      `non-provenance client content changed on line ${index + 1}`)
  }
}
assert.equal(seen.size, 2, 'expected exactly two owner CSS provenance comments')
assert.equal(newLines.filter(line => region.test(line)).length, 2,
  'unexpected CSS provenance comment added')
assert.ok(!/(?:\/Users\/|\/home\/|[A-Za-z]:\\+Users\\+)/.test(newCode),
  'account path remains in the new client')
assert.ok(Array.isArray(map.sources) && map.sources.every(source =>
  typeof source === 'string' && !/(?:\/Users\/|\/home\/|[A-Za-z]:\\+Users\\+)/.test(source)),
  'account path remains in source map sources')
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')
console.log(JSON.stringify({ result: 'PASS', changed_comment_lines: changedLines,
  comment_changes: 2, other_client_content: 'IDENTICAL', css_payload: 'IDENTICAL',
  source_map_bytes: 'IDENTICAL', comment_line_mappings: 'EMPTY', account_paths: 'ABSENT',
  old_client_sha256: sha256(oldBytes), new_client_sha256: sha256(newBytes),
  source_map_sha256: sha256(newMapBytes), runtime_acceptance: 'UNPERFORMED' }))
