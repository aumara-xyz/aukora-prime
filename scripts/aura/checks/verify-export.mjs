// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise the offline gate export verdict and removal of its verification guards.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { gateEntryBody } from '../gate-snapshot.mjs'

const root = fileURLToPath(new URL('../../../', import.meta.url))
const cli = join(root, 'scripts/aura/verify-export.mjs')
const evidence = join(root, 'docs/evidence/l2-demo-2026-10-04')
const entries = JSON.parse(readFileSync(join(evidence, 'ledger-entries.json'), 'utf8'))
const publicKey = join(evidence, 'gate-ed25519.pub')
const pem = readFileSync(publicKey, 'utf8')
const keyHash = '6cdce2bbeb7b725cf02493af784a71047e18d5fa9384c1518c948c2377fd4e63'
const head = entry => ({ seq: entry.seq, head: entry.hash, gate_fp: keyHash.slice(0, 16) })
const tail = head(entries.at(-1))
const bundle = () => ({ kind: 'aukora-gate-export/v1', public_key_pem: pem,
  gate_pubkey_sha256: keyHash, entries: structuredClone(entries), head: { ...tail } })
const mutations = {
  verification: ['verify-export.mjs', '  verifyGateSnapshot(snapshot, source, key)', '  void 0'],
  signature: ['gate-snapshot.mjs', 'if (!verify(null, Buffer.from(entry.hash, \'hex\'), publicKeyOf(publicKey), signature))', 'if (false)'],
  hash: ['gate-snapshot.mjs', 'if (gateEntryHash(entry_body) !== entry.hash)', 'if (false)'],
  sequence: ['verify-collected.mjs', 'record.position !== index + 1 || ', ''],
  link: ['verify-collected.mjs', '|| record.entry.prev !== previous', ''],
  anchor: ['verify-export.mjs', '    verifyHeads(anchors, snapshot)', '    void 0'],
  'anchor-key': ['verify-export.mjs', 'if (head.gate_fp !== snapshot.source.key_sha256.slice(0, 16))', 'if (false)'],
  'anchor-order': ['verify-export.mjs', 'head.seq <= previous', 'head.seq < 1'],
  'anchor-empty': ['verify-export.mjs', "if (!Array.isArray(anchors) || anchors.length === 0) refuse('anchor-required')", 'void 0'],
  'bundle-key': ['verify-export.mjs', 'document.gate_pubkey_sha256 !== keySha256', 'false'],
  'bundle-head': ['verify-export.mjs', '    verifyHeads([document.head], snapshot)', '    void 0'],
  'bundle-tail': ['verify-export.mjs', "if (document.head?.seq !== entries.length) refuse('bundle-head-mismatch')", 'void 0'],
  'strict-json': ['verify-export.mjs', 'parseUniqueJson(text, { maxBytes: 8 * 1024 * 1024 })', 'JSON.parse(text)'],
}

if (process.argv.includes('--mutations')) {
  for (const name of Object.keys(mutations)) {
    const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--mutant', name],
      { cwd: root, encoding: 'utf8', timeout: 60000 })
    assert.equal(result.status, 1, `${name} survived: ${result.stdout}\n${result.stderr}`)
    assert.match(result.stdout, /ERR_ASSERTION/, `${name} did not fail an assertion`)
    console.log(`KILLED ${name}`)
  }
  console.log(`PASS verify-export mutations ${Object.keys(mutations).length}/${Object.keys(mutations).length}`)
} else {
  const mutant = process.argv[process.argv.indexOf('--mutant') + 1]
  const mutation = process.argv.includes('--mutant') ? mutations[mutant] : null
  const scratch = mkdtempSync(join(root, '.aura-verify-check-'))
  let count = 0
  const hook = join(scratch, 'hook.mjs')
  if (mutation) {
    const [file, before, after] = mutation
    assert(readFileSync(join(root, 'scripts/aura', file), 'utf8').includes(before), 'mutation target exists')
    writeFileSync(hook, `import { registerHooks } from 'node:module';
      registerHooks({ load(url, context, next) {
        const result = next(url, context);
        if (url === ${JSON.stringify(new URL(`../${file}`, import.meta.url).href)}) {
          const source = String(result.source);
          if (!source.includes(${JSON.stringify(before)})) throw Error('mutation target absent');
          return { ...result, source: source.replace(${JSON.stringify(before)}, ${JSON.stringify(after)}) };
        }
        return result;
      }});\n`)
  }
  process.on('exit', () => rmSync(scratch, { recursive: true, force: true }))
  const run = (document, anchor, options = {}) => {
    const file = join(scratch, `export-${++count}.json`)
    writeFileSync(file, options.raw ?? JSON.stringify(document))
    const args = [cli, file, ...(options.key === false ? [] : ['--public-key', options.key ?? publicKey])]
    if (anchor !== undefined) {
      const path = join(scratch, `anchor-${count}.json`)
      writeFileSync(path, typeof anchor === 'string' ? anchor : JSON.stringify(anchor))
      args.push('--anchor', path)
    }
    return spawnSync(process.execPath, [...(mutation ? ['--import', hook] : []), ...args],
      { cwd: root, encoding: 'utf8', timeout: 10000 })
  }
  const accepted = (result, reason) => {
    assert.equal(result.status, 0, result.stdout + result.stderr)
    assert.match(result.stdout, new RegExp(`^VERIFIED ${reason}`, 'm'))
  }
  const refused = (result, reason) => {
    assert.equal(result.status, 1, result.stdout + result.stderr)
    assert.match(result.stdout, new RegExp(`^NOT VERIFIED ${reason}`, 'm'))
    assert.doesNotMatch(result.stdout, /^VERIFIED /m)
  }
  test('real 10-04 export: accepts 24 signed entries, raw and bundled, with supplied tail', () => {
    accepted(run(entries), 'gate-chain-only')
    accepted(run(entries, tail), 'gate-chain-and-supplied-anchor')
    accepted(run(bundle(), undefined, { key: false }), 'gate-chain-only')
    accepted(run(entries, bundle()), 'gate-chain-and-supplied-anchor')
    const rows = [head(entries[9]), tail].map(row => JSON.stringify(row)).join('\n') + '\n'
    accepted(run(entries, rows), 'gate-chain-and-supplied-anchor')
  })
  test('signed one-byte change and changed signature refuse with and without anchor', () => {
    for (const anchor of [undefined, tail]) {
      const changed = structuredClone(entries); changed[0].event = 'x' + changed[0].event.slice(1)
      refused(run(changed, anchor), 'aura-collected:gate-record-invalid')
      const signature = structuredClone(entries); signature[0].sig = 'A'.repeat(86) + '=='
      refused(run(signature, anchor), 'aura-collected:gate-record-invalid')
    }
  })
  test('interior removal, first entry removal and reordered entries refuse', () => {
    for (const anchor of [undefined, tail]) {
      const removed = structuredClone(entries); removed.splice(10, 1)
      refused(run(removed, anchor), 'aura-collected:source-sequence-gap')
      refused(run(entries.slice(1), anchor), 'aura-collected:source-sequence-gap')
      const reordered = structuredClone(entries); [reordered[10], reordered[11]] = [reordered[11], reordered[10]]
      refused(run(reordered, anchor), 'aura-collected:source-sequence-gap')
    }
  })
  test('valid tail removal is undetectable without a retained later anchor', () => {
    accepted(run(entries.slice(0, -1)), 'gate-chain-only')
    refused(run(entries.slice(0, -1), tail), 'aura-export:anchor-beyond-export')
    const earlier = run(entries.slice(0, -1), head(entries[9]))
    accepted(earlier, 'gate-chain-and-supplied-anchor')
    assert.match(earlier.stdout, /anchored_through=10 unanchored_entries=13/)
    refused(run(entries, undefined, { raw: JSON.stringify(entries).slice(0, -1) }), 'aura-collected:json-invalid')
  })
  test('divergent head, foreign key, empty and reversed anchor histories refuse', () => {
    refused(run(entries, { ...tail, head: '0'.repeat(64) }), 'aura-export:anchor-head-mismatch')
    refused(run(entries, { ...tail, gate_fp: '0'.repeat(16) }), 'aura-export:anchor-key-mismatch')
    refused(run(entries, []), 'aura-export:anchor-required')
    refused(run(entries, [tail, head(entries[9])]), 'aura-export:anchor-sequence')
    refused(run(entries, [tail, tail]), 'aura-export:anchor-sequence')
    refused(run(entries, ''), 'aura-export:anchor-required')
  })
  test('bundle key and observed head must match the signed export', () => {
    const wrongKey = bundle(); wrongKey.gate_pubkey_sha256 = '0'.repeat(64)
    refused(run(wrongKey), 'aura-export:bundle-key-mismatch')
    const wrongHead = bundle(); wrongHead.head.head = '0'.repeat(64)
    refused(run(wrongHead), 'aura-export:anchor-head-mismatch')
    const oldHead = bundle(); oldHead.head = head(entries[9])
    refused(run(oldHead), 'aura-export:bundle-head-mismatch')
    const truncated = bundle(); truncated.entries.pop()
    refused(run(truncated), 'aura-export:bundle-head-mismatch')
    truncated.head = head(truncated.entries.at(-1))
    accepted(run(truncated), 'gate-chain-only')
  })
  test('ambiguous JSON and empty export refuse; no private data is printed on errors', () => {
    const raw = JSON.stringify(entries).replace('"seq":1', '"seq":0,"seq":1')
    refused(run(entries, undefined, { raw }), 'aura-collected:json-duplicate-key')
    refused(run(entries, `{"seq":0,"seq":24,"head":"${tail.head}","gate_fp":"${tail.gate_fp}"}`), 'aura-collected:json-duplicate-key')
    refused(run([]), 'aura-export:empty-or-invalid-entries')
    refused(run(entries, undefined, { key: false }), 'aura-export:public-key-required-or-invalid')
    const error = run(entries, undefined, { raw: '{"private-fixture":"do-not-print"' })
    refused(error, 'aura-collected:json-invalid'); assert.doesNotMatch(error.stdout + error.stderr, /do-not-print/)
  })
  test('valid signatures cannot conceal a sequence gap or a broken predecessor link', () => {
    const { privateKey, publicKey: publicPart } = generateKeyPairSync('ed25519')
    const key = join(scratch, 'synthetic.pub')
    writeFileSync(key, publicPart.export({ type: 'spki', format: 'pem' }))
    const signed = entry => {
      const hash = createHash('sha256').update(gateEntryBody(entry)).digest('hex')
      return { ...entry, hash, sig: sign(null, Buffer.from(hash, 'hex'), privateKey).toString('base64') }
    }
    const first = signed(entries[0])
    const gap = signed({ ...entries[1], seq: 3, prev: first.hash })
    refused(run([first, gap], undefined, { key }), 'aura-collected:source-sequence-gap')
    const broken = signed({ ...entries[1], prev: '0'.repeat(64) })
    refused(run([first, broken], undefined, { key }), 'aura-collected:source-sequence-gap')
  })
}
