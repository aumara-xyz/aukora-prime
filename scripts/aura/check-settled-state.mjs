// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara LLC
// Check broker memory rows against stored objects and latest key projections, read-only.
import { createHash } from 'node:crypto'
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { isMainModule } from '../lib/is-main.mjs'
import { readVerifiedChain } from '../../plugins/aukora-box/aukora/aura/record.mjs'
import { effectBody } from '../../plugins/aukora-box/aukora/broker/effect-body.mjs'
import { KEY_SHAPE } from '../../plugins/aukora-box/aukora/broker/memory-put-args.mjs'
import { definitionDigest, MEMORY_PUT } from '../../plugins/aukora-box/aukora/broker/effect-definition.mjs'
import { requestDigest } from '../../plugins/aukora-box/aukora/broker/receipt.mjs'
import { classAtLeast, CONFINEMENT_CLASS, isConfinementField } from '../../plugins/aukora-box/aukora/broker/confinement.mjs'

const HEX64 = /^[0-9a-f]{64}$/
const NONCE = /^[a-zA-Z0-9_-]{1,128}$/
const DECIMAL = /^(?:0|[1-9][0-9]*)$/
const FIELDS = ['hash', 'prev', 'verdict', 'sequence', 'key', 'requestDigest', 'definitionId',
  'nonce', 'receiptSha256', 'path', 'bytes', 'contentSha256', 'inode', 'mtimeNs', 'confinement'].sort().join(',')

function requireCheck(condition, code) {
  if (!condition) throw Object.assign(new Error(code), { code: `settled:${code}` })
}

// Check every ancestor before opening; descriptors refuse links and non-regular files.
function readRegular(file) {
  let parent = dirname(file)
  for (;;) {
    const stat = lstatSync(parent)
    requireCheck(stat.isDirectory() && !stat.isSymbolicLink(), 'unsafe-parent')
    const next = dirname(parent)
    if (next === parent) break
    parent = next
  }
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const stat = fstatSync(fd)
    requireCheck(stat.isFile() && stat.nlink === 1, 'unsafe-file')
    return readFileSync(fd)
  } finally { closeSync(fd) }
}

function snapshot(root) {
  const file = join(root, 'aura.jsonl')
  const bytes = readRegular(file)
  const chain = readVerifiedChain(file)
  requireCheck(chain.ok, 'invalid-chain')
  requireCheck(bytes.equals(Buffer.from(chain.entries.map(row => JSON.stringify(row) + '\n').join(''))), 'state-changed')
  requireCheck(chain.count > 0, 'empty-chain')
  const seq = readRegular(join(root, 'seq')).toString('utf8')
  requireCheck(seq === String(chain.count), 'sequence-witness')
  return chain
}

// Require the original root's absolute paths. Unrecorded files and signatures are outside this check.
export function checkSettledState(stateDir) {
  try {
    const root = resolve(stateDir)
    const before = snapshot(root)
    const newest = new Map()
    const nonces = new Set()
    for (const [index, row] of before.entries.entries()) {
      requireCheck(Object.keys(row).sort().join(',') === FIELDS, 'row-fields')
      requireCheck(row.verdict === 'settled' && row.sequence === index + 1, 'row-order')
      requireCheck(typeof row.key === 'string' && KEY_SHAPE.test(row.key), 'key')
      requireCheck(typeof row.contentSha256 === 'string' && HEX64.test(row.contentSha256), 'content-digest')
      requireCheck(typeof row.nonce === 'string' && NONCE.test(row.nonce), 'nonce')
      requireCheck(!nonces.has(row.nonce), 'nonce-reused')
      nonces.add(row.nonce)
      requireCheck(row.definitionId === definitionDigest(MEMORY_PUT), 'definition')
      requireCheck(typeof row.receiptSha256 === 'string' && HEX64.test(row.receiptSha256)
        && Number.isSafeInteger(row.inode) && row.inode >= 0
        && typeof row.mtimeNs === 'string' && DECIMAL.test(row.mtimeNs)
        && isConfinementField(row.confinement)
        && classAtLeast(row.confinement.class, CONFINEMENT_CLASS.STATE_OWNED), 'row-metadata')
      const objectPath = join(root, 'memory', 'objects', `${row.contentSha256}.json`)
      requireCheck(row.path === objectPath, 'object-path')
      const body = readRegular(objectPath)
      requireCheck(createHash('sha256').update(body).digest('hex') === row.contentSha256, 'object-digest')
      requireCheck(body.length === row.bytes, 'object-size')
      let args
      try { args = JSON.parse(body.toString('utf8')) } catch { requireCheck(false, 'object-body') }
      let canonical
      try { canonical = effectBody(args) } catch { requireCheck(false, 'object-body') }
      requireCheck(body.equals(Buffer.from(canonical)), 'object-canonical')
      requireCheck(args.key === row.key, 'object-key')
      requireCheck(requestDigest(MEMORY_PUT, args) === row.requestDigest, 'request-digest')
      newest.set(row.key, row)
    }
    for (const [key, row] of newest) {
      const body = readRegular(join(root, 'memory', 'keys', `${key}.json`))
      const expected = `${JSON.stringify({ key, contentSha256: row.contentSha256 })}\n`
      requireCheck(body.equals(Buffer.from(expected)), 'projection')
    }
    const after = snapshot(root)
    requireCheck(after.count === before.count && after.lastChainHash === before.lastChainHash, 'state-changed')
    return { rows: before.count, keys: newest.size, head: before.lastChainHash }
  } catch (error) {
    if (error?.code?.startsWith('settled:')) throw error
    throw Object.assign(new Error('state unavailable'), { code: 'settled:unavailable' })
  }
}

if (isMainModule(import.meta.url)) {
  if (process.argv.length !== 3) {
    process.stderr.write('usage: check-settled-state.mjs <broker-state-root>\n')
    process.exitCode = 2
  } else {
    try {
      const result = checkSettledState(process.argv[2])
      process.stdout.write(`rows verified: ${result.rows}; keys projected: ${result.keys}\n`)
      process.stdout.write('Scope: quiescent broker memory only; no receipt signatures, authorization, orphan inventory, atomic snapshot or live execution proof.\n')
    } catch (error) {
      process.stderr.write(`${error.code}\n`)
      process.exitCode = 1
    }
  }
}
