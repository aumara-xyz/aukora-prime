#!/usr/bin/env node
// Checks gate signatures and the full ledger against a supplied anchor; an exporter-supplied anchor proves no completeness.
// Independent anchor provenance requires the caller's explicit declaration; this offline checker cannot verify its source.
// Run from a checkout; this stranger checker is deliberately absent from releases and their plugin-set records.
import fs from 'node:fs'
import { verifyChannelReceipt, MAX_RECEIPT_EVENT_BYTES, MAX_RECEIPT_LEDGER_BYTES, RECEIPT_REFUSE } from '../lib/receipt.mjs'

const usage = `node plugins/aukora-buzz-door/bin/verify-channel-receipt.mjs EVENT.json --gate-key GATE.pub --ledger LEDGER.json --anchor ANCHORS.jsonl --door-key HEX --channel UUID [--independent-anchor-source HOW]

Checks every ledger row from GENESIS to the supplied anchor: sequence, hash links and gate signatures,
plus the receipt's signature and inclusion. Trust the door key, channel and gate key independently.
An export and anchor from the same party prove signed consistency against that supplied anchor only;
they do not prove that later entries were not withheld, current state, or who approved at the desktop.
For independent evidence, the anchor must come from somewhere the exporting party does not control.
Fetch anchors directly from https://raw.githubusercontent.com/aumara-xyz/aukora-prime/ledger-anchor/anchors/gate-ledger.jsonl
and retain the checkpoint and its commit independently. Use an export ending at that checkpoint.
The ledger-anchor branch is outside the pilot, but the repository owner controls it: if that owner
is the exporter, use a checkpoint retained by an independent witness instead.
Only pass --independent-anchor-source HOW after obtaining such an anchor; name the source and checkpoint.
That flag records your assertion, not a fact this offline checker can verify.`
const fail = code => { throw Object.assign(new Error(code), { code }) }
function read(file, maxBytes) {
  let fd
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK)
    const stat = fs.fstatSync(fd)
    if (!stat.isFile()) fail('buzz-receipt:input')
    if (stat.size > maxBytes) fail(RECEIPT_REFUSE.SIZE)
    const buffer = Buffer.alloc(maxBytes + 1)
    let size = 0, n
    while (size < buffer.length && (n = fs.readSync(fd, buffer, size, buffer.length - size, null)) > 0) size += n
    if (size > maxBytes) fail(RECEIPT_REFUSE.SIZE)
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, size))
  } finally { if (fd !== undefined) fs.closeSync(fd) }
}

function main(argv) {
  if (argv.length === 1 && argv[0] === '--help') { console.log(usage); return }
  let result
  try {
    const [eventFile, ...flags] = argv
    const names = ['--gate-key', '--ledger', '--anchor', '--door-key', '--channel'], options = {}
    const sourceFlag = '--independent-anchor-source'
    if (!eventFile || eventFile.startsWith('--') || ![names.length * 2, names.length * 2 + 2].includes(flags.length)) fail('buzz-receipt:usage')
    for (let i = 0; i < flags.length; i += 2) {
      if (![...names, sourceFlag].includes(flags[i]) || Object.hasOwn(options, flags[i]) || !flags[i + 1]?.trim() || flags[i + 1].startsWith('--')) fail('buzz-receipt:usage')
      options[flags[i]] = flags[i + 1]
    }
    if (names.some(name => !Object.hasOwn(options, name))) fail('buzz-receipt:usage')
    result = verifyChannelReceipt(JSON.parse(read(eventFile, MAX_RECEIPT_EVENT_BYTES)), {
      gatePublicKey: read(options['--gate-key'], 1024),
      entries: JSON.parse(read(options['--ledger'], MAX_RECEIPT_LEDGER_BYTES)),
      anchors: read(options['--anchor'], MAX_RECEIPT_LEDGER_BYTES).split('\n').filter(line => line.trim()).map(line => JSON.parse(line)),
      doorPubkey: options['--door-key'], channel: options['--channel'],
    })
    if (result.valid && Object.hasOwn(options, sourceFlag)) {
      result = { ...result, reason: 'valid, anchor independently obtained', anchor_source: options[sourceFlag], anchor_source_verified: false }
    }
  } catch (error) {
    result = { valid: false, reason: [RECEIPT_REFUSE.SIZE, 'buzz-receipt:usage', 'buzz-receipt:input'].includes(error?.code) ? error.code : 'buzz-receipt:input' }
  }
  console.log(JSON.stringify(result))
  process.exitCode = result.valid ? 0 : 1
}
main(process.argv.slice(2))
