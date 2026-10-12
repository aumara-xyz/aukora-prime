#!/usr/bin/env node
// Checks local event and ledger exports against independently supplied door, channel, gate key and head anchors.
import fs from 'node:fs'
import { verifyChannelReceipt, MAX_RECEIPT_EVENT_BYTES, MAX_RECEIPT_LEDGER_BYTES, RECEIPT_REFUSE } from '../lib/receipt.mjs'

const usage = 'node plugins/aukora-buzz-door/bin/verify-channel-receipt.mjs EVENT.json --gate-key GATE.pub --ledger LEDGER.json --anchor ANCHORS.jsonl --door-key HEX --channel UUID'
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
    if (!eventFile || eventFile.startsWith('--') || flags.length !== names.length * 2) fail('buzz-receipt:usage')
    for (let i = 0; i < flags.length; i += 2) {
      if (!names.includes(flags[i]) || Object.hasOwn(options, flags[i]) || !flags[i + 1] || flags[i + 1].startsWith('--')) fail('buzz-receipt:usage')
      options[flags[i]] = flags[i + 1]
    }
    result = verifyChannelReceipt(JSON.parse(read(eventFile, MAX_RECEIPT_EVENT_BYTES)), {
      gatePublicKey: read(options['--gate-key'], 1024),
      entries: JSON.parse(read(options['--ledger'], MAX_RECEIPT_LEDGER_BYTES)),
      anchors: read(options['--anchor'], MAX_RECEIPT_LEDGER_BYTES).split('\n').filter(line => line.trim()).map(line => JSON.parse(line)),
      doorPubkey: options['--door-key'], channel: options['--channel'],
    })
  } catch (error) {
    result = { valid: false, reason: [RECEIPT_REFUSE.SIZE, 'buzz-receipt:usage', 'buzz-receipt:input'].includes(error?.code) ? error.code : 'buzz-receipt:input' }
  }
  console.log(JSON.stringify(result))
  process.exitCode = result.valid ? 0 : 1
}
main(process.argv.slice(2))
