// Checks signed v2 receipts and the full ledger against supplied pins; anchor independence is not verified here.
import { createPublicKey } from 'node:crypto'
import { boundedLedgerJson, keyFingerprint } from '../../../packages/boundary-gate/src/ledger.mjs'
import { verifyReceipt, verifyReceiptSignature } from '../../../packages/boundary-gate/src/receipts.mjs'
import { verifyEvent } from '../../aukora-nostr/lib/event.mjs'

export const RECEIPT_KIND = 9
export const RECEIPT_FORMAT = 'aukora-gate-receipt-v1'
export const RECEIPT_LINE = 'Gate-signed result; verify with the gate key and anchored ledger.\n'
export const MAX_RECEIPT_CONTENT_BYTES = 2000
export const MAX_RECEIPT_EVENT_BYTES = 8192
export const MAX_RECEIPT_LEDGER_BYTES = 16 * 1024 * 1024
export const RECEIPT_REFUSE = Object.freeze({
  FORMAT: 'buzz-receipt:format', SIZE: 'buzz-receipt:oversized', VERSION: 'buzz-receipt:unsupported-version',
  CHANNEL: 'buzz-receipt:channel', AUTHOR: 'buzz-receipt:author', EVENT: 'buzz-receipt:event-signature',
  GATE_KEY: 'buzz-receipt:gate-key', RECEIPT: 'buzz-receipt:receipt-signature',
  LEDGER: 'buzz-receipt:ledger', ANCHOR: 'buzz-receipt:anchor',
})
const refuse = code => { throw Object.assign(new Error(code), { code }) }
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value)
const hex64 = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
const tagsFor = channel => [['h', channel], ['t', RECEIPT_FORMAT]]

function contentEnvelope(content) {
  if (typeof content !== 'string') refuse(RECEIPT_REFUSE.FORMAT)
  if (Buffer.byteLength(content, 'utf8') > MAX_RECEIPT_CONTENT_BYTES) refuse(RECEIPT_REFUSE.SIZE)
  if (!content.startsWith(RECEIPT_LINE)) refuse(RECEIPT_REFUSE.FORMAT)
  const json = content.slice(RECEIPT_LINE.length)
  let envelope
  try { envelope = JSON.parse(json) } catch { refuse(RECEIPT_REFUSE.FORMAT) }
  if (!envelope || Object.keys(envelope).join(',') !== 'receipt,receipt_sig'
    || !envelope.receipt || typeof envelope.receipt !== 'object' || Array.isArray(envelope.receipt)
    || typeof envelope.receipt_sig !== 'string' || !/^[A-Za-z0-9+/]{86}==$/u.test(envelope.receipt_sig)
    || JSON.stringify(envelope) !== json) refuse(RECEIPT_REFUSE.FORMAT)
  if (envelope.receipt.v !== 2) refuse(RECEIPT_REFUSE.VERSION)
  return envelope
}

// JSON.stringify order is the gate's signed byte form. Sorting receipt keys would invalidate the signature.
export function receiptMessage(result, { channel } = {}) {
  if (!uuid(channel)) refuse(RECEIPT_REFUSE.CHANNEL)
  let json
  try { json = boundedLedgerJson({ receipt: result?.receipt, receipt_sig: result?.receipt_sig }) }
  catch { refuse(RECEIPT_REFUSE.FORMAT) }
  const content = RECEIPT_LINE + json
  contentEnvelope(content)
  return { kind: RECEIPT_KIND, tags: tagsFor(channel), content }
}

// Parsing preserves bytes; it does not establish either signature or ledger inclusion.
export function parseReceiptMessage(event) {
  if (!event || event.kind !== RECEIPT_KIND || !Array.isArray(event.tags) || event.tags.length !== 2) refuse(RECEIPT_REFUSE.FORMAT)
  const envelope = contentEnvelope(event.content)
  if (Buffer.byteLength(JSON.stringify(event), 'utf8') > MAX_RECEIPT_EVENT_BYTES) refuse(RECEIPT_REFUSE.SIZE)
  const channel = event.tags[0]?.[1]
  if (!uuid(channel) || JSON.stringify(event.tags) !== JSON.stringify(tagsFor(channel))) refuse(RECEIPT_REFUSE.CHANNEL)
  return { ...envelope, receiptBytes: Buffer.from(JSON.stringify(envelope.receipt), 'utf8'), channel }
}

export function verifyChannelReceipt(event, { doorPubkey, channel, gatePublicKey, entries, anchors } = {}) {
  try {
    const parsed = parseReceiptMessage(event)
    if (!hex64(doorPubkey) || event.pubkey !== doorPubkey) refuse(RECEIPT_REFUSE.AUTHOR)
    if (!uuid(channel) || parsed.channel !== channel) refuse(RECEIPT_REFUSE.CHANNEL)
    try { verifyEvent(event) } catch { refuse(RECEIPT_REFUSE.EVENT) }
    let pub
    try { pub = createPublicKey(gatePublicKey) } catch { refuse(RECEIPT_REFUSE.GATE_KEY) }
    if (pub.asymmetricKeyType !== 'ed25519') refuse(RECEIPT_REFUSE.GATE_KEY)
    const { receipt, receipt_sig } = parsed
    if (!verifyReceiptSignature(receipt, receipt_sig, pub).ok) refuse(RECEIPT_REFUSE.RECEIPT)
    if (!Array.isArray(entries) || !entries.length) refuse(RECEIPT_REFUSE.LEDGER)
    if (Buffer.byteLength(JSON.stringify(entries), 'utf8') > MAX_RECEIPT_LEDGER_BYTES) refuse(RECEIPT_REFUSE.SIZE)
    // verifyReceipt reuses verifyLedger: GENESIS, consecutive seqs, every hash/link and gate signature.
    // Preserve input order and signed detail TEXT verbatim; the anchor does not authenticate the export alone.
    const db = { prepare: () => ({
      iterate: () => entries,
      all: proposal => entries.filter(e => e.proposal === proposal && ['apply', 'revert-applied'].includes(e.event)),
    }) }
    let checked
    try { checked = verifyReceipt(db, receipt, receipt_sig, pub) } catch { refuse(RECEIPT_REFUSE.LEDGER) }
    if (!checked.ok) refuse(RECEIPT_REFUSE.LEDGER)
    const apply = entries.find(e => e.seq === checked.ledger_seq)
    if (apply.proposal !== receipt.proposal || apply.target !== receipt.target
      || apply.event !== (receipt.kind === 'revert' ? 'revert-applied' : 'apply')) refuse(RECEIPT_REFUSE.LEDGER)
    if (!Array.isArray(anchors) || !anchors.length) refuse(RECEIPT_REFUSE.ANCHOR)
    const fp = keyFingerprint(pub), bySeq = new Map(entries.map(e => [e.seq, e]))
    let previous = 0
    for (const anchor of anchors) {
      if (!anchor || !Number.isSafeInteger(anchor.seq) || anchor.seq <= previous || !hex64(anchor.head)
        || anchor.gate_fp !== fp || bySeq.get(anchor.seq)?.hash !== anchor.head) refuse(RECEIPT_REFUSE.ANCHOR)
      previous = anchor.seq
    }
    // A head before the receipt or beyond this export is not a proof of inclusion. Require the supplied tail.
    if (anchors.at(-1).seq !== entries.at(-1).seq || anchors.at(-1).seq < checked.ledger_seq) refuse(RECEIPT_REFUSE.ANCHOR)
    return { valid: true, reason: 'valid against the supplied anchor', proposal: receipt.proposal, ledger_seq: checked.ledger_seq, anchored_seq: anchors.at(-1).seq }
  } catch (error) {
    return { valid: false, reason: Object.values(RECEIPT_REFUSE).includes(error?.code) ? error.code : RECEIPT_REFUSE.FORMAT }
  }
}
