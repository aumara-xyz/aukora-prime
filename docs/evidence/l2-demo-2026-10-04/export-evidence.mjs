// Run on the pilot as the gate user: node export-evidence.mjs <first-seq> <last-seq> > raw.json
// Opens the gate database READ-ONLY and prints the ledger entries in range plus the receipt of the LAST apply.
import { DatabaseSync } from 'node:sqlite'
const [a, b] = process.argv.slice(2).map(Number)
const db = new DatabaseSync('/home/aukora-gate/gate.db', { readOnly: true })
const entries = db.prepare('SELECT seq,at,event,proposal,target,base_sha,new_sha,detail,prev,hash,sig FROM ledger WHERE seq BETWEEN ? AND ? ORDER BY seq').all(a, b)
const apply = entries.filter(e => e.event === 'apply').at(-1)
const d = apply ? JSON.parse(apply.detail) : null
process.stdout.write(JSON.stringify({ entries, receipt: d?.receipt ?? null, receipt_sig: d?.receipt_sig ?? null }))
