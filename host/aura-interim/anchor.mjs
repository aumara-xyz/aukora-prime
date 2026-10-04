// Root records an INTERIM anchor (current live gate head) for the cold verifier.
import { DatabaseSync } from 'node:sqlite'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
const fp = readFileSync('/etc/aukora-aura/gate-key.sha256', 'utf8').trim().slice(0, 16)
const db = new DatabaseSync(process.argv[2], { readOnly: true })
const row = db.prepare('SELECT seq, hash, at FROM ledger ORDER BY seq DESC LIMIT 1').get(); db.close()
const f = '/etc/aukora-aura/anchors.json'
const anchors = existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) : []
if (!anchors.length || anchors.at(-1).seq < row.seq) anchors.push({ seq: row.seq, head: row.hash, gate_fp: fp, entry_at: row.at, anchored_at: new Date().toISOString() })
writeFileSync(f, JSON.stringify(anchors, null, 2) + '\n', { mode: 0o644 })
console.log('anchor seq', anchors.at(-1).seq, anchors.at(-1).head.slice(0, 12))
