// Root-run consistent snapshot of the live gate ledger for the unprivileged collector (INTERIM install).
import { DatabaseSync } from 'node:sqlite'
import { rmSync, renameSync, chownSync, chmodSync } from 'node:fs'
const [src, out, uid, gid] = [process.argv[2], process.argv[3], Number(process.argv[4]), Number(process.argv[5])]
const tmp = `${out}.tmp`; rmSync(tmp, { force: true })
const db = new DatabaseSync(src, { readOnly: true }); db.exec(`VACUUM INTO '${tmp.replaceAll("'", "''")}'`); db.close()
chownSync(tmp, uid, gid); chmodSync(tmp, 0o440); renameSync(tmp, out)
