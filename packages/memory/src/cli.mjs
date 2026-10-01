// SPDX-License-Identifier: AGPL-3.0-or-later
import { resolve, dirname } from 'node:path'
import { pathToFileURL } from 'node:url'
import { readBytesStrict, durableWrite } from '../genesis/plugins/aukora-kira/lib/strict-read.mjs'
import { parseOriginal, requireMemory } from './codecs.mjs'
import { inspectSnapshot } from './snapshot.mjs'
import { createPostgresMemory } from './index.mjs'

export const MEMORY_CLI_USAGE = [
  'verify SNAPSHOT OWNER [RETAINED_HEADS_JSON]',
  'export OWNER OUTPUT',
  'restore SNAPSHOT OWNER --synthetic-fixture',
  'Database commands require an explicitly configured PRIME_MEMORY_DATABASE_URL and a Prime-owned pg dependency.'
]

export async function runMemoryCommand(argv,{pool}={}) {
  const [command,first,second,third] = argv
  if(command==='--help' || command==='help') return {usage:MEMORY_CLI_USAGE}
  requireMemory(['verify','export','restore'].includes(command) && first && second, 'memory:cli-arguments-invalid')
  if(command==='verify') {
    const snapshot=parseOriginal(readBytesStrict(resolve(first)).bytes)
    const expectedHeads=third ? parseOriginal(readBytesStrict(resolve(third)).bytes) : undefined
    const checked=inspectSnapshot(snapshot,second,{expectedHeads})
    return {snapshot_integrity:'VERIFIED',records:checked.records.length,heads:snapshot.heads,
      citations:checked.records.map(r=>({record_id:r.meta.id,revision:String(r.file.revision),...r.citation})),
      independent_trust_anchor_supplied:Boolean(third),grants_authority:false}
  }
  if(command==='restore') requireMemory(third==='--synthetic-fixture','memory:real-data-import-not-authorized')
  let ownedPool=false
  if(!pool) {
    const configured=process.env.PRIME_MEMORY_DATABASE_URL
    requireMemory(typeof configured==='string' && configured.length>0,'memory:postgres-unavailable')
    const {Pool}=await import('pg').catch(()=>{throw Object.assign(new Error('memory:postgres-driver-unavailable'),{code:'memory:postgres-driver-unavailable'})})
    pool=new Pool({connectionString:configured});ownedPool=true
  }
  try {
    const memory=createPostgresMemory({pool,allowSyntheticImport:command==='restore'})
    if(command==='export') {
      const snapshot=await memory.exportSnapshot({owner_subject:first})
      const output=resolve(second)
      durableWrite(output,JSON.stringify(snapshot)+'\n',{dir:dirname(output)})
      return {snapshot_integrity:'VERIFIED',manifest_sha256:snapshot.manifest_sha256,output,grants_authority:false}
    }
    await memory.migrate()
    const snapshot=parseOriginal(readBytesStrict(resolve(first)).bytes)
    const restored=await memory.restoreSnapshot({owner_subject:second,task_id:'synthetic-restore'},snapshot,{mode:'synthetic-fixture'})
    return {...restored,index_status:'pending',grants_authority:false}
  } finally {if(ownedPool) await pool.end()}
}

if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  runMemoryCommand(process.argv.slice(2)).then(result=>process.stdout.write(JSON.stringify(result)+'\n')).catch(error=>{
    process.stderr.write(JSON.stringify({verdict:'REFUSED',reason:error.code ?? 'memory:command-unavailable'})+'\n')
    process.exitCode=1
  })
}
