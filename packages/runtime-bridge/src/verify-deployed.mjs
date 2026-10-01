// SPDX-License-Identifier: AGPL-3.0-or-later
// Host-configured synthetic client only. H owns service setup/restart and PG proof.
import {readFile,writeFile,lstat,realpath} from 'node:fs/promises'
import {resolve} from 'node:path'
import {pathToFileURL} from 'node:url'
import {createHash} from 'node:crypto'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createPrimeTransport} from '../../ui/adapters/transport.mjs'
import {createUiAdapters} from './ui-adapter.mjs'
import {createIpcClient} from './ipc.mjs'
const check=(result)=>{if(result?.ok!==true)throw Object.assign(new Error('DEPLOYED_JOIN_REFUSED'),{code:result?.error_code??'UNAVAILABLE'});return result}
const hash=value=>'sha256:'+createHash('sha256').update(value).digest('hex')
async function main() {
  const args=process.argv.slice(2)
  if(args.length!==4||args[0]!=='--config'||args[2]!=='--phase'||!['save','read'].includes(args[3])||resolve(args[1])!==args[1])throw new TypeError('INVALID: explicit config and save/read phase required')
  const stat=await lstat(args[1]);if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o7777)!==0o600||await realpath(args[1])!==args[1]||process.getuid&&![0,process.getuid()].includes(stat.uid))throw new TypeError('INVALID: private synthetic client config required')
  const cfg=(await import(pathToFileURL(args[1]).href)).default
  if(cfg?.profile!=='synthetic-prime-cd-check/v1'||typeof cfg.passkeySigner!=='function'||resolve(cfg.witness_path)!==cfg.witness_path)throw new TypeError('INVALID: synthetic check config required')
  const client=await createIpcClient(cfg.client)
  let sessionToken
  const adapters=createUiAdapters({call:async(method,input)=>{const result=await client.request(method,input);if(method==='owner.loginComplete'&&result?.ok===true)sessionToken=result.session_token;return result}})
  try {
    const ui=createPrimeTransport({authority:adapters.authority,contracts,passkeySigner:cfg.passkeySigner})
    await ui.login({owner_id:cfg.owner_id})
    if(args[3]==='save') {
      const draft={extraction_json:cfg.extraction_json,idempotency_key:cfg.idempotency_key}
      const proposed=check(await adapters.memory.proposeSave(draft)),approved=await ui.approve(await ui.prepareApproval(proposed.operation))
      const saved=check(await adapters.memory.save({...draft,operation:proposed.operation,approval_proof:approved.approval_proof}))
      if(saved.authority_settlement!=='completed'||saved.record.storage_status!=='saved')throw new Error('DEPLOYED_JOIN_SETTLEMENT_PENDING')
      const cite=check(await adapters.memory.cite({record_id:saved.record.record_id,revision:null,retained_head:null})).citation
      if(cite.verdict!=='VERIFIED'||cite.grants_authority!==false)throw new Error('DEPLOYED_JOIN_CITATION_REFUSED')
      const witness={version:1,record_id:saved.record.record_id,operation_id:proposed.operation.operation_id,canonical_bytes_digest:hash(saved.record.canonical_bytes),retained_head:cite.verified_head}
      await writeFile(cfg.witness_path,contracts.canonicalJson(witness)+'\n',{mode:0o600,flag:'wx'})
      process.stdout.write(JSON.stringify({status:'PASS',phase:'save',storage:saved.record.storage_status,index:saved.record.index_status,authority_settlement:saved.authority_settlement,citation:cite.verdict,...witness})+'\n')
    } else {
      const witness=contracts.parseStrictJson(await readFile(cfg.witness_path,'utf8'),{maxBytes:8192,maxDepth:8})
      const read={record_id:witness.record_id,revision:null},state=check(await adapters.memory.status(read))
      if(hash(state.record.canonical_bytes)!==witness.canonical_bytes_digest)throw new Error('DEPLOYED_JOIN_RESTART_BYTES_CHANGED')
      const cite=check(await adapters.memory.cite({...read,retained_head:witness.retained_head})).citation
      const authority=check(await client.request('owner.status',{session_token:sessionToken,operation_id:witness.operation_id}))
      if(cite.verdict!=='VERIFIED'||authority.status!=='COMPLETED')throw new Error('DEPLOYED_JOIN_RESTART_EVIDENCE_MISSING')
      process.stdout.write(JSON.stringify({status:'PASS',phase:'read',saved:state.saved,indexed:state.indexed,searchable:state.searchable,authority:authority.status,citation:cite.verdict,...witness})+'\n')
    }
  } finally {await client.close()}
}
main().catch(error=>{process.stderr.write('DEPLOYED_JOIN_NOT_VERIFIED:'+String(error.code??'UNAVAILABLE')+'\n');process.exitCode=1})
