// SPDX-License-Identifier: AGPL-3.0-or-later
import {canonicalJson,validateContract,operationDigest} from '../../contracts/src/runtime.mjs'
import {getUnsentClosureCertificate} from './unsent-closure.mjs'

const stores=new WeakSet()
const DIGEST=/^sha256:[a-f0-9]{64}$/
const RAW_DIGEST=/^[a-f0-9]{64}$/
const SUBJECT=/^aukora:1:[a-f0-9]{64}$/
const ACTIONS=['memory.save','memory.forget']
const PHASES=['proposed','attempted','known_unsent','saved','forgotten']
const COLUMNS='owner_subject,owner_id,task_id,operation_id,operation_digest,action_type,idempotency_key_sha256,record_id,phase,request_id,request_digest,receipt_digest,created_at'
const METADATA=['record_id','request_id','request_digest','receipt_digest']

// Reference metadata only. D retains effects/receipts and C retains authority.
// This initializer must be called explicitly by the approved schema initializer.
export const WORKFLOW_SCHEMA_SQL=`CREATE TABLE IF NOT EXISTS prime_runtime_workflows (
  owner_subject text NOT NULL, owner_id text NOT NULL, task_id text NOT NULL,
  operation_id text NOT NULL, operation_digest text NOT NULL,
  action_type text NOT NULL CHECK (action_type IN ('memory.save','memory.forget')),
  idempotency_key_sha256 text, record_id text,
  phase text NOT NULL CHECK (phase IN ('proposed','attempted','known_unsent','saved','forgotten')),
  request_id text, request_digest text, receipt_digest text, created_at text NOT NULL,
  PRIMARY KEY (owner_subject,operation_id),
  UNIQUE (owner_subject,task_id,idempotency_key_sha256)
);
CREATE INDEX IF NOT EXISTS prime_runtime_workflows_owner_task
  ON prime_runtime_workflows(owner_subject,owner_id,task_id,phase,created_at,operation_id);`

function refuse(reason,error_code='INVALID',extra={}) {
  const error=new Error(reason)
  error.error_code=error_code;error.code='workflow:'+reason.toLowerCase().replaceAll('_','-')
  Object.assign(error,extra);throw error
}
function closed(value,required,optional=[]) {
  canonicalJson(value) // Refuse getters, exotic prototypes and non-JSON fields before reading them.
  if(!value||typeof value!=='object'||Array.isArray(value)
    ||required.some(key=>!Object.hasOwn(value,key))
    ||Object.keys(value).some(key=>!required.includes(key)&&!optional.includes(key)))refuse('WORKFLOW_CLOSED_FIELDS')
  return value
}
function text(value) {
  if(typeof value!=='string'||!value.length||Buffer.byteLength(value,'utf8')>1024
    ||/[\x00-\x1f\x7f]/u.test(value))refuse('WORKFLOW_IDENTIFIER_INVALID')
  canonicalJson(value);return value
}
function digest(value,{nullable=false,raw=false}={}) {
  if(nullable&&value===null)return null
  if(typeof value!=='string'||!(raw?RAW_DIGEST:DIGEST).test(value))refuse('WORKFLOW_DIGEST_INVALID')
  return value
}
function nullableText(value) {return value===null?null:text(value)}
function identity(host) {
  // Existing memory hosts include byte-bearing source data. Read only their
  // three trusted identity properties, without serializing or retaining events.
  if(!host||typeof host!=='object'||Array.isArray(host)
    ||![Object.prototype,null].includes(Object.getPrototypeOf(host)))refuse('WORKFLOW_TRUSTED_HOST_REQUIRED')
  const result={}
  for(const key of ['owner_subject','owner_id','task_id']) {
    const descriptor=Object.getOwnPropertyDescriptor(host,key)
    if(!descriptor||!Object.hasOwn(descriptor,'value'))refuse('WORKFLOW_TRUSTED_HOST_REQUIRED')
    result[key]=text(descriptor.value)
  }
  if(!SUBJECT.test(result.owner_subject))refuse('WORKFLOW_OWNER_SUBJECT_INVALID')
  return Object.freeze(result)
}
function resultRow(row,host) {
  if(!row)refuse('WORKFLOW_REFERENCE_UNAVAILABLE','UNAVAILABLE')
  const result=Object.fromEntries(COLUMNS.split(',').map(key=>[key,row[key]]))
  closed(result,COLUMNS.split(','))
  if(result.owner_subject!==host.owner_subject||result.owner_id!==host.owner_id
    ||result.task_id!==host.task_id)refuse('WORKFLOW_REFERENCE_BINDING_INVALID','UNAVAILABLE')
  text(result.operation_id);digest(result.operation_digest)
  if(!ACTIONS.includes(result.action_type)||!PHASES.includes(result.phase))refuse('WORKFLOW_REFERENCE_INVALID','UNAVAILABLE')
  digest(result.idempotency_key_sha256,{nullable:true,raw:true});nullableText(result.record_id)
  nullableText(result.request_id);digest(result.request_digest,{nullable:true});digest(result.receipt_digest,{nullable:true})
  if((result.request_id===null)!==(result.request_digest===null)
    ||typeof result.created_at!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(result.created_at)
    ||!Number.isFinite(Date.parse(result.created_at))||new Date(result.created_at).toISOString()!==result.created_at
    ||result.phase==='saved'&&result.action_type!=='memory.save'
    ||result.phase==='forgotten'&&result.action_type!=='memory.forget'
    ||['saved','forgotten'].includes(result.phase)&&result.record_id===null)refuse('WORKFLOW_REFERENCE_INVALID','UNAVAILABLE')
  return Object.freeze(result)
}
const rows=async(db,sql,values=[])=>{
  const result=await db.query(sql,values)
  if(!Array.isArray(result?.rows))refuse('WORKFLOW_POSTGRES_RESULT_INVALID','UNAVAILABLE')
  return result.rows
}

/** Host-supplied PostgreSQL pool. No credentials, automatic migration or
 * authority/effect calls are discovered or made by this reference journal. */
export function createPostgresWorkflowStore({pool}={}) {
  if(typeof pool?.query!=='function'||typeof pool?.connect!=='function')refuse('WORKFLOW_POSTGRES_POOL_REQUIRED','UNAVAILABLE')
  async function transaction(work,{readOnly=false}={}) {
    const client=await pool.connect()
    if(typeof client?.query!=='function'||typeof client?.release!=='function') {
      if(typeof client?.release==='function')client.release()
      refuse('WORKFLOW_POSTGRES_CLIENT_REQUIRED','UNAVAILABLE')
    }
    try {
      await client.query(readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN')
      if(!readOnly)await client.query('SET LOCAL synchronous_commit = on')
      const result=await work(client)
      await client.query('COMMIT');return result
    } catch(error) {await client.query('ROLLBACK').catch(()=>{});throw error}
    finally {client.release()}
  }
  async function migrate() {
    const [settings]=await rows(pool,"SELECT current_setting('fsync') AS fsync, current_setting('full_page_writes') AS full_page_writes")
    if(settings?.fsync!=='on'||settings.full_page_writes!=='on')refuse('WORKFLOW_POSTGRES_DURABILITY_UNAVAILABLE','UNAVAILABLE')
    await transaction(db=>db.query(WORKFLOW_SCHEMA_SQL))
    return Object.freeze({migrated:true})
  }
  function admissionClosures(host,certificates) {
    if(!Array.isArray(certificates)||certificates.length>256)refuse('WORKFLOW_CLOSURE_CERTIFICATES_REQUIRED')
    return certificates.map(certificate=>{
      const facts=getUnsentClosureCertificate(certificate)
      if(facts.reference.owner_id!==host.owner_id||facts.reference.owner_subject!==host.owner_subject
        ||facts.host.authorization_epoch!==host.authorization_epoch)refuse('WORKFLOW_CLOSURE_BINDING_REQUIRED')
      return facts.reference
    })
  }
  async function guardAdmission(db,owner,certified,{exclude=null}={}) {
    const unresolved=await rows(db,`SELECT ${COLUMNS} FROM prime_runtime_workflows
      WHERE owner_subject=$1 AND phase IN ('attempted','known_unsent')`,[owner.owner_subject])
    for(const row of unresolved) {
      if(row.operation_id===exclude)continue
      // A metadata-only legacy mark creates no exemption. Only exact C/D
      // facts validated before this owner lock may exempt a closed reference.
      if(row.phase==='known_unsent'&&certified.some(reference=>
        ['owner_subject','owner_id','task_id','operation_id','operation_digest','action_type']
          .every(key=>reference[key]===row[key])))continue
      refuse('WORKFLOW_OWNER_RECONCILIATION_REQUIRED','RECONCILIATION_REQUIRED')
    }
  }
  async function insertReference(host,input,{admission=false,closures=[]}={}) {
    const owner=identity(host)
    const certified=admission?admissionClosures(host,closures):[]
    closed(input,['operation','idempotency_key_sha256','record_id'])
    // Detach before the first wait, while preserving the fixed v1 digest profile.
    const operation=JSON.parse(canonicalJson(input.operation))
    validateContract('OperationProposal',operation)
    text(operation.operation_id)
    closed(operation.target_identity,['kind','owner_subject'])
    if(operation.owner_id!==owner.owner_id||operation.task_id!==owner.task_id
      ||operation.audience!=='aukora-prime.memory'||!ACTIONS.includes(operation.action_type)
      ||operation.target_identity.kind!=='prime-memory'||operation.target_identity.owner_subject!==owner.owner_subject)refuse('WORKFLOW_OPERATION_BINDING_REQUIRED')
    const hash=operationDigest(operation)
    const key=digest(input.idempotency_key_sha256,{nullable:true,raw:true})
    const record=nullableText(input.record_id)
    if(operation.action_type==='memory.forget'
      &&(record===null||operation.canonical_parameters.record_id!==record||key!==null))refuse('WORKFLOW_FORGET_REFERENCE_INVALID')
    const created=new Date().toISOString()
    return transaction(async db=>{
      if(admission) {
        // The Bridge's final proposal admission shares the effect-attempt
        // writer lock. A draft read taken before a competing attempt cannot
        // admit a new proposal after that unresolved attempt has committed.
        await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',[owner.owner_subject])
        await guardAdmission(db,owner,certified)
      }
      const values=[owner.owner_subject,owner.owner_id,owner.task_id,operation.operation_id,hash,operation.action_type,key,record,created]
      const [inserted]=await rows(db,`INSERT INTO prime_runtime_workflows
        (${COLUMNS}) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'proposed',NULL,NULL,NULL,$9)
        ON CONFLICT DO NOTHING RETURNING ${COLUMNS}`,values)
      const [prior]=inserted?[inserted]:await rows(db,`SELECT ${COLUMNS} FROM prime_runtime_workflows
        WHERE owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4`,values.slice(0,4))
      if(!prior)refuse('WORKFLOW_IDEMPOTENCY_CONFLICT','REPLAYED')
      const result=resultRow(prior,owner)
      if(result.operation_digest!==hash||result.action_type!==operation.action_type
        ||result.idempotency_key_sha256!==key||record!==null&&result.record_id!==record)refuse('WORKFLOW_OPERATION_CONFLICT','REPLAYED')
      return result
    })
  }
  const insert=(host,input)=>insertReference(host,input)
  const insertForAdmission=(host,input,{closures=[]}={})=>insertReference(host,input,{admission:true,closures})
  async function listReferences(host,input,{admission=false}={}) {
    const owner=identity(host)
    closed(input,['active'],['limit'])
    if(typeof input.active!=='boolean')refuse('WORKFLOW_ACTIVE_BOOLEAN_REQUIRED')
    const active=input.active,limit=input.limit??256
    if(!Number.isSafeInteger(limit)||limit<1||limit>256)refuse('WORKFLOW_LIMIT_INVALID')
    return transaction(async db=>{
      const found=await rows(db,`SELECT ${COLUMNS} FROM prime_runtime_workflows
        WHERE owner_subject=$1 AND owner_id=$2 AND task_id=$3
        ${active?(admission?"AND phase NOT IN ('saved','forgotten')":"AND phase NOT IN ('known_unsent','saved','forgotten')"):''}
        ORDER BY created_at${active?'':' DESC'},operation_id${active?'':' DESC'} LIMIT $4`,[owner.owner_subject,owner.owner_id,owner.task_id,limit+1])
      const overflow=found.length>limit
      if(active&&overflow)refuse('WORKFLOW_LIST_OVERFLOW','UNAVAILABLE',{overflow:true})
      return Object.freeze({items:Object.freeze(found.slice(0,limit).map(row=>resultRow(row,owner))),overflow})
    },{readOnly:true})
  }
  // Legacy list/mark are reference metadata APIs. Safety admission separately
  // includes known_unsent labels and revalidates original C/D closure facts.
  const list=(host,input)=>listReferences(host,input)
  const admissionCandidates=host=>listReferences(host,{active:true},{admission:true})
  async function get(host,operation_id) {
    const owner=identity(host),id=text(operation_id)
    return transaction(async db=>{
      const [row]=await rows(db,`SELECT ${COLUMNS} FROM prime_runtime_workflows
        WHERE owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4`,
      [owner.owner_subject,owner.owner_id,owner.task_id,id])
      return resultRow(row,owner)
    },{readOnly:true})
  }
  async function attemptReference(host,operation_id,operation_digest,{admission=false,closures=[]}={}) {
    const owner=identity(host),id=text(operation_id),hash=digest(operation_digest)
    const certified=admission?admissionClosures(host,closures):[]
    return transaction(async db=>{
      // Serialize admission across this owner's tasks. This transaction ends
      // before the caller invokes C or D; no authority/effect callback is held.
      await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',[owner.owner_subject])
      if(admission)await guardAdmission(db,owner,certified,{exclude:id})
      const [other]=await rows(db,`SELECT operation_id FROM prime_runtime_workflows
        WHERE owner_subject=$1 AND phase='attempted' AND operation_id<>$2 LIMIT 1`,[owner.owner_subject,id])
      if(other)refuse('WORKFLOW_OWNER_RECONCILIATION_REQUIRED','RECONCILIATION_REQUIRED')
      const [row]=await rows(db,`UPDATE prime_runtime_workflows SET phase='attempted'
        WHERE owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4
          AND operation_digest=$5 AND phase='proposed' RETURNING ${COLUMNS}`,
      [owner.owner_subject,owner.owner_id,owner.task_id,id,hash])
      if(!row)refuse('WORKFLOW_ATTEMPT_REFUSED','REPLAYED')
      return resultRow(row,owner)
    })
  }
  const attempt=(host,id,digest)=>attemptReference(host,id,digest)
  const attemptForAdmission=(host,id,digest,{closures=[]}={})=>attemptReference(host,id,digest,{admission:true,closures})
  async function markClosed(host,certificate) {
    const owner=identity(host),[reference]=admissionClosures(host,[certificate])
    if(reference.task_id!==owner.task_id)refuse('WORKFLOW_CLOSURE_BINDING_REQUIRED')
    return transaction(async db=>{
      await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',[owner.owner_subject])
      const [row]=await rows(db,`UPDATE prime_runtime_workflows SET phase='known_unsent'
        WHERE owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4
          AND operation_digest=$5 AND action_type=$6
          AND phase IN ('attempted','known_unsent')
          AND request_id IS NULL AND request_digest IS NULL AND receipt_digest IS NULL
        RETURNING ${COLUMNS}`,['owner_subject','owner_id','task_id','operation_id','operation_digest','action_type'].map(key=>reference[key]))
      if(!row)refuse('WORKFLOW_CLOSURE_MARK_REFUSED','RECONCILIATION_REQUIRED')
      return resultRow(row,owner)
    })
  }
  // Internal callers must verify C/D facts before marking. This cannot clear
  // C's unknown outcome, authorize a retry, or dispatch any operation itself.
  async function mark(host,operation_id,phase,input={}) {
    const owner=identity(host),id=text(operation_id)
    if(!['known_unsent','saved','forgotten'].includes(phase))refuse('WORKFLOW_MARK_PHASE_INVALID')
    closed(input,[],METADATA)
    const metadata=Object.fromEntries(METADATA.map(key=>[key,Object.hasOwn(input,key)?input[key]:null]))
    nullableText(metadata.record_id);nullableText(metadata.request_id)
    digest(metadata.request_digest,{nullable:true});digest(metadata.receipt_digest,{nullable:true})
    if((metadata.request_id===null)!==(metadata.request_digest===null))refuse('WORKFLOW_REQUEST_BINDING_REQUIRED')
    return transaction(async db=>{
      const [row]=await rows(db,`UPDATE prime_runtime_workflows SET phase=$5,
        record_id=COALESCE(record_id,$6),request_id=COALESCE(request_id,$7),
        request_digest=COALESCE(request_digest,$8),receipt_digest=COALESCE(receipt_digest,$9)
        WHERE owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4
          AND (phase='attempted' OR phase=$5 OR ($5='known_unsent' AND phase='proposed'))
          AND ($5='known_unsent' OR ($5='saved' AND action_type='memory.save') OR ($5='forgotten' AND action_type='memory.forget'))
          AND ($6 IS NULL OR record_id IS NULL OR record_id=$6)
          AND ($7 IS NULL OR request_id IS NULL OR request_id=$7)
          AND ($8 IS NULL OR request_digest IS NULL OR request_digest=$8)
          AND ($9 IS NULL OR receipt_digest IS NULL OR receipt_digest=$9)
        RETURNING ${COLUMNS}`,[owner.owner_subject,owner.owner_id,owner.task_id,id,phase,...METADATA.map(key=>metadata[key])])
      if(!row)refuse('WORKFLOW_MARK_REFUSED','REPLAYED')
      return resultRow(row,owner)
    })
  }
  const store=Object.freeze({migrate,insert,insertForAdmission,list,admissionCandidates,get,attempt,attemptForAdmission,mark,markClosed})
  stores.add(store);return store
}
export function isWorkflowStore(value) {return stores.has(value)}
