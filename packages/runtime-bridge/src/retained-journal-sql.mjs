// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixed journal statements for D's authenticated, branded, live owner query
// facade. D owns the transaction, profile checks and retained publication;
// these mutators return no evidence and never open or complete a transaction.
import {types} from 'node:util'
import {canonicalJson,parseStrictJson,MAX_JSON_BYTES} from '../../contracts/src/runtime.mjs'
import {validateNormalTransitionSyntax,validateJournalTransitionSyntax,
  validateWorkflowRow,validateWorkflowAdvance,validateClosureProgressSyntax,
  validateProgressAdvanceSyntax,workflowDigest,progressDigest,closedClosureData,
  copyClosureData,validateClosureHost,validateClosureReference} from './closure-v2.mjs'

const WORKFLOW_COLUMNS='owner_subject,owner_id,task_id,operation_id,operation_digest,action_type,idempotency_key_sha256,record_id,phase,request_id,request_digest,receipt_digest,created_at'
const WORKFLOW_FIELDS=Object.freeze(WORKFLOW_COLUMNS.split(','))
const PROGRESS_COLUMNS='owner_subject,owner_id,task_id,operation_id,progress_bytes,progress_digest'
const PROGRESS_FIELDS=Object.freeze(PROGRESS_COLUMNS.split(','))
const REFERENCE_FIELDS=Object.freeze(['owner_id','owner_subject','task_id','operation_id','operation_digest','action_type'])
const MUTABLE_FIELDS=Object.freeze(['record_id','phase','request_id','request_digest','receipt_digest'])
const PRIOR_WORKFLOW=`owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4
  AND operation_digest=$5 AND action_type=$6 AND idempotency_key_sha256 IS NOT DISTINCT FROM $7
  AND record_id IS NOT DISTINCT FROM $8 AND phase=$9
  AND request_id IS NOT DISTINCT FROM $10 AND request_digest IS NOT DISTINCT FROM $11
  AND receipt_digest IS NOT DISTINCT FROM $12 AND created_at=$13`

// Setup-only statements. Importing this module never installs a schema. The
// existing original table/columns/index are preserved without modification.
export const RETAINED_JOURNAL_SCHEMA=Object.freeze([
  `CREATE TABLE IF NOT EXISTS prime_runtime_workflows (
  owner_subject text NOT NULL, owner_id text NOT NULL, task_id text NOT NULL,
  operation_id text NOT NULL, operation_digest text NOT NULL,
  action_type text NOT NULL CHECK (action_type IN ('memory.save','memory.forget')),
  idempotency_key_sha256 text, record_id text,
  phase text NOT NULL CHECK (phase IN ('proposed','attempted','known_unsent','saved','forgotten')),
  request_id text, request_digest text, receipt_digest text, created_at text NOT NULL,
  PRIMARY KEY (owner_subject,operation_id),
  UNIQUE (owner_subject,task_id,idempotency_key_sha256)
);`,
  `CREATE INDEX IF NOT EXISTS prime_runtime_workflows_owner_task
  ON prime_runtime_workflows(owner_subject,owner_id,task_id,phase,created_at,operation_id);`,
  `CREATE TABLE IF NOT EXISTS prime_runtime_workflow_closure_progress_v2 (
  owner_subject text NOT NULL, owner_id text NOT NULL, task_id text NOT NULL,
  operation_id text NOT NULL, progress_bytes bytea NOT NULL, progress_digest text NOT NULL,
  PRIMARY KEY (owner_subject,operation_id),
  FOREIGN KEY (owner_subject,operation_id) REFERENCES prime_runtime_workflows(owner_subject,operation_id)
);`,
])

// D imports these exact templates as its only journal query allowlist. Owner
// parameters are always first; the facade independently binds them to its host.
export const RETAINED_JOURNAL_STATEMENTS=Object.freeze({
  lockWorkflow:`SELECT ${WORKFLOW_COLUMNS} FROM prime_runtime_workflows
  WHERE owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4 FOR UPDATE`,
  lockProgress:`SELECT ${PROGRESS_COLUMNS} FROM prime_runtime_workflow_closure_progress_v2
  WHERE owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4 FOR UPDATE`,
  lockOwnerWorkflows:`SELECT ${WORKFLOW_COLUMNS} FROM prime_runtime_workflows
  WHERE owner_subject=$1 AND owner_id=$2 ORDER BY task_id COLLATE "C",operation_id COLLATE "C" FOR UPDATE`,
  lockOwnerProgress:`SELECT ${PROGRESS_COLUMNS} FROM prime_runtime_workflow_closure_progress_v2
  WHERE owner_subject=$1 AND owner_id=$2 ORDER BY task_id COLLATE "C",operation_id COLLATE "C" FOR UPDATE`,
  insertWorkflow:`INSERT INTO prime_runtime_workflows (${WORKFLOW_COLUMNS})
  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
  ON CONFLICT DO NOTHING RETURNING ${WORKFLOW_COLUMNS}`,
  updateWorkflow:`UPDATE prime_runtime_workflows
  SET record_id=$14,phase=$15,request_id=$16,request_digest=$17,receipt_digest=$18
  WHERE ${PRIOR_WORKFLOW} RETURNING ${WORKFLOW_COLUMNS}`,
  insertProgress:`INSERT INTO prime_runtime_workflow_closure_progress_v2 (${PROGRESS_COLUMNS})
  VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING ${PROGRESS_COLUMNS}`,
  updateProgress:`UPDATE prime_runtime_workflow_closure_progress_v2
  SET progress_bytes=$8,progress_digest=$9
  WHERE owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4
    AND progress_bytes=$5 AND progress_digest=$6 AND convert_from(progress_bytes,'UTF8')::jsonb->>'stage'=$7
  RETURNING ${PROGRESS_COLUMNS}`,
  completeProgress:`WITH changed_workflow AS (
    UPDATE prime_runtime_workflows SET phase='known_unsent'
    WHERE ${PRIOR_WORKFLOW} AND phase='attempted'
      AND EXISTS (SELECT 1 FROM prime_runtime_workflow_closure_progress_v2
        WHERE owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4
          AND progress_bytes=$14 AND progress_digest=$15 AND convert_from(progress_bytes,'UTF8')::jsonb->>'stage'=$16)
    RETURNING ${WORKFLOW_COLUMNS}
  ) UPDATE prime_runtime_workflow_closure_progress_v2
  SET progress_bytes=$17,progress_digest=$18
  WHERE owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4
    AND progress_bytes=$14 AND progress_digest=$15 AND convert_from(progress_bytes,'UTF8')::jsonb->>'stage'=$16
    AND EXISTS (SELECT 1 FROM changed_workflow)
  RETURNING ${PROGRESS_COLUMNS}`,
})

// Exact local descriptors agreed with D's fixed private-v2 registry. D derives
// baseline/derived values from guarded actual state; callback values are not a
// substitute. Keep these ordered selectors alongside the unchanged owned SQL.
const DESCRIPTOR_OWNER_REFERENCE=Object.freeze(['host.owner_subject','host.owner_id','host.task_id','transition.reference.operation_id'])
const DESCRIPTOR_OWNER=Object.freeze(DESCRIPTOR_OWNER_REFERENCE.slice(0,2))
const descriptorTargetWorkflow=WORKFLOW_FIELDS.map(key=>'transition.target_workflow.'+key)
const descriptorPriorWorkflow=WORKFLOW_FIELDS.map(key=>'baseline.workflow.'+key)
descriptorTargetWorkflow.splice(0,4,...DESCRIPTOR_OWNER_REFERENCE)
descriptorPriorWorkflow.splice(0,4,...DESCRIPTOR_OWNER_REFERENCE)
const descriptorPreviousProgress=Object.freeze(['baseline.progress.progress_bytes','baseline.progress.progress_digest','baseline.progress.stage'])
const descriptorTargetProgress=Object.freeze(['transition.target_progress','derived.target_progress_digest'])
const DESCRIPTOR_PARAMETERS=Object.freeze({
  lockWorkflow:DESCRIPTOR_OWNER_REFERENCE,
  lockProgress:DESCRIPTOR_OWNER_REFERENCE,
  lockOwnerWorkflows:DESCRIPTOR_OWNER,
  lockOwnerProgress:DESCRIPTOR_OWNER,
  insertWorkflow:Object.freeze(descriptorTargetWorkflow),
  updateWorkflow:Object.freeze([...descriptorPriorWorkflow,...MUTABLE_FIELDS.map(key=>'transition.target_workflow.'+key)]),
  insertProgress:Object.freeze([...DESCRIPTOR_OWNER_REFERENCE,...descriptorTargetProgress]),
  updateProgress:Object.freeze([...DESCRIPTOR_OWNER_REFERENCE,...descriptorPreviousProgress,...descriptorTargetProgress]),
  completeProgress:Object.freeze([...descriptorPriorWorkflow,...descriptorPreviousProgress,...descriptorTargetProgress]),
})
export const RETAINED_JOURNAL_DESCRIPTORS=Object.freeze(Object.entries(RETAINED_JOURNAL_STATEMENTS).map(([name,text])=>
  Object.freeze({name,text,parameters:DESCRIPTOR_PARAMETERS[name]})))

function unknown(reason) {
  throw Object.assign(new Error(reason),{error_code:'OUTCOME_UNKNOWN',reason,
    reconciliation_required:true,automatic_retry:false})
}
function same(left,right) {return canonicalJson(left)===canonicalJson(right)}
function requireFacade(tx) {
  // The shape is no brand: only D's query implementation establishes lifetime,
  // owner binding and statement authorization. No pool/client is discovered.
  if(!tx||typeof tx.query!=='function')unknown('RETAINED_JOURNAL_SCOPE_REQUIRED')
}
async function query(tx,statement,parameters,{single=false}={}) {
  requireFacade(tx)
  const result=await tx.query(statement,parameters)
  if(!result||!Array.isArray(result.rows)
    ||Object.hasOwn(result,'rowCount')&&result.rowCount!==result.rows.length
    ||single&&result.rows.length>1)unknown('RETAINED_JOURNAL_RESULT_INVALID')
  return result.rows
}
const ownerParameters=reference=>['owner_subject','owner_id','task_id','operation_id'].map(key=>reference[key])
function requireReference(row,reference,key) {
  if(REFERENCE_FIELDS.some(field=>row[field]!==reference[field])
    ||row.idempotency_key_sha256!==key)unknown('RETAINED_JOURNAL_REFERENCE_CHANGED')
}
async function lockedWorkflow(tx,reference) {
  const [row]=await query(tx,RETAINED_JOURNAL_STATEMENTS.lockWorkflow,ownerParameters(reference),{single:true})
  return row===undefined?null:validateWorkflowRow(row)
}
const UTF8=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true})
function progressRow(row,workflow) {
  // This is the one native byte column. Do not widen the inert JSON grammar or
  // accept text/base64 at the actual SQL boundary. Detach before parsing.
  if(!row||typeof row!=='object'||types.isProxy(row)
    ||![Object.prototype,null].includes(Object.getPrototypeOf(row)))unknown('RETAINED_JOURNAL_PROGRESS_BINDING_INVALID')
  const descriptors=Object.getOwnPropertyDescriptors(row)
  if(Reflect.ownKeys(descriptors).length!==PROGRESS_FIELDS.length
    ||!PROGRESS_FIELDS.every(key=>descriptors[key]&&Object.hasOwn(descriptors[key],'value')&&descriptors[key].enumerable))
    unknown('RETAINED_JOURNAL_PROGRESS_BINDING_INVALID')
  const raw=descriptors.progress_bytes.value
  if(!raw||typeof raw!=='object'||types.isProxy(raw)||Object.getPrototypeOf(raw)!==Buffer.prototype
    ||!Reflect.ownKeys(raw).every(key=>typeof key==='string'&&/^(?:0|[1-9][0-9]*)$/.test(key)))
    unknown('RETAINED_JOURNAL_PROGRESS_BYTES_INVALID')
  const bytes=Buffer.from(raw)
  if(bytes.length===0||bytes.length>MAX_JSON_BYTES)unknown('RETAINED_JOURNAL_PROGRESS_BYTES_INVALID')
  const fields=PROGRESS_FIELDS.filter(key=>key!=='progress_bytes')
  const value={...closedClosureData(Object.fromEntries(fields.map(key=>[key,descriptors[key].value])),fields),progress_bytes:bytes}
  if(['owner_subject','owner_id','task_id','operation_id'].some(key=>value[key]!==workflow[key]))
    unknown('RETAINED_JOURNAL_PROGRESS_BINDING_INVALID')
  let parsed
  try {parsed=parseStrictJson(UTF8.decode(bytes))} catch {unknown('RETAINED_JOURNAL_PROGRESS_BYTES_INVALID')}
  const progress=validateClosureProgressSyntax(parsed)
  if(!bytes.equals(Buffer.from(canonicalJson(progress),'utf8'))||progressDigest(progress)!==value.progress_digest)
    unknown('RETAINED_JOURNAL_PROGRESS_DIGEST_INVALID')
  requireReference(workflow,progress.reference,progress.idempotency_key_sha256)
  return {row:value,progress}
}
async function lockedProgress(tx,reference,workflow) {
  const [row]=await query(tx,RETAINED_JOURNAL_STATEMENTS.lockProgress,ownerParameters(reference),{single:true})
  return row===undefined?null:progressRow(row,workflow)
}
function requireUnsent(workflow) {
  if(workflow.request_id!==null||workflow.request_digest!==null||workflow.receipt_digest!==null
    ||workflow.action_type==='memory.save'&&workflow.record_id!==null)
    unknown('RETAINED_JOURNAL_EFFECT_METADATA_PRESENT')
}
function verifyWorkflowRows(rows,target) {
  if(rows.length!==1||!same(validateWorkflowRow(rows[0]),target))unknown('RETAINED_JOURNAL_WORKFLOW_CAS_REFUSED')
}
function verifyProgressRows(rows,workflow,target) {
  if(rows.length!==1||!same(progressRow(rows[0],workflow).progress,target))unknown('RETAINED_JOURNAL_PROGRESS_CAS_REFUSED')
}

/** Called only within D's already authenticated normal mutation callback. */
export async function mutateRetainedWorkflow(tx,input) {
  const transition=validateNormalTransitionSyntax(input),target=transition.target_workflow
  const before=await lockedWorkflow(tx,transition.reference)
  const progressRows=await query(tx,RETAINED_JOURNAL_STATEMENTS.lockProgress,ownerParameters(transition.reference),{single:true})
  if(progressRows.length)unknown('RETAINED_JOURNAL_CLOSURE_ALREADY_STARTED')
  if(before===null) {
    if(transition.previous_workflow_digest!==null)unknown('RETAINED_JOURNAL_PRIOR_WORKFLOW_MISSING')
    validateWorkflowAdvance(null,target)
    const inserted=await query(tx,RETAINED_JOURNAL_STATEMENTS.insertWorkflow,
      WORKFLOW_FIELDS.map(key=>target[key]),{single:true})
    verifyWorkflowRows(inserted,target)
    return
  }
  requireReference(before,transition.reference,transition.idempotency_key_sha256)
  if(transition.previous_workflow_digest===null||workflowDigest(before)!==transition.previous_workflow_digest)
    unknown('RETAINED_JOURNAL_PRIOR_WORKFLOW_CHANGED')
  validateWorkflowAdvance(before,target)
  if(same(before,target))return
  const updated=await query(tx,RETAINED_JOURNAL_STATEMENTS.updateWorkflow,
    [...WORKFLOW_FIELDS.map(key=>before[key]),...MUTABLE_FIELDS.map(key=>target[key])],{single:true})
  verifyWorkflowRows(updated,target)
}

/** Closure stages never create/promote an ordinary proposal or effect attempt. */
export async function mutateRetainedClosure(tx,input) {
  const transition=validateJournalTransitionSyntax(input),target=transition.target_progress
  const workflow=await lockedWorkflow(tx,transition.reference)
  if(workflow===null)unknown('RETAINED_JOURNAL_ATTEMPT_MISSING')
  requireReference(workflow,transition.reference,transition.idempotency_key_sha256)
  requireUnsent(workflow)
  const before=await lockedProgress(tx,transition.reference,workflow)
  if(before===null) {
    if(workflow.phase!=='attempted'||transition.previous_progress_digest!==null||target.stage!=='started')
      unknown('RETAINED_JOURNAL_INITIAL_STAGE_REFUSED')
    validateProgressAdvanceSyntax(null,target,null)
    const inserted=await query(tx,RETAINED_JOURNAL_STATEMENTS.insertProgress,
      [...ownerParameters(transition.reference),Buffer.from(canonicalJson(target),'utf8'),progressDigest(target)],{single:true})
    verifyProgressRows(inserted,workflow,target)
    return
  }
  if(transition.previous_progress_digest!==before.row.progress_digest)
    unknown('RETAINED_JOURNAL_PRIOR_PROGRESS_CHANGED')
  validateProgressAdvanceSyntax(before.progress,target,transition.previous_progress_digest)
  if(same(before.progress,target)) {
    if(workflow.phase!==(target.stage==='complete'?'known_unsent':'attempted'))
      unknown('RETAINED_JOURNAL_PHASE_PROGRESS_CONFLICT')
    return
  }
  if(workflow.phase!=='attempted')unknown('RETAINED_JOURNAL_ATTEMPT_REQUIRED')
  const bytes=Buffer.from(canonicalJson(target),'utf8'),digest=progressDigest(target)
  if(target.stage==='complete') {
    const completed=await query(tx,RETAINED_JOURNAL_STATEMENTS.completeProgress,
      [...WORKFLOW_FIELDS.map(key=>workflow[key]),before.row.progress_bytes,before.row.progress_digest,
        before.progress.stage,bytes,digest],{single:true})
    const closedWorkflow=validateWorkflowRow({...workflow,phase:'known_unsent'})
    verifyProgressRows(completed,closedWorkflow,target)
    const actual=await lockedWorkflow(tx,transition.reference)
    if(actual===null||!same(actual,closedWorkflow))unknown('RETAINED_JOURNAL_TERMINAL_PHASE_CAS_REFUSED')
  } else {
    const updated=await query(tx,RETAINED_JOURNAL_STATEMENTS.updateProgress,
      [...ownerParameters(transition.reference),before.row.progress_bytes,before.row.progress_digest,
        before.progress.stage,bytes,digest],{single:true})
    verifyProgressRows(updated,workflow,target)
  }
}

/** Fresh C/D facts are projected by the trusted Bridge adapter, never a guest. */
export async function assertRetainedAdmission(tx,inputHost,inputFacts,inputOptions={exclude:null}) {
  const host=validateClosureHost(inputHost),{exclude}=closedClosureData(inputOptions,['exclude'])
  if(exclude!==null&&(typeof exclude!=='string'||!exclude.length||Buffer.byteLength(exclude,'utf8')>1024
      ||/[\x00-\x1f\x7f]/u.test(exclude)))unknown('RETAINED_JOURNAL_ADMISSION_SCOPE_INVALID')
  const facts=copyClosureData(inputFacts),certified=new Map()
  if(!Array.isArray(facts))unknown('RETAINED_JOURNAL_FACTS_REQUIRED')
  for(const fact of facts) {
    closedClosureData(fact,['reference','progress_digest']);validateClosureReference(fact.reference)
    if(fact.reference.owner_id!==host.owner_id||fact.reference.owner_subject!==host.owner_subject
      ||typeof fact.progress_digest!=='string'||!/^sha256:[a-f0-9]{64}$/.test(fact.progress_digest))
      unknown('RETAINED_JOURNAL_CERTIFIED_FACTS_INVALID')
    const prior=certified.get(fact.reference.operation_id)
    if(prior&&!same(prior,fact))unknown('RETAINED_JOURNAL_CERTIFIED_FACTS_CONFLICT')
    certified.set(fact.reference.operation_id,fact)
  }
  const workflows=await query(tx,RETAINED_JOURNAL_STATEMENTS.lockOwnerWorkflows,[host.owner_subject,host.owner_id])
  const progressRows=await query(tx,RETAINED_JOURNAL_STATEMENTS.lockOwnerProgress,[host.owner_subject,host.owner_id])
  const owned=new Map(),progress=new Map()
  for(const row of workflows) {
    const workflow=validateWorkflowRow(row)
    if(workflow.owner_id!==host.owner_id||workflow.owner_subject!==host.owner_subject||owned.has(workflow.operation_id))
      unknown('RETAINED_JOURNAL_OWNER_HISTORY_INVALID')
    owned.set(workflow.operation_id,workflow)
  }
  for(const row of progressRows) {
    const workflow=owned.get(row.operation_id)
    if(!workflow||progress.has(row.operation_id))unknown('RETAINED_JOURNAL_DANGLING_PROGRESS')
    const entry=progressRow(row,workflow)
    if(workflow.phase!==(entry.progress.stage==='complete'?'known_unsent':'attempted'))
      unknown('RETAINED_JOURNAL_PHASE_PROGRESS_CONFLICT')
    progress.set(row.operation_id,entry)
  }
  for(const workflow of owned.values()) {
    if(workflow.phase==='attempted') {
      if(workflow.operation_id===exclude&&workflow.task_id===host.task_id&&!progress.has(workflow.operation_id))continue
      unknown('RETAINED_JOURNAL_OWNER_RECONCILIATION_REQUIRED')
    }
    if(workflow.phase!=='known_unsent')continue
    const entry=progress.get(workflow.operation_id),fact=certified.get(workflow.operation_id)
    if(!entry||entry.progress.stage!=='complete'||entry.progress.closing_authorization_epoch!==host.authorization_epoch
      ||!fact||fact.progress_digest!==entry.row.progress_digest
      ||!REFERENCE_FIELDS.every(key=>fact.reference[key]===workflow[key]))
      unknown('RETAINED_JOURNAL_CURRENT_CLOSED_FACTS_REQUIRED')
    requireUnsent(workflow)
  }
}
