// SPDX-License-Identifier: AGPL-3.0-or-later
// Selected owned SQL copied without template changes from the Bridge checkpoint below.
// All query text lives inside Prime; no external checkout is needed at build/runtime.
import { types } from 'node:util'

export const PRIVATE_V2_JOURNAL_SOURCE = Object.freeze({
  source_path: 'packages/runtime-bridge/src/retained-journal-sql.mjs',
  source_commit: '9b43424778db7d7089ea0f6cfdb1d5dc54136db6',
  source_sha256: '63bde08a26cf13c62f239d6e21addb9b72afe69fb94263e2d9aaef330192703f',
  license: 'AGPL-3.0-or-later',
})

const WORKFLOW_COLUMNS='owner_subject,owner_id,task_id,operation_id,operation_digest,action_type,idempotency_key_sha256,record_id,phase,request_id,request_digest,receipt_digest,created_at'
const PROGRESS_COLUMNS='owner_subject,owner_id,task_id,operation_id,progress_bytes,progress_digest'
const PRIOR_WORKFLOW=`owner_subject=$1 AND owner_id=$2 AND task_id=$3 AND operation_id=$4
  AND operation_digest=$5 AND action_type=$6 AND idempotency_key_sha256 IS NOT DISTINCT FROM $7
  AND record_id IS NOT DISTINCT FROM $8 AND phase=$9
  AND request_id IS NOT DISTINCT FROM $10 AND request_digest IS NOT DISTINCT FROM $11
  AND receipt_digest IS NOT DISTINCT FROM $12 AND created_at=$13`

const OWNED_SQL=Object.freeze({
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

const WORKFLOW_FIELDS = Object.freeze(WORKFLOW_COLUMNS.split(','))
const MUTABLE_FIELDS = Object.freeze(['record_id','phase','request_id','request_digest','receipt_digest'])
const OWNER_REFERENCE = Object.freeze(['host.owner_subject','host.owner_id','host.task_id','transition.reference.operation_id'])
const OWNER = Object.freeze(OWNER_REFERENCE.slice(0,2))
const targetWorkflow = WORKFLOW_FIELDS.map(key => 'transition.target_workflow.' + key)
const priorWorkflow = WORKFLOW_FIELDS.map(key => 'baseline.workflow.' + key)
// The first owner parameters are always the authenticated host, even where SQL
// compares a complete prior row. Other CAS values come only from guarded SQL.
targetWorkflow.splice(0,4,...OWNER_REFERENCE)
priorWorkflow.splice(0,4,...OWNER_REFERENCE)
const previousProgress = ['baseline.progress.progress_bytes','baseline.progress.progress_digest','baseline.progress.stage']
const targetProgress = ['transition.target_progress','derived.target_progress_digest']
const PARAMETERS = Object.freeze({
  lockWorkflow: OWNER_REFERENCE,
  lockProgress: OWNER_REFERENCE,
  lockOwnerWorkflows: OWNER,
  lockOwnerProgress: OWNER,
  insertWorkflow: Object.freeze(targetWorkflow),
  updateWorkflow: Object.freeze([...priorWorkflow,...MUTABLE_FIELDS.map(key => 'transition.target_workflow.' + key)]),
  insertProgress: Object.freeze([...OWNER_REFERENCE,...targetProgress]),
  updateProgress: Object.freeze([...OWNER_REFERENCE,...previousProgress,...targetProgress]),
  completeProgress: Object.freeze([...priorWorkflow,...previousProgress,...targetProgress]),
})
export const RETAINED_JOURNAL_DESCRIPTORS = Object.freeze(Object.entries(OWNED_SQL).map(([name,text]) =>
  Object.freeze({name,text,parameters:PARAMETERS[name]})))
export const PRIVATE_V2_JOURNAL_STATEMENTS = RETAINED_JOURNAL_DESCRIPTORS
const byName = new Map(RETAINED_JOURNAL_DESCRIPTORS.map(value => [value.name,value]))

/** Exact inert descriptor identity, including ordered source-owned selectors.
 * UPDATE SET and the sole terminal CTE are accepted only by this fixed registry.
 */
export function isPrivateV2JournalStatement(input) {
  if (!input || typeof input !== 'object' || types.isProxy(input)
    || ![Object.prototype,null].includes(Object.getPrototypeOf(input))) return false
  const ds = Object.getOwnPropertyDescriptors(input)
  if (Reflect.ownKeys(ds).length !== 3 || !['name','text','parameters'].every(key => ds[key]
    && Object.hasOwn(ds[key],'value') && ds[key].enumerable)) return false
  const owned = byName.get(ds.name.value), parameters = ds.parameters.value
  if (!owned || ds.text.value !== owned.text || !Array.isArray(parameters) || types.isProxy(parameters)
    || Object.getPrototypeOf(parameters) !== Array.prototype) return false
  const ps = Object.getOwnPropertyDescriptors(parameters)
  return ps.length && Object.hasOwn(ps.length,'value') && ps.length.value === owned.parameters.length
    && Reflect.ownKeys(ps).length === owned.parameters.length + 1
    && owned.parameters.every((value,index) => ps[index] && Object.hasOwn(ps[index],'value')
      && ps[index].enumerable && ps[index].value === value)
}
