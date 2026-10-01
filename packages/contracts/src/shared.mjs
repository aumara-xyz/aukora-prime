export const CONTRACT_VERSION = 1;
export const ERROR_CODES = Object.freeze(['UNAVAILABLE','INVALID','UNAUTHORIZED','STALE','REVOKED','REPLAYED','EXPIRED','TARGET_MISMATCH','SCOPE_MISMATCH','CANCELLED','OUTCOME_UNKNOWN','RECONCILIATION_REQUIRED']);
const fields = {
 Task: ['version','task_id','owner_id','agent_id','conversation_id','status','created_at','route_id','allowed_data_classes','max_input_tokens','max_output_tokens','max_requests','task_spend_ceiling'],
 OperationProposal: ['version','operation_id','task_id','owner_id','agent_id','audience','action_type','target_identity','canonical_parameters','data_scope','expected_state_version','provider_and_region','maximum_cost','expiry','nonce','policy_version','authorization_epoch'],
 ApprovalProof: ['version','operation_id','operation_digest','owner_id','audience','authorization_epoch','expiry','nonce','material'],
 ConsumedGrant: ['version','grant_id','operation_id','operation_digest','owner_id','audience','authorization_epoch','prepared_at','reservation_id'],
 ExecutionReceipt: ['version','receipt_id','operation_id','task_id','owner_id','operation_digest','grant_id','request_id','status','stdout','stderr','exit_code','rpc_completion','output_truncated','sandbox','cleanup','started_at','finished_at','error_code','reconciliation_required'],
 BrowserSession: ['version','session_id','owner_id','task_id','state','lease_id','controller','worker_identity','permitted_origins','expires_at'],
 ModelRoute: ['version','route_id','provider','endpoint','model','region','allowed_data_classes','allowed_tools','max_input_tokens','max_output_tokens','max_requests','task_spend_ceiling','status'],
 MemoryRecord: ['version','record_id','owner_subject','task_id','scope','privacy','record_format','canonicalizer','canonical_bytes','revision','grants_authority','source_event_digest','evidence','chain_domain','source_span','storage_status','index_status']
};
const choices = {
 Task: {status:['pending','running','paused','completed','failed','cancelled']},
 ExecutionReceipt: {status:['completed','failed','cancelled','unavailable','outcome_unknown'], rpc_completion:['complete','transport_failed','not_started'],cleanup:['not_created','pending','confirmed_absent','unknown']},
 BrowserSession: {state:['queued','starting','agent_controlled','human_controlled','paused','completed','failed'],controller:['agent','owner',null]},
 ModelRoute: {status:['unavailable','approved']},
 MemoryRecord: {chain_domain:['remembered','approved','legacy-presplit'],storage_status:['pending','saved','failed'],index_status:['pending','indexing','indexed','searchable','failed']}
};
export function canonicalJson(value) {
 if (value===null || typeof value==='boolean' || typeof value==='string') return JSON.stringify(value);
 if (typeof value==='number') { if(!Number.isSafeInteger(value)) throw new TypeError('INVALID: only safe integers in transport JSON'); return JSON.stringify(value); }
 if(Array.isArray(value)) { if(Object.keys(value).length!==value.length || value.some((_,i)=>!Object.hasOwn(value,i))) throw new TypeError('INVALID: sparse/extended array'); for(const k of Reflect.ownKeys(value)) {if(k==='length')continue;const d=Object.getOwnPropertyDescriptor(value,k);if(typeof k!=='string'||!d||!Object.hasOwn(d,'value'))throw new TypeError('INVALID: accessor/symbol');} return '['+value.map(canonicalJson).join(',')+']'; }
 if(value && (Object.getPrototypeOf(value)===Object.prototype || Object.getPrototypeOf(value)===null)) { for(const k of Reflect.ownKeys(value)){const d=Object.getOwnPropertyDescriptor(value,k);if(typeof k!=='string'||!d?.enumerable||!Object.hasOwn(d,'value'))throw new TypeError('INVALID: accessor/symbol/nonenumerable');} return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonicalJson(value[k])).join(',')+'}'; }
 throw new TypeError('INVALID: non-JSON transport value');
}
export function validateContract(kind, value) {
 if(!fields[kind]) throw new TypeError('INVALID: unknown contract');
 if(!value || Array.isArray(value) || typeof value!=='object') throw new TypeError('INVALID: expected object');
 const keys=Object.keys(value);
 if(keys.some(k=>!fields[kind].includes(k)) || fields[kind].some(k=>!Object.hasOwn(value,k))) throw new TypeError('INVALID: closed '+kind+' fields');
 if(value.version!==1) throw new TypeError('INVALID: contract version');
 canonicalJson(value);
 for(const [k,v] of Object.entries(value)) {
  if(k.endsWith('_id') || ['owner_subject','agent_id','audience','nonce','policy_version','expected_state_version','record_format','canonicalizer','revision','scope','privacy'].includes(k)) {
   if(!(v===null && ['route_id','lease_id'].includes(k)) && (typeof v!=='string' || !v.length || v.length>1024)) throw new TypeError('INVALID: '+k);
  }
  if(k.endsWith('_tokens') || ['authorization_epoch','max_requests'].includes(k)) if(!Number.isSafeInteger(v)||v<0) throw new TypeError('INVALID: '+k);
  if(['created_at','expiry','expires_at','prepared_at','finished_at','started_at'].includes(k) && v!==null && (typeof v!=='string'||!/^\d{4}-\d{2}-\d{2}T.*Z$/.test(v)||!Number.isFinite(Date.parse(v)))) throw new TypeError('INVALID: '+k);
  if(['operation_digest','source_event_digest'].includes(k)&&v!==null&& (typeof v!=='string' || !/^sha256:[a-f0-9]{64}$/.test(v))) throw new TypeError('INVALID: '+k);
 }
 for(const [k,allowed] of Object.entries(choices[kind]||{})) if(!allowed.includes(value[k])) throw new TypeError('INVALID: '+k);
 for(const k of ['allowed_data_classes','allowed_tools','data_scope','permitted_origins']) if(Object.hasOwn(value,k)&&(!Array.isArray(value[k])||value[k].some(v=>typeof v!=='string'||!v.length))) throw new TypeError('INVALID: '+k);
 for(const k of ['maximum_cost','task_spend_ceiling']) if(Object.hasOwn(value,k)) {const c=value[k]; if(!c||Object.keys(c).sort().join(',')!=='amount,currency'||c.currency!=='USD'||typeof c.amount!=='string'||!/^\d+(\.\d{1,8})?$/.test(c.amount))throw new TypeError('INVALID: '+k);}
 if(kind==='OperationProposal' && (!value.provider_and_region || Object.keys(value.provider_and_region).sort().join(',')!=='provider,region' || Object.values(value.provider_and_region).some(v=>typeof v!=='string'||!v.length))) throw new TypeError('INVALID: provider_and_region');
 if(kind==='ApprovalProof' && !['owner_key','passkey'].includes(value.material?.kind)) throw new TypeError('INVALID: proof material kind');
 if(kind==='MemoryRecord' && (value.grants_authority!==false || typeof value.canonical_bytes!=='string')) throw new TypeError('INVALID: memory bytes/authority');
 if(kind==='ExecutionReceipt') {
  if(typeof value.stdout!=='string'||typeof value.stderr!=='string'||typeof value.output_truncated!=='boolean'||typeof value.reconciliation_required!=='boolean'||(value.exit_code!==null&&!Number.isSafeInteger(value.exit_code))||(value.error_code!==null&&!ERROR_CODES.includes(value.error_code))) throw new TypeError('INVALID: receipt result');
  if(value.status==='completed' && (value.exit_code!==0||value.rpc_completion!=='complete'||value.cleanup!=='confirmed_absent'||value.reconciliation_required))throw new TypeError('INVALID: incomplete receipt cannot claim completed');
 }
 return value;
}
export const CONTRACT_FIELDS = Object.freeze(fields);
