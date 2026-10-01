// SPDX-License-Identifier: AGPL-3.0-or-later
import {canonicalJson, parseStrictJson, invalid} from './json.mjs';
export * from './json.mjs';
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
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const RAW_DIGEST = /^[a-f0-9]{64}$/;
const IMAGE = /^(?:[-a-zA-Z0-9._:/]+@)?sha256:[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function closed(value, keys, path) {
 if (!value || typeof value !== 'object' || Array.isArray(value)) invalid('CONTRACT_OBJECT', path);
 if (Object.keys(value).some(k => !keys.includes(k)) || keys.some(k => !Object.hasOwn(value, k))) invalid('CONTRACT_FIELDS', path);
}
function string(value, path, {empty = false, max = 1024} = {}) {
 if (typeof value !== 'string' || (!empty && !value.length) || value.length > max) invalid('CONTRACT_STRING', path);
}
function integer(value, path, min = 0, max = Number.MAX_SAFE_INTEGER) {
 if (!Number.isSafeInteger(value) || value < min || value > max) invalid('CONTRACT_INTEGER', path);
}
function boolean(value, path) { if (typeof value !== 'boolean') invalid('CONTRACT_BOOLEAN', path); }
function pattern(value, regex, path) { string(value, path); if (!regex.test(value)) invalid('CONTRACT_FORMAT', path); }
function money(value, path) {
 closed(value, ['currency','amount'], path);
 if (value.currency !== 'USD' || typeof value.amount !== 'string' || !/^(?:0|[1-9]\d*)(?:\.\d{1,8})?$/.test(value.amount)) invalid('CONTRACT_MONEY', path);
}
function timestamp(value, path) {
 if (typeof value !== 'string') invalid('CONTRACT_TIMESTAMP', path);
 const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/.exec(value);
 if (!m) invalid('CONTRACT_TIMESTAMP', path);
 const [year,month,day,hour,minute,second] = m.slice(1).map(Number);
 const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
 const days = [31,leap ? 29 : 28,31,30,31,30,31,31,30,31,30,31];
 if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59 || !Number.isFinite(Date.parse(value))) invalid('CONTRACT_TIMESTAMP', path);
}
function strings(value, path) {
 if (!Array.isArray(value)) invalid('CONTRACT_ARRAY', path);
 value.forEach((s, i) => string(s, `${path}[${i}]`));
}
function provider(value, path) {
 closed(value, ['provider','region'], path);
 string(value.provider, path + '.provider'); string(value.region, path + '.region');
}
function logicalPath(value, path) {
 string(value, path);
 if (!value.startsWith('/') || /[\x00-\x1f\x7f]/u.test(value)
  || (value !== '/' && value.slice(1).split('/').some(part => !part || part === '.' || part === '..'))) invalid('CONTRACT_PATH', path);
}
function shellOperation(op) {
 const t = op.target_identity, p = op.canonical_parameters;
 closed(t, ['backend','workspace','image_digest','policy_digest','logical_workspace_root'], '$.target_identity');
 if (t.backend !== 'openshell-linux') invalid('CONTRACT_ENUM', '$.target_identity.backend');
 pattern(t.workspace, /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/, '$.target_identity.workspace');
 pattern(t.image_digest, IMAGE, '$.target_identity.image_digest');
 pattern(t.policy_digest, DIGEST, '$.target_identity.policy_digest');
 logicalPath(t.logical_workspace_root, '$.target_identity.logical_workspace_root');
 closed(p, ['command','workdir','sandbox_mode','stdin','env','dsh_env','timeout_ms','max_output_bytes'], '$.canonical_parameters');
 if (typeof p.command !== 'string' || p.command.includes('\0') || new TextEncoder().encode(p.command).length > 262_144) invalid('CONTRACT_COMMAND', '$.canonical_parameters.command');
 if (typeof p.stdin !== 'string' || new TextEncoder().encode(p.stdin).length > 4_194_304) invalid('CONTRACT_STDIN', '$.canonical_parameters.stdin');
 if (p.workdir !== t.logical_workspace_root) invalid('CONTRACT_PATH', '$.canonical_parameters.workdir');
 if (!['read-only','workspace-write'].includes(p.sandbox_mode)) invalid('CONTRACT_ENUM', '$.canonical_parameters.sandbox_mode');
 integer(p.timeout_ms, '$.canonical_parameters.timeout_ms', 1, 600_000);
 integer(p.max_output_bytes, '$.canonical_parameters.max_output_bytes', 1, 1_048_576);
 const env = {PATH:'/usr/bin:/bin',NO_COLOR:'1',TERM:'dumb',PAGER:'cat',GIT_PAGER:'cat'};
 for (const [key,map] of [['env',p.env],['dsh_env',p.dsh_env]]) {
  if (!map || typeof map !== 'object' || Array.isArray(map)) invalid('CONTRACT_OBJECT', '$.canonical_parameters.' + key);
  for (const [name,value] of Object.entries(map)) {
   const path = '$.canonical_parameters.' + key + '.' + name;
   if (key === 'env') { if (!Object.hasOwn(env,name) || value !== env[name]) invalid('CONTRACT_ENV', path); }
   else if (typeof value !== 'string' || value.includes('\0') || !(name === 'DSH_HOME' && value.startsWith('/') || name === 'DSH_SHELL' && value === '1' || name === 'DSH_SESSION_ID' && /^[a-zA-Z0-9_.-]{1,128}$/.test(value))) invalid('CONTRACT_ENV', path);
  }
 }
}
function base64url(value, maxBytes, path) {
 // Canonical unpadded spelling: low unused bits of the final sextet are zero.
 if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1
  || Math.floor(value.length * 6 / 8) > maxBytes
  || value.length % 4 === 2 && !/[AQgw]$/.test(value)
  || value.length % 4 === 3 && !/[AEIMQUYcgkosw048]$/.test(value)) invalid('CONTRACT_BASE64URL', path);
}
function approvalRequest(request) {
 const path = '$.material.request';
 closed(request, ['domain','subject','activeControlDigest','operationDigest','challenge','issuedAt','expiresAt'], path);
 if (request.domain !== 'aukora:owner-approval-request:v1') invalid('CONTRACT_ENUM', path + '.domain');
 pattern(request.subject, /^aukora:1:[a-f0-9]{64}$/, path + '.subject');
 for (const key of ['activeControlDigest','operationDigest','challenge']) pattern(request[key], RAW_DIGEST, path + '.' + key);
 integer(request.issuedAt, path + '.issuedAt'); integer(request.expiresAt, path + '.expiresAt');
 if (request.expiresAt <= request.issuedAt) invalid('CONTRACT_TIMESTAMP', path + '.expiresAt');
}
function proofMaterial(material, template) {
 const path = '$.material';
 if (!material || typeof material !== 'object' || Array.isArray(material)) invalid('CONTRACT_OBJECT', path);
 if (material.kind === 'owner_key') {
  closed(material, ['kind','request','signature'], path); approvalRequest(material.request);
  if (template ? material.signature !== '' : typeof material.signature !== 'string' || !/^[a-f0-9]{128}$/.test(material.signature)) invalid(template ? 'CONTRACT_TEMPLATE' : 'CONTRACT_SIGNATURE', path + '.signature');
 } else if (material.kind === 'passkey') {
  if (template) closed(material, ['kind'], path);
  else {
   closed(material, ['kind','credential_id','client_data_json','authenticator_data','signature','user_handle'], path);
   for (const [key,max] of [['credential_id',1024],['client_data_json',16384],['authenticator_data',4096],['signature',128]]) base64url(material[key], max, path + '.' + key);
   if (material.user_handle !== null) base64url(material.user_handle, 64, path + '.user_handle');
  }
 } else invalid('CONTRACT_ENUM', path + '.kind');
}
function receipt(value) {
 for (const key of ['stdout','stderr']) if (typeof value[key] !== 'string') invalid('CONTRACT_STRING', '$.' + key);
 boolean(value.output_truncated, '$.output_truncated'); boolean(value.reconciliation_required, '$.reconciliation_required');
 if (value.exit_code !== null) integer(value.exit_code, '$.exit_code', -Number.MAX_SAFE_INTEGER);
 if (value.error_code !== null && !ERROR_CODES.includes(value.error_code)) invalid('CONTRACT_ENUM', '$.error_code');
 if (value.sandbox !== null) {
  const s = value.sandbox, path = '$.sandbox';
  closed(s, ['uid','name','identity','image_digest','policy_digest'], path);
  pattern(s.uid, UUID, path + '.uid'); string(s.name, path + '.name'); string(s.identity, path + '.identity');
  if (!s.identity.endsWith('/' + s.uid) || s.identity.length <= s.uid.length + 1) invalid('CONTRACT_FORMAT', path + '.identity');
  pattern(s.image_digest, IMAGE, path + '.image_digest'); pattern(s.policy_digest, DIGEST, path + '.policy_digest');
 }
 if (value.status === 'completed' && (value.exit_code !== 0 || value.rpc_completion !== 'complete' || value.cleanup !== 'confirmed_absent' || value.reconciliation_required)) invalid('CONTRACT_RECEIPT_STATE', '$.status');
}
function validate(kind, value, template = false) {
 if (!Object.hasOwn(fields, kind)) invalid('CONTRACT_KIND');
 canonicalJson(value); // Check descriptors before reading any property.
 closed(value, fields[kind], '$');
 if (value.version !== CONTRACT_VERSION) invalid('CONTRACT_VERSION', '$.version');
 for (const [key,v] of Object.entries(value)) {
  if (key.endsWith('_id') || ['owner_subject','audience','nonce','policy_version','expected_state_version','record_format','canonicalizer','revision','scope','privacy'].includes(key)) {
   if (!(v === null && ['route_id','lease_id'].includes(key))) string(v, '$.' + key);
  }
  if (key.endsWith('_tokens') || ['authorization_epoch','max_requests'].includes(key)) integer(v, '$.' + key);
  if (['created_at','expiry','expires_at','prepared_at','finished_at','started_at'].includes(key) && !(kind === 'ExecutionReceipt' && key === 'started_at' && v === null)) timestamp(v, '$.' + key);
  if (['operation_digest','source_event_digest'].includes(key) && !(kind === 'MemoryRecord' && key === 'source_event_digest' && v === null)) pattern(v, DIGEST, '$.' + key);
 }
 for (const [key,allowed] of Object.entries(choices[kind] ?? {})) if (!allowed.includes(value[key])) invalid('CONTRACT_ENUM', '$.' + key);
 for (const key of ['allowed_data_classes','allowed_tools','data_scope','permitted_origins']) if (Object.hasOwn(value,key)) strings(value[key], '$.' + key);
 for (const key of ['maximum_cost','task_spend_ceiling']) if (Object.hasOwn(value,key)) money(value[key], '$.' + key);
 if (kind === 'OperationProposal') {
  string(value.action_type, '$.action_type'); provider(value.provider_and_region, '$.provider_and_region');
  if (value.target_identity === null || value.canonical_parameters === null) invalid('CONTRACT_OPERATION_DATA');
  if (value.action_type === 'shell.bash.foreground') shellOperation(value);
 }
 if (kind === 'ApprovalProof') proofMaterial(value.material, template);
 if (kind === 'ExecutionReceipt') receipt(value);
 if (kind === 'BrowserSession' && value.worker_identity !== null) string(value.worker_identity, '$.worker_identity');
 if (kind === 'ModelRoute') for (const key of ['provider','endpoint','model','region']) string(value[key], '$.' + key);
 if (kind === 'MemoryRecord' && (value.grants_authority !== false || typeof value.canonical_bytes !== 'string')) invalid('CONTRACT_MEMORY_BYTES');
 return value;
}
export function validateContract(kind, value) { return validate(kind, value); }
export function validateApprovalTemplate(value) { return validate('ApprovalProof', value, true); }
export function parseContract(kind, text, options) { return validateContract(kind, parseStrictJson(text, options)); }
for (const list of Object.values(fields)) Object.freeze(list);
export const CONTRACT_FIELDS = Object.freeze(fields);
