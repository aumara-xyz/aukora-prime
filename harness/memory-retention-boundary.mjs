// SPDX-License-Identifier: AGPL-3.0-or-later
// Unmounted H assembly gate. This module grants no authority, runs no memory
// operation and creates no file. Current D/C do not expose the internal hooks
// below, so neither a protected profile nor a successful trace can activate it.
import {constants} from 'node:fs';
import {lstat,open,realpath} from 'node:fs/promises';
import {dirname,isAbsolute,resolve,sep} from 'node:path';
import {createHash} from 'node:crypto';
import {existsSync} from 'node:fs';
const owned=existsSync(new URL('../prime-release.json',import.meta.url))?'../prime-packages/':'../packages/';
const contracts=await import(new URL(owned+'contracts/src/runtime.mjs',import.meta.url));

export const MEMORY_RETENTION_BOUNDARY_KIND='prime-memory-retention-boundary/v1';
export const MEMORY_RETENTION_PREREQUISITES=Object.freeze([
 'D_OWNED_BRANDED_ALL_CONTROL_WRITE_PARTICIPANT',
 'D_OWNER_SERIALIZATION_HELD_ACROSS_MARKER_AND_CONTROL_COMMIT',
 'C_BEFORE_ANY_DURABLE_PREPARED_WRITE_AWAITS_DURABLE_MARKER',
 'D_RESTORE_PREFLIGHT_BEFORE_MARKER_AND_OPERATION_BOUND_PENDING_OBSERVATION',
 'D_COMMITTED_LOCKED_FULL_CONTROL_EXPORT_WITH_MATCHING_OPERATION',
 'PUBLISH_ACTUAL_COMMITTED_CONTROL_BEFORE_MARKER_CLEAR',
 'CRASH_OR_UNCERTAINTY_RETAINS_MARKER_AND_FORBIDS_RETRY',
 'ACTUAL_SEPARATED_ROLE_STORAGE_AND_PARTICIPANT_JOIN_EVIDENCE',
]);
const digest=/^sha256:[0-9a-f]{64}$/;
const hex=/^[0-9a-f]{64}$/;
const decimal=/^(?:0|[1-9][0-9]*)$/;
const fail=reason=>{throw Object.assign(new Error(reason),{error_code:'UNAVAILABLE',reason});};
const requireValue=(value,reason)=>{if(!value)fail(reason);};
const closed=(value,keys,reason)=>{
 requireValue(value&&Object.getPrototypeOf(value)===Object.prototype
  &&Reflect.ownKeys(value).length===keys.length&&keys.every(key=>{
   const property=Object.getOwnPropertyDescriptor(value,key);
   return property&&property.enumerable&&Object.hasOwn(property,'value');
  }),reason);
 return value;
};
const inert=value=>contracts.parseStrictJson(contracts.canonicalJson(value),{maxBytes:65536,maxDepth:16});
const frozen=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))frozen(child);Object.freeze(value);}return value;};
const canonicalPath=value=>typeof value==='string'&&isAbsolute(value)&&resolve(value)===value&&value!==sep;
const identity=stat=>({device:String(stat.dev),inode:String(stat.ino)});
const sameIdentity=(a,b)=>a.device===b.device&&a.inode===b.inode;
const contains=(root,candidate)=>candidate===root||candidate.startsWith(root+sep);
const byteDigest=value=>'sha256:'+createHash('sha256').update(value).digest('hex');

/** Shape/integrity only. Even a valid fixed binding is not runtime acceptance. */
export function validateMemoryRetentionBinding(input) {
 const profile=inert(input);
 closed(profile,['version','kind','roles','storage','source_pins'],'RETENTION_PROFILE_FIELDS');
 requireValue(profile.version===1&&profile.kind==='prime-memory-retention-bindings/v1','RETENTION_PROFILE_VERSION');
 closed(profile.roles,['app_uid','app_gid','memory_uid','authority_uid','publisher_uid','retention_gid'],'RETENTION_ROLE_FIELDS');
 requireValue(Object.values(profile.roles).every(id=>Number.isSafeInteger(id)&&id>0),'RETENTION_NONROOT_ROLES_REQUIRED');
 requireValue(new Set(['app_uid','memory_uid','authority_uid','publisher_uid'].map(key=>profile.roles[key])).size===4
  &&profile.roles.app_gid!==profile.roles.retention_gid,'RETENTION_SEPARATE_ROLES_REQUIRED');
 closed(profile.storage,['retention','memory','authority_state','authority_witness'],'RETENTION_STORAGE_FIELDS');
 for(const entry of Object.values(profile.storage)) {
  closed(entry,['path','device','inode'],'RETENTION_STORAGE_IDENTITY_FIELDS');
  requireValue(canonicalPath(entry.path)&&typeof entry.device==='string'&&typeof entry.inode==='string'
   &&decimal.test(entry.device)&&decimal.test(entry.inode),'RETENTION_FIXED_CANONICAL_STORAGE_REQUIRED');
 }
 const stores=Object.values(profile.storage);
 for(let i=0;i<stores.length;i++)for(let j=i+1;j<stores.length;j++)
  requireValue(!contains(stores[i].path,stores[j].path)&&!contains(stores[j].path,stores[i].path)
   &&!sameIdentity(stores[i],stores[j]),'RETENTION_INDEPENDENT_STORAGE_REQUIRED');
 closed(profile.source_pins,['harness','memory','authority','bridge'],'RETENTION_SOURCE_PIN_FIELDS');
 requireValue(Object.values(profile.source_pins).every(pin=>typeof pin==='string'&&digest.test(pin)),'RETENTION_EXACT_SOURCE_PINS_REQUIRED');
 return Object.freeze({profile:frozen(profile),storage_binding_sha256:byteDigest('aukora-prime.memory-retention-bindings.v1\0'+contracts.canonicalJson(profile))});
}

async function protectedAncestors(filename,{directGid}={}) {
 let parent=dirname(filename),direct=true;
 for(;;) {
  const stat=await lstat(parent,{bigint:true});
  requireValue(stat.isDirectory()&&!stat.isSymbolicLink()&&await realpath(parent)===parent
   &&stat.uid===0n&&(Number(stat.mode)&0o022)===0
   &&(!direct||directGid===undefined||(Number(stat.mode)&0o7777)===0o750&&stat.gid===BigInt(directGid)),
  'RETENTION_ROOT_PROTECTED_ANCESTORS_REQUIRED');
  if(parent===dirname(parent))return;
  parent=dirname(parent);direct=false;
 }
}
/** Metadata checks of an explicitly pinned, already provisioned profile only.
 * No discovery, mkdir, chmod, chown, bootstrap or OS-identity provisioning. */
export async function inspectMemoryRetentionProfile(input) {
 const options=inert(input);
 closed(options,['profile_path','profile_identity'],'RETENTION_PROFILE_ARGUMENTS');
 closed(options.profile_identity,['device','inode'],'RETENTION_PROFILE_IDENTITY_FIELDS');
 requireValue(canonicalPath(options.profile_path)&&Object.values(options.profile_identity).every(value=>typeof value==='string'&&decimal.test(value)),
  'RETENTION_PINNED_PROFILE_PATH_REQUIRED');
 const uid=process.getuid?.(),euid=process.geteuid?.(),gid=process.getgid?.(),egid=process.getegid?.();
 requireValue(Number.isSafeInteger(uid)&&uid>0&&uid===euid&&Number.isSafeInteger(gid)&&gid===egid,'RETENTION_NONROOT_CALLER_REQUIRED');
 await protectedAncestors(options.profile_path,{directGid:gid});
 const handle=await open(options.profile_path,constants.O_RDONLY|constants.O_NOFOLLOW);
 let profile;
 try {
  const stat=await handle.stat({bigint:true});
  requireValue(stat.isFile()&&stat.nlink===1n&&stat.uid===0n&&stat.gid===BigInt(gid)
   &&(Number(stat.mode)&0o7777)===0o440&&stat.size>0n&&stat.size<=16384n
   &&sameIdentity(identity(stat),options.profile_identity)
   &&sameIdentity(identity(await lstat(options.profile_path,{bigint:true})),options.profile_identity),
  'RETENTION_ROOT_PROFILE_IDENTITY_REQUIRED');
  const bytes=Buffer.alloc(Number(stat.size));
  let offset=0;
  while(offset<bytes.length) {
   const result=await handle.read(bytes,offset,bytes.length-offset,offset);
   requireValue(result.bytesRead>0,'RETENTION_PROFILE_CHANGED');offset+=result.bytesRead;
  }
  const extra=Buffer.alloc(1);
  requireValue((await handle.read(extra,0,1,bytes.length)).bytesRead===0,'RETENTION_PROFILE_CHANGED');
  const text=bytes.toString('utf8');
  requireValue(Buffer.from(text).equals(bytes),'RETENTION_PROFILE_UTF8_REQUIRED');
  profile=validateMemoryRetentionBinding(contracts.parseStrictJson(text,{maxBytes:16384,maxDepth:8}));
  const after=await handle.stat({bigint:true}),named=await lstat(options.profile_path,{bigint:true});
  requireValue(stat.size===after.size&&stat.mtimeNs===after.mtimeNs&&stat.ctimeNs===after.ctimeNs
   &&sameIdentity(identity(after),options.profile_identity)&&sameIdentity(identity(named),options.profile_identity),
  'RETENTION_PROFILE_CHANGED');
 } finally {await handle.close();}
 const {roles,storage}=profile.profile;
 requireValue(roles.app_uid===uid&&roles.app_gid===gid&&!(process.getgroups?.()??[]).includes(roles.retention_gid),
  'RETENTION_APPLICATION_IDENTITY_MISMATCH');
 for(const [name,entry]of Object.entries(storage)) {
  await protectedAncestors(entry.path);
  const stat=await lstat(entry.path,{bigint:true});
  const expectedUid=name==='retention'?roles.publisher_uid:name==='memory'?roles.memory_uid:roles.authority_uid;
  requireValue(stat.isDirectory()&&!stat.isSymbolicLink()&&await realpath(entry.path)===entry.path
   &&sameIdentity(identity(stat),entry)&&stat.uid===BigInt(expectedUid)
   &&(Number(stat.mode)&0o7777)===(name==='retention'?0o2750:0o700)
   &&(name!=='retention'||stat.gid===BigInt(roles.retention_gid)),'RETENTION_STORAGE_IDENTITY_MISMATCH');
 }
 return Object.freeze({storage_binding_sha256:profile.storage_binding_sha256,profile_metadata_verified:true,
  runtime_qualified:false,participant_join:'UNPERFORMED'});
}

/** Required ordering of a supplied trace only, not proof the events occurred.
 * Trace success grants no execute/restore/qualification capability. A crash or
 * uncertainty ends with the marker retained. A fresh factual reconciliation
 * must be implemented by the actual participants; no retry/clear is offered. */
export function validateMemoryRetentionTrace(input) {
 const record=inert(input);
 closed(record,['version','kind','action','operation_digest','storage_binding_sha256','events'],'RETENTION_TRACE_FIELDS');
 requireValue(record.version===1&&record.kind==='prime-memory-retention-trace/v1'
  &&['control-write','restore'].includes(record.action)&&typeof record.operation_digest==='string'&&digest.test(record.operation_digest)
  &&typeof record.storage_binding_sha256==='string'&&digest.test(record.storage_binding_sha256)
  &&Array.isArray(record.events)&&record.events.length<=16,'RETENTION_TRACE_VERSION');
 const expected=['owner_lock_acquired','retained_snapshot',...(record.action==='restore'?['restore_preflight']:[]),
  'marker_write_attempted','marker_durable',...(record.action==='restore'?['restore_scope_opened']:[]),
  'authority_prepared','intent_committed','effect_committed','control_exported','checkpoint_published','marker_cleared','owner_lock_released'];
 let position=0,snapshot,commit,published,marked=false,markerAttempted=false;
 for(const event of record.events) {
  requireValue(event&&typeof event==='object','RETENTION_TRACE_EVENT');
  if(event.step==='outcome_uncertain') {
   closed(event,['step','operation_digest','storage_binding_sha256'],'RETENTION_TRACE_UNCERTAINTY_FIELDS');
   requireValue(markerAttempted&&event.operation_digest===record.operation_digest
    &&event.storage_binding_sha256===record.storage_binding_sha256
    &&position<expected.indexOf('marker_cleared')+1&&event===record.events.at(-1),'RETENTION_TRACE_UNCERTAINTY_REQUIRES_FENCE');
   return Object.freeze({status:'RECONCILIATION_REQUIRED',marker:marked?'RETAINED':'PRESENCE_UNCONFIRMED',automatic_retry:false,runtime_qualified:false});
  }
  requireValue(event.step===expected[position],'RETENTION_TRACE_ORDER');
  const extra={retained_snapshot:['checkpoint_sha256','control_sha256'],restore_preflight:['checkpoint_sha256','control_sha256'],
   marker_durable:['expected_checkpoint_sha256'],restore_scope_opened:['checkpoint_sha256','control_sha256'],
   effect_committed:['commit_id','control_sha256'],control_exported:['commit_id','control_sha256'],
   checkpoint_published:['commit_id','control_sha256','previous_checkpoint_sha256','checkpoint_sha256'],
   marker_cleared:['checkpoint_sha256']}[event.step]??[];
  closed(event,['step','operation_digest','storage_binding_sha256',...extra],'RETENTION_TRACE_EVENT_FIELDS');
  requireValue(event.operation_digest===record.operation_digest&&event.storage_binding_sha256===record.storage_binding_sha256,
   'RETENTION_TRACE_BINDING_MISMATCH');
  requireValue(extra.every(key=>typeof event[key]==='string'&&(key==='commit_id'?/^[a-z0-9-]{1,128}$/.test(event[key]):hex.test(event[key]))),
   'RETENTION_TRACE_COMMITMENT_FIELDS');
  if(event.step==='retained_snapshot')snapshot=event;
  if(['restore_preflight','restore_scope_opened'].includes(event.step))
   requireValue(event.checkpoint_sha256===snapshot.checkpoint_sha256&&event.control_sha256===snapshot.control_sha256,
    'RETENTION_TRACE_RESTORE_SNAPSHOT_SUBSTITUTION');
  if(event.step==='marker_write_attempted')markerAttempted=true;
  if(event.step==='marker_durable') {
   requireValue(event.expected_checkpoint_sha256===snapshot.checkpoint_sha256,'RETENTION_TRACE_MARKER_PREDECESSOR');marked=true;
  }
  if(event.step==='effect_committed')commit=event;
  if(['control_exported','checkpoint_published'].includes(event.step))
   requireValue(event.commit_id===commit.commit_id&&event.control_sha256===commit.control_sha256,'RETENTION_TRACE_UNCOMMITTED_EXPORT');
  if(event.step==='checkpoint_published') {
   requireValue(event.previous_checkpoint_sha256===snapshot.checkpoint_sha256&&event.checkpoint_sha256!==snapshot.checkpoint_sha256,
    'RETENTION_TRACE_PUBLICATION_PREDECESSOR');published=event;
  }
  if(event.step==='marker_cleared')requireValue(event.checkpoint_sha256===published.checkpoint_sha256,'RETENTION_TRACE_CLEAR_UNPUBLISHED');
  position++;
 }
 requireValue(position===expected.length,'RETENTION_TRACE_INCOMPLETE');
 return Object.freeze({status:'TRACE_VALID',qualification:'UNPERFORMED',runtime_qualified:false});
}

/** Intentionally no participant callback acceptance or positive execution path.
 * Adding actual D/C owned branded hooks + independent join evidence requires a
 * separately reviewed source change. Protected files and traces alone are not
 * the acceptance proof. Current beginUpdate after PREPARED is too late; calling
 * it before restore prevents D's normal reader preflight. */
export async function createMemoryRetentionBoundary(profileOptions) {
 const observation=profileOptions===undefined?null:await inspectMemoryRetentionProfile(profileOptions);
 const status=Object.freeze({version:1,kind:MEMORY_RETENTION_BOUNDARY_KIND,phase:'unavailable',runtime_qualified:false,
  reason:'MEMORY_RETENTION_PARTICIPANT_JOIN_UNIMPLEMENTED',profile_metadata_verified:observation?.profile_metadata_verified??false,
  prerequisites:MEMORY_RETENTION_PREREQUISITES});
 const unavailable=async()=>fail(status.reason);
 return Object.freeze({status,execute:unavailable,restore:unavailable,reconcile:unavailable});
}
