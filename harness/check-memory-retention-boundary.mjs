// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable source/protocol checks only. No C/D, PostgreSQL, role setup,
// production file publisher, runtime activation or qualification is exercised.
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,lstat,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createMemoryRetentionBoundary,inspectMemoryRetentionProfile,
 validateMemoryRetentionBinding,validateMemoryRetentionTrace} from './memory-retention-boundary.mjs';

let checks=0;
const check=(actual,expected)=>{assert.deepEqual(actual,expected);checks++;};
const refused=(fn,reason)=>{assert.throws(fn,error=>error.reason===reason);checks++;};
const clone=value=>structuredClone(value);
const binding={version:1,kind:'prime-memory-retention-bindings/v1',
 roles:{app_uid:997,app_gid:987,memory_uid:994,authority_uid:995,publisher_uid:993,retention_gid:982},
 storage:{retention:{path:'/fixture/control-retention',device:'1',inode:'10'},
  memory:{path:'/fixture/memory',device:'1',inode:'20'},authority_state:{path:'/fixture/authority-state',device:'1',inode:'30'},
  authority_witness:{path:'/fixture/authority-witness',device:'1',inode:'40'}},
 source_pins:Object.fromEntries(['harness','memory','authority','bridge'].map((key,index)=>[key,'sha256:'+String(index+1).repeat(64)]))};
const verifiedBinding=validateMemoryRetentionBinding(binding);
check(verifiedBinding.profile,binding);
check(/^sha256:[a-f0-9]{64}$/.test(verifiedBinding.storage_binding_sha256),true);
assert.throws(()=>{verifiedBinding.profile.storage.retention.inode='99';},TypeError);checks++;
check(verifiedBinding.profile.storage.retention.inode,'10');
for(const [change,reason]of [
 [value=>value.version=2,'RETENTION_PROFILE_VERSION'],
 [value=>value.roles.publisher_uid=value.roles.memory_uid,'RETENTION_SEPARATE_ROLES_REQUIRED'],
 [value=>value.roles.memory_uid=0,'RETENTION_NONROOT_ROLES_REQUIRED'],
 [value=>value.roles.app_gid=value.roles.retention_gid,'RETENTION_SEPARATE_ROLES_REQUIRED'],
 [value=>value.storage.retention.path='/fixture/memory/control','RETENTION_INDEPENDENT_STORAGE_REQUIRED'],
 [value=>value.storage.retention.path='/fixture','RETENTION_INDEPENDENT_STORAGE_REQUIRED'],
 [value=>value.storage.retention.inode=value.storage.memory.inode,'RETENTION_INDEPENDENT_STORAGE_REQUIRED'],
 [value=>value.storage.retention.path='/fixture/../fixture/control-retention','RETENTION_FIXED_CANONICAL_STORAGE_REQUIRED'],
 [value=>value.storage.retention.inode=10,'RETENTION_FIXED_CANONICAL_STORAGE_REQUIRED'],
 [value=>value.source_pins.memory='synthetic:true','RETENTION_EXACT_SOURCE_PINS_REQUIRED'],
 [value=>value.authorized=true,'RETENTION_PROFILE_FIELDS'],
 ]) {
 const candidate=clone(binding);change(candidate);refused(()=>validateMemoryRetentionBinding(candidate),reason);
}
const relocated=clone(binding);relocated.storage.retention.inode='11';
check(validateMemoryRetentionBinding(relocated).storage_binding_sha256===verifiedBinding.storage_binding_sha256,false);

const op='sha256:'+'a'.repeat(64),storage=verifiedBinding.storage_binding_sha256;
const before='1'.repeat(64),controlBefore='2'.repeat(64),after='3'.repeat(64),controlAfter='4'.repeat(64);
const event=(step,extra={})=>({step,operation_digest:op,storage_binding_sha256:storage,...extra});
// Fixed positive chronology independent of the implementation's expected list.
const trace={version:1,kind:'prime-memory-retention-trace/v1',action:'control-write',operation_digest:op,storage_binding_sha256:storage,events:[
 event('owner_lock_acquired'),event('retained_snapshot',{checkpoint_sha256:before,control_sha256:controlBefore}),
 event('marker_write_attempted'),event('marker_durable',{expected_checkpoint_sha256:before}),event('authority_prepared'),
 event('intent_committed'),event('effect_committed',{commit_id:'fixture-commit-1',control_sha256:controlAfter}),
 event('control_exported',{commit_id:'fixture-commit-1',control_sha256:controlAfter}),
 event('checkpoint_published',{commit_id:'fixture-commit-1',control_sha256:controlAfter,previous_checkpoint_sha256:before,checkpoint_sha256:after}),
 event('marker_cleared',{checkpoint_sha256:after}),event('owner_lock_released')]};
check(validateMemoryRetentionTrace(trace),{status:'TRACE_VALID',qualification:'UNPERFORMED',runtime_qualified:false});
const restore=clone(trace);restore.action='restore';
restore.events.splice(2,0,event('restore_preflight',{checkpoint_sha256:before,control_sha256:controlBefore}));
restore.events.splice(5,0,event('restore_scope_opened',{checkpoint_sha256:before,control_sha256:controlBefore}));
check(validateMemoryRetentionTrace(restore),{status:'TRACE_VALID',qualification:'UNPERFORMED',runtime_qualified:false});

const alter=(original,fn,reason)=>{const candidate=clone(original);fn(candidate.events);refused(()=>validateMemoryRetentionTrace(candidate),reason);};
alter(trace,events=>events.splice(3,1),'RETENTION_TRACE_ORDER'); // no durable marker before PREPARED
alter(trace,events=>[events[3],events[4]]=[events[4],events[3]],'RETENTION_TRACE_ORDER'); // late marker
alter(trace,events=>events.splice(0,1),'RETENTION_TRACE_ORDER'); // no owner serialization
alter(trace,events=>events.splice(5,1),'RETENTION_TRACE_ORDER'); // effect without committed intent
alter(trace,events=>[events[7],events[8]]=[events[8],events[7]],'RETENTION_TRACE_ORDER'); // publication before export
alter(trace,events=>events[7].commit_id='another-commit','RETENTION_TRACE_UNCOMMITTED_EXPORT');
alter(trace,events=>events[7].control_sha256='5'.repeat(64),'RETENTION_TRACE_UNCOMMITTED_EXPORT');
alter(trace,events=>events[8].previous_checkpoint_sha256='5'.repeat(64),'RETENTION_TRACE_PUBLICATION_PREDECESSOR');
alter(trace,events=>events[9].checkpoint_sha256=before,'RETENTION_TRACE_CLEAR_UNPUBLISHED');
alter(trace,events=>[events[8],events[9]]=[events[9],events[8]],'RETENTION_TRACE_ORDER');
alter(trace,events=>events[3].expected_checkpoint_sha256='5'.repeat(64),'RETENTION_TRACE_MARKER_PREDECESSOR');
alter(trace,events=>events[1].control_sha256=[controlBefore],'RETENTION_TRACE_COMMITMENT_FIELDS');
alter(trace,events=>events[4].operation_digest='sha256:'+'b'.repeat(64),'RETENTION_TRACE_BINDING_MISMATCH');
alter(trace,events=>events[4].storage_binding_sha256='sha256:'+'b'.repeat(64),'RETENTION_TRACE_BINDING_MISMATCH');
alter(trace,events=>events.splice(-1,1),'RETENTION_TRACE_INCOMPLETE');
alter(restore,events=>events[2].control_sha256='5'.repeat(64),'RETENTION_TRACE_RESTORE_SNAPSHOT_SUBSTITUTION');
alter(restore,events=>events[5].checkpoint_sha256='5'.repeat(64),'RETENTION_TRACE_RESTORE_SNAPSHOT_SUBSTITUTION');
alter(restore,events=>[events[2],events[3]]=[events[3],events[2]],'RETENTION_TRACE_ORDER');
alter(restore,events=>events.splice(5,1),'RETENTION_TRACE_ORDER');
alter(restore,events=>events[5].operation_digest='sha256:'+'b'.repeat(64),'RETENTION_TRACE_BINDING_MISMATCH');

for(const position of [3,4,5,6,7,8,9]) {
 const uncertain=clone(trace);uncertain.events=uncertain.events.slice(0,position);
 uncertain.events.push(event('outcome_uncertain'));
 check(validateMemoryRetentionTrace(uncertain),{status:'RECONCILIATION_REQUIRED',
  marker:position===3?'PRESENCE_UNCONFIRMED':'RETAINED',automatic_retry:false,runtime_qualified:false});
}
alter(trace,events=>events.splice(10,0,event('outcome_uncertain')),'RETENTION_TRACE_UNCERTAINTY_REQUIRES_FENCE');
const retry=clone(trace);retry.events=retry.events.slice(0,5);retry.events.push(event('outcome_uncertain'),event('authority_prepared'));
refused(()=>validateMemoryRetentionTrace(retry),'RETENTION_TRACE_UNCERTAINTY_REQUIRES_FENCE');

const boundary=await createMemoryRetentionBoundary();
check(boundary.status.phase,'unavailable');check(boundary.status.runtime_qualified,false);
check(boundary.status.profile_metadata_verified,false);
for(const method of ['execute','restore','reconcile']) {
 await assert.rejects(boundary[method]({operation_digest:op}),error=>error.reason==='MEMORY_RETENTION_PARTICIPANT_JOIN_UNIMPLEMENTED');checks++;
}
// A caller-owned profile cannot establish the independent protected binding.
const directory=await mkdtemp(join(tmpdir(),'prime-retention-gate-'));
try {
 const filename=join(directory,'profile.json');await writeFile(filename,JSON.stringify(binding),{mode:0o600});
 const stat=await lstat(filename,{bigint:true});
 await assert.rejects(inspectMemoryRetentionProfile({profile_path:filename,profile_identity:{device:String(stat.dev),inode:String(stat.ino)}}),
  error=>error.error_code==='UNAVAILABLE');checks++;
 let called=false;
 await assert.rejects(createMemoryRetentionBoundary({profile_path:filename,profile_identity:{device:String(stat.dev),inode:String(stat.ino)},
  verify:()=>{called=true;return true;}}));checks++;
 check(called,false);
} finally {await rm(directory,{recursive:true,force:true});}
process.stdout.write(JSON.stringify({status:'PASS',assertions:checks,scope:'synthetic H binding/trace/refusal only',
 participant_join:'UNPERFORMED',PostgreSQL:'UNPERFORMED',runtime_qualified:false})+'\n');
