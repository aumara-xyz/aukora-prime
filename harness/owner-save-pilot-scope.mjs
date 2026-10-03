// SPDX-License-Identifier: AGPL-3.0-or-later
// Separate interim scope metadata. This never grants authority or qualifies the
// full owner-memory path; canonical C/D operations and receipts are unchanged.
import {existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {parseIngressBytes} from './ingress.mjs';
const owned=existsSync(new URL('../prime-release.json',import.meta.url))?'../prime-packages/':'../packages/';
const contracts=await import(new URL(owned+'contracts/src/runtime.mjs',import.meta.url));
const {memoryReceiptDigest,memoryResultDigest}=await import(new URL(owned+'memory/src/authorization.mjs',import.meta.url));
export const OWNER_SAVE_PILOT_OMISSIONS=Object.freeze(['independent-witness','second-host-anchor','hardware-hash-display']);
const LABEL='REDUCED-GUARANTEE';
const HASH=/^sha256:[a-f0-9]{64}$/,COMMIT=/^[a-f0-9]{40}$/,ID=/^[A-Za-z0-9_.-]{1,128}$/;
const digest=(domain,value)=>'sha256:'+createHash('sha256').update(domain+'\0'+contracts.canonicalJson(value)).digest('hex');
const closed=(v,keys)=>{
 if(!v||Object.getPrototypeOf(v)!==Object.prototype||Object.keys(v).sort().join(',')!==[...keys].sort().join(','))throw new TypeError('INVALID: closed owner-save pilot metadata');
};
const freeze=v=>{if(v&&typeof v==='object'){for(const x of Object.values(v))freeze(x);Object.freeze(v);}return v;};
const detached=v=>contracts.parseStrictJson(contracts.canonicalJson(v),{maxBytes:65536,maxDepth:32});
function profile(v){
 closed(v,['version','kind','scope_label','omitted_guarantees','app_deployment','worker_deployment','owner_id','owner_subject','task_id']);
 if(v.version!==1||v.kind!=='prime-reduced-owner-save-scope/v1'||v.scope_label!==LABEL
  ||contracts.canonicalJson(v.omitted_guarantees)!==contracts.canonicalJson(OWNER_SAVE_PILOT_OMISSIONS)
  ||typeof v.owner_id!=='string'||!ID.test(v.owner_id)||typeof v.task_id!=='string'||!ID.test(v.task_id)
  ||typeof v.owner_subject!=='string'||!/^aukora:1:[a-f0-9]{64}$/.test(v.owner_subject))throw new TypeError('INVALID: exact reduced owner-save scope');
 for(const pin of [v.app_deployment,v.worker_deployment]){
  closed(pin,['source_commit','release_digest']);
  if(typeof pin.source_commit!=='string'||!COMMIT.test(pin.source_commit)||typeof pin.release_digest!=='string'||!HASH.test(pin.release_digest))throw new TypeError('INVALID: pilot deployment binding');
 }
 return freeze(v);
}
/** Syntax/digest binding only. This does not verify enrollment, provenance,
 * installed measurements, consent, protection or readiness for an effect. */
export function parseOwnerSavePilotScope(bytes){
 return profile(parseIngressBytes(bytes,contracts.parseStrictJson,{maxBytes:8192,maxDepth:8}));
}
export const ownerSavePilotScopeDigest=value=>digest('aukora-prime.owner-save-pilot.scope.v1',profile(detached(value)));

/** Hashes the existing genuine receipt into a separate versioned sidecar. The
 * caller must first validate the actual C/D save/receipt path. A sidecar is not
 * an approval, storage proof or a substitute for C's one-use owner proof. */
export function createOwnerSavePilotReceiptSidecar({scope,operation,receipt}={}){
 const p=profile(detached(scope)),op=detached(operation),r=detached(receipt);
 contracts.validateContract('OperationProposal',op);
 closed(op.target_identity,['kind','owner_subject']);
 closed(r,['version','kind','operation_id','operation_digest','grant_id','request_id','request_digest','owner_subject','action_type','status','result_digest','result']);
 const operationDigest=contracts.operationDigest(op);
 if(op.action_type!=='memory.save'||op.audience!=='aukora-prime.memory'||op.owner_id!==p.owner_id||op.task_id!==p.task_id
  ||op.target_identity.kind!=='prime-memory'||op.target_identity.owner_subject!==p.owner_subject||r.version!==1||r.kind!=='prime-memory-effect/v1'
  ||r.status!=='applied'||r.action_type!=='memory.save'||r.owner_subject!==p.owner_subject
  ||r.operation_id!==op.operation_id||r.operation_digest!==operationDigest
  ||typeof r.grant_id!=='string'||!r.grant_id.length||Buffer.byteLength(r.grant_id)>1024
  ||typeof r.request_id!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(r.request_id)
  ||typeof r.request_digest!=='string'||!HASH.test(r.request_digest)||r.result_digest!==memoryResultDigest(r.result))throw new TypeError('INVALID: pilot save receipt binding');
 const sidecar={version:1,kind:'prime-reduced-owner-save-receipt-scope/v1',scope_label:LABEL,
  omitted_guarantees:[...OWNER_SAVE_PILOT_OMISSIONS],scope_digest:ownerSavePilotScopeDigest(p),
  operation_digest:operationDigest,receipt_digest:memoryReceiptDigest(r)};
 return freeze({...sidecar,sidecar_digest:digest('aukora-prime.owner-save-pilot.receipt-scope.v1',sidecar)});
}
export function validateOwnerSavePilotReceiptSidecar(sidecar,binding){
 const value=detached(sidecar),expected=createOwnerSavePilotReceiptSidecar(binding);
 if(contracts.canonicalJson(value)!==contracts.canonicalJson(expected))throw new TypeError('INVALID: pilot receipt scope mismatch');
 return freeze(value);
}
/** Separate status sidecar for a future measured pilot assembly. No allowed
 * phase qualifies a factory or enables an action; UI must retain this scope. */
export function createOwnerSavePilotStatusSidecar({scope,runtime_state}={}){
 const p=profile(detached(scope));
 if(!['SOURCE-ONLY','BLOCKED','STARTING','RUNNING','STOPPED','OUTCOME_UNKNOWN'].includes(runtime_state))throw new TypeError('INVALID: pilot status state');
 const value={version:1,kind:'prime-reduced-owner-save-status-scope/v1',scope_label:LABEL,
  omitted_guarantees:[...OWNER_SAVE_PILOT_OMISSIONS],scope_digest:ownerSavePilotScopeDigest(p),runtime_state,
  app_deployment:p.app_deployment,worker_deployment:p.worker_deployment};
 return freeze({...value,sidecar_digest:digest('aukora-prime.owner-save-pilot.status-scope.v1',value)});
}
export function validateOwnerSavePilotStatusSidecar(sidecar,binding){
 const value=detached(sidecar),expected=createOwnerSavePilotStatusSidecar(binding);
 if(contracts.canonicalJson(value)!==contracts.canonicalJson(expected))throw new TypeError('INVALID: pilot status scope mismatch');
 return freeze(value);
}
