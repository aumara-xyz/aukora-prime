// SPDX-License-Identifier: AGPL-3.0-or-later
// Narrow disposable transport regressions. No authority, guest, network or app activation.
import assert from 'node:assert/strict';
import {readFileSync, mkdtempSync, cpSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const here = fileURLToPath(new URL('.', import.meta.url));
const sourceFlag = process.argv.indexOf('--source-root');
const source = sourceFlag < 0 ? join(here, 'src') : process.argv[sourceFlag + 1];
const node = await import(pathToFileURL(join(source, 'runtime.mjs')));
const browser = await import(pathToFileURL(join(source, 'browser.mjs')));
const golden = JSON.parse(readFileSync(join(here, 'golden-v1.json'), 'utf8'));
const clone = value => structuredClone(value);
let assertions = 0;
function same(actual, expected) { assert.deepEqual(actual, expected); assertions++; }
function refuses(fn, reason, path) {
 assert.throws(fn, error => error instanceof node.ContractValidationError && error.code === 'INVALID'
  && error.error_code === 'INVALID' && error.reason === reason && (path === undefined || error.path === path));
 assertions++;
}
const op = golden.vectors[0].proposal, shell = golden.vectors[1].proposal;
for (const vector of golden.vectors) {
 for (const api of [node, browser]) {
  same(api.canonicalJson(vector.proposal), vector.canonical_json);
  same(Buffer.from(api.operationBytes(vector.proposal)).toString('hex'), vector.bytes_hex);
  same(await api.operationDigest(vector.proposal), vector.digest);
 }
}
// Every mutable top-level operation field must affect both Node and browser bytes.
const changes = {version:2,operation_id:'different-op',task_id:'different-task',owner_id:'different-owner',
 agent_id:'different-agent',audience:'different-audience',action_type:'different.action',
 target_identity:{store:'different-store'},canonical_parameters:{content:'different-parameters'},
 data_scope:['private'],expected_state_version:'r2',provider_and_region:{provider:'different',region:'elsewhere'},
 maximum_cost:{currency:'USD',amount:'1.5'},expiry:'2031-01-02T03:04:05.000Z',nonce:'different-nonce',
 policy_version:'p2',authorization_epoch:1};
same(Object.keys(changes).sort(), [...node.CONTRACT_FIELDS.OperationProposal].sort());
for (const [field,value] of Object.entries(changes)) {
 const changed = {...clone(op),[field]:value};
 if (field === 'version') { refuses(() => node.operationBytes(changed), 'CONTRACT_VERSION'); continue; }
 for (const api of [node,browser]) {
  assert.notDeepEqual(api.operationBytes(changed), api.operationBytes(op), field + ' bytes'); assertions++;
  assert.notEqual(await api.operationDigest(changed), await api.operationDigest(op), field + ' digest'); assertions++;
 }
}

const request = {domain:'aukora:owner-approval-request:v1',subject:op.owner_id,
 activeControlDigest:'1'.repeat(64),operationDigest:golden.vectors[0].digest.slice(7),challenge:'2'.repeat(64),issuedAt:1,expiresAt:2};
const proof = {version:1,operation_id:op.operation_id,operation_digest:golden.vectors[0].digest,
 owner_id:op.owner_id,audience:op.audience,authorization_epoch:0,expiry:op.expiry,nonce:request.challenge,
 material:{kind:'owner_key',request,signature:'a'.repeat(128)}};
const uid = '11111111-1111-4111-8111-111111111111';
const receipt = {version:1,receipt_id:'r1',operation_id:op.operation_id,task_id:op.task_id,owner_id:op.owner_id,
 operation_digest:proof.operation_digest,grant_id:'g1',request_id:'q1',status:'completed',stdout:'',stderr:'',exit_code:0,
 rpc_completion:'complete',output_truncated:false,sandbox:{uid,name:'fixture',identity:'fixture/' + uid,
 image_digest:shell.target_identity.image_digest,policy_digest:shell.target_identity.policy_digest},
 cleanup:'confirmed_absent',started_at:null,finished_at:op.expiry,error_code:null,reconciliation_required:false};
const contracts = {
 OperationProposal:op, ApprovalProof:proof, ExecutionReceipt:receipt,
 Task:{version:1,task_id:'t',owner_id:'o',agent_id:'a',conversation_id:'c',status:'pending',created_at:op.expiry,route_id:null,
  allowed_data_classes:['public'],max_input_tokens:1,max_output_tokens:1,max_requests:1,task_spend_ceiling:op.maximum_cost},
 ConsumedGrant:{version:1,grant_id:'g',operation_id:'op',operation_digest:proof.operation_digest,owner_id:'o',audience:'a',authorization_epoch:0,prepared_at:op.expiry,reservation_id:'r'},
 BrowserSession:{version:1,session_id:'s',owner_id:'o',task_id:'t',state:'queued',lease_id:null,controller:null,worker_identity:null,permitted_origins:[],expires_at:op.expiry},
 ModelRoute:{version:1,route_id:'r',provider:'none',endpoint:'unavailable',model:'none',region:'local',allowed_data_classes:[],allowed_tools:[],max_input_tokens:1,max_output_tokens:1,max_requests:1,task_spend_ceiling:op.maximum_cost,status:'unavailable'},
 MemoryRecord:{version:1,record_id:'r',owner_subject:op.owner_id,task_id:'t',scope:'owner',privacy:'local',record_format:'v0',canonicalizer:'original',canonical_bytes:'{"decimal":1.5}',revision:'1',grants_authority:false,source_event_digest:null,evidence:[],chain_domain:'approved',source_span:null,storage_status:'saved',index_status:'pending'},
};
same(Object.keys(contracts).sort(), Object.keys(node.CONTRACT_FIELDS).sort());
for (const [kind,value] of Object.entries(contracts)) {
 same(node.validateContract(kind,value),value);
 same(node.parseContract(kind,JSON.stringify(value)),value);
 refuses(() => node.validateContract(kind,{...value,smuggled:true}), 'CONTRACT_FIELDS');
 for (const field of node.CONTRACT_FIELDS[kind]) {
  const missing = clone(value); delete missing[field];
  refuses(() => node.validateContract(kind,missing), 'CONTRACT_FIELDS');
 }
 for (const field of ['created_at','expiry','expires_at','prepared_at','finished_at']) if (field in value) {
  for (const date of [null,42,'2030-02-31T00:00:00Z','1900-02-29T00:00:00Z','2030-13-01T00:00:00Z','2030-01-00T00:00:00Z','2030-01-01T24:00:00Z','2030-01-01T00:00:60Z','2030-01-01T00:00:00+00:00']) {
   refuses(() => node.validateContract(kind,{...value,[field]:date}), 'CONTRACT_TIMESTAMP');
  }
 }
}
same(node.validateContract('OperationProposal',{...op,expiry:'2000-02-29T23:59:59.123456789Z'}).expiry,'2000-02-29T23:59:59.123456789Z');
for (const action_type of [42,null,'']) refuses(() => node.validateContract('OperationProposal',{...op,action_type}), 'CONTRACT_STRING');
for (const amount of ['00.5','01','-1','+1','1e0','1.','0.123456789',0,null]) refuses(() => node.validateContract('OperationProposal',{...op,maximum_cost:{currency:'USD',amount}}), 'CONTRACT_MONEY');
for (const material of [{...proof.material,smuggled:true},{kind:'owner_key',signature:proof.material.signature}]) refuses(() => node.validateContract('ApprovalProof',{...proof,material}), 'CONTRACT_FIELDS');
refuses(() => node.validateContract('ApprovalProof',{...proof,material:{...proof.material,request:{...request,smuggled:true}}}), 'CONTRACT_FIELDS');
for (const signature of ['',null,'A'.repeat(128),'a'.repeat(127)]) refuses(() => node.validateContract('ApprovalProof',{...proof,material:{...proof.material,signature}}), 'CONTRACT_SIGNATURE');
for (const field of Object.keys(request)) { const r=clone(request); delete r[field]; refuses(() => node.validateContract('ApprovalProof',{...proof,material:{...proof.material,request:r}}), 'CONTRACT_FIELDS'); }
for (const [field,value] of [['issuedAt',-1],['expiresAt','2']]) refuses(() => node.validateContract('ApprovalProof',{...proof,material:{...proof.material,request:{...request,[field]:value}}}), 'CONTRACT_INTEGER');
refuses(() => node.validateContract('ApprovalProof',{...proof,material:{...proof.material,request:{...request,expiresAt:1}}}), 'CONTRACT_TIMESTAMP');
const passkey={kind:'passkey',credential_id:'AQ',client_data_json:'AQ',authenticator_data:'AQ',signature:'AQ',user_handle:null};
same(node.validateContract('ApprovalProof',{...proof,material:passkey}).material,passkey);
for (const encoded of ['',42,'A','AR','AAB','AQ=','+/']) refuses(() => node.validateContract('ApprovalProof',{...proof,material:{...passkey,signature:encoded}}), 'CONTRACT_BASE64URL');
refuses(() => node.validateContract('ApprovalProof',{...proof,material:{...passkey,user_handle:Buffer.alloc(65).toString('base64url')}}), 'CONTRACT_BASE64URL');
for (const material of [{kind:'passkey'},{...proof.material,signature:''}]) {
 same(node.validateApprovalTemplate({...proof,material}).material,material);
 refuses(() => node.validateContract('ApprovalProof',{...proof,material}), material.kind==='passkey' ? 'CONTRACT_FIELDS' : 'CONTRACT_SIGNATURE');
 refuses(() => node.validateApprovalTemplate({...proof,material:{...material,smuggled:true}}), 'CONTRACT_FIELDS');
}
for (const sandbox of ['string',{evil:true},{...receipt.sandbox,evil:true}]) refuses(() => node.validateContract('ExecutionReceipt',{...receipt,sandbox}), typeof sandbox==='string' ? 'CONTRACT_OBJECT' : 'CONTRACT_FIELDS');
refuses(() => node.validateContract('ExecutionReceipt',{...receipt,cleanup:'pending'}), 'CONTRACT_RECEIPT_STATE');
refuses(() => node.validateContract('ExecutionReceipt',{...receipt,output_truncated:1}), 'CONTRACT_BOOLEAN');
refuses(() => node.validateContract('BrowserSession',{...contracts.BrowserSession,worker_identity:42}), 'CONTRACT_STRING');
refuses(() => node.validateContract('ModelRoute',{...contracts.ModelRoute,endpoint:{}}), 'CONTRACT_STRING');
refuses(() => node.validateContract('MemoryRecord',{...contracts.MemoryRecord,grants_authority:true}), 'CONTRACT_MEMORY_BYTES');
for (const field of ['status','rpc_completion','cleanup','error_code']) refuses(() => node.validateContract('ExecutionReceipt',{...receipt,[field]:'evil'}), 'CONTRACT_ENUM');
for (const field of ['target_identity','canonical_parameters']) {
 refuses(() => node.validateContract('OperationProposal',{...shell,[field]:{...shell[field],evil:true}}), 'CONTRACT_FIELDS');
 for (const key of Object.keys(shell[field])) { const changed=clone(shell); delete changed[field][key]; refuses(() => node.validateContract('OperationProposal',changed), 'CONTRACT_FIELDS'); }
}
for (const [key,value,reason] of [['command',42,'CONTRACT_COMMAND'],['command','a\0','CONTRACT_COMMAND'],['stdin',42,'CONTRACT_STDIN'],['sandbox_mode','full-access','CONTRACT_ENUM'],['timeout_ms',0,'CONTRACT_INTEGER'],['timeout_ms',600001,'CONTRACT_INTEGER'],['max_output_bytes',1048577,'CONTRACT_INTEGER'],['env',{EVIL:'yes'},'CONTRACT_ENV'],['env',{PATH:'elsewhere'},'CONTRACT_ENV'],['dsh_env',{DSH_HOME:'relative'},'CONTRACT_ENV'],['workdir','/different','CONTRACT_PATH']]) {
 refuses(() => node.validateContract('OperationProposal',{...shell,canonical_parameters:{...shell.canonical_parameters,[key]:value}}),reason);
}
same(node.validateContract('OperationProposal',{...shell,canonical_parameters:{...shell.canonical_parameters,env:{PATH:'/usr/bin:/bin'},dsh_env:{DSH_HOME:'/logical/.dsh',DSH_SHELL:'1',DSH_SESSION_ID:'fixture'}}}).version,1);
for (const key of ['timeout_ms','max_output_bytes']) {
 const changed=clone(shell); changed.canonical_parameters[key]++;
 assert.notEqual(node.operationDigest(changed),node.operationDigest(shell));assertions++;
}

for (const bad of [-0,{a:-0}]) refuses(() => node.canonicalJson(bad),'JSON_NEGATIVE_ZERO');
for (const bad of ['\ud800','\udc00',{'\ud800':'key'},{value:'\udc00'}]) refuses(() => node.canonicalJson(bad),'JSON_LONE_SURROGATE');
for (const bad of [1.5,NaN,Infinity,Number.MAX_SAFE_INTEGER+1]) refuses(() => node.canonicalJson(bad),'JSON_UNSAFE_NUMBER');
same(node.canonicalJson({'😀':'雪',a:[null,0]}),'{"a":[null,0],"😀":"雪"}');
const cycle={}; cycle.self=cycle; refuses(() => node.canonicalJson(cycle),'JSON_CYCLE');
refuses(() => node.canonicalJson(Array(1)),'JSON_ARRAY');
refuses(() => node.canonicalJson(Object.assign([],{evil:true})),'JSON_ARRAY');
let getterRead=false;const getter={};Object.defineProperty(getter,'version',{enumerable:true,get(){getterRead=true;return 1;}});
refuses(() => node.validateContract('OperationProposal',getter),'JSON_DATA_PROPERTY');same(getterRead,false);
refuses(() => node.canonicalJson(Object.create({inherited:true})),'JSON_PROTOTYPE');
refuses(() => node.canonicalJson(Object.defineProperty({},'x',{value:1})),'JSON_DATA_PROPERTY');

for (const text of ['{"x":1,"x":2}','{"x":1,"\\u0078":2}','{"a":[{"x":1,"x":2}]}','{"__proto__":1,"__proto__":2}','{"😀":1,"\\ud83d\\ude00":2}']) refuses(() => node.parseStrictJson(text),'JSON_DUPLICATE_KEY');
same(node.parseStrictJson('{"a":{"x":1},"b":{"x":2},"s":"\\\"x\\\":2"}'),{a:{x:1},b:{x:2},s:'"x":2'});
for (const text of ['{"s":"\\ud800"}','{"\\udc00":1}']) refuses(() => node.parseStrictJson(text),'JSON_LONE_SURROGATE');
for (const text of ['-0','-0.0','-0e0']) refuses(() => node.parseStrictJson(text),'JSON_NEGATIVE_ZERO');
for (const text of ['1.00000000000000001','9007199254740993','9007199254740991.1','1e309','1e-999','1.5']) refuses(() => node.parseStrictJson(text),'JSON_UNSAFE_NUMBER');
for (const text of ['1e0','1.0','100e-2','0e999']) same(node.parseStrictJson(text),text==='0e999'?0:1);
for (const text of ['', '[1,]', '{"a":}', 'true false','{"a":"unterminated}', '[}', '+1', '\uFEFF{}']) refuses(() => node.parseStrictJson(text),'JSON_MALFORMED');
refuses(() => node.parseStrictJson(' '.repeat(11)+'0',{maxBytes:10}),'JSON_SIZE');
refuses(() => node.parseStrictJson('"雪"',{maxBytes:4}),'JSON_SIZE');
refuses(() => node.parseStrictJson('[[0]]',{maxDepth:1}),'JSON_DEPTH');
refuses(() => node.parseStrictJson('0',{maxDepth:65}),'JSON_LIMIT');
refuses(() => node.parseStrictJson('0',null),'JSON_LIMIT');
refuses(() => node.parseStrictJson({}),'JSON_TEXT_REQUIRED');
const duplicatedOperation=JSON.stringify(op).replace('"version":1','"version":1,"version":1');
refuses(() => node.parseContract('OperationProposal',duplicatedOperation),'JSON_DUPLICATE_KEY');
// Native parsing loses the evidence: require the TEXT helper at actual ingress.
same(node.validateContract('OperationProposal',JSON.parse(duplicatedOperation)).version,1);
for (const v of golden.kira_vectors) {
 const record={...contracts.MemoryRecord,canonical_bytes:v.canonical_bytes,record_id:v.record_id,record_format:v.record_format,canonicalizer:v.canonicalizer};
 const restored=node.parseContract('MemoryRecord',node.canonicalJson(record));
 same(restored.canonical_bytes,v.canonical_bytes);same(restored.record_id,v.record_id);
 same(createHash('sha256').update(restored.canonical_bytes).digest('hex'),v.original_sha256);
}
for (const filename of ['browser.mjs','shared.mjs','json.mjs']) {
 assert.doesNotMatch(readFileSync(join(source,filename),'utf8'), /from ['"]node:|\bBuffer\b|\bprocess\./);assertions++;
}
console.log(`contracts: ${assertions} assertions; 3 frozen v1 vectors (Node/browser), 17 mutable fields + fixed version, 2 Kira byte vectors`);

if (process.argv.includes('--mutations')) {
 const mutations = [
  ['canonical_parameters omitted (Node)','runtime.mjs','canonicalJson(proposal)',"canonicalJson(Object.fromEntries(Object.entries(proposal).filter(([k])=>k!=='canonical_parameters')))"],
  ['canonical_parameters omitted (browser)','browser.mjs','canonicalJson(p)',"canonicalJson(Object.fromEntries(Object.entries(p).filter(([k])=>k!=='canonical_parameters')))"],
  ['negative-zero guard','json.mjs',"if (Object.is(node, -0)) invalid('JSON_NEGATIVE_ZERO');",''],
  ['Unicode guard','json.mjs',"if (/[\\uD800-\\uDBFF](?![\\uDC00-\\uDFFF])|(?<![\\uD800-\\uDBFF])[\\uDC00-\\uDFFF]/u.test(value)) invalid('JSON_LONE_SURROGATE', path);",''],
  ['duplicate-key guard','json.mjs',"if (frame.has(key)) invalid('JSON_DUPLICATE_KEY');",''],
  ['money leading-zero guard','shared.mjs','(?:0|[1-9]\\d*)','\\d+'],
  ['calendar rollover guard','shared.mjs','day > days[month - 1]','false'],
  ['owner material closure','shared.mjs',"closed(material, ['kind','request','signature'], path);",''],
 ];
 const dir=mkdtempSync(join(tmpdir(),'prime-contract-mutations-'));
 try {
  for (let i=0;i<mutations.length;i++) {
   const [label,file,before,after]=mutations[i],root=join(dir,String(i));cpSync(join(here,'src'),root,{recursive:true});
   const path=join(root,file),text=readFileSync(path,'utf8');same(text.split(before).length,2);
   writeFileSync(path,text.replace(before,after));
   const answer=spawnSync(process.execPath,[fileURLToPath(import.meta.url),'--source-root',root],{encoding:'utf8',timeout:30000});
   assert.equal(answer.error,undefined,label);assert.equal(answer.signal,null,label);
   assert.notEqual(answer.status,0,label+' survived');assert.match(answer.stderr,/AssertionError/,label+' did not fail a regression assertion');
   console.log('mutation killed: '+label);
  }
 } finally {rmSync(dir,{recursive:true,force:true});}
 console.log('contracts: 8 single-guard/digest mutation regressions killed; disposable copies removed');
}
