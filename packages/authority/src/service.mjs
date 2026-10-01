import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto'
import { dirname, join, resolve } from 'node:path'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { validateContract, canonicalJson } from '../../contracts/src/runtime.mjs'
import { canonicalBytes } from '../upstream/vendor/authority/lib/index.js'
import { decideApproval, decideVerifiedPasskey } from '../upstream/scripts/aukora/decide.mjs'
import { createApprovalRequest, approvalSigningBytes } from '../upstream/plugins/aukora-aumlok/lib/owner-approval.mjs'
import { createApprovalReceipt } from '../upstream/plugins/aukora-aumlok/lib/approval-receipt.mjs'
import { ed25519PublicKeyFromDidKey, didKeyFromEd25519PublicKey } from '../upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import { readClosedDataRecord } from '../upstream/plugins/aukora-aumlok/lib/validation.mjs'
import { PrimeApprovalStateStore, EMPTY_KERNEL_STATE } from './state-store.mjs'
import { RollbackRefusedError } from '../upstream/scripts/aukora/trusted-state-store.mjs'
import { detachContract, operationDigest, dollars, deepFreeze, assertData } from './operation.mjs'
import { prepareWebauthnConfig, webauthnChallenge, webauthnOptions, verifyWebauthnAssertion } from './webauthn.mjs'
import { DIGEST, UUID, executionReceiptDigest, validatedReceipt, settlementStatus } from './execution.mjs'
import { memoryEffectReceipt, memoryEffectReceiptDigest } from './memory-effect.mjs'

const hex = /^[a-f0-9]{64}$/
const sha = value => createHash('sha256').update(value).digest('hex')
const keyOf = value => sha(value)
const operationKey = (ownerId,operationId) => sha(canonicalJson([ownerId,operationId]))
const iso = ms => new Date(ms).toISOString()
const equal = (a,b) => canonicalJson(a) === canonicalJson(b)
class Refusal extends Error {
  constructor(error_code, reason) { super(reason); this.error_code = error_code }
}
const refuse = (code, reason) => { throw new Refusal(code, reason) }
const resultError = error => ({ ok:false, error_code:error.error_code ?? (error instanceof RollbackRefusedError ? 'RECONCILIATION_REQUIRED' : error instanceof TypeError || error.name==='KernelInputError' ? 'INVALID' : 'UNAVAILABLE'), reason:error.message })
function closed(value, fields) { assertData(value); canonicalBytes(value); return readClosedDataRecord(value,fields,'Prime authority input') }
function pinnedKey(did) {
  const raw = ed25519PublicKeyFromDidKey(did)
  if (didKeyFromEd25519PublicKey(raw) !== did) throw new TypeError('INVALID: noncanonical pinned DID')
  return createPublicKey({format:'jwk',key:{kty:'OKP',crv:'Ed25519',x:Buffer.from(raw,'hex').toString('base64url')}})
}
function validSignature(bytes, signature, did) {
  return typeof signature === 'string' && /^[a-f0-9]{128}$/.test(signature) && verify(null,bytes,pinnedKey(did),Buffer.from(signature,'hex'))
}
export function loginSigningBytes(input) {
  const request = closed(input,['version','owner_id','audience','challenge','issued_at','expiry','authorization_epoch'])
  return Buffer.from('aukora-prime.owner-login.v1\0'+canonicalJson(request),'utf8')
}
export { approvalSigningBytes }

// All options are provisioner inputs, never guest/wire fields. No private keys, signer,
// executor or enrollment endpoint exists here. identities must come from owner-approved
// enrollment. Empty/unprovisioned deployments fail closed. Tests use disposable public keys.
export function createAuthorityService(options) { return authorityService(options,false) }
// Setup-only local entry point. Never mount this function on a worker/guest route.
// Ordinary API calls cannot create missing state, even with a sticky provision flag.
export function provisionNewAuthorityStore(options) { return authorityService(options,true) }
function authorityService(options, provisionNew) {
  const c = { ...options }
  const defaults={logins_per_owner:32,sessions_per_owner:16,operations_per_owner:128,operations_total:256,pending_ttl_ms:300000,denied_per_owner:32,denied_total:64,operation_bytes:65536,state_bytes:16*1024*1024}
  assertData(c.limits??{})
  if(Object.keys(c.limits??{}).some(k=>!Object.hasOwn(defaults,k))) throw new TypeError('INVALID: authority quota config')
  c.limits=deepFreeze({...defaults,...c.limits})
  if(Object.values(c.limits).some(n=>!Number.isSafeInteger(n)||n<1)) throw new TypeError('INVALID: positive authority quotas')
  assertData(c.policy);assertData(c.identities ?? [])
  assertData(c.loginKinds ?? ['passkey'])
  c.loginKinds=deepFreeze([...(c.loginKinds ?? ['passkey'])])
  if(!c.loginKinds.length||new Set(c.loginKinds).size!==c.loginKinds.length||c.loginKinds.some(k=>!['owner_key','passkey'].includes(k))) throw new TypeError('INVALID: configured login kinds')
  c.webauthn=deepFreeze(prepareWebauthnConfig(c.webauthn))
  for (const p of ['statePath','stateRoot','witnessDir']) {
    if (typeof c[p] !== 'string' || !c[p].startsWith('/')) throw new TypeError(`INVALID: absolute ${p}`)
    c[p] = resolve(c[p])
  }
  if (typeof c.audience !== 'string' || !c.audience) throw new TypeError('INVALID: broker audience')
  c.policy = deepFreeze(JSON.parse(canonicalJson(c.policy)))
  if (!c.policy.version || !Array.isArray(c.policy.actions) || !Array.isArray(c.policy.agents) || !Array.isArray(c.policy.data_scope)) throw new TypeError('INVALID: immutable broker policy')
  dollars(c.policy.maximum_cost)
  const identities = deepFreeze(JSON.parse(canonicalJson(c.identities ?? [])))
  const pinned = new Map()
  for (const id of identities) {
    closed(id,['owner_id','subject','approval_key_did','control_digest','authorization_epoch'])
    if(typeof id.owner_id!=='string'||!id.owner_id||!/^aukora:1:[a-f0-9]{64}$/.test(id.subject)||!hex.test(id.control_digest)||!Number.isSafeInteger(id.authorization_epoch)||id.authorization_epoch<0) throw new TypeError('INVALID: registered public identity')
    pinnedKey(id.approval_key_did)
    if(pinned.has(id.owner_id)) throw new TypeError('INVALID: duplicate registered owner')
    pinned.set(id.owner_id,id)
  }
  const now = () => Date.now() // wire callers can never select an audit clock
  class ConfiguredStore extends PrimeApprovalStateStore {constructor(args){super({...args,maxStateBytes:c.limits.state_bytes})}}
  if(provisionNew) return attempt(()=>{
    if(c.provisionTrustedState!==true) refuse('UNAVAILABLE','EXPLICIT_NEW_STORE_PROVISIONING_REQUIRED')
    if(!identities.length) refuse('UNAVAILABLE','OWNER_PUBLIC_CONFIGURATION_REQUIRED')
    const store=new PrimeApprovalStateStore({statePath:c.statePath,stateRoot:c.stateRoot,witnessDir:c.witnessDir,createConsumedIds:true,maxStateBytes:c.limits.state_bytes})
    try {
      store.open()
      if(store.protectedRead(store.stateFile)!==null) refuse('REPLAYED','STORE_ALREADY_PROVISIONED')
      store.load(structuredClone(EMPTY_KERNEL_STATE))
      for(const id of identities) store.broker.owners[keyOf(id.owner_id)]={...id,revoked:false,passkey_counters:Object.fromEntries((c.webauthn?.credentials.filter(x=>x.owner_id===id.owner_id)??[]).map(x=>[keyOf(x.credential_id),x.sign_count]))}
      store.commitBroker()
      return {ok:true,status:'PROVISIONED',store_id:store.store_id}
    } finally {store.close()}
  })
  function discardablePending(store,row) {
    if(!['PROPOSED','APPROVED','DENIED'].includes(row.status)||row.grant||row.dispatch) return false
    const nonce=row.approval?.proof?.nonce
    if(nonce&&store.currentRecord.state.consumedIds.includes('approval:'+nonce)) return false
    // A crash can retain kernel PREPARED without matching broker grant metadata.
    // Keep that obligation even if its old approval was subsequently declined.
    return !store.currentRecord.prepared.some(p=>p.contentHash===row.operation_digest?.slice(7))
  }
  function prunePending(store) {
    const stamp=now()
    for(const [key,row] of Object.entries(store.broker.operations)) {
      if(!discardablePending(store,row)) continue
      row.pending_until??=iso(Math.min(Date.parse(row.operation.expiry),stamp+c.limits.pending_ttl_ms))
      if(Date.parse(row.operation.expiry)<=stamp||Date.parse(row.pending_until)<=stamp) delete store.broker.operations[key]
    }
    const denied=Object.entries(store.broker.operations).filter(([,row])=>row.status==='DENIED'&&discardablePending(store,row))
      .sort(([ka,a],[kb,b])=>Date.parse(b.pending_until)-Date.parse(a.pending_until)||ka.localeCompare(kb))
    const keptByOwner=new Map();let total=0
    for(const [key,row] of denied) {
      const ownerCount=keptByOwner.get(row.operation.owner_id)??0
      if(total>=c.limits.denied_total||ownerCount>=c.limits.denied_per_owner) delete store.broker.operations[key]
      else {total++;keptByOwner.set(row.operation.owner_id,ownerCount+1)}
    }
  }
  function newPending(op) {
    return {operation:op,operation_digest:operationDigest(op),status:'PROPOSED',review:null,approval:null,grant:null,pending_until:iso(Math.min(Date.parse(op.expiry),now()+c.limits.pending_ttl_ms))}
  }
  function tx(fn) {
    const store = new PrimeApprovalStateStore({ statePath:c.statePath,stateRoot:c.stateRoot,witnessDir:c.witnessDir,createConsumedIds:false,maxStateBytes:c.limits.state_bytes })
    try {
      store.open();store.load(structuredClone(EMPTY_KERNEL_STATE))
      // Ephemeral challenges/sessions may expire; authority consumption and operation
      // tombstones are never evicted to admit a replay. Quota failures write nothing.
      for(const [k,v] of Object.entries(store.broker.logins)) if(Date.parse(v.challenge.expiry)<=now()) delete store.broker.logins[k]
      for(const [k,v] of Object.entries(store.broker.sessions)) if(Date.parse(v.expiry)<=now()) delete store.broker.sessions[k]
      prunePending(store)
      return fn(store)
    } finally { store.close() }
  }
  function owner(store, ownerId) {
    if(typeof ownerId!=='string'||!pinned.has(ownerId)) refuse('UNAUTHORIZED','OWNER_NOT_ENROLLED')
    const id=store.broker.owners[keyOf(ownerId)], pin=pinned.get(ownerId)
    if(!id) refuse('UNAVAILABLE','TRUSTED_IDENTITY_UNAVAILABLE')
    if(id.revoked) refuse('REVOKED','OWNER_REVOKED')
    for(const field of ['subject','approval_key_did','control_digest']) if(id[field]!==pin[field]) refuse('REVOKED','CONTROL_PIN_CHANGED')
    return id
  }
  function session(store, token) {
    if(typeof token!=='string'||!hex.test(token)) refuse('UNAUTHORIZED','OWNER_SESSION_REQUIRED')
    const s=store.broker.sessions[keyOf(token)]
    if(!s) refuse('UNAUTHORIZED','OWNER_SESSION_INVALID')
    const id=owner(store,s.owner_id)
    if(s.audience!==c.audience) refuse('SCOPE_MISMATCH','SESSION_AUDIENCE_CHANGED')
    if(s.authorization_epoch!==id.authorization_epoch) refuse('REVOKED','SESSION_EPOCH_REVOKED')
    if(Date.parse(s.expiry)<=now()) refuse('EXPIRED','SESSION_EXPIRED')
    return id
  }
  function policy(store, op) {
    const id=owner(store,op.owner_id)
    if(op.audience!==c.audience) refuse('SCOPE_MISMATCH','AUDIENCE_MISMATCH')
    if(op.authorization_epoch!==id.authorization_epoch) refuse('REVOKED','AUTHORIZATION_EPOCH_CHANGED')
    if(op.policy_version!==c.policy.version) refuse('STALE','POLICY_VERSION_CHANGED')
    if(Date.parse(op.expiry)<=now()) refuse('EXPIRED','OPERATION_EXPIRED')
    if(!c.policy.actions.includes(op.action_type)||!c.policy.agents.includes(op.agent_id)||op.data_scope.some(x=>!c.policy.data_scope.includes(x))||dollars(op.maximum_cost)>dollars(c.policy.maximum_cost)) refuse('SCOPE_MISMATCH','POLICY_SCOPE_REFUSED')
    if(typeof c.authorizeTask!=='function') refuse('UNAUTHORIZED','TASK_SCOPE_NOT_AUTHENTICATED')
    const authorized=c.authorizeTask(deepFreeze(structuredClone(op)))
    if(!authorized||authorized.authenticated!==true) refuse('UNAUTHORIZED','TASK_SCOPE_NOT_AUTHENTICATED')
    closed(authorized,['authenticated','task'])
    const task=detachContract('Task',authorized.task)
    if(task.task_id!==op.task_id||task.owner_id!==op.owner_id||task.agent_id!==op.agent_id||
       !['pending','running'].includes(task.status)||op.data_scope.some(x=>!task.allowed_data_classes.includes(x))||dollars(op.maximum_cost)>dollars(task.task_spend_ceiling)) refuse('UNAUTHORIZED','OWNED_TASK_BINDING_MISMATCH')
    return id
  }
  function liveTarget(op) {
    if(typeof c.observeTarget!=='function') refuse('UNAVAILABLE','TARGET_STATE_UNAVAILABLE')
    let observed
    try { observed=c.observeTarget(deepFreeze(structuredClone(op)));canonicalBytes(observed) } catch { refuse('UNAVAILABLE','TARGET_STATE_UNAVAILABLE') }
    if(!equal(observed.target_identity,op.target_identity)||observed.state_version!==op.expected_state_version) refuse('TARGET_MISMATCH','TARGET_STATE_CHANGED')
  }
  function operationRow(store,op) {
    const row=store.broker.operations[operationKey(op.owner_id,op.operation_id)]
    if(!row) refuse('UNAVAILABLE','OPERATION_NOT_PROPOSED')
    if(row.operation_digest!==operationDigest(op)||!equal(row.operation,op)) refuse('INVALID','EXACT_OPERATION_CHANGED')
    if(row.approval && !row.grant && store.currentRecord.state.consumedIds.includes('approval:'+row.approval.proof.nonce)) refuse('RECONCILIATION_REQUIRED','CONSUMED_AUTHORITY_WITHOUT_MATCHING_RESERVATION')
    return row
  }
  function approvalSession(store,row) {
    const s=store.broker.sessions[row.review?.session_hash]
    if(!s||s.owner_id!==row.operation.owner_id||s.audience!==c.audience||
       s.authorization_epoch!==row.operation.authorization_epoch||Date.parse(s.expiry)<=now()) {
      refuse('UNAUTHORIZED','APPROVAL_SESSION_REVOKED_OR_EXPIRED')
    }
  }
  function attempt(fn) { try {return fn()} catch(error) {return resultError(error)} }
  function boundedOperation(input) {
    const op=detachContract('OperationProposal',input)
    if(Buffer.byteLength(canonicalJson(op))>c.limits.operation_bytes) refuse('INVALID','OPERATION_BYTE_QUOTA')
    return op
  }
  function admitOperation(store,ownerId) {
    const rows=Object.values(store.broker.operations).filter(r=>['PROPOSED','APPROVED'].includes(r.status)&&discardablePending(store,r))
    if(rows.length>=c.limits.operations_total||rows.filter(r=>r.operation.owner_id===ownerId).length>=c.limits.operations_per_owner) refuse('UNAVAILABLE','PENDING_OPERATION_QUOTA_REACHED')
  }
  function propose(input) { return attempt(()=>{
    const v=closed(input,['session_token','operation']),op=boundedOperation(v.operation)
    return tx(store=>{
      const id=session(store,v.session_token)
      if(id.owner_id!==op.owner_id) refuse('UNAUTHORIZED','CROSS_OWNER_PROPOSAL')
      policy(store,op)
      const k=operationKey(op.owner_id,op.operation_id)
      if(store.broker.operations[k]) refuse('REPLAYED','OPERATION_ID_ALREADY_EXISTS')
      admitOperation(store,op.owner_id)
      const row=newPending(op),digest=row.operation_digest
      store.broker.operations[k]=row
      store.commitBroker()
      return {ok:true,operation:deepFreeze(op),operation_digest:digest,status:'PROPOSED'}
    })
  }) }
  function loginChallenge(input) { return attempt(()=>{
    const v=closed(input,['owner_id','kind'])
    if(!['owner_key','passkey'].includes(v.kind)) refuse('INVALID','LOGIN_MATERIAL_KIND')
    if(!c.loginKinds.includes(v.kind)) refuse('UNAVAILABLE','LOGIN_METHOD_NOT_CONFIGURED')
    return tx(store=>{
      const id=owner(store,v.owner_id),stamp=now()
      if(Object.values(store.broker.logins).filter(x=>x.challenge.owner_id===id.owner_id).length>=c.limits.logins_per_owner) refuse('UNAVAILABLE','LOGIN_CHALLENGE_QUOTA_REACHED')
      const challenge={version:1,owner_id:id.owner_id,audience:c.audience,challenge:randomBytes(32).toString('hex'),issued_at:iso(stamp),expiry:iso(stamp+60000),authorization_epoch:id.authorization_epoch}
      const public_key=v.kind==='passkey'?webauthnOptions(c.webauthn,id.owner_id,webauthnChallenge(loginSigningBytes(challenge))):undefined
      store.broker.logins[challenge.challenge]={challenge,kind:v.kind,used:false}
      store.commitBroker()
      return {ok:true,challenge:deepFreeze(challenge),...(public_key?{public_key}: {})}
    })
  }) }
  function loginComplete(input) { return attempt(()=>{
    const v=closed(input,['challenge','material'])
    const m=v.material
    return tx(store=>{
      const entry=store.broker.logins[v.challenge?.challenge]
      if(!entry||!equal(entry.challenge,v.challenge)) refuse('UNAUTHORIZED','LOGIN_CHALLENGE_MISMATCH')
      if(entry.used) refuse('REPLAYED','LOGIN_CHALLENGE_USED')
      const id=owner(store,entry.challenge.owner_id)
      if(Object.values(store.broker.sessions).filter(x=>x.owner_id===id.owner_id).length>=c.limits.sessions_per_owner) refuse('UNAVAILABLE','OWNER_SESSION_QUOTA_REACHED')
      if(m.kind!==entry.kind) refuse('UNAUTHORIZED','LOGIN_MATERIAL_KIND_CHANGED')
      if(entry.challenge.authorization_epoch!==id.authorization_epoch) refuse('REVOKED','LOGIN_EPOCH_CHANGED')
      if(Date.parse(entry.challenge.expiry)<=now()) refuse('EXPIRED','LOGIN_CHALLENGE_EXPIRED')
      if(m.kind==='passkey') {
        const checked=verifyWebauthnAssertion({material:m,config:c.webauthn,ownerId:id.owner_id,challenge:webauthnChallenge(loginSigningBytes(entry.challenge)),counter:id.passkey_counters[keyOf(m.credential_id)]})
        id.passkey_counters[keyOf(m.credential_id)]=checked.sign_count
      } else {
        closed(m,['kind','signature'])
        if(!validSignature(loginSigningBytes(entry.challenge),m.signature,id.approval_key_did)) refuse('UNAUTHORIZED','LOGIN_SIGNATURE_INVALID')
      }
      entry.used=true
      const token=randomBytes(32).toString('hex'),expiry=iso(now()+300000)
      store.broker.sessions[keyOf(token)]={owner_id:id.owner_id,audience:c.audience,authorization_epoch:id.authorization_epoch,expiry,kind:m.kind}
      store.commitBroker()
      return {ok:true,session_token:token,owner_id:id.owner_id,expiry}
    })
  }) }
  function approvalChallenge(input) { return attempt(()=>{
    const v=closed(input,['session_token','operation']),op=boundedOperation(v.operation)
    return tx(store=>{
      const id=session(store,v.session_token)
      if(id.owner_id!==op.owner_id) refuse('UNAUTHORIZED','CROSS_OWNER_APPROVAL')
      policy(store,op);liveTarget(op)
      let row=store.broker.operations[operationKey(op.owner_id,op.operation_id)]
      if(!row) { admitOperation(store,op.owner_id);row=newPending(op);store.broker.operations[operationKey(op.owner_id,op.operation_id)]=row }
      operationRow(store,op)
      if(row.status!=='PROPOSED') refuse(row.status==='DENIED'?'CANCELLED':'REPLAYED','OPERATION_NOT_REVIEWABLE')
      const issuedAt=Math.floor(now()/1000),expiresAt=Math.min(issuedAt+120,Math.floor(Date.parse(op.expiry)/1000))
      if(expiresAt<=issuedAt) refuse('EXPIRED','APPROVAL_WINDOW_EMPTY')
      const request=createApprovalRequest({subject:id.subject,activeControlDigest:id.control_digest,operationDigest:row.operation_digest.slice(7),challenge:randomBytes(32).toString('hex'),issuedAt,expiresAt})
      const template={version:1,operation_id:op.operation_id,operation_digest:row.operation_digest,owner_id:id.owner_id,audience:op.audience,authorization_epoch:id.authorization_epoch,expiry:iso(expiresAt*1000),nonce:request.challenge}
      const kind=store.broker.sessions[keyOf(v.session_token)].kind
      const public_key=kind==='passkey'?webauthnOptions(c.webauthn,id.owner_id,webauthnChallenge(approvalSigningBytes(request))):undefined
      row.pending_until=iso(expiresAt*1000)
      row.review={request,template,kind,session_hash:keyOf(v.session_token)}
      store.commitBroker()
      return {ok:true,operation:deepFreeze(structuredClone(op)),operation_digest:row.operation_digest,approval_request:request,proof_template:deepFreeze({...template,material:kind==='passkey'?{kind:'passkey'}:{kind:'owner_key',request,signature:''}}),...(public_key?{public_key}: {})}
    })
  }) }
  function approvalComplete(input) { return attempt(()=>{
    const v=closed(input,['session_token','proof']),proof=detachContract('ApprovalProof',v.proof)
    const m=proof.material
    return tx(store=>{
      const id=session(store,v.session_token),row=store.broker.operations[operationKey(proof.owner_id,proof.operation_id)]
      if(!row||!row.review) refuse('UNAUTHORIZED','EXACT_REVIEW_REQUIRED')
      if(row.status!=='PROPOSED') refuse(row.status==='DENIED'?'CANCELLED':'REPLAYED','OPERATION_NOT_REVIEWABLE')
      if(id.owner_id!==row.operation.owner_id||row.review.session_hash!==keyOf(v.session_token)) refuse('UNAUTHORIZED','AUTHENTICATED_OWNER_APPROVAL_REQUIRED')
      policy(store,row.operation);liveTarget(row.operation)
      const {material,...envelope}=proof
      if(!equal(envelope,row.review.template)||m.kind!==row.review.kind) refuse('INVALID','APPROVAL_BINDING_MISMATCH')
      if(Date.parse(proof.expiry)<=now()) refuse('EXPIRED','APPROVAL_EXPIRED')
      if(m.kind==='passkey') {
        const assertion=verifyWebauthnAssertion({material:m,config:c.webauthn,ownerId:id.owner_id,challenge:webauthnChallenge(approvalSigningBytes(row.review.request)),counter:id.passkey_counters[keyOf(m.credential_id)]})
        id.passkey_counters[keyOf(m.credential_id)]=assertion.sign_count
        row.status='APPROVED';row.approval={proof,receipt:null,assertion};store.commitBroker()
        return {ok:true,approval_proof:deepFreeze(proof),status:'APPROVED'}
      }
      closed(m,['kind','request','signature'])
      if(!equal(m.request,row.review.request)) refuse('INVALID','APPROVAL_BINDING_MISMATCH')
      if(!validSignature(approvalSigningBytes(m.request),m.signature,id.approval_key_did)) refuse('UNAUTHORIZED','APPROVAL_SIGNATURE_INVALID')
      const receipt=createApprovalReceipt({approval:{ok:true,operationDigest:row.operation_digest.slice(7),challenge:proof.nonce,signature:m.signature,verifiedAt:Math.floor(now()/1000)},projection:{domain:'prime-public-control',subject:id.subject,epoch:id.authorization_epoch,activeControlDigest:id.control_digest,revoked:false,approvalKeyDid:id.approval_key_did,custodyClass:'B'},keyClass:'B',request:m.request})
      row.status='APPROVED';row.approval={proof,receipt};store.commitBroker()
      return {ok:true,approval_proof:deepFreeze(proof),status:'APPROVED'}
    })
  }) }
  function declineApproval(input) { return attempt(()=>{
    const v=closed(input,['session_token','operation_id'])
    return tx(store=>{
      const id=session(store,v.session_token),row=store.broker.operations[operationKey(id.owner_id,v.operation_id)]
      if(!row||row.operation.owner_id!==id.owner_id) refuse('UNAUTHORIZED','OWNER_OPERATION_REQUIRED')
      if(!['PROPOSED','APPROVED'].includes(row.status)) refuse('RECONCILIATION_REQUIRED','PREPARED_EFFECT_CANNOT_BE_UNCONSUMED')
      row.status='DENIED';row.review=null;row.approval=null;prunePending(store);store.commitBroker()
      return {ok:true,status:'DENIED'}
    })
  }) }
  function reserve(input) { return attempt(()=>{
    const v=closed(input,['operation','approval_proof']),op=boundedOperation(v.operation),proof=detachContract('ApprovalProof',v.approval_proof)
    const approved=tx(store=>{
      policy(store,op);const row=operationRow(store,op)
      if(row.status==='DENIED') refuse('CANCELLED','OWNER_DECLINED')
      if(row.status!=='APPROVED'||!row.approval) refuse(row.grant?'REPLAYED':'UNAUTHORIZED',row.grant?'GRANT_ALREADY_CONSUMED':'AUTHENTICATED_OWNER_APPROVAL_REQUIRED')
      approvalSession(store,row)
      if(!equal(proof,row.approval.proof)) refuse('INVALID','APPROVAL_PROOF_CHANGED')
      return structuredClone(row.approval)
    })
    const receipt=approved.receipt
    let grant
    const bindAtUse=({store})=>{
        try {
          policy(store,op);liveTarget(op);const row=operationRow(store,op)
          if(proof.operation_digest!==row.operation_digest||proof.operation_digest!==operationDigest(op)) refuse('INVALID','VERIFIED_OPERATION_DIGEST_MISMATCH')
          if(row.status==='DENIED') refuse('CANCELLED','OWNER_DECLINED')
          if(row.status!=='APPROVED'||!row.approval||!equal(row.approval.proof,proof)) refuse(row.grant?'REPLAYED':'UNAUTHORIZED','AUTHENTICATED_OWNER_APPROVAL_REQUIRED')
          approvalSession(store,row)
          if(Date.parse(proof.expiry)<=now()) refuse('EXPIRED','APPROVAL_EXPIRED')
          if(proof.material.kind==='passkey') {
            const checked=verifyWebauthnAssertion({material:proof.material,config:c.webauthn,ownerId:op.owner_id,challenge:webauthnChallenge(approvalSigningBytes(row.review.request)),checkCounter:false})
            if(checked.signed_bytes_digest!==row.approval.assertion.signed_bytes_digest) refuse('INVALID','ASSERTION_PREIMAGE_CHANGED')
          }
          grant={version:1,grant_id:'grant:'+proof.nonce,operation_id:op.operation_id,operation_digest:proof.operation_digest,owner_id:op.owner_id,audience:op.audience,authorization_epoch:op.authorization_epoch,prepared_at:iso(now()),reservation_id:'prepared:'+(receipt?.signedBytesDigest ?? sha(canonicalJson(proof)))}
          validateContract('ConsumedGrant',grant)
          row.status='PREPARED';row.grant=grant
        } catch(error) { return {decision:'DENY',reason:error.error_code??'UNAVAILABLE',detail:error.message} }
    }
    const id=pinned.get(op.owner_id)
    const args={subject:id.subject,controlDigest:id.control_digest,consumedIdsPath:c.statePath,stateRoot:c.stateRoot,witnessDirectory:c.witnessDir,Store:ConfiguredStore,beforePrepare:bindAtUse,operationDigest:operationDigest(op).slice(7)}
    let verdict
    if(proof.material.kind==='passkey') verdict=decideVerifiedPasskey({...args,proof})
    else {
      const tmp=mkdtempSync(join(dirname(c.statePath),'.prime-proof-')),path=join(tmp,'receipt.json')
      try {
        writeFileSync(path,JSON.stringify(receipt),{mode:0o600,flag:'wx'})
        verdict=decideApproval({...args,approvalPath:path,approverDid:id.approval_key_did,operationDigest:operationDigest(op).slice(7),createConsumedIds:false})
      } finally {rmSync(tmp,{recursive:true,force:true})}
    }
      if(verdict.decision!=='ALLOW') return {ok:false,error_code:['REPLAYED','EXPIRED','REVOKED','CANCELLED','TARGET_MISMATCH','INVALID','UNAUTHORIZED','UNAVAILABLE','RECONCILIATION_REQUIRED'].includes(verdict.reason)?verdict.reason:verdict.reason.includes('rollback')?'RECONCILIATION_REQUIRED':verdict.reason.includes('replay')?'REPLAYED':verdict.reason.includes('expired')?'EXPIRED':'UNAVAILABLE',reason:verdict.reason,detail:verdict.detail}
    return {ok:true,status:'PREPARED',consumed_grant:deepFreeze(grant),kernel_receipt:verdict.receiptDraft,profile:proof.material.kind+'/local-write/authorization:null'}
  }) }
  function reservedRow(store,op,grant) {
    const row=operationRow(store,op),nonce=row.approval?.proof?.nonce
    if(!equal(row.grant,grant)||grant.operation_digest!==row.operation_digest||grant.operation_digest!==operationDigest(op)||row.approval?.proof?.operation_digest!==grant.operation_digest) refuse('UNAUTHORIZED','EXACT_CONSUMED_GRANT_REQUIRED')
    const effectId=grant.reservation_id.startsWith('prepared:')?grant.reservation_id.slice(9):null
    if(!nonce||!store.currentRecord.state.consumedIds.includes('approval:'+nonce)||!store.currentRecord.prepared.some(p=>p.consumptionId==='approval:'+nonce&&p.effectId===effectId&&p.contentHash===grant.operation_digest.slice(7)&&p.receiptCountAfter<=store.currentRecord.state.receiptHead.count)) refuse('RECONCILIATION_REQUIRED','DURABLE_KERNEL_PREPARATION_REQUIRED')
    return row
  }
  function claimDispatch(input) { return attempt(()=>{
    const v=closed(input,['operation','consumed_grant','request_id','request_digest']),op=boundedOperation(v.operation),grant=detachContract('ConsumedGrant',v.consumed_grant)
    if(!UUID.test(v.request_id)||!DIGEST.test(v.request_digest)) refuse('INVALID','EXACT_EXECUTOR_REQUEST_BINDING_REQUIRED')
    return tx(store=>{
      policy(store,op);liveTarget(op);const row=reservedRow(store,op,grant)
      if(row.status!=='PREPARED'||!equal(row.grant,grant)) refuse('REPLAYED','RESERVATION_NOT_DISPATCHABLE')
      approvalSession(store,row)
      if(Date.parse(row.approval.proof.expiry)<=now()) refuse('EXPIRED','APPROVAL_EXPIRED')
      row.status='DISPATCHED';row.dispatch={request_id:v.request_id,request_digest:v.request_digest,cancel_requested:false,cancel_reason:null,receipt:null,receipt_digest:null,settlement_digests:[]};store.commitBroker()
      return {ok:true,status:'DISPATCHED',consumed_grant:deepFreeze(grant),request_id:v.request_id,request_digest:v.request_digest}
    })
  }) }
  const terminal=['COMPLETED','FAILED','CANCELLED','UNAVAILABLE']
  function dispatchedRow(store,op,grant,requestId,requestDigest) {
    const row=reservedRow(store,op,grant)
    if(!row.dispatch||row.dispatch.request_id!==requestId||(requestDigest!==undefined&&row.dispatch.request_digest!==requestDigest)) refuse('UNAUTHORIZED','DISPATCH_REQUEST_BINDING_MISMATCH')
    return row
  }
  function requestCancel(input) {return attempt(()=>{
    const v=closed(input,['operation','consumed_grant','request_id','reason']),op=boundedOperation(v.operation),grant=detachContract('ConsumedGrant',v.consumed_grant)
    if(!['caller','timeout','dispose'].includes(v.reason))refuse('INVALID','CANCELLATION_REASON')
    return tx(store=>{
      const row=dispatchedRow(store,op,grant,v.request_id)
      if(terminal.includes(row.status))return {ok:true,status:row.status,request_id:v.request_id,cancel_recorded:false}
      if(!row.dispatch.cancel_requested) {
        row.dispatch.cancel_requested=true;row.dispatch.cancel_reason=v.reason;row.status='CANCEL_REQUESTED';store.commitBroker()
      }
      return {ok:true,status:row.status,request_id:v.request_id,cancel_recorded:true}
    })
  })}
  function settleExecution(input,reconcile=false) {return attempt(()=>{
    const v=closed(input,['operation','consumed_grant','request_id','request_digest','receipt','receipt_digest']),op=boundedOperation(v.operation),grant=detachContract('ConsumedGrant',v.consumed_grant),receipt=validatedReceipt(v.receipt)
    const receiptDigest=executionReceiptDigest(receipt)
    if(receiptDigest!==v.receipt_digest)refuse('INVALID','EXECUTOR_RECEIPT_DIGEST_MISMATCH')
    return tx(store=>{
      // Factual evidence after dispatch is recorded even after owner/session/epoch
      // expiry. It cannot reauthorize, relaunch, or undo an already attempted effect.
      const row=dispatchedRow(store,op,grant,v.request_id,v.request_digest),d=row.dispatch
      for(const [field,expected] of Object.entries({operation_id:op.operation_id,task_id:op.task_id,owner_id:op.owner_id,operation_digest:grant.operation_digest,grant_id:grant.grant_id,request_id:v.request_id})) if(receipt[field]!==expected)refuse('INVALID','EXECUTOR_RECEIPT_BINDING_MISMATCH')
      if(receipt.sandbox&&op.target_identity&&typeof op.target_identity==='object') {
        for(const field of ['image_digest','policy_digest'])if(Object.hasOwn(op.target_identity,field)&&receipt.sandbox[field]!==op.target_identity[field])refuse('INVALID','EXECUTOR_SANDBOX_DIGEST_MISMATCH')
      }
      const result=idempotent=>({ok:true,status:row.status,request_id:v.request_id,request_digest:d.request_digest,receipt_digest:d.receipt_digest,idempotent,reconciliation_required:row.status==='OUTCOME_UNKNOWN'})
      if(d.settlement_digests.includes(receiptDigest))return result(true)
      if(d.receipt) {
        if(!reconcile||!['OUTCOME_UNKNOWN','CANCEL_REQUESTED'].includes(row.status))refuse('STALE','EXPLICIT_UNKNOWN_RECONCILIATION_REQUIRED')
        const old=d.receipt
        if(receipt.receipt_id!==old.receipt_id||(old.sandbox!==null&&!equal(old.sandbox,receipt.sandbox))||
           (old.exit_code!==null&&receipt.exit_code!==old.exit_code)||(old.started_at!==null&&receipt.started_at!==old.started_at)||
           (old.rpc_completion==='complete'&&receipt.rpc_completion!=='complete')||
           (['confirmed_absent','not_created'].includes(old.cleanup)&&receipt.cleanup!==old.cleanup)||
           (old.stdout!==''&&receipt.stdout!==old.stdout)||(old.stderr!==''&&receipt.stderr!==old.stderr))refuse('INVALID','CONFLICTING_RECONCILIATION_EVIDENCE')
      }
      if(d.settlement_digests.length>=32)refuse('UNAVAILABLE','SETTLEMENT_EVIDENCE_QUOTA_REACHED')
      row.status=settlementStatus(receipt,d.cancel_requested)
      d.receipt=receipt;d.receipt_digest=receiptDigest;d.settlement_digests.push(receiptDigest);store.commitBroker()
      return result(false)
    })
  })}
  const settle=input=>settleExecution(input,false)
  const reconcileSettlement=input=>settleExecution(input,true)
  function markOutcomeUnknown(input) {return attempt(()=>{
    const v=closed(input,['operation','consumed_grant','request_id','request_digest']),op=boundedOperation(v.operation),grant=detachContract('ConsumedGrant',v.consumed_grant)
    return tx(store=>{
      const row=dispatchedRow(store,op,grant,v.request_id,v.request_digest)
      if(!terminal.includes(row.status)&&row.status!=='OUTCOME_UNKNOWN'){row.status='OUTCOME_UNKNOWN';store.commitBroker()}
      return {ok:true,status:row.status,request_id:v.request_id,reconciliation_required:row.status==='OUTCOME_UNKNOWN'}
    })
  })}
  function settleMemory(input) {return attempt(()=>{
    const v=closed(input,['operation','consumed_grant','request_id','request_digest','receipt']),op=boundedOperation(v.operation),grant=detachContract('ConsumedGrant',v.consumed_grant),receipt=memoryEffectReceipt(v.receipt),receiptDigest=memoryEffectReceiptDigest(receipt)
    return tx(store=>{
      const row=dispatchedRow(store,op,grant,v.request_id,v.request_digest),d=row.dispatch
      for(const [field,expected]of Object.entries({operation_id:op.operation_id,operation_digest:grant.operation_digest,grant_id:grant.grant_id,request_id:v.request_id,request_digest:v.request_digest,owner_subject:op.target_identity?.owner_subject,action_type:op.action_type}))if(receipt[field]!==expected)refuse('INVALID','MEMORY_RECEIPT_BINDING_MISMATCH')
      if(op.target_identity?.kind!=='prime-memory'||!op.action_type.startsWith('memory.')||receipt.owner_subject!==store.broker.owners[keyOf(op.owner_id)]?.subject)refuse('INVALID','MEMORY_OWNER_TARGET_REQUIRED')
      const result=idempotent=>({ok:true,status:row.status,request_id:v.request_id,request_digest:d.request_digest,receipt_digest:d.receipt_digest,idempotent,reconciliation_required:false})
      if(d.settlement_digests.includes(receiptDigest))return result(true)
      if(d.receipt)refuse('STALE','COMMITTED_MEMORY_RECEIPT_CONFLICT')
      row.status='COMPLETED';d.receipt=receipt;d.receipt_digest=receiptDigest;d.settlement_digests.push(receiptDigest);store.commitBroker()
      return result(false)
    })
  })}
  function authenticateSession(input) {return attempt(()=>{
    const v=closed(input,['session_token'])
    return tx(store=>{
      const id=session(store,v.session_token),s=store.broker.sessions[keyOf(v.session_token)]
      return {ok:true,owner_id:id.owner_id,subject:id.subject,authorization_epoch:id.authorization_epoch,expiry:s.expiry}
    })
  })}
  function logoutSession(input) {return attempt(()=>{
    const v=closed(input,['session_token'])
    return tx(store=>{
      session(store,v.session_token)
      delete store.broker.sessions[keyOf(v.session_token)]
      store.commitBroker()
      return {ok:true,status:'LOGGED_OUT'}
    })
  })}
  function advanceAuthorizationEpoch(input) { return attempt(()=>{
    closed(input,['session_token'])
    refuse('UNAVAILABLE','EPOCH_CHANGE_AUTHENTICATION_DESIGN_UNAPPROVED')
  }) }
  function status(input) { return attempt(()=>{
    const v=closed(input,['session_token','operation_id'])
    return tx(store=>{
      const id=session(store,v.session_token),row=store.broker.operations[operationKey(id.owner_id,v.operation_id)]
      if(!row||row.operation.owner_id!==id.owner_id) refuse('UNAUTHORIZED','OWNER_OPERATION_REQUIRED')
      return {ok:true,status:row.status,operation_digest:row.operation_digest,reconciliation_required:['PREPARED','DISPATCHED','CANCEL_REQUESTED','OUTCOME_UNKNOWN'].includes(row.status)}
    })
  }) }
  return Object.freeze({propose,loginChallenge,loginComplete,authenticateSession,logoutSession,approvalChallenge,approvalComplete,declineApproval,reserve,claimDispatch,requestCancel,settle,reconcileSettlement,markOutcomeUnknown,settleMemory,advanceAuthorizationEpoch,status})
}
