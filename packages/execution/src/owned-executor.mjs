// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash, randomUUID } from 'node:crypto'
import { canonicalJson, operationDigest, validateContract } from '../../contracts/src/runtime.mjs'
import { guestEnvironment, guestPolicy, refused, validateSpec } from './policy.mjs'
import { SDK_SOURCE_COMMIT, SDK_PACKAGE_VERSION } from './sdk-transport.ts'
import { executorRequestDigest,executionReceiptDigest,requireBroker,brokerRefusal } from './binding.mjs'
import { inspectQualification } from './qualification.mjs'

const LABEL='aukora.openshell/owner'
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const DIGEST=/^sha256:[0-9a-f]{64}$/
const iso=()=>new Date().toISOString()
const hash=value=>'sha256:'+createHash('sha256').update(canonicalJson(value)).digest('hex')
const clone=value=>JSON.parse(canonicalJson(value))
function closed(value, keys) {
  if (!value || typeof value!=='object' || Array.isArray(value) || Object.keys(value).sort().join(',')!==[...keys].sort().join(',')) throw refused('closed operation parameters required','INVALID')
}
export function wirePolicy(mode) {
  const p=guestPolicy(mode)
  return { version:p.version,filesystem:{includeWorkdir:p.filesystem_policy.include_workdir,
    readOnly:p.filesystem_policy.read_only,readWrite:p.filesystem_policy.read_write},landlock:p.landlock,
    process:{runAsUser:p.process.run_as_user,runAsGroup:p.process.run_as_group},networkPolicies:{},networkMiddlewares:{} }
}
export const policyDigest=mode=>hash(wirePolicy(mode))

function snapshot(request, settings) {
  const {signal,...json}=request
  closed(json,['operation','consumed_grant','request_id','image_digest','policy_digest','wall_time_ms','max_output_bytes'])
  const r=clone(json), op=r.operation, grant=r.consumed_grant
  validateContract('OperationProposal',op); validateContract('ConsumedGrant',grant)
  const digest=operationDigest(op)
  for (const key of ['operation_id','owner_id','audience','authorization_epoch']) if(op[key]!==grant[key]) throw refused('consumed grant binding differs','UNAUTHORIZED')
  if(grant.operation_digest!==digest || !UUID.test(r.request_id) || !DIGEST.test(r.policy_digest)) throw refused('operation digest or launch fence differs','UNAUTHORIZED')
  if(op.action_type!=='shell.bash.foreground' || Date.parse(op.expiry)<=Date.now()) throw refused('wrong action or expired operation','EXPIRED')
  closed(op.target_identity,['backend','workspace','image_digest','policy_digest','logical_workspace_root'])
  const target=op.target_identity
  if(target.backend!=='openshell-linux'||target.workspace!==settings.workspace||target.image_digest!==settings.image_digest
    ||target.logical_workspace_root!==settings.logical_workspace_root||target.policy_digest!==r.policy_digest||r.image_digest!==settings.image_digest) throw refused('operation target differs from trusted host','TARGET_MISMATCH')
  closed(op.canonical_parameters,['command','workdir','sandbox_mode','stdin','env','dsh_env','timeout_ms','max_output_bytes'])
  const p=op.canonical_parameters
  const spec={command:p.command,workdir:p.workdir,stdin:p.stdin,env:p.env,dshEnv:p.dsh_env,
    timeoutMs:p.timeout_ms,stdoutMaxBytes:p.max_output_bytes,
    sandboxPolicy:{mode:p.sandbox_mode,workspaceRoot:settings.logical_workspace_root},signal}
  validateSpec(spec,{workspaceRoot:settings.logical_workspace_root})
  if(r.wall_time_ms!==spec.timeoutMs||r.max_output_bytes!==spec.stdoutMaxBytes||r.policy_digest!==policyDigest(p.sandbox_mode)) throw refused('approved execution bounds/policy differ','TARGET_MISMATCH')
  return {r,spec,env:guestEnvironment(spec),policy:wirePolicy(p.sandbox_mode),digest,signal}
}

function own(sandbox,job,settings) {
  const m=sandbox?.metadata
  if(!m||m.name!==job.name||m.workspace!==settings.workspace||!UUID.test(m.id)||m.labels?.[LABEL]!==job.token
    ||(job.id&&m.id!==job.id)) throw refused('sandbox ownership differs; refusing delete','TARGET_MISMATCH')
  job.id??=m.id
  job.receipt.sandbox={uid:job.id,name:job.name,identity:`${settings.workspace}/${job.id}`,
    image_digest:settings.image_digest,policy_digest:job.policy_digest}
}
function admitted(s,job,settings,policy,env) {
  own(s,job,settings)
  const actual=s.spec?.policy
  const normalized=actual&&{version:actual.version,filesystem:actual.filesystem&&{
    includeWorkdir:actual.filesystem.includeWorkdir,readOnly:actual.filesystem.readOnly,readWrite:actual.filesystem.readWrite},
    landlock:actual.landlock&&{compatibility:actual.landlock.compatibility},
    process:actual.process&&{runAsUser:actual.process.runAsUser,runAsGroup:actual.process.runAsGroup},
    networkPolicies:actual.networkPolicies,networkMiddlewares:actual.networkMiddlewares}
  if(s.status?.phase!==2||s.status.configurationAdmission?.state!==2||!s.status.configurationAdmission.policyHash
    ||hash(normalized)!==hash(policy)||s.spec.template?.image!==settings.image_digest||s.spec.tty!==false
    ||s.spec.providers?.length!==0||canonicalJson(s.spec.environment)!==canonicalJson(env)
    ||canonicalJson(s.spec.command)!==canonicalJson(['/bin/sleep','infinity'])) throw refused('exact guest configuration was not admitted','UNAVAILABLE')
}
function tail(text,chunk,max) {
  const data=Buffer.concat([Buffer.from(text,'base64'),Buffer.from(chunk)])
  return {data:Buffer.from(data.subarray(Math.max(0,data.length-max))).toString('base64'),truncated:data.length>max}
}

export class OpenShellOwnedExecutor {
  constructor({settings,transport,ledger,broker,qualification=null,runtimeBinding=null}) {
    closed(settings,['workspace','logical_workspace_root','image_digest','control_timeout_ms','cleanup_timeout_ms','poll_ms'])
    if(!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(settings.workspace)
      ||typeof settings.image_digest!=='string'||!/^(?:[-a-zA-Z0-9._:/]+@)?sha256:[0-9a-f]{64}$/.test(settings.image_digest)
      ||transport.sourceCommit!==SDK_SOURCE_COMMIT||transport.packageVersion!==SDK_PACKAGE_VERSION) throw refused('pinned SDK/image required','UNAVAILABLE')
    for(const key of ['control_timeout_ms','cleanup_timeout_ms','poll_ms']) if(!Number.isSafeInteger(settings[key])||settings[key]<1||settings[key]>120_000)throw refused('invalid lifecycle bound','INVALID')
    this.settings=Object.freeze(clone(settings));this.transport=transport;this.ledger=ledger
    this.broker=requireBroker(broker);this.qualification=qualification;this.runtimeBinding=runtimeBinding?Object.freeze(clone(runtimeBinding)):null;this.disposed=false;this.active=null
  }
  acceptedQualification(policy=null,bounds=null) {return this.disposed?null:inspectQualification(this.qualification,this.settings,policy,bounds,{binding:this.runtimeBinding,ledger_id:this.ledger.identity,gateway_identity:this.transport.gatewayIdentity})}
  get capability() {return this.acceptedQualification()?'qualified':'unavailable'}
  admission(request) {return !!this.acceptedQualification(request.policy_digest,request)}
  availability() {
    const record=this.acceptedQualification()
    return {backend:'openshell-linux',state:record?'qualified':'unavailable',cleanup:this.ledger.pending().length?'pending':'unprobed',
      source:'pinned_source',protocol:'unperformed',runtime:record?'accepted':'unavailable',runtimeEnforcementVerified:!!record,
      qualification_id:record?.qualification_id??null,host_profile:record?.host_profile??null,settlement:this.ledger.recovery().length?'pending':'settled'}
  }
  async brokerCall(method,input) {
    let timer
    try {return await Promise.race([Promise.resolve().then(()=>this.broker[method](clone(input))),new Promise((_,reject)=>{timer=setTimeout(()=>reject(refused('authority reply uncertain','RECONCILIATION_REQUIRED')),this.settings.control_timeout_ms)})])}
    finally {clearTimeout(timer)}
  }
  async execute(request) {
    const snap=snapshot(request,this.settings)
    if(!this.admission(snap.r))throw refused('accepted runtime evidence unavailable','UNAVAILABLE')
    const controller=new AbortController()
    return this.ledger.withLease(async()=>{
      // Recovery includes the durable C settlement outbox, even after guest absence.
      await this.reconcileLocked()
      if(this.ledger.recovery().length)throw refused('unfinished owned jobs block admission','RECONCILIATION_REQUIRED')
      if(!this.admission(snap.r))throw refused('runtime evidence revoked','UNAVAILABLE')
      snap.signal?.throwIfAborted()
      if(Date.parse(snap.r.operation.expiry)<=Date.now())throw refused('operation expired before dispatch','EXPIRED')
      const token=randomUUID(),job={token,name:`prime-bash-${token}`,id:null,
        create_request_id:randomUUID(),delete_request_id:randomUUID(),request_id:snap.r.request_id,
        reservation_id:snap.r.consumed_grant.reservation_id,request:snap.r,request_digest:executorRequestDigest(snap.r),
        claim_state:'prepared',claim_reply:null,outbox:[],cancel_state:null,
        stage:'prepared',create_confirmed:false,policy_digest:snap.r.policy_digest,workspace:this.settings.workspace,image_digest:this.settings.image_digest,
        gateway_identity:this.transport.gatewayIdentity,ledger_id:this.ledger.identity,runtime_binding:this.runtimeBinding,
        stdout_b64:'',stderr_b64:'',receipt:{version:1,receipt_id:randomUUID(),operation_id:snap.r.operation.operation_id,
          task_id:snap.r.operation.task_id,owner_id:snap.r.operation.owner_id,operation_digest:snap.digest,
          grant_id:snap.r.consumed_grant.grant_id,request_id:snap.r.request_id,status:'outcome_unknown',stdout:'',stderr:'',
          exit_code:null,rpc_completion:'not_started',output_truncated:false,sandbox:null,cleanup:'pending',
          started_at:null,finished_at:iso(),error_code:'OUTCOME_UNKNOWN',reconciliation_required:true}}
      // F's non-launch fence exists before the actual one-use durable C claim.
      this.ledger.reserve(job)
      this.active={controller,job}
      try {this.active.promise=this.run(job,snap,controller);return await this.active.promise}
      finally {this.active=null}
    })
  }
  binding(job) {return {operation:job.request.operation,consumed_grant:job.request.consumed_grant,request_id:job.request_id,request_digest:job.request_digest}}
  async claim(job) {
    job.claim_state='attempted';this.ledger.save(job)
    let reply
    try {reply=await this.brokerCall('claimDispatch',this.binding(job))}
    catch(error) {job.claim_state='unknown';this.ledger.save(job);throw error}
    if(reply?.ok===false) {job.claim_state='refused';job.claim_reply=clone(reply);this.ledger.save(job);throw brokerRefusal(reply)}
    try {
      closed(reply,['ok','status','consumed_grant','request_id','request_digest'])
      if(reply.ok!==true||reply.status!=='DISPATCHED'||reply.request_id!==job.request_id||reply.request_digest!==job.request_digest
        ||canonicalJson(reply.consumed_grant)!==canonicalJson(job.request.consumed_grant))throw refused('authority dispatch binding differs','RECONCILIATION_REQUIRED')
    } catch(error) {job.claim_state='unknown';this.ledger.save(job);throw error}
    job.claim_state='accepted';job.claim_reply=clone(reply);this.ledger.save(job)
  }
  async requestCancellation(job) {
    if(!job.cancel_cause||job.cancel_state==='recorded'||job.cancel_state==='late'||job.claim_state==='refused')return
    job.cancel_state='attempted';this.ledger.save(job)
    try {
      const {request_digest,...binding}=this.binding(job)
      const reply=await this.brokerCall('requestCancel',{...binding,reason:job.cancel_cause})
      if(reply?.ok===false)throw brokerRefusal(reply)
      closed(reply,['ok','status','request_id','cancel_recorded'])
      if(reply.ok!==true||reply.request_id!==job.request_id||typeof reply.cancel_recorded!=='boolean'
        ||!['CANCEL_REQUESTED','COMPLETED','FAILED','CANCELLED','UNAVAILABLE','OUTCOME_UNKNOWN'].includes(reply.status))throw refused('authority cancellation binding differs','RECONCILIATION_REQUIRED')
      if(reply.cancel_recorded&&reply.status!=='CANCEL_REQUESTED')throw refused('invalid cancellation intent reply','RECONCILIATION_REQUIRED')
      job.cancel_state=reply.cancel_recorded?'recorded':'late';job.cancel_reply=clone(reply)
    } catch {job.cancel_state='unknown'}
    this.ledger.save(job)
  }
  normalize(job) {
    const r=job.receipt
    r.reconciliation_required=!['not_created','confirmed_absent'].includes(r.cleanup)
    if(r.reconciliation_required) {r.status='outcome_unknown';r.error_code='RECONCILIATION_REQUIRED'}
    else if(r.rpc_completion==='complete'&&r.exit_code!==null) {r.status=r.exit_code===0?'completed':'failed';r.error_code=null}
    else if(job.cancel_state==='recorded'&&r.rpc_completion==='not_started'&&r.started_at===null&&r.exit_code===null) {r.status='cancelled';r.error_code='CANCELLED'}
    else if(job.claim_state==='refused') {r.status='unavailable';r.error_code=job.claim_reply?.error_code??'UNAVAILABLE'}
    else {r.status='outcome_unknown';r.error_code='OUTCOME_UNKNOWN';r.reconciliation_required=true}
    r.stdout=Buffer.from(job.stdout_b64,'base64').toString('utf8');r.stderr=Buffer.from(job.stderr_b64,'base64').toString('utf8')
  }
  queueSettlement(job) {
    if(job.claim_state==='refused')return
    const receipt=validateContract('ExecutionReceipt',clone(job.receipt)),receipt_digest=executionReceiptDigest(receipt)
    if(job.outbox.at(-1)?.receipt_digest===receipt_digest)return
    job.outbox.push({method:job.outbox.length?'reconcileSettlement':'settle',receipt,receipt_digest,state:'pending',reply:null})
    this.ledger.save(job)
  }
  async publish(job) {
    for(const item of job.outbox) {
      if(item.state==='acked')continue
      const reply=await this.brokerCall(item.method,{...this.binding(job),receipt:item.receipt,receipt_digest:item.receipt_digest})
      if(reply?.ok===false)throw brokerRefusal(reply)
      closed(reply,['ok','status','request_id','request_digest','receipt_digest','idempotent','reconciliation_required'])
      if(reply.ok!==true||reply.request_id!==job.request_id||reply.request_digest!==job.request_digest||reply.receipt_digest!==item.receipt_digest
        ||typeof reply.idempotent!=='boolean'||typeof reply.reconciliation_required!=='boolean'
        ||!['COMPLETED','FAILED','CANCELLED','UNAVAILABLE','OUTCOME_UNKNOWN'].includes(reply.status))throw refused('authority settlement binding differs','RECONCILIATION_REQUIRED')
      const expected=item.receipt.status.toUpperCase()
      if(reply.status!==expected||reply.reconciliation_required!==item.receipt.reconciliation_required)throw refused('authority settlement outcome differs','RECONCILIATION_REQUIRED')
      item.state='acked';item.reply=clone(reply);this.ledger.save(job)
    }
  }
  async run(job,snap,controller) {
    let timer,cancelPromise=null,dispatchError=null
    const cutShort=cause=>{
      // Drained typed command evidence outranks late cancellation intent.
      if(job.receipt.rpc_completion==='complete'||job.cancel_cause)return
      job.cancel_cause=cause;job.cancel_state='pending';this.ledger.save(job)
      if(job.claim_state==='accepted')cancelPromise=this.requestCancellation(job)
      controller.abort()
    }
    const abort=()=>cutShort('caller'),ownerAbort=()=>cutShort('dispose')
    controller.signal.addEventListener('abort',ownerAbort,{once:true});snap.signal?.addEventListener('abort',abort,{once:true})
    if(snap.signal?.aborted)abort()
    timer=setTimeout(()=>cutShort('timeout'),snap.spec.timeoutMs)
    try {
      await this.claim(job)
      if(job.cancel_cause&&!cancelPromise)cancelPromise=this.requestCancellation(job)
      if(this.disposed&&!controller.signal.aborted)cutShort('dispose')
      if(!controller.signal.aborted) {
        if(!this.admission(snap.r)||Date.parse(snap.r.operation.expiry)<=Date.now())throw refused('runtime evidence revoked or operation expired before create','UNAVAILABLE')
        job.stage='create_attempted';this.ledger.save(job)
        const created=await this.transport.create(job,this.settings,clone(snap.policy),clone(snap.env),{timeoutMs:this.settings.control_timeout_ms,signal:controller.signal})
        own(created,job,this.settings);job.create_confirmed=true;job.stage='created';this.ledger.save(job)
        const readyUntil=Date.now()+this.settings.control_timeout_ms
        while(!controller.signal.aborted) {
          const observed=await this.transport.get(job,this.settings,{timeoutMs:Math.max(1,readyUntil-Date.now()),signal:controller.signal})
          own(observed,job,this.settings)
          if(observed?.status?.phase===2){admitted(observed,job,this.settings,snap.policy,snap.env);break}
          if(Date.now()>=readyUntil||[3,4,7,9].includes(observed?.status?.phase))throw refused('sandbox failed readiness','UNAVAILABLE')
          await new Promise(r=>setTimeout(r,this.settings.poll_ms))
        }
        if(!controller.signal.aborted) {
          if(!this.admission(snap.r)||Date.parse(snap.r.operation.expiry)<=Date.now())throw refused('operation expired or runtime evidence revoked before exec','UNAVAILABLE')
          job.stage='exec_attempted';job.receipt.started_at=iso();job.receipt.rpc_completion='transport_failed';this.ledger.save(job)
          for await(const event of this.transport.execStream(job,this.settings,snap.spec,snap.env,controller.signal)) {
            if(event.type==='exit')job.receipt.exit_code=event.exitCode
            else {const field=event.stream==='stdout'?'stdout_b64':'stderr_b64',retained=tail(job[field],event.data,snap.spec.stdoutMaxBytes);job[field]=retained.data;job.receipt.output_truncated ||= retained.truncated}
            this.ledger.save(job)
          }
          if(job.receipt.exit_code===null)throw refused('typed exit missing','OUTCOME_UNKNOWN')
          job.receipt.rpc_completion='complete';job.stage='exec_drained';this.ledger.save(job)
        }
      }
    } catch(error) {dispatchError=error}
    finally {clearTimeout(timer);snap.signal?.removeEventListener('abort',abort);controller.signal.removeEventListener('abort',ownerAbort)}
    if(cancelPromise)await cancelPromise
    try {await this.cleanup(job)}catch {job.receipt.cleanup='unknown'}
    this.normalize(job);job.receipt.finished_at=iso();this.ledger.save(job)
    this.queueSettlement(job)
    try {await this.publish(job)}catch(error) {throw Object.assign(refused('durable authority settlement pending','RECONCILIATION_REQUIRED'),{cause:error,executionReceipt:clone(job.receipt)})}
    if(job.claim_state==='refused')throw Object.assign(dispatchError??refused('dispatch refused','UNAVAILABLE'),{executionReceipt:clone(job.receipt)})
    return validateContract('ExecutionReceipt',clone(job.receipt))
  }
  async find(job,deadline) {
    let token='',found=null;const seen=new Set()
    for(let page=0;page<100;page++) {
      if(Date.now()>=deadline)throw refused('cleanup deadline','RECONCILIATION_REQUIRED')
      const result=await this.transport.inventory(this.settings,token,{timeoutMs:Math.min(this.settings.control_timeout_ms,deadline-Date.now())})
      if(!Array.isArray(result.sandboxes)||typeof result.nextPageToken!=='string')throw refused('incomplete inventory','RECONCILIATION_REQUIRED')
      for(const s of result.sandboxes)if(s?.metadata?.name===job.name){if(found)throw refused('duplicate inventory identity','TARGET_MISMATCH');own(s,job,this.settings);found=s}
      token=result.nextPageToken;if(!token)return found
      if(seen.has(token))throw refused('inventory cycle','RECONCILIATION_REQUIRED');seen.add(token)
    }
    throw refused('inventory exceeds bound','RECONCILIATION_REQUIRED')
  }
  async cleanup(job) {
    if(job.workspace!==this.settings.workspace||job.image_digest!==this.settings.image_digest||job.gateway_identity!==this.transport.gatewayIdentity
      ||job.ledger_id!==this.ledger.identity||canonicalJson(job.runtime_binding)!==canonicalJson(this.runtimeBinding))throw refused('ledger deployment scope changed','TARGET_MISMATCH')
    if(['confirmed_absent','not_created'].includes(job.receipt.cleanup))return
    if(job.stage==='prepared'){job.receipt.cleanup='not_created';return}
    const deadline=Date.now()+this.settings.cleanup_timeout_ms,found=await this.find(job,deadline)
    if(found) {
      job.create_confirmed=true;this.ledger.save(job)
      own(await this.transport.get(job,this.settings,{timeoutMs:Math.max(1,deadline-Date.now())}),job,this.settings)
      job.stage='delete_attempted';this.ledger.save(job)
      const result=await this.transport.delete(job,this.settings,{timeoutMs:Math.max(1,deadline-Date.now())})
      if(![1,2,3].includes(result.outcome)||(result.sandboxId&&result.sandboxId!==job.id))throw refused('deletion identity/outcome uncertain','RECONCILIATION_REQUIRED')
      while(await this.find(job,deadline))await new Promise(r=>setTimeout(r,this.settings.poll_ms))
    }
    if(!job.create_confirmed)throw refused('late creation cannot be excluded','RECONCILIATION_REQUIRED')
    job.receipt.cleanup='confirmed_absent';job.stage='cleaned'
  }
  async reconcileLocked() {
    const receipts=[]
    for(const job of this.ledger.recovery()) {
      if(!job.request||!job.request_digest||!Array.isArray(job.outbox))throw refused('legacy/incomplete ledger requires trusted reconciliation; never reconstruct authority','RECONCILIATION_REQUIRED')
      if(executorRequestDigest(job.request)!==job.request_digest||job.request.request_id!==job.request_id)throw refused('durable request binding differs','RECONCILIATION_REQUIRED')
      const before=canonicalJson(job.receipt)
      if(job.claim_state==='prepared') {
        // The attempt checkpoint is durable before invoking C. This state is
        // proof no claim call occurred, not permission to retry or unconsume.
        job.claim_state='refused';job.claim_reply={ok:false,error_code:'UNAVAILABLE',reason:'dispatch never attempted; reservation retained'}
      }
      if(job.cancel_cause&&!['recorded','late'].includes(job.cancel_state))await this.requestCancellation(job)
      try {await this.cleanup(job)}catch {job.receipt.cleanup='unknown'}
      this.normalize(job)
      if(canonicalJson(job.receipt)!==before)job.receipt.finished_at=iso()
      this.ledger.save(job);this.queueSettlement(job)
      try {await this.publish(job)}catch(error) {throw Object.assign(refused('reconciliation settlement pending','RECONCILIATION_REQUIRED'),{cause:error,executionReceipts:[...receipts,clone(job.receipt)]})}
      receipts.push(validateContract('ExecutionReceipt',clone(job.receipt)))
    }
    return receipts
  }
  async reconcileOwned(){return this.ledger.withLease(()=>this.reconcileLocked())}
  cancellationCause(requestId){return this.ledger.lookup(requestId)?.cancel_cause??null}
  async dispose() {
    this.disposed=true
    const active=this.active
    if(active){active.controller.abort();await active.promise}
    if(this.ledger.recovery().length)throw refused('dispose left owned reconciliation pending','RECONCILIATION_REQUIRED')
  }
}
