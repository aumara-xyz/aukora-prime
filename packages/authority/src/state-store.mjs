import { createHash, randomBytes } from 'node:crypto'
import { lstatSync, openSync, closeSync, fstatSync, fsyncSync, constants as FS } from 'node:fs'
import { resolve } from 'node:path'
import { ApprovalStateStore } from '../upstream/scripts/aukora/approval-state-store.mjs'
import { TrustedStateStore, RollbackRefusedError, TrustedStoreCorruptError, TrustedStoreUnsafePathError, WriterLockedError } from '../upstream/scripts/aukora/trusted-state-store.mjs'
import { parseStrictText } from '../upstream/plugins/aukora-kira/lib/strict-read.mjs'
import { canonicalBytes } from '../upstream/vendor/authority/lib/index.js'
import {compactRetainedRows,validateRetainedRows} from './retention.mjs'
import {validateRetainedMemoryRows} from './retained-memory.mjs'
import {validatePreparationHistory} from './preparation-history.mjs'
import {validateUnconsumedClosureRows} from './unconsumed-closure.mjs'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {CLOSURE_PENDING_FILE,validateClosureProfile,closureProfileKey,closureInclusionKey,createClosurePending,
  validateClosurePending,validateWitnessInclusion,readClosurePending,writeClosurePending,
  removeClosurePending,finishClosurePendingAbsence} from './closure-retention.mjs'

export const EMPTY_KERNEL_STATE = Object.freeze({
  schema: 'aukora-trusted-state-v1', salama: { active: false, reason: null },
  trustedRoots: [], consumedIds: [], receiptHead: { count: 0, headHash: null },
})
const hash = text => createHash('sha256').update(text).digest('hex')
const fresh = store_id => ({ schema: 'prime-broker-state-v1', store_id, revision: 0, owners: {}, operations: {}, logins: {}, sessions: {} })
// Keep the donor opener guard/lock algorithm, while v2 replaces only its
// directory-opening boundary. This superclass is the original SafeOpenStore.
const safeOpen=Object.getPrototypeOf(ApprovalStateStore.prototype).open
function openExistingDirectory(store) {
  if(store.dirFd!==null) {store.assertDir();return}
  const before=lstatSync(store.dir) // Missing directories are never initialized.
  if(before.isSymbolicLink()||!before.isDirectory())throw new TrustedStoreUnsafePathError('Prime v2 requires an existing protected directory')
  const fd=openSync(store.dir,FS.O_RDONLY|(FS.O_DIRECTORY??0)|(FS.O_NOFOLLOW??0))
  try {
    const info=fstatSync(fd)
    if(!info.isDirectory()||info.dev!==before.dev||info.ino!==before.ino||
       (typeof process.getuid==='function'&&info.uid!==process.getuid())||(info.mode&0o077)!==0) {
      throw new TrustedStoreUnsafePathError('Prime v2 directory is replaced or not owner-only')
    }
    store.pinnedDev=info.dev;store.pinnedIno=info.ino;store.dirFd=fd
  } catch(error) {closeSync(fd);throw error}
}
function ancestors(path) {
  const found=[]
  let current=''
  for(const part of resolve(path).split('/').filter(Boolean)) {
    current+='/'+part
    let s
    try {s=lstatSync(current)} catch(e) {if(e.code==='ENOENT')break;throw e}
    if(s.isSymbolicLink()) throw new TrustedStoreUnsafePathError(`Prime refuses symlink ancestor: ${current}`)
    found.push([current,s.dev,s.ino])
  }
  return found
}
// Existing kernel/stores stay byte-for-byte donor code. This subclass adds a
// random persisted history identity and identity-keyed witness, never a path key.
// SAME UID CAN FORGE BOTH; no deployed process/UID containment is claimed.
export class PrimeApprovalStateStore extends ApprovalStateStore {
  constructor(options) {
    super(options)
    this.maxStateBytes=options.maxStateBytes??16*1024*1024
    this.retainedMemoryProfile=options.retainedMemoryProfile===true
    Object.defineProperty(this,'closureRetentionProfile',{value:options.closureProfile===undefined?null:validateClosureProfile(options.closureProfile),enumerable:true})
    this.closureProvisioning=options.closureProvisioning===true&&options.createConsumedIds===true
    this.closureLoadMode='normal'
    if(this.closureRetentionProfile) {
      this.bindIdentity(this.closureRetentionProfile.expected_store_id)
      // A normal v2 opener may acquire ephemeral locks, never mkdir/chmod the
      // existing state or witness directories through the donor open path.
      if(!this.closureProvisioning)this.witness.openProtectedDir=()=>openExistingDirectory(this.witness)
    }
    const assertWitness=this.witness.assertDir.bind(this.witness)
    this.witness.assertDir=()=>{this.assertAncestors();return assertWitness()}
  }
  assertAncestors() {
    const current=[...ancestors(this.dir),...ancestors(this.stateRoot),...ancestors(this.witnessDir)]
    for(const [path,dev,ino] of this.ancestorPins??[]) {
      const found=current.find(x=>x[0]===path)
      if(!found||found[1]!==dev||found[2]!==ino) throw new TrustedStoreUnsafePathError(`Prime ancestor replaced after open: ${path}`)
    }
  }
  assertWitnessOutside() {this.assertAncestors();return super.assertWitnessOutside()}
  assertDir() {this.assertAncestors();return super.assertDir()}
  openProtectedDir() {
    if(this.closureRetentionProfile&&!this.closureProvisioning)return openExistingDirectory(this)
    return super.openProtectedDir()
  }
  open() {
    if(!this.closureRetentionProfile||this.closureProvisioning)super.open()
    else {
      this.ancestorPins=[...ancestors(this.dir),...ancestors(this.stateRoot),...ancestors(this.witnessDir)]
      this.assertWitnessOutside()
      // Pin both preexisting inodes before invoking either donor lock opener.
      try {
        this.openProtectedDir();this.witness.openProtectedDir()
        this.witness.open();safeOpen.call(this)
        this.assertWitnessOutside()
        this.witnessRecord=this.readWitnessRecord()
      } catch(error) {super.close();throw error}
    }
    if(this.closureRetentionProfile)this.bindIdentity(this.closureRetentionProfile.expected_store_id)
    this.ancestorPins=[...ancestors(this.dir),...ancestors(this.stateRoot),...ancestors(this.witnessDir)]
  }
  bindIdentity(storeId) {
    if(!/^[a-f0-9]{64}$/.test(storeId??'')) throw new TrustedStoreCorruptError('Prime store_id missing or invalid; no implicit legacy migration')
    if(this.store_id&&this.store_id!==storeId) throw new RollbackRefusedError('Prime history identity changed under writer lock')
    this.store_id=storeId
    this.stateKey=hash(`aukora-prime.kernel-history.v1\0${storeId}`)
    this.brokerWitnessKey=hash(`aukora-prime.broker-history.v1\0${storeId}`)
  }
  protectedRead(fileName) {
    try {return this.readPrimeState(fileName)} catch(error) {
      if(this.closureRetentionProfile&&(error instanceof TypeError||error.name==='StrictReadRefusal')) {
        throw new TrustedStoreCorruptError('Prime v2 protected history is malformed; reconciliation required')
      }
      throw error
    }
  }
  readPrimeState(fileName) {
    this.assertAncestors()
    // v2 never accepts the donor's implicit naked-state legacy wrapper.
    const text=this.closureRetentionProfile?TrustedStateStore.prototype.protectedRead.call(this,fileName):super.protectedRead(fileName)
    if(fileName!==this.stateFile)return text
    if(text===null) {
      // A retained namespace identifies a previously provisioned history even
      // when its heads are zero. Never mint a new identity to evade those keys.
      if(Object.keys(this.witnessRecord?.heads??{}).length || this.witness.protectedRead('kernel-high-water.json')!==null) {
        throw new RollbackRefusedError('Prime state missing with retained witness namespace; restore the same history identity')
      }
      if(!this.createConsumedIds) throw new TrustedStoreCorruptError('Prime state missing; explicit new-store provisioning required')
      if(this.closureRetentionProfile&&!this.closureProvisioning)throw new RollbackRefusedError('Prime v2 missing original history; no initialization or migration')
      this.bindIdentity(this.store_id??randomBytes(32).toString('hex'))
      if(this.closureRetentionProfile&&readClosurePending(this)!==null)throw new RollbackRefusedError('Prime v2 pending history cannot be provisioned again')
      return null
    }
    const record=parseStrictText(text,this.statePath),broker=record.broker
    if(this.closureRetentionProfile&&(record?.storeSchema!==1||!broker||broker.store_id!==this.closureRetentionProfile.expected_store_id)) {
      throw new RollbackRefusedError('Prime v2 original store/profile identity mismatch; no migration or witness promotion')
    }
    // ApprovalStateStore.load may retain a higher kernel witness count. Validate
    // the complete PREPARED history before returning bytes to that donor path;
    // malformed history must not advance the retained witness before refusal.
    try {validatePreparationHistory(record)} catch {throw Object.assign(new TrustedStoreCorruptError('Prime kernel PREPARED history incomplete or incoherent; preserve history and refuse'),{error_code:'RECONCILIATION_REQUIRED',primeRefusal:true,code:'RECONCILIATION_REQUIRED'})}
    try {validateUnconsumedClosureRows(record)} catch {throw new TrustedStoreCorruptError('Prime never-consumed closure metadata incoherent; preserve history and refuse')}
    this.bindIdentity(broker?.store_id)
    if(!this.closureRetentionProfile&&(Object.hasOwn(this.witnessRecord.heads,closureProfileKey({version:2,kind:'prime-authority-closure-retention/v2',expected_store_id:this.store_id}))||
       this.witness.protectedRead(CLOSURE_PENDING_FILE)!==null)) {
      throw new RollbackRefusedError('Prime v2 retained history requires the independently configured closure profile; legacy downgrade refused')
    }
    if(this.closureRetentionProfile) {
      this.closurePending=readClosurePending(this)
      validateWitnessInclusion(this,record,{pending:this.closurePending,allowPending:this.closureLoadMode==='close'})
    }
    const hasHistory=record.state?.receiptHead?.count>0||broker?.revision>0
    if(hasHistory&&(!Object.hasOwn(this.witnessRecord.heads,this.stateKey)||!Object.hasOwn(this.witnessRecord.heads,this.brokerWitnessKey))) {
      throw new RollbackRefusedError('Prime retained history witness missing; refusing rebaseline')
    }
    return text
  }
  load(genesis = structuredClone(EMPTY_KERNEL_STATE)) {
    // TrustedStateStore.load retains the original kernel validation/high-water
    // comparison but has no ApprovalStateStore witness promotion side effect.
    const record=this.closureRetentionProfile&&!this.closureProvisioning
      ?TrustedStateStore.prototype.load.call(this,genesis):super.load(genesis)
    try {validatePreparationHistory(record)} catch {throw Object.assign(new TrustedStoreCorruptError('Prime kernel PREPARED history incomplete or incoherent; preserve history and refuse'),{error_code:'RECONCILIATION_REQUIRED',primeRefusal:true,code:'RECONCILIATION_REQUIRED'})}
    const broker=record.broker??fresh(this.store_id)
    canonicalBytes(broker)
    if(broker.schema!=='prime-broker-state-v1'||broker.store_id!==this.store_id||!Number.isSafeInteger(broker.revision)||broker.revision<0||
       Object.keys(broker).sort().join(',')!=='logins,operations,owners,revision,schema,sessions,store_id'||
       ['owners','operations','logins','sessions'].some(k=>!broker[k]||Array.isArray(broker[k])||typeof broker[k]!=='object')) {
      throw new TrustedStoreCorruptError('Prime broker metadata malformed')
    }
    const retained=this.witnessRecord.heads[this.brokerWitnessKey]??0
    if(broker.revision<retained) throw new RollbackRefusedError(`Prime broker revision ${broker.revision} below retained ${retained}`)
    try {validateRetainedRows(broker.operations);validateRetainedMemoryRows(broker.operations,{expectedAuthorityStoreId:this.store_id})} catch {throw new TrustedStoreCorruptError('Prime terminal retention metadata malformed')}
    this.broker=structuredClone(broker)
    this.currentRecord={...record,broker:this.broker}
    try {validateUnconsumedClosureRows(this.currentRecord)} catch {throw new TrustedStoreCorruptError('Prime never-consumed closure metadata incoherent; preserve history and refuse')}
    this.closurePins=Object.fromEntries(Object.entries(broker.operations).filter(([,row])=>row.status==='CLOSED_UNCONSUMED').map(([key,row])=>[key,canonicalJson(row)]))
    if(record.broker===undefined)this.commitBroker() // Setup only; normal v2 rejected missing broker above.
    else if(broker.revision>retained&&!this.closureRetentionProfile)this.retainBrokerRevision(broker.revision)
    return this.currentRecord
  }
  assertClosureMutationAllowed() {
    if(this.closureRetentionProfile&&this.closureLoadMode==='factual')throw new RollbackRefusedError('Prime v2 factual loader forbids state and witness mutation')
  }
  writeWitnessCount(count) {this.assertClosureMutationAllowed();return super.writeWitnessCount(count)}
  retainBrokerRevision(revision) {
    this.assertClosureMutationAllowed()
    const primaryKey=this.stateKey
    this.stateKey=this.brokerWitnessKey
    try {super.writeWitnessCount(revision)} finally {this.stateKey=primaryKey}
  }
  retainClosureKey(key) {
    this.assertClosureMutationAllowed()
    if(this.closureRetentionProfile&&!this.closureProvisioning&&this.closureLoadMode!=='close')throw new RollbackRefusedError('Prime v2 inclusion mutation requires explicit negative command')
    const primaryKey=this.stateKey
    this.stateKey=key
    try {super.writeWitnessCount(1)} finally {this.stateKey=primaryKey}
  }
  loadClosureForCommand(genesis) {this.closureLoadMode='close';return this.load(genesis)}
  loadClosureForRead(genesis) {this.closureLoadMode='factual';return this.load(genesis)}
  assertNoClosureRetirement() {
    if(this.closureRetentionProfile&&readClosurePending(this)!==null)throw new RollbackRefusedError('Prime v2 retirement pending; ordinary admission and preparation refused')
  }
  finishClosedRetirement(operationKey,closureRow) {
    finishClosurePendingAbsence(this,operationKey,closureRow)
  }
  retireClosure(operationKey,closureRow) {
    if(!this.closureRetentionProfile||this.closureLoadMode!=='close')throw new RollbackRefusedError('Prime v2 explicit negative command required')
    let pending=readClosurePending(this)
    if(pending===null) {
      pending=createClosurePending(this.currentRecord,this.closureRetentionProfile,operationKey,closureRow)
      writeClosurePending(this,pending) // Full exact candidate durable BEFORE broker commit.
    }
    if(pending.operation_key!==operationKey||canonicalJson(pending.closure_row)!==canonicalJson(closureRow))throw new RollbackRefusedError('Prime v2 pending reference/candidate changed')
    const candidate=validateClosurePending(pending,this.currentRecord,this.closureRetentionProfile)
    validateWitnessInclusion(this,this.currentRecord,{pending,allowPending:true})
    if(candidate.stage==='precommit') {
      this.broker.operations[operationKey]=structuredClone(pending.closure_row)
      this.primeClosingPending=pending
      try {this.commitBroker()} finally {this.primeClosingPending=null}
    } else {
      // A previous commit may have renamed the exact journal then lost the
      // directory-fsync reply. Finish that durability step without another row,
      // revision or timestamp before retaining the observed candidate.
      this.assertDir();fsyncSync(this.dirFd)
      if(this.witnessRecord.heads[this.brokerWitnessKey]!==this.broker.revision)this.retainBrokerRevision(this.broker.revision)
    }
    const inclusion=validateWitnessInclusion(this,this.currentRecord,{pending,allowPending:true})
    if(!inclusion.inclusion_retained)this.retainClosureKey(closureInclusionKey(this.closureRetentionProfile,pending.row_digest))
    const complete=validateWitnessInclusion(this,this.currentRecord,{pending,allowPending:true})
    if(!complete.inclusion_retained||!complete.counters_converged||complete.pending_stage!=='committed')throw new RollbackRefusedError('Prime v2 exact closure inclusion not converged')
    removeClosurePending(this,pending)
    this.closurePending=null
    validateWitnessInclusion(this,this.currentRecord)
    return this.broker.operations[operationKey]
  }
  commit(record) {
    this.assertClosureMutationAllowed()
    if(!this.broker||!this.brokerWitnessKey) throw new TrustedStoreCorruptError('Prime store must load before commit')
    try {validatePreparationHistory(record)} catch {throw Object.assign(new TrustedStoreCorruptError('Prime kernel PREPARED history incomplete or incoherent; preserve history and refuse'),{error_code:'RECONCILIATION_REQUIRED',primeRefusal:true,code:'RECONCILIATION_REQUIRED'})}
    let broker
    try {broker=compactRetainedRows(structuredClone(this.broker),record,{deferMemoryPayloads:this.retainedMemoryProfile,
      memorySettlementPermit:this.primeRetainedSettlement??null})} catch {throw new TrustedStoreCorruptError('Prime terminal retention evidence invalid; history preserved')}
    broker.revision+=1
    canonicalBytes(broker)
    const next={...record,broker}
    if(this.closureRetentionProfile&&!this.closureProvisioning) {
      const pending=readClosurePending(this)
      if(pending!==null) {
        if(!this.primeClosingPending||canonicalJson(pending)!==canonicalJson(this.primeClosingPending)||this.closureLoadMode!=='close')throw new RollbackRefusedError('Prime v2 pending retirement forbids ordinary commit')
        const candidate=validateClosurePending(pending,next,this.closureRetentionProfile)
        if(candidate.stage!=='committed')throw new RollbackRefusedError('Prime v2 commit must preserve exact pending candidate')
      } else {
        validateWitnessInclusion(this,this.currentRecord)
        // New closed rows cannot reach the original journal without a prior
        // durable pending candidate; existing inclusion cannot be rewritten.
        const before=Object.keys(this.closurePins??{}).sort()
        const after=Object.entries(broker.operations).filter(([,row])=>row.status==='CLOSED_UNCONSUMED').map(([key])=>key).sort()
        if(canonicalJson(before)!==canonicalJson(after))throw new RollbackRefusedError('Prime v2 closure commit requires durable pending')
      }
    }
    try {
      validateUnconsumedClosureRows(next)
      for(const [key,pin]of Object.entries(this.closurePins??{})) {
        if(!Object.hasOwn(broker.operations,key)||canonicalJson(broker.operations[key])!==pin)throw new TypeError('closed operation changed')
      }
    } catch {throw new TrustedStoreCorruptError('Prime never-consumed closure changed or conflicts with kernel preparation; preserve history and refuse')}
    if(Buffer.byteLength(JSON.stringify(next))>this.maxStateBytes) throw new TrustedStoreCorruptError('Prime durable state quota reached; preserve history and refuse admission')
    super.commit(next) // Original fsync + rename + unchanged kernel high-water durability.
    this.retainBrokerRevision(broker.revision)
    this.broker=broker;this.currentRecord=next
    this.closurePins=Object.fromEntries(Object.entries(broker.operations).filter(([,row])=>row.status==='CLOSED_UNCONSUMED').map(([key,row])=>[key,canonicalJson(row)]))
    if(this.closureRetentionProfile&&this.closureProvisioning)this.retainClosureKey(closureProfileKey(this.closureRetentionProfile))
  }
  commitBroker() {this.commit({...this.currentRecord,broker:this.broker})}
  async authorizeAndPrepareRetained(args,beforeRetainedPrepare) {
    this.assertNoClosureRetirement()
    if(typeof beforeRetainedPrepare!=='function') throw new TypeError('Prime retained preparation requires the private preparation participant')
    if(!this.locked||!this.witness.locked) throw new WriterLockedError('Prime retained preparation requires both original writer locks')
    this.assertAncestors()
    this.load(args.genesis)
    // The service validates the exact approval without mutation, then awaits the
    // private durable marker while both original store locks remain held.
    await beforeRetainedPrepare({store:this})
    if(!this.locked||!this.witness.locked) throw new WriterLockedError('Prime retained preparation lost an original writer lock')
    this.assertAncestors()
    // Intentional reload: no callback's mutable broker snapshot becomes the
    // at-use state. The existing synchronous hook and original kernel commit run
    // together only after the retained preparation participant has completed.
    return this.authorizeAndPrepare({...args,nowMs:Date.now()})
  }
  authorizeAndPrepare(args) {
    this.assertNoClosureRetirement()
    const decide=this.decide
    this.decide=(...inputs)=>{
      const refusal=this.primeBeforeKernel?.()
      if(refusal) throw Object.assign(new Error(refusal.detail),{code:refusal.reason,primeRefusal:true})
      return decide(...inputs)
    }
    try {return super.authorizeAndPrepare(args)} finally {this.decide=decide}
  }
}
