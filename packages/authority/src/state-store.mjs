import { createHash, randomBytes } from 'node:crypto'
import { lstatSync } from 'node:fs'
import { resolve } from 'node:path'
import { ApprovalStateStore } from '../upstream/scripts/aukora/approval-state-store.mjs'
import { RollbackRefusedError, TrustedStoreCorruptError, TrustedStoreUnsafePathError } from '../upstream/scripts/aukora/trusted-state-store.mjs'
import { parseStrictText } from '../upstream/plugins/aukora-kira/lib/strict-read.mjs'
import { canonicalBytes } from '../upstream/vendor/authority/lib/index.js'
import {compactRetainedRows,validateRetainedRows} from './retention.mjs'

export const EMPTY_KERNEL_STATE = Object.freeze({
  schema: 'aukora-trusted-state-v1', salama: { active: false, reason: null },
  trustedRoots: [], consumedIds: [], receiptHead: { count: 0, headHash: null },
})
const hash = text => createHash('sha256').update(text).digest('hex')
const fresh = store_id => ({ schema: 'prime-broker-state-v1', store_id, revision: 0, owners: {}, operations: {}, logins: {}, sessions: {} })
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
  open() {
    super.open()
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
    this.assertAncestors()
    const text=super.protectedRead(fileName)
    if(fileName!==this.stateFile)return text
    if(text===null) {
      // A retained namespace identifies a previously provisioned history even
      // when its heads are zero. Never mint a new identity to evade those keys.
      if(Object.keys(this.witnessRecord?.heads??{}).length || this.witness.protectedRead('kernel-high-water.json')!==null) {
        throw new RollbackRefusedError('Prime state missing with retained witness namespace; restore the same history identity')
      }
      if(!this.createConsumedIds) throw new TrustedStoreCorruptError('Prime state missing; explicit new-store provisioning required')
      this.bindIdentity(this.store_id??randomBytes(32).toString('hex'))
      return null
    }
    const record=parseStrictText(text,this.statePath),broker=record.broker
    this.bindIdentity(broker?.store_id)
    const hasHistory=record.state?.receiptHead?.count>0||broker?.revision>0
    if(hasHistory&&(!Object.hasOwn(this.witnessRecord.heads,this.stateKey)||!Object.hasOwn(this.witnessRecord.heads,this.brokerWitnessKey))) {
      throw new RollbackRefusedError('Prime retained history witness missing; refusing rebaseline')
    }
    return text
  }
  load(genesis = structuredClone(EMPTY_KERNEL_STATE)) {
    const record=super.load(genesis)
    const broker=record.broker??fresh(this.store_id)
    canonicalBytes(broker)
    if(broker.schema!=='prime-broker-state-v1'||broker.store_id!==this.store_id||!Number.isSafeInteger(broker.revision)||broker.revision<0||
       Object.keys(broker).sort().join(',')!=='logins,operations,owners,revision,schema,sessions,store_id'||
       ['owners','operations','logins','sessions'].some(k=>!broker[k]||Array.isArray(broker[k])||typeof broker[k]!=='object')) {
      throw new TrustedStoreCorruptError('Prime broker metadata malformed')
    }
    const retained=this.witnessRecord.heads[this.brokerWitnessKey]??0
    if(broker.revision<retained) throw new RollbackRefusedError(`Prime broker revision ${broker.revision} below retained ${retained}`)
    try {validateRetainedRows(broker.operations)} catch {throw new TrustedStoreCorruptError('Prime terminal retention metadata malformed')}
    this.broker=structuredClone(broker)
    this.currentRecord={...record,broker:this.broker}
    if(record.broker===undefined) this.commitBroker() // Persist NEW identity before any successful API result.
    else if(broker.revision>retained) this.retainBrokerRevision(broker.revision)
    return this.currentRecord
  }
  retainBrokerRevision(revision) {
    const primaryKey=this.stateKey
    this.stateKey=this.brokerWitnessKey
    try {super.writeWitnessCount(revision)} finally {this.stateKey=primaryKey}
  }
  commit(record) {
    if(!this.broker||!this.brokerWitnessKey) throw new TrustedStoreCorruptError('Prime store must load before commit')
    let broker
    try {broker=compactRetainedRows(structuredClone(this.broker),record)} catch {throw new TrustedStoreCorruptError('Prime terminal retention evidence invalid; history preserved')}
    broker.revision+=1
    canonicalBytes(broker)
    const next={...record,broker}
    if(Buffer.byteLength(JSON.stringify(next))>this.maxStateBytes) throw new TrustedStoreCorruptError('Prime durable state quota reached; preserve history and refuse admission')
    super.commit(next) // Original fsync + rename + unchanged kernel high-water durability.
    this.retainBrokerRevision(broker.revision)
    this.broker=broker;this.currentRecord=next
  }
  commitBroker() {this.commit({...this.currentRecord,broker:this.broker})}
  authorizeAndPrepare(args) {
    const decide=this.decide
    this.decide=(...inputs)=>{
      const refusal=this.primeBeforeKernel?.()
      if(refusal) throw Object.assign(new Error(refusal.detail),{code:refusal.reason,primeRefusal:true})
      return decide(...inputs)
    }
    try {return super.authorizeAndPrepare(args)} finally {this.decide=decide}
  }
}
