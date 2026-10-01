import { createHash } from 'node:crypto'
import { ApprovalStateStore } from '../upstream/scripts/aukora/approval-state-store.mjs'
import { RollbackRefusedError, TrustedStoreCorruptError } from '../upstream/scripts/aukora/trusted-state-store.mjs'
import { canonicalBytes } from '../upstream/vendor/authority/lib/index.js'

export const EMPTY_KERNEL_STATE = Object.freeze({
  schema: 'aukora-trusted-state-v1', salama: { active: false, reason: null },
  trustedRoots: [], consumedIds: [], receiptHead: { count: 0, headHash: null },
})
const fresh = () => ({ schema: 'prime-broker-state-v1', revision: 0, owners: {}, operations: {}, logins: {}, sessions: {} })

// Extends the copied store; kernel consumed IDs and broker lifecycle share its atomic journal.
// The second retained counter covers denial, owner epoch and session changes too. It is
// outside stateRoot, but SAME UID CAN REWRITE BOTH. This does not claim deployment isolation.
export class PrimeApprovalStateStore extends ApprovalStateStore {
  load(genesis = structuredClone(EMPTY_KERNEL_STATE)) {
    const record = super.load(genesis)
    if (record.broker === undefined && record.state.receiptHead.count !== 0) {
      throw new TrustedStoreCorruptError('Prime broker metadata missing; no legacy authority migration')
    }
    const broker = record.broker ?? fresh()
    canonicalBytes(broker) // parsed JSON must also satisfy kernel canonical value rules
    if (broker.schema !== 'prime-broker-state-v1' || !Number.isSafeInteger(broker.revision) || broker.revision < 0 ||
        Object.keys(broker).sort().join(',') !== 'logins,operations,owners,revision,schema,sessions' ||
        ['owners', 'operations', 'logins', 'sessions'].some(k => !broker[k] || Array.isArray(broker[k]) || typeof broker[k] !== 'object')) {
      throw new TrustedStoreCorruptError('Prime broker metadata malformed')
    }
    this.brokerWitnessKey = createHash('sha256').update(`${this.stateKey}:prime-broker-v1`).digest('hex')
    const retained = this.witnessRecord.heads[this.brokerWitnessKey] ?? 0
    if (broker.revision < retained) throw new RollbackRefusedError(`Prime broker revision ${broker.revision} below retained ${retained}`)
    this.broker = structuredClone(broker)
    this.currentRecord = { ...record, broker: this.broker }
    // A durable state newer than witness can result from interrupted commit; retaining it
    // fences retries. It never resurrects an earlier operation or resets the witness.
    if (broker.revision > retained) this.retainBrokerRevision(broker.revision)
    return this.currentRecord
  }

  retainBrokerRevision(revision) {
    const primaryKey = this.stateKey
    this.stateKey = this.brokerWitnessKey
    try { super.writeWitnessCount(revision) } finally { this.stateKey = primaryKey }
  }

  commit(record) {
    if (!this.broker || !this.brokerWitnessKey) throw new TrustedStoreCorruptError('Prime store must load before commit')
    const broker = structuredClone(this.broker)
    broker.revision += 1
    canonicalBytes(broker)
    const next = { ...record, broker }
    super.commit(next) // copied fsync + rename + kernel high-water durability
    this.retainBrokerRevision(broker.revision) // required before success, including revocation
    this.broker = broker
    this.currentRecord = next
  }

  commitBroker() { this.commit({ ...this.currentRecord, broker: this.broker }) }

  authorizeAndPrepare(args) {
    const decide = this.decide
    this.decide = (...inputs) => {
      // The copied transaction has loaded current metadata under its writer lock.
      const refusal = this.primeBeforeKernel?.()
      if (refusal) throw Object.assign(new Error(refusal.detail), { code: refusal.reason, primeRefusal: true })
      return decide(...inputs)
    }
    try { return super.authorizeAndPrepare(args) } finally { this.decide = decide }
  }
}
