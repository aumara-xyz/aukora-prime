#!/usr/bin/env node
/**
 * Disposable, synthetic admission/provisioning regressions. No installed application,
 * network, executor, database, or real enrollment is touched. Consumed history is
 * obtained only through signed login/review/reserve/dispatch/settlement calls.
 */
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'
import { canonicalJson } from '../contracts/src/runtime.mjs'
import { createAuthorityService, provisionNewAuthorityStore, loginSigningBytes, approvalSigningBytes, operationDigest, memoryResultDigest, memoryEffectReceiptDigest } from './src/index.mjs'
import { PrimeApprovalStateStore } from './src/state-store.mjs'
import { didKeyFromEd25519PublicKey } from './upstream/plugins/aukora-aumlok/lib/did-key.mjs'

const SELF = fileURLToPath(import.meta.url)
const PACKAGE = dirname(SELF)
const digest = (domain, value) => 'sha256:' + createHash('sha256').update(domain + '\0' + canonicalJson(value)).digest('hex')
const oldTime = '2000-01-01T00:00:00.000Z'
class AdmissionCheckError extends Error {
  constructor(check, observed) { super(check); this.name = 'AdmissionCheckError'; this.check = check; this.observed = observed }
}

function harness(root) {
  let checks = 0
  const check = (condition, name, observed) => {
    if (!condition) throw new AdmissionCheckError(name, observed)
    checks++
  }
  const ok = (result, name = 'SYNTHETIC_CALL_ACCEPTED') => { check(result.ok === true, name, result); return result }
  const no = (result, code, name = 'SYNTHETIC_CALL_REFUSED') => {
    check(result.ok === false && (!code || result.error_code === code), name, result)
    return result
  }
  const owners = [1, 2, 3].map(n => {
    const key = generateKeyPairSync('ed25519')
    const raw = Buffer.from(key.publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex')
    const identity = { owner_id: `synthetic-owner-${n}`, subject: 'aukora:1:' + String(n).repeat(64), approval_key_did: didKeyFromEd25519PublicKey(raw), control_digest: String(n + 3).repeat(64), authorization_epoch: 0 }
    return { identity, key }
  })
  const trustedTask = owner_id => ({ authenticated: true, task: { version: 1, task_id: 'synthetic-task', owner_id, agent_id: 'synthetic-agent', conversation_id: 'synthetic-conversation', status: 'running', created_at: new Date().toISOString(), route_id: null, allowed_data_classes: ['public'], max_input_tokens: 0, max_output_tokens: 0, max_requests: 0, task_spend_ceiling: { currency: 'USD', amount: '0' } } })
  function fixture(name, extra = {}, provision = true) {
    const dir = join(root, name)
    mkdirSync(dir, { mode: 0o700 })
    mkdirSync(join(dir, 'state'), { mode: 0o700 })
    const config = {
      statePath: join(dir, 'state', 'authority.json'), stateRoot: join(dir, 'state'), witnessDir: join(dir, 'witness'),
      audience: 'prime:admission-test', identities: owners.map(x => x.identity), loginKinds: ['owner_key'],
      policy: { version: 'synthetic-policy-1', actions: ['memory.save'], agents: ['synthetic-agent'], data_scope: ['public'], maximum_cost: { currency: 'USD', amount: '0' } },
      provisionTrustedState: true, authorizeTask: op => trustedTask(op.owner_id),
      observeTarget: op => ({ target_identity: op.target_identity, state_version: 'synthetic-r1' }), ...extra,
    }
    if (provision) ok(provisionNewAuthorityStore(config), 'EXPLICIT_NEW_STORE_PROVISIONED')
    return { config, service: createAuthorityService(config) }
  }
  function operation(name, owner = owners[0], extra = {}) {
    return { version: 1, operation_id: name, task_id: 'synthetic-task', owner_id: owner.identity.owner_id, agent_id: 'synthetic-agent', audience: 'prime:admission-test', action_type: 'memory.save', target_identity: { kind: 'prime-memory', owner_subject: owner.identity.subject }, canonical_parameters: { content: 'Public synthetic admission fixture' }, data_scope: ['public'], expected_state_version: 'synthetic-r1', provider_and_region: { provider: 'none', region: 'local' }, maximum_cost: { currency: 'USD', amount: '0' }, expiry: new Date(Date.now() + 30 * 60 * 1000).toISOString(), nonce: randomBytes(32).toString('hex'), policy_version: 'synthetic-policy-1', authorization_epoch: 0, ...extra }
  }
  function loginSession(service, owner = owners[0]) {
    const challenge = ok(service.loginChallenge({ owner_id: owner.identity.owner_id, kind: 'owner_key' })).challenge
    return ok(service.loginComplete({ challenge, material: { kind: 'owner_key', signature: sign(null, loginSigningBytes(challenge), owner.key.privateKey).toString('hex') } }))
  }
  function login(service, owner = owners[0]) {
    return loginSession(service, owner).session_token
  }
  function renewableLogin(service, owner = owners[0]) {
    let current, logins = 0
    return {
      token() {
        // Refresh before a cycle when the session has a minute left under load.
        // Use signed login calls; production TTL and quotas still apply.
        if (!current || Date.parse(current.expiry) - Date.now() <= 60000) {
          current = loginSession(service, owner)
          logins++
        }
        return current.session_token
      },
      get expiry() { return current?.expiry },
      get logins() { return logins },
    }
  }
  function approve(service, token, op, owner = owners[0]) {
    const review = ok(service.approvalChallenge({ session_token: token, operation: op }))
    const proof = { ...review.proof_template, material: { kind: 'owner_key', request: review.approval_request, signature: sign(null, approvalSigningBytes(review.approval_request), owner.key.privateKey).toString('hex') } }
    ok(service.approvalComplete({ session_token: token, proof }))
    return proof
  }
  function prepared(f, token, op, owner = owners[0]) {
    ok(f.service.propose({ session_token: token, operation: op }))
    const proof = approve(f.service, token, op, owner)
    const grant = ok(f.service.reserve({ operation: op, approval_proof: proof })).consumed_grant
    check(read(f).state.consumedIds.includes('approval:' + proof.nonce), 'REAL_KERNEL_APPROVAL_CONSUMED')
    return { op, proof, grant }
  }
  function binding(value) {
    // D's exact memory request shape/domain; request_id is a separate dispatch ID.
    const request = Object.freeze({ version: 1, action_type: value.op.action_type, owner_subject: value.op.target_identity.owner_subject, operation_id: value.op.operation_id, operation_digest: operationDigest(value.op), parameters: value.op.canonical_parameters })
    return { operation: value.op, consumed_grant: value.grant, request_id: randomUUID(), request_digest: digest('aukora-prime.memory.effect.v1', request) }
  }
  function receipt(b, result) {
    return { version: 1, kind: 'prime-memory-effect/v1', operation_id: b.operation.operation_id, operation_digest: operationDigest(b.operation), grant_id: b.consumed_grant.grant_id, request_id: b.request_id, request_digest: b.request_digest, owner_subject: b.operation.target_identity.owner_subject, action_type: b.operation.action_type, status: 'applied', result_digest: memoryResultDigest(result), result }
  }
  const read = f => JSON.parse(readFileSync(f.config.statePath, 'utf8'))
  const rows = f => Object.values(read(f).broker.operations)
  const witnessPath = f => join(f.config.witnessDir, 'kernel-high-water.json')
  function unchanged(f, body, name) {
    const state = readFileSync(f.config.statePath), witness = readFileSync(witnessPath(f))
    const result = body()
    check(readFileSync(f.config.statePath).equals(state), name + '_STATE_BYTES_UNCHANGED')
    check(readFileSync(witnessPath(f)).equals(witness), name + '_WITNESS_BYTES_UNCHANGED')
    return result
  }
  function editBroker(f, body) {
    const store = new PrimeApprovalStateStore({ statePath: f.config.statePath, stateRoot: f.config.stateRoot, witnessDir: f.config.witnessDir })
    try { store.open(); store.load(); body(store); store.commitBroker() } finally { store.close() }
  }
  return { check, ok, no, owners, trustedTask, fixture, operation, login, renewableLogin, approve, prepared, binding, receipt, read, rows, witnessPath, unchanged, editBroker, get checks() { return checks } }
}

async function probe(scenario) {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'prime-admission-probe-'))
  const h = harness(root)
  try {
    if (scenario === 'proposal-session') {
      const f = h.fixture('proposal-session')
      h.unchanged(f, () => h.no(f.service.propose({ session_token: '0'.repeat(64), operation: h.operation('unowned') }), 'UNAUTHORIZED', 'PROPOSE_INVALID_SESSION_REFUSED'), 'PROPOSE_INVALID_SESSION')
    } else if (scenario === 'retained-zero-witness') {
      const f = h.fixture('retained-zero', {}, false)
      mkdirSync(f.config.witnessDir, { mode: 0o700 })
      const bytes = Buffer.from(JSON.stringify({ schema: 1, heads: { ['7'.repeat(64)]: 0 } }))
      writeFileSync(h.witnessPath(f), bytes, { mode: 0o600 })
      h.no(provisionNewAuthorityStore(f.config), 'RECONCILIATION_REQUIRED', 'PROVISION_ZERO_WITNESS_REFUSED')
      h.check(!existsSync(f.config.statePath), 'PROVISION_ZERO_WITNESS_STORE_ABSENT')
      h.check(readFileSync(h.witnessPath(f)).equals(bytes), 'PROVISION_ZERO_WITNESS_BYTES_UNCHANGED')
    } else if (scenario === 'session-renewal') {
      const realNow = Date.now
      let stamp = realNow()
      Date.now = () => stamp
      try {
        const f = h.fixture('session-renewal'), session = h.renewableLogin(f.service)
        const first = session.token(), expiry = Date.parse(session.expiry)
        h.check(expiry === stamp + 300000, 'RENEWAL_DEFAULT_SESSION_TTL_FIVE_MINUTES')
        h.check(session.token() === first && session.logins === 1, 'RENEWAL_VALID_SESSION_REUSED')
        const completeCycle = name => {
          const p = h.prepared(f, session.token(), h.operation(name)), b = h.binding(p)
          h.ok(f.service.claimDispatch(b))
          h.check(h.ok(f.service.settleMemory({ ...b, receipt: h.receipt(b, { storage_status: 'saved', revision: name }) })).status === 'COMPLETED', 'RENEWAL_SIGNED_SAVE_CYCLE_COMPLETED')
        }
        completeCycle('before-renewal')
        stamp = expiry - 60000
        const renewed = session.token()
        h.check(renewed !== first && session.logins === 2, 'RENEWAL_BEFORE_SESSION_BOUNDARY_SIGNED_IN')
        stamp = Date.parse(session.expiry) + 1
        h.unchanged(f, () => h.no(f.service.authenticateSession({ session_token: renewed }), 'UNAUTHORIZED', 'RENEWAL_EXPIRED_SESSION_REFUSED'), 'RENEWAL_EXPIRED_SESSION')
        completeCycle('after-session-expiry')
        h.check(session.token() !== renewed && session.logins === 3, 'RENEWAL_EXPIRED_SESSION_SIGNED_IN')
        const state = h.read(f)
        h.check(h.rows(f).length === 2 && h.rows(f).every(row => row.status === 'COMPLETED') && state.state.consumedIds.length === 2 && state.prepared.length === 2 && state.state.receiptHead.count === 2, 'RENEWAL_RETAINS_BOTH_REAL_CONSUMED_CYCLES')
      } finally { Date.now = realNow }
    } else throw new Error('Unknown admission probe: ' + scenario)
    return { status: 'PASS', scenario, checks: h.checks }
  } finally { rmSync(root, { recursive: true, force: true }) }
}

function runChild(file, scenario) {
  return new Promise((resolveChild, reject) => {
    const child = spawn(process.execPath, [file, 'admission-probe', scenario], { stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = '', stderr = ''
    child.stdout.on('data', bytes => { stdout += bytes })
    child.stderr.on('data', bytes => { stderr += bytes })
    child.on('error', reject)
    child.on('close', code => {
      let report
      try { report = JSON.parse(stdout.trim()) } catch { /* Import/process failures cannot kill a guard mutant. */ }
      resolveChild({ code, report, stdout, stderr })
    })
  })
}

async function mutations(root, h) {
  const cases = [
    { name: 'proposal-session', file: 'service.mjs', before: '      const id=session(store,v.session_token)\n      if(id.owner_id!==op.owner_id) refuse(\'UNAUTHORIZED\',\'CROSS_OWNER_PROPOSAL\')', after: '      const id=owner(store,op.owner_id)\n      if(id.owner_id!==op.owner_id) refuse(\'UNAUTHORIZED\',\'CROSS_OWNER_PROPOSAL\')', failure: 'PROPOSE_INVALID_SESSION_REFUSED' },
    { name: 'retained-zero-witness', file: 'state-store.mjs', before: "Object.keys(this.witnessRecord?.heads??{}).length || this.witness.protectedRead('kernel-high-water.json')!==null", after: 'Object.values(this.witnessRecord?.heads??{}).some(count=>count>0)', failure: 'PROVISION_ZERO_WITNESS_REFUSED' },
  ]
  for (const c of cases) {
    const baseline = await runChild(SELF, c.name)
    h.check(baseline.code === 0 && baseline.report?.status === 'PASS', 'MUTATION_BASELINE_' + c.name, baseline)
    const packageDir = join(root, 'mutant-' + c.name, 'packages', 'authority')
    cpSync(PACKAGE, packageDir, { recursive: true })
    cpSync(join(PACKAGE, '..', 'contracts'), join(dirname(packageDir), 'contracts'), { recursive: true })
    const path = join(packageDir, 'src', c.file), source = readFileSync(path, 'utf8')
    h.check(source.split(c.before).length === 2, 'MUTATION_EXACT_TARGET_' + c.name)
    writeFileSync(path, source.replace(c.before, c.after))
    const mutant = await runChild(join(packageDir, 'check-admission.mjs'), c.name)
    h.check(mutant.code !== 0 && mutant.report?.status === 'FAIL' && mutant.report.check === c.failure, 'MUTATION_SPECIFIC_GUARD_CAUGHT_' + c.name, mutant)
  }
  return cases.map(c => ({ guard: c.name, outcome: 'CAUGHT', check: c.failure }))
}

export async function runAdmissionChecks() {
  const start = performance.now()
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'prime-admission-fixture-'))
  const h = harness(root)
  const groups = []
  try {
    const f = h.fixture('proposal-auth'), token = h.login(f.service), op = h.operation('valid-proposal')
    for (const [name, input, code] of [
      ['RAW_PROPOSAL', h.operation('raw'), 'INVALID'],
      ['MISSING_SESSION', { operation: h.operation('missing-session') }, 'INVALID'],
      ['INVALID_SESSION', { session_token: '0'.repeat(64), operation: h.operation('invalid-session') }, 'UNAUTHORIZED'],
      ['MALFORMED_SESSION', { session_token: 'bad', operation: h.operation('malformed-session') }, 'UNAUTHORIZED'],
      ['CROSS_OWNER', { session_token: token, operation: h.operation('cross-owner', h.owners[1]) }, 'UNAUTHORIZED'],
    ]) h.unchanged(f, () => h.no(f.service.propose(input), code, name + '_REFUSED'), name)
    for (const [name, authorizeTask] of [
      ['TASK_UNAUTHENTICATED', x => ({ ...h.trustedTask(x.owner_id), authenticated: false })],
      ['TASK_WRONG_OWNER', () => h.trustedTask(h.owners[1].identity.owner_id)],
      ['TASK_WRONG_ID', x => ({ authenticated: true, task: { ...h.trustedTask(x.owner_id).task, task_id: 'another-task' } })],
    ]) {
      const s = createAuthorityService({ ...f.config, authorizeTask })
      h.unchanged(f, () => h.no(s.propose({ session_token: token, operation: h.operation(name) }), 'UNAUTHORIZED', name + '_REFUSED'), name)
    }
    h.ok(f.service.propose({ session_token: token, operation: op }))
    h.check(h.rows(f).length === 1, 'ONLY_AUTHENTICATED_PROPOSAL_RETAINED')
    groups.push('authenticated admission refuses raw, missing/invalid session, cross-owner and unauthenticated/wrong owned task without writes')

    const quota = h.fixture('pending-default-quota'), qt = h.owners.map(owner => h.login(quota.service, owner))
    const firstProposalStart = Date.now()
    h.ok(quota.service.propose({ session_token: qt[0], operation: h.operation('owner-a-0') }))
    const firstProposalFinish = Date.now()
    for (let n = 1; n < 128; n++) h.ok(quota.service.propose({ session_token: qt[0], operation: h.operation('owner-a-' + n) }))
    const first = h.rows(quota)[0]
    h.check(Date.parse(first.pending_until) >= firstProposalStart + 300000 && Date.parse(first.pending_until) <= firstProposalFinish + 300000, 'DEFAULT_PENDING_TTL_FIVE_MINUTES')
    h.approve(quota.service, qt[0], first.operation)
    const refuseQuota = (token, op, name) => h.unchanged(quota, () => {
      const result = h.no(quota.service.propose({ session_token: token, operation: op }), 'UNAVAILABLE', name)
      h.check(result.reason === 'PENDING_OPERATION_QUOTA_REACHED', name + '_REASON', result)
    }, name)
    refuseQuota(qt[0], h.operation('owner-a-overflow'), 'OWNER_PENDING_DEFAULT_128_REFUSED')
    for (let n = 0; n < 128; n++) h.ok(quota.service.propose({ session_token: qt[1], operation: h.operation('owner-b-' + n, h.owners[1]) }))
    refuseQuota(qt[2], h.operation('total-overflow', h.owners[2]), 'TOTAL_PENDING_DEFAULT_256_REFUSED')
    h.check(h.rows(quota).length === 256 && h.rows(quota).filter(x => x.status === 'APPROVED').length === 1, 'PROPOSED_AND_APPROVED_COUNT_TOWARD_PENDING_QUOTA')
    // Expiration is fixture metadata committed through the real store. No kernel
    // preparation, consumed ID, or grant is injected by these pruning fixtures.
    h.editBroker(quota, store => { for (const row of Object.values(store.broker.operations)) row.pending_until = oldTime })
    h.ok(quota.service.propose({ session_token: qt[0], operation: h.operation('after-pending-prune') }))
    h.check(h.rows(quota).length === 1, 'EXPIRED_UNCONSUMED_PROPOSED_AND_APPROVED_PRUNED')
    const expired = h.rows(quota)[0].operation
    h.editBroker(quota, store => { const row = Object.values(store.broker.operations)[0]; row.operation.expiry = oldTime; row.pending_until = '2099-01-01T00:00:00.000Z' })
    h.ok(quota.service.propose({ session_token: qt[0], operation: h.operation('after-operation-expiry') }))
    h.check(h.rows(quota).length === 1 && h.rows(quota)[0].operation.operation_id !== expired.operation_id, 'OPERATION_EXPIRY_PRUNES_WITH_FUTURE_PENDING_TTL')
    groups.push('default active quotas 128 per owner/256 total; approved rows count; expired unconsumed proposals and approvals prune')

    const denied = h.fixture('denied-default-quota'), dt = h.owners.map(owner => h.login(denied.service, owner))
    for (let ownerIndex = 0; ownerIndex < 3; ownerIndex++) {
      for (let n = 0; n < 40; n++) {
        const dop = h.operation('deny-' + ownerIndex + '-' + n, h.owners[ownerIndex])
        h.ok(denied.service.propose({ session_token: dt[ownerIndex], operation: dop }))
        h.ok(denied.service.declineApproval({ session_token: dt[ownerIndex], operation_id: dop.operation_id }))
        const dr = h.rows(denied)
        h.check(dr.length <= 64 && h.owners.every(owner => dr.filter(x => x.operation.owner_id === owner.identity.owner_id).length <= 32), 'DENIED_DEFAULT_OWNER_32_TOTAL_64_BOUNDED')
      }
    }
    h.check(h.rows(denied).length === 64, 'DENIED_HISTORY_REACHES_BOUNDED_TOTAL')
    h.editBroker(denied, store => { for (const row of Object.values(store.broker.operations)) row.pending_until = oldTime })
    h.ok(denied.service.propose({ session_token: dt[0], operation: h.operation('after-denied-expiry') }))
    h.check(h.rows(denied).length === 1, 'EXPIRED_UNCONSUMED_DENIED_PRUNED')
    groups.push('denied rows bounded at 32 per owner/64 total and expired denied rows prune')

    const lifecycle = h.fixture('completed-save-lifecycles'), lt = h.renewableLogin(lifecycle.service)
    for (let n = 0; n < 265; n++) {
      const p = h.prepared(lifecycle, lt.token(), h.operation('completed-save-' + n)), b = h.binding(p)
      h.ok(lifecycle.service.claimDispatch(b))
      const result = { storage_status: 'saved', revision: 'synthetic-r' + (n + 2), public_fixture: true }
      const mr = h.receipt(b, result), settled = h.ok(lifecycle.service.settleMemory({ ...b, receipt: mr }))
      h.check(settled.status === 'COMPLETED' && settled.receipt_digest === digest('aukora-prime.memory-receipt.v1', mr), 'NORMAL_SAVE_SETTLES_EXACT_MEMORY_RECEIPT')
      h.check(mr.result_digest === digest('aukora-prime.memory-result.v1', result), 'EXACT_MEMORY_RESULT_DOMAIN')
      if (n === 0) {
        h.check(memoryEffectReceiptDigest(mr) === settled.receipt_digest, 'EXACT_MEMORY_RECEIPT_DOMAIN')
        h.unchanged(lifecycle, () => h.no(lifecycle.service.settleMemory({ ...b, receipt: { ...mr, request_digest: 'sha256:' + '0'.repeat(64) } }), 'INVALID'), 'WRONG_MEMORY_REQUEST_BINDING')
        h.unchanged(lifecycle, () => h.no(lifecycle.service.settleMemory({ ...b, receipt: { ...mr, result_digest: 'sha256:' + '0'.repeat(64) } }), 'INVALID'), 'WRONG_MEMORY_RESULT_DIGEST')
        h.check(h.ok(lifecycle.service.settleMemory({ ...b, receipt: mr })).idempotent === true, 'MEMORY_SETTLEMENT_IDEMPOTENT')
      }
    }
    const complete = h.read(lifecycle)
    h.check(Object.values(complete.broker.operations).length === 265 && Object.values(complete.broker.operations).every(row => row.status === 'COMPLETED'), 'MORE_THAN_128_OWNER_AND_256_TOTAL_COMPLETED_LIFECYCLES')
    h.check(complete.state.consumedIds.length === 265 && new Set(complete.state.consumedIds).size === 265 && complete.prepared.length === 265 && complete.state.receiptHead.count === 265, 'ALL_265_CONSUMPTIONS_PREPARATIONS_AND_KERNEL_RECEIPTS_RETAINED')
    groups.push('265 same-owner signed login/review/reserve/dispatch/memory settlement lifecycles retain all consumed history beyond both pending limits')

    const preserve = h.fixture('preserve-consumed'), pt = h.login(preserve.service)
    const pop = h.operation('preserve-prepared', h.owners[0], { expiry: new Date(Date.now() + 15000).toISOString() })
    const uop = h.operation('preserve-unknown', h.owners[0], { expiry: pop.expiry })
    const prep = h.prepared(preserve, pt, pop), unknown = h.prepared(preserve, pt, uop), ub = h.binding(unknown)
    h.ok(preserve.service.claimDispatch(ub)); h.ok(preserve.service.markOutcomeUnknown(ub))
    const before = h.read(preserve)
    await new Promise(resolveWait => setTimeout(resolveWait, Math.max(0, Date.parse(pop.expiry) - Date.now() + 40)))
    h.ok(preserve.service.propose({ session_token: pt, operation: h.operation('prune-after-consumed-expiry') }))
    const after = h.read(preserve), retained = Object.values(after.broker.operations)
    h.check(retained.some(row => row.status === 'PREPARED' && row.operation.operation_id === pop.operation_id) && retained.some(row => row.status === 'OUTCOME_UNKNOWN' && row.operation.operation_id === uop.operation_id), 'EXPIRED_CONSUMED_PREPARED_AND_UNKNOWN_RETAINED')
    h.check(canonicalJson(after.state.consumedIds) === canonicalJson(before.state.consumedIds) && canonicalJson(after.prepared) === canonicalJson(before.prepared) && canonicalJson(after.state.receiptHead) === canonicalJson(before.state.receiptHead), 'EXPIRY_PRUNE_PRESERVES_KERNEL_CONSUMPTIONS_PREPARED_AND_RECEIPT_HEAD')
    h.unchanged(preserve, () => h.no(preserve.service.reserve({ operation: prep.op, approval_proof: prep.proof }), 'EXPIRED'), 'EXPIRED_PREPARED_NO_REAUTHORIZATION')
    const factual = h.ok(preserve.service.settleMemory({ ...ub, receipt: h.receipt(ub, { storage_status: 'saved', revision: 'synthetic-after-expiry' }) }))
    h.check(factual.status === 'COMPLETED', 'UNKNOWN_FACTUAL_SETTLEMENT_ACCEPTED_AFTER_EXPIRY')
    groups.push('real consumed PREPARED and OUTCOME_UNKNOWN obligations survive expiry and pruning; factual unknown settlement still records')

    const absent = h.fixture('never-auto-provision', {}, false)
    h.no(absent.service.loginChallenge({ owner_id: h.owners[0].identity.owner_id, kind: 'owner_key' }), 'UNAVAILABLE', 'NORMAL_STICKY_FLAG_FRESH_STORE_REFUSED')
    h.check(!existsSync(absent.config.statePath) && !existsSync(h.witnessPath(absent)), 'NORMAL_STICKY_FLAG_CREATES_NO_STATE_OR_WITNESS')
    h.no(provisionNewAuthorityStore({ ...absent.config, provisionTrustedState: false }), 'UNAVAILABLE', 'PROVISION_EXPLICIT_FLAG_REQUIRED')
    h.check(!existsSync(absent.config.statePath) && !existsSync(h.witnessPath(absent)), 'UNAUTHORIZED_PROVISION_CREATES_NO_HISTORY')
    h.ok(provisionNewAuthorityStore(absent.config))
    h.unchanged(absent, () => h.no(provisionNewAuthorityStore(absent.config), 'REPLAYED'), 'EXPLICIT_HELPER_EXISTING_STORE_REFUSED')
    const deleted = h.fixture('deleted-retained-history'), deletedToken = h.login(deleted.service)
    h.ok(deleted.service.propose({ session_token: deletedToken, operation: h.operation('retained-history') }))
    const retainedWitness = readFileSync(h.witnessPath(deleted))
    rmSync(deleted.config.statePath)
    for (const [name, action] of [
      ['STICKY_FLAG_MISSING_STATE', () => deleted.service.loginChallenge({ owner_id: h.owners[0].identity.owner_id, kind: 'owner_key' })],
      ['EXPLICIT_HELPER_MISSING_STATE', () => provisionNewAuthorityStore(deleted.config)],
    ]) {
      h.no(action(), 'RECONCILIATION_REQUIRED', name + '_REFUSED')
      h.check(!existsSync(deleted.config.statePath) && readFileSync(h.witnessPath(deleted)).equals(retainedWitness), name + '_ABSENT_AND_WITNESS_UNCHANGED')
    }
    for (const [name, heads] of [['zero-count', { ['8'.repeat(64)]: 0 }], ['empty-heads', {}]]) {
      const z = h.fixture('retained-' + name, {}, false)
      mkdirSync(z.config.witnessDir, { mode: 0o700 })
      const bytes = Buffer.from(JSON.stringify({ schema: 1, heads }))
      writeFileSync(h.witnessPath(z), bytes, { mode: 0o600 })
      h.no(z.service.loginChallenge({ owner_id: h.owners[0].identity.owner_id, kind: 'owner_key' }), 'RECONCILIATION_REQUIRED', 'NORMAL_RETAINED_' + name + '_REFUSED')
      h.no(provisionNewAuthorityStore(z.config), 'RECONCILIATION_REQUIRED', 'EXPLICIT_RETAINED_' + name + '_REFUSED')
      h.check(!existsSync(z.config.statePath) && readFileSync(h.witnessPath(z)).equals(bytes), 'RETAINED_' + name + '_UNCHANGED_AND_ABSENT')
    }
    const shared = h.fixture('shared-namespace', { witnessDir: absent.config.witnessDir }, false), sharedBytes = readFileSync(h.witnessPath(absent))
    h.no(provisionNewAuthorityStore(shared.config), 'RECONCILIATION_REQUIRED', 'EXPLICIT_HELPER_SHARED_NAMESPACE_REFUSED')
    h.check(!existsSync(shared.config.statePath) && readFileSync(h.witnessPath(absent)).equals(sharedBytes), 'SHARED_NAMESPACE_UNCHANGED_NEW_STORE_ABSENT')
    const empty = h.fixture('healthy-empty-owners')
    h.editBroker(empty, store => { store.broker.owners = {} })
    h.unchanged(empty, () => h.no(empty.service.loginChallenge({ owner_id: h.owners[0].identity.owner_id, kind: 'owner_key' }), 'UNAVAILABLE', 'HEALTHY_EMPTY_OWNER_MAP_REFUSED'), 'HEALTHY_EMPTY_OWNER_MAP')
    h.check(Object.keys(h.read(empty).broker.owners).length === 0, 'HEALTHY_EMPTY_OWNER_MAP_NOT_REENROLLED')
    groups.push('normal methods never provision; sticky flag, retained nonzero/zero/empty witnesses, existing/shared namespace and empty owners all fail closed')

    const killed = await mutations(root, h)
    return { status: 'PASS', checks: h.checks, completed_save_lifecycles: 265, mutations: killed, runtime_ms: Math.round(performance.now() - start), groups, scope: 'synthetic keys and temporary realpath stores only; no installed runtime, network, executor or DB effects' }
  } finally { rmSync(root, { recursive: true, force: true }) }
}

if (process.argv[1] && resolve(process.argv[1]) === SELF) {
  try {
    const result = process.argv[2] === 'admission-probe' ? await probe(process.argv[3]) : await runAdmissionChecks()
    console.log(JSON.stringify(result))
  } catch (error) {
    console.log(JSON.stringify({ status: 'FAIL', check: error.check ?? 'UNEXPECTED_ERROR', observed: error.observed, error: error.message }))
    process.exitCode = 1
  }
}
