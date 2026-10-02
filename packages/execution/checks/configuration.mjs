// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable protocol responses only. No SDK connection, gateway, guest, keys,
// installation or production runtime qualification is performed here.
import assert from 'node:assert/strict'
import { rm } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { fileURLToPath } from 'node:url'
import { validateContract } from '../../contracts/src/runtime.mjs'
import { OwnedLedger, SdkTransport } from '../src/index.mjs'
import { fixture, request, settings, mock, MockedProtocolExecutor, MockedDurableBroker } from './harness.mjs'

if (process.argv[2] === 'post-readback-crash-child') {
  const root = process.argv[3], ledger = new OwnedLedger(root)
  const protocol = mock({ configurationHook({ config, read }) {
    if (read === 3) {
      // The stream has drained and its typed result is already durable. This
      // process dies before its final effective readback can be corroborated.
      process.stdout.write('POST_READBACK_CRASH\n')
      process.exit(0)
    }
    return config
  } })
  const executor = new MockedProtocolExecutor({ settings, ledger,
    transport: new SdkTransport(protocol.raw, { gatewayIdentity: 'https://synthetic.invalid:19443/' }),
    broker: new MockedDurableBroker(root) })
  await executor.execute(request())
  throw new Error('post-readback crash child unexpectedly returned')
}

const fixtures = []
const calls = (f, method) => f.protocol.calls.filter(([name]) => name === method)
const make = async (options, hooks) => {
  const f = await fixture(options, hooks)
  fixtures.push(f)
  return f
}
function assertUnstarted(receipt) {
  assert.equal(receipt.status, 'outcome_unknown')
  assert.equal(receipt.rpc_completion, 'not_started')
  assert.equal(receipt.started_at, null)
  assert.equal(receipt.exit_code, null)
  assert.equal(receipt.cleanup, 'confirmed_absent')
  assert.equal(receipt.reconciliation_required, true)
  assert.equal(validateContract('ExecutionReceipt', receipt), receipt)
}
function assertStartedUnknown(receipt, exit = 0) {
  assert.equal(receipt.status, 'outcome_unknown')
  assert.equal(receipt.rpc_completion, 'complete', 'drained RPC remains factual evidence')
  assert.notEqual(receipt.started_at, null)
  assert.equal(receipt.exit_code, exit, 'observed typed command exit must be retained')
  assert.equal(receipt.cleanup, 'confirmed_absent')
  assert.equal(receipt.reconciliation_required, true)
  assert.equal(receipt.stdout, 'retained synthetic output')
  assert.equal(receipt.stderr, 'retained error')
  assert.equal(validateContract('ExecutionReceipt', receipt), receipt)
}
function assertJsonSafe(value) {
  const text = JSON.stringify(value)
  assert.deepEqual(JSON.parse(text), value, 'persisted fingerprint must round-trip ordinary JSON')
  const inspect = item => {
    assert.notEqual(typeof item, 'bigint', 'raw uint64 revisions cannot enter the durable JSON ledger')
    if (item && typeof item === 'object') for (const [key, child] of Object.entries(item)) {
      if (/revision$/i.test(key)) {
        assert.equal(typeof child, 'string', 'durable uint64 revisions preserve exact decimal strings')
        assert.match(child, /^(?:0|[1-9][0-9]*)$/)
      }
      inspect(child)
    }
  }
  inspect(value)
}
async function refusedConfiguration(change, expectedReads = 1) {
  const f = await make({ configurationHook({ config, sandbox, read }) {
    change(config, sandbox, read)
    return config
  } })
  const r = request(), receipt = await f.executor.execute(r)
  assertUnstarted(receipt)
  assert.equal(calls(f, 'create').length, 1)
  assert.equal(calls(f, 'exec').length, 0, 'unapproved effective configuration must never reach exec')
  assert.equal(calls(f, 'config').length, expectedReads)
  assert.equal(calls(f, 'delete').length, 1, 'unchanged ownership permits scoped cleanup')
  assert.equal(f.broker.read().rows[r.operation.operation_id].status, 'OUTCOME_UNKNOWN')
  assert.equal(f.ledger.recovery().length, 1, 'configuration refusal retains the consumed launch fence')
  return { f, r, receipt }
}

const cases = {
  async configuration_untouched_exit_zero_and_one() {
    for (const exit of [0, 1]) {
      const f = await make({ exit }), r = request(), receipt = await f.executor.execute(r)
      assert.equal(receipt.status, exit === 0 ? 'completed' : 'failed')
      assert.equal(receipt.exit_code, exit)
      assert.equal(receipt.rpc_completion, 'complete')
      assert.equal(receipt.cleanup, 'confirmed_absent')
      assert.equal(receipt.reconciliation_required, false)
      assert.equal(receipt.stdout, 'retained synthetic output')
      assert.equal(receipt.stderr, 'retained error')
      assert.equal(calls(f, 'config').length, 3, 'initial, immediately pre-exec and post-drain readbacks are required')
      assert.equal(calls(f, 'exec').length, 1)
      const job = f.ledger.lookup(r.request_id)
      assert.ok(job.effective_configuration, 'admitted effective fingerprint must be durable before exec')
      assertJsonSafe(job.effective_configuration)
      assert.equal(f.ledger.recovery().length, 0)
      assert.equal(f.broker.read().rows[r.operation.operation_id].status, exit === 0 ? 'COMPLETED' : 'FAILED')
    }
  },
  async configuration_global_policy_source() {
    await refusedConfiguration(config => { config.policySource = 2; config.globalPolicyVersion = 1 })
  },
  async configuration_global_version_on_sandbox_source() {
    await refusedConfiguration(config => { config.globalPolicyVersion = 1 })
  },
  async configuration_altered_filesystem_policy() {
    await refusedConfiguration(config => { config.policy.filesystem.readWrite.push('/unapproved') })
  },
  async configuration_network_policy_overlay() {
    await refusedConfiguration(config => { config.policy.networkPolicies = { unapproved: {} } })
  },
  async configuration_matching_foreign_policy_hash() {
    await refusedConfiguration((config, sandbox) => {
      config.policyHash = 'b'.repeat(64)
      sandbox.status.configurationAdmission.policyHash = config.policyHash
    })
  },
  async configuration_policy_version_drift() {
    await refusedConfiguration((config, sandbox, read) => {
      if (read === 2) {
        config.version++
        sandbox.status.configurationAdmission.policyVersion = config.version
      }
    }, 2)
  },
  async configuration_initial_history_revision() {
    await refusedConfiguration((config, sandbox) => {
      config.version = 2
      sandbox.status.configurationAdmission.policyVersion = 2
    })
  },
  async configuration_nonempty_setting() {
    await refusedConfiguration(config => {
      config.settings.agent_policy_proposals_enabled = { scope: 1, value: { value: { case: 'boolValue', value: true } } }
    })
  },
  async configuration_missing_registered_setting() {
    await refusedConfiguration(config => { delete config.settings.proposal_approval_mode })
  },
  async configuration_unknown_setting() {
    await refusedConfiguration(config => { config.settings.unapproved_setting = { scope: 0 } })
  },
  async configuration_operator_middleware() {
    await refusedConfiguration(config => {
      config.supervisorMiddlewareServices = [{ name: 'synthetic-unapproved', endpoint: 'http://synthetic.invalid:1234' }]
    })
  },
  async configuration_retain_last_valid_posture() {
    await refusedConfiguration(config => { config.policyValidationFailureMode = 'retain_last_valid' })
  },
  async configuration_extension_authentication() {
    await refusedConfiguration(config => { config.extensionAuthenticationEnabled = true })
  },
  async configuration_not_admitted() {
    await refusedConfiguration(config => { config.configurationAdmitted = false })
  },
  async configuration_admission_error() {
    await refusedConfiguration(config => { config.configurationError = 'synthetic admission error' })
  },
  async configuration_instance_mismatch() {
    await refusedConfiguration(config => { config.configurationInstanceId = randomUUID() })
  },
  async configuration_attachment_epoch_mismatch() {
    await refusedConfiguration(config => { config.providerAttachmentEpoch = randomUUID() })
  },
  async configuration_workspace_mismatch() {
    await refusedConfiguration(config => { config.workspace = 'different-disposable-workspace' })
  },
  async configuration_config_revision_mismatch() {
    await refusedConfiguration(config => { config.configRevision += 1n })
  },
  async configuration_provider_revision_mismatch() {
    await refusedConfiguration(config => { config.providerEnvRevision += 1n })
  },
  async configuration_lossy_number_config_revision() {
    await refusedConfiguration((config, sandbox) => {
      // Both replies carry the same rounded number. Cross-reply equality alone
      // cannot recover the uint64 that the SDK was supposed to preserve.
      config.configRevision = Number(2n ** 63n + 1n)
      sandbox.status.configurationAdmission.configRevision = config.configRevision
    })
  },
  async configuration_lossy_number_provider_revision() {
    await refusedConfiguration((config, sandbox) => {
      config.providerEnvRevision = Number(2n ** 63n + 1n)
      sandbox.status.configurationAdmission.providerEnvRevision = config.providerEnvRevision
    })
  },
  async configuration_matching_changed_setting_revision() {
    await refusedConfiguration((config, sandbox) => {
      config.settings.proposal_approval_mode = { scope: 1, value: { value: { case: 'stringValue', value: 'manual' } } }
      config.configRevision += 1n
      sandbox.status.configurationAdmission.configRevision = config.configRevision
    })
  },
  async configuration_matching_changed_config_revision() {
    await refusedConfiguration((config, sandbox) => {
      config.configRevision += 1n
      sandbox.status.configurationAdmission.configRevision = config.configRevision
    })
  },
  async configuration_unknown_response_field() {
    await refusedConfiguration(config => { config.unapprovedOverlay = true })
  },
  async configuration_pre_exec_identity_drift() {
    const { f, r } = await refusedConfiguration((config, sandbox, read) => {
      if (read === 2) {
        config.configurationInstanceId = randomUUID()
        sandbox.status.configurationAdmission.instanceId = config.configurationInstanceId
      }
    }, 2)
    assert.ok(f.ledger.lookup(r.request_id).effective_configuration, 'the original admission checkpoint remains retained')
  },
  async configuration_pre_exec_cancel_after_readback() {
    const controller = new AbortController(), f = await make({ configurationHook({ config, read }) {
      if (read === 2) controller.abort()
      // A transport may still deliver its valid response after cancellation.
      // Admission must recheck the signal after that awaited response.
      return config
    } }), r = request({ signal: controller.signal }), receipt = await f.executor.execute(r)
    assert.equal(receipt.status, 'cancelled')
    assert.equal(receipt.rpc_completion, 'not_started')
    assert.equal(receipt.started_at, null)
    assert.equal(receipt.exit_code, null)
    assert.equal(receipt.cleanup, 'confirmed_absent')
    assert.equal(receipt.reconciliation_required, false)
    assert.equal(calls(f, 'config').length, 2)
    assert.equal(calls(f, 'exec').length, 0, 'a valid late readback cannot override cancellation')
    assert.equal(f.ledger.lookup(r.request_id).cancel_state, 'recorded')
    assert.equal(f.broker.read().rows[r.operation.operation_id].status, 'CANCELLED')
  },
  async configuration_pre_exec_qualification_revoked_during_readback() {
    let admitted = true
    const f = await make({ configurationHook({ config, read }) {
      if (read === 2) admitted = false
      return config
    } }, { protocolAdmission: () => admitted }), receipt = await f.executor.execute(request())
    assertUnstarted(receipt)
    assert.equal(calls(f, 'config').length, 2)
    assert.equal(calls(f, 'exec').length, 0, 'qualification must be current after awaited readback')
  },
  async configuration_pre_exec_expiry_during_readback() {
    const r = request(), now = Date.now
    const f = await make({ configurationHook({ config, read }) {
      if (read === 2) Date.now = () => Date.parse(r.operation.expiry) + 1
      return config
    } })
    try {
      const receipt = await f.executor.execute(r)
      assertUnstarted(receipt)
      assert.equal(calls(f, 'config').length, 2)
      assert.equal(calls(f, 'exec').length, 0, 'approval expiry must be rechecked after awaited readback')
    } finally { Date.now = now }
  },
  async configuration_post_drain_identity_drift() {
    const f = await make({ configurationHook({ config, sandbox, read }) {
      if (read === 3) {
        config.configurationInstanceId = randomUUID()
        sandbox.status.configurationAdmission.instanceId = config.configurationInstanceId
      }
      return config
    } }), r = request(), receipt = await f.executor.execute(r)
    assertStartedUnknown(receipt)
    assert.equal(calls(f, 'exec').length, 1)
    assert.equal(calls(f, 'config').length, 3)
    const job = f.ledger.lookup(r.request_id)
    assert.equal(job.configuration_uncertain, true)
    assertJsonSafe(job.effective_configuration)
    assert.equal(f.broker.read().rows[r.operation.operation_id].status, 'OUTCOME_UNKNOWN')
    const [reconciled] = await f.executor.reconcileOwned()
    assertStartedUnknown(reconciled)
    await assert.rejects(f.executor.execute(r), error => error.code === 'RECONCILIATION_REQUIRED')
    assert.equal(calls(f, 'create').length, 1)
    assert.equal(calls(f, 'exec').length, 1, 'reconciliation cannot relaunch after drift')
  },
  async configuration_post_drain_readback_exception() {
    const f = await make({ exit: 1, configurationHook({ config, read }) {
      if (read === 3) throw new Error('synthetic effective readback unavailable')
      return config
    } }), r = request(), receipt = await f.executor.execute(r)
    assertStartedUnknown(receipt, 1)
    assert.equal(calls(f, 'exec').length, 1)
    assert.equal(calls(f, 'config').length, 3)
    assert.equal(f.ledger.lookup(r.request_id).configuration_uncertain, true)
    assert.equal(f.broker.read().rows[r.operation.operation_id].status, 'OUTCOME_UNKNOWN')
  },
  async configuration_post_drain_process_death_preserves_unknown() {
    const f = await make(), child = spawn(process.execPath,
      [fileURLToPath(import.meta.url), 'post-readback-crash-child', f.root],
      { stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = '', stderr = ''
    child.stdout.on('data', chunk => { stdout += chunk })
    child.stderr.on('data', chunk => { stderr += chunk })
    const [code, signal] = await once(child, 'close')
    assert.equal(code, 0, 'child must die at the intended checkpoint: ' + stderr)
    assert.equal(signal, null)
    assert.match(stdout, /POST_READBACK_CRASH/)

    const pending = f.ledger.pending()
    assert.equal(pending.length, 1)
    const [job] = pending
    assert.equal(job.stage, 'exec_drained')
    assert.equal(job.configuration_verification, 'pending', 'final readback has no durable corroboration')
    assert.equal(job.receipt.rpc_completion, 'complete')
    assert.equal(job.receipt.exit_code, 0)
    assert.notEqual(job.receipt.started_at, null)
    assert.equal(job.receipt.cleanup, 'pending')
    assert.equal(Buffer.from(job.stdout_b64, 'base64').toString('utf8'), 'retained synthetic output')
    assert.equal(Buffer.from(job.stderr_b64, 'base64').toString('utf8'), 'retained error')
    assert.equal(job.outbox.length, 0, 'death precedes terminal settlement')
    assert.equal(f.broker.read().rows[job.request.operation.operation_id].status, 'DISPATCHED')

    // The child mock's memory dies with it. A separate mocked control plane now
    // reports only the exact owned sandbox checkpoint and confirms its removal.
    // This is disposable test evidence, never actual guest termination proof.
    let present = true
    const sandbox = { metadata: { id: job.id, name: job.name, workspace: settings.workspace,
      labels: { 'aukora.openshell/owner': job.token } } }
    f.transport.raw.listSandboxes = async input => {
      f.protocol.calls.push(['list', input])
      return { sandboxes: present ? [sandbox] : [], nextPageToken: '' }
    }
    f.transport.raw.getSandbox = async input => {
      f.protocol.calls.push(['get', input])
      assert.equal(input.name, job.name)
      return { sandbox }
    }
    f.transport.raw.deleteSandbox = async input => {
      f.protocol.calls.push(['delete', input])
      assert.equal(input.name, job.name)
      assert.equal(input.requestId, job.delete_request_id)
      present = false
      return { outcome: 1, sandboxId: job.id }
    }
    const [receipt] = await f.executor.reconcileOwned()
    assertStartedUnknown(receipt)
    assert.equal(receipt.receipt_id, job.receipt.receipt_id)
    assert.equal(calls(f, 'delete').length, 1)
    assert.equal(calls(f, 'exec').length, 0, 'restart only reconciles owned cleanup and never re-executes')
    assert.equal(calls(f, 'config').length, 0, 'later readback cannot stand in for missing post-exec corroboration')
    const recovered = f.ledger.lookup(job.request_id)
    assert.equal(recovered.configuration_verification, 'pending', 'cleanup cannot promote an unverified result')
    assert.equal(recovered.outbox.at(-1).state, 'acked')
    assert.equal(f.broker.read().rows[job.request.operation.operation_id].status, 'OUTCOME_UNKNOWN')
    assert.equal(f.ledger.recovery().length, 1)
    await assert.rejects(f.executor.execute(job.request), error => error.code === 'RECONCILIATION_REQUIRED')
    await assert.rejects(f.executor.execute(request()), error => error.code === 'RECONCILIATION_REQUIRED')
    assert.equal(calls(f, 'create').length, 0)
    assert.equal(calls(f, 'exec').length, 0)
    assert.equal(f.broker.read().calls.filter(([name]) => name === 'claimDispatch').length, 1)
  },
}

let checked = 0
try {
  const selector = process.argv[2]
  if (selector && !Object.hasOwn(cases, selector)) throw new Error('unknown configuration case: ' + selector)
  for (const [label, run] of Object.entries(cases)) {
    if (selector && label !== selector) continue
    await run()
    checked++
    console.log('PASS ' + label)
  }
  console.log(`PASS ${checked} scoped effective-configuration cases; mocked protocol only; runtime unavailable`)
} finally {
  for (const f of fixtures) f.ledger.close()
  for (const f of fixtures) await rm(f.root, { recursive: true, force: true })
}
