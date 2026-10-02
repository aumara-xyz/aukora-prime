// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { ActionButton, Panel } from '@aukora/face-layout/client'
import type { ApprovalActionResult, Controller, OwnerState } from './controller.mjs'
import type { ForgetWorkflowSnapshot } from '../../../adapters/forget-result.mjs'
import css from './OwnerSurface.module.css'

interface SnapshotStore<Snapshot> {
  getSnapshot():Snapshot
  subscribe(listener:()=>void):()=>void
}

/** Structural subset of H's existing, attached createOwnerMemoryClient result.
 * It supplies no route, source context, session, signer or authority itself. */
export interface MemoryPilotBinding {
  readonly ownerController:Controller
  readonly client:{
    readonly binding:{readonly owner_id:string}
    readonly workflow:SnapshotStore<ApprovalActionResult>|undefined
    readonly forgetWorkflow:SnapshotStore<ForgetWorkflowSnapshot>|undefined
    proposeSave(draft:{extraction_json:string;idempotency_key:string}):Promise<ApprovalActionResult>
    refresh():Promise<ApprovalActionResult>
    recover(input?:{operation_id:string|null}):Promise<ApprovalActionResult>
    recoverForget(input?:{operation_id:string|null}):Promise<ForgetWorkflowSnapshot>
  }
}

type Owner = NonNullable<OwnerState['owner']>
type MemoryClient = MemoryPilotBinding['client']

function currentOwner(controller:Controller,binding:MemoryPilotBinding,expected?:Owner):Owner|null {
  const state = controller.getSnapshot()
  const owner = state.owner
  const ownerId = binding.client.binding?.owner_id
  if (binding.ownerController !== controller || typeof ownerId !== 'string' || !ownerId
    || !owner || state.owner_id !== ownerId || owner.owner_id !== ownerId
    || expected && owner !== expected || !state.authority_available || state.expired
    || state.logout_status === 'pending' || !Number.isFinite(Date.parse(owner.expiry))
    || Date.parse(owner.expiry) <= Date.now()) return null
  return owner
}

function attached(client:MemoryClient):boolean {
  return !!client.workflow && !!client.forgetWorkflow
    && typeof client.workflow.getSnapshot === 'function' && typeof client.workflow.subscribe === 'function'
    && typeof client.forgetWorkflow.getSnapshot === 'function' && typeof client.forgetWorkflow.subscribe === 'function'
    && ['proposeSave','refresh','recover','recoverForget'].every(name => typeof client[name as keyof MemoryClient] === 'function')
}

function Unavailable({reason}:{reason:string}) {
  return <Panel className={css.card} data-memory-pilot data-memory-pilot-unavailable>
    <h2>Owner-approved memory</h2>
    <p role="status">{reason}</p>
    <div className={css.actions}>
      <ActionButton disabled>Read memory recovery</ActionButton>
      <ActionButton disabled>Read forget recovery</ActionButton>
      <ActionButton disabled>Refresh record</ActionButton>
      <ActionButton disabled>Prepare memory proposal</ActionButton>
    </div>
  </Panel>
}

export function PilotMemoryPanel({controller,binding}:{controller:Controller;binding?:MemoryPilotBinding}) {
  useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot)
  const session = useRef<{binding:MemoryPilotBinding|undefined;owner:Owner|null;key:number}>({binding:undefined,owner:null,key:0})
  if (!binding) return <Unavailable reason="The host has not supplied an owner memory client." />
  if (binding.ownerController !== controller || binding.client.binding?.owner_id !== controller.getSnapshot().owner_id) {
    return <Unavailable reason="The memory client does not match this configured owner controller." />
  }
  if (!attached(binding.client)) return <Unavailable reason="The host has not attached the owner memory workflows." />
  const owner = currentOwner(controller,binding)
  if (!owner) return <Unavailable reason="Sign in with the configured owner's current, unexpired credential before reading or proposing memory." />
  if (session.current.binding !== binding || session.current.owner !== owner) {
    session.current = {binding,owner,key:session.current.key+1}
  }
  return <AttachedMemoryPanel key={session.current.key} controller={controller} binding={binding} owner={owner}
    workflow={binding.client.workflow!} forgetWorkflow={binding.client.forgetWorkflow!} />
}

function AttachedMemoryPanel({controller,binding,owner,workflow,forgetWorkflow}:{
  controller:Controller;binding:MemoryPilotBinding;owner:Owner
  workflow:SnapshotStore<ApprovalActionResult>;forgetWorkflow:SnapshotStore<ForgetWorkflowSnapshot>
}) {
  const rendered = useRef({binding,owner,workflow,forgetWorkflow})
  rendered.current = {binding,owner,workflow,forgetWorkflow}
  const mounted = useRef(true)
  const flight = useRef<object|null>(null)
  const statementInput = useRef<HTMLTextAreaElement>(null)
  const [pending,setPending] = useState<string|null>(null)
  const [reason,setReason] = useState('Recovery reads existing facts and may deliver an already committed settlement receipt. It does not restore data or repeat an effect.')
  const live = useCallback(() => mounted.current && rendered.current.binding === binding
    && rendered.current.owner === owner && rendered.current.workflow === workflow && rendered.current.forgetWorkflow === forgetWorkflow
    && binding.client.workflow === workflow && binding.client.forgetWorkflow === forgetWorkflow
    && currentOwner(controller,binding,owner) !== null,[controller,binding,owner,workflow,forgetWorkflow])
  const readMemory = useCallback(() => live() ? workflow.getSnapshot() : null,[live,workflow])
  const readForget = useCallback(() => live() ? forgetWorkflow.getSnapshot() : null,[live,forgetWorkflow])
  const memory = useSyncExternalStore(workflow.subscribe,readMemory,readMemory)
  const forget = useSyncExternalStore(forgetWorkflow.subscribe,readForget,readForget)
  const state = useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot)

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false;flight.current = null }
  },[])
  useEffect(() => {
    // A draft remains only in this owner's transient DOM input. Changing the
    // owner or composition clears it without normalizing its original text.
    const input = statementInput.current
    if (input) input.value = ''
    setReason('Recovery reads existing facts and may deliver an already committed settlement receipt. It does not restore data or repeat an effect.')
    setPending(null)
    return () => { if (input) input.value = '' }
  },[binding,owner,workflow,forgetWorkflow])

  if (!memory || !forget || !live()) return <Unavailable reason="The owner session or memory binding has changed." />
  const busy = pending !== null || state.phase.endsWith('_pending') || state.approval_action_pending
    || state.logout_status === 'pending' || memory.phase.endsWith('_pending') || forget.phase.endsWith('_pending')
    || forget.recovery_status === 'pending'
  const uncertain = state.phase === 'outcome_unknown' || state.error_code === 'OUTCOME_UNKNOWN'
    || state.error_code === 'RECONCILIATION_REQUIRED' || memory.reconciliation_required || forget.reconciliation_required
    || memory.phase === 'outcome_unknown' || forget.phase === 'outcome_unknown'
    || memory.save === 'unknown' || forget.forget === 'unknown'
    || state.approval_action_result?.reconciliation_required === true || state.forget_action_result?.reconciliation_required === true
  const canRefresh = memory.saved === true && memory.record !== null && memory.operation !== null
  const randomUuid = typeof globalThis.crypto?.randomUUID === 'function'

  async function run(label:string,action:()=>Promise<ApprovalActionResult|ForgetWorkflowSnapshot>) {
    if (flight.current || busy || !live()) return
    const current = controller.getSnapshot()
    const currentMemory = workflow.getSnapshot(),currentForget = forgetWorkflow.getSnapshot()
    if (current.phase.endsWith('_pending') || current.approval_action_pending || current.logout_status === 'pending'
      || currentMemory.phase.endsWith('_pending') || currentForget.phase.endsWith('_pending')
      || currentForget.recovery_status === 'pending') return
    if (label === 'proposal' && (current.phase === 'outcome_unknown' || current.error_code === 'OUTCOME_UNKNOWN'
      || current.error_code === 'RECONCILIATION_REQUIRED' || currentMemory.reconciliation_required || currentForget.reconciliation_required
      || currentMemory.phase === 'outcome_unknown' || currentForget.phase === 'outcome_unknown'
      || currentMemory.save === 'unknown' || currentForget.forget === 'unknown'
      || current.approval_action_result?.reconciliation_required || current.forget_action_result?.reconciliation_required)) return
    if (!live()) return
    const token = {};flight.current = token;setPending(label)
    try {
      const result = await action()
      if (flight.current !== token || !live()) return
      setReason(result.reconciliation_required
        ? 'The outcome still requires reconciliation. Do not repeat the attempted effect.'
        : result.error_code ? `The memory request was refused or unavailable: ${result.error_code}.`
          : label === 'proposal' ? 'The proposal is prepared. Use Exact operation to request a fresh review and approve it explicitly.'
            : 'The current workflow facts are shown below. No effect was retried.')
    } catch {
      if (flight.current === token && live()) setReason('The memory request is unavailable or its outcome is unconfirmed. No effect was retried.')
    } finally {
      if (flight.current === token) { flight.current = null;if (live()) setPending(null) }
    }
  }

  return <Panel className={css.card} data-memory-pilot>
    <h2>Owner-approved memory</h2>
    <p>Read the current workflow directly, including recovery after a fresh owner session. Storage, indexing, citation and authority settlement remain separate facts.</p>
    <div className={css.actions}>
      <ActionButton disabled={busy} onClick={() => { void run('memory recovery',() => binding.client.recover({operation_id:null})) }}>Read memory recovery</ActionButton>
      <ActionButton disabled={busy} onClick={() => { void run('forget recovery',() => binding.client.recoverForget({operation_id:null})) }}>Read forget recovery</ActionButton>
      <ActionButton disabled={busy || !canRefresh} onClick={() => { void run('record refresh',() => binding.client.refresh()) }}>Refresh record</ActionButton>
    </div>
    {!canRefresh && <p data-memory-refresh-unavailable>Refresh requires an active confirmed save. Read recovery to inspect retained facts after a fresh session.</p>}
    <form onSubmit={event => {
      event.preventDefault()
      const statement = statementInput.current?.value
      if (busy || uncertain || !randomUuid || !live()) return
      if (typeof statement !== 'string' || !statement.trim() || statement.length > 4096) {
        setReason('Enter a nonblank literal statement of at most 4,096 characters before preparing a proposal.')
        return
      }
      // Preserve the complete literal statement. The worker supplies the source,
      // attribution and fixed metadata; its existing policy admits or refuses it.
      void run('proposal',() => binding.client.proposeSave({
        extraction_json:JSON.stringify({statement}),idempotency_key:globalThis.crypto.randomUUID(),
      }))
    }}>
      <label className={css.owner}>Literal memory statement
        <textarea ref={statementInput} aria-label="Literal memory statement" autoComplete="off" spellCheck={false}
          disabled={busy || uncertain} rows={4} />
      </label>
      <p>Preparing a proposal does not save memory. Use the existing Exact operation card to request a fresh review, inspect the exact source quotation and approve explicitly. New capture text must already satisfy the worker's text policy.</p>
      <div className={css.actions}><ActionButton disabled={busy || uncertain || !randomUuid}
        onClick={() => { statementInput.current?.form?.requestSubmit() }}>Prepare memory proposal</ActionButton></div>
    </form>
    {!randomUuid && <p role="status">A secure browser UUID is unavailable; proposal preparation is disabled.</p>}
    {uncertain && <p role="alert" data-memory-pilot-uncertain>An attempted operation remains unresolved. New memory proposals are disabled; read recovery without repeating the effect.</p>}
    <p role="status" aria-live="polite" data-memory-pilot-status>{pending ? `Reading or preparing ${pending}.` : reason}</p>
    <MemoryFacts snapshot={memory} />
    <ForgetFacts snapshot={forget} />
  </Panel>
}

const booleanFact = (value:boolean|null) => value === null ? 'Unconfirmed' : value ? 'Yes' : 'No'

function MemoryFacts({snapshot}:{snapshot:ApprovalActionResult}) {
  const record = snapshot.saved === true ? snapshot.record : null
  const evidence = record && Array.isArray(record.evidence) ? record.evidence : []
  return <div data-memory-pilot-facts>
    <h3>Memory workflow and retained save facts</h3>
    <dl className={css.fields}>
      <div><dt>Workflow</dt><dd>{snapshot.phase}</dd></div>
      <div><dt>Approval</dt><dd>{snapshot.approval}</dd></div>
      <div><dt>Save</dt><dd>{snapshot.save}</dd></div>
      <div><dt>Saved</dt><dd>{booleanFact(snapshot.saved)}</dd></div>
      <div><dt>Storage</dt><dd>{typeof record?.storage_status === 'string' ? record.storage_status : 'Unconfirmed'}</dd></div>
      <div><dt>Index</dt><dd>{snapshot.index.status}; indexed: {booleanFact(snapshot.index.indexed)}; searchable: {booleanFact(snapshot.index.searchable)}</dd></div>
      <div><dt>Citation</dt><dd>{snapshot.citation_status}</dd></div>
      <div><dt>Authority settlement</dt><dd>{snapshot.authority_settlement ?? 'Unconfirmed'}</dd></div>
      <div><dt>Operation digest</dt><dd><pre>{snapshot.operation_digest ?? 'Unavailable'}</pre></dd></div>
      <div><dt>Receipt digest</dt><dd><pre>{snapshot.receipt_digest ?? 'Unavailable'}</pre></dd></div>
    </dl>
    {snapshot.error_code && <p role="status">Memory request status: {snapshot.error_code}</p>}
    {snapshot.read_error_code && <p role="status">Index or citation read unavailable: {snapshot.read_error_code}</p>}
    {record && <div data-memory-pilot-saved-content>
      <h3>Exact saved canonical bytes</h3>
      <pre>{typeof record.canonical_bytes === 'string' ? record.canonical_bytes : 'Unavailable'}</pre>
      <h3>Exact saved source evidence</h3>
      {evidence.map((entry:unknown,index:number) => {
        const quote = entry && typeof entry === 'object' && 'quote' in entry ? entry.quote : null
        return <div key={index}>
          {typeof quote === 'string' && <pre data-memory-pilot-evidence-quote>{quote}</pre>}
          <pre>{JSON.stringify(entry,null,2)}</pre>
        </div>
      })}
      {evidence.length === 0 && <p>No source evidence was supplied in this record.</p>}
    </div>}
    {snapshot.receipt && <details><summary>Exact retained save receipt</summary><pre>{JSON.stringify(snapshot.receipt,null,2)}</pre></details>}
    {snapshot.citation && <details><summary>Exact retained citation</summary><pre>{JSON.stringify(snapshot.citation,null,2)}</pre></details>}
  </div>
}

function ForgetFacts({snapshot}:{snapshot:ForgetWorkflowSnapshot}) {
  return <div data-memory-pilot-forget-facts>
    <h3>Logical-forget recovery facts</h3>
    <dl className={css.fields}>
      <div><dt>Workflow</dt><dd>{snapshot.phase}</dd></div>
      <div><dt>Recovery</dt><dd>{snapshot.recovery_status}</dd></div>
      <div><dt>Approval</dt><dd>{snapshot.approval}</dd></div>
      <div><dt>Logical forget</dt><dd>{snapshot.forget}</dd></div>
      <div><dt>Forgotten</dt><dd>{booleanFact(snapshot.forgotten)}</dd></div>
      <div><dt>Authority settlement</dt><dd>{snapshot.authority_settlement ?? 'Unconfirmed'}</dd></div>
      <div><dt>Recovery operation</dt><dd><pre>{snapshot.recovery_operation_id ?? 'Unavailable'}</pre></dd></div>
      <div><dt>Receipt digest</dt><dd><pre>{snapshot.receipt_digest ?? 'Unavailable'}</pre></dd></div>
    </dl>
    {snapshot.error_code && <p role="status">Forget request status: {snapshot.error_code}</p>}
    {snapshot.forgotten === true && <p>Logical forget removed visibility. Canonical payloads, authority history, backups, WAL and physical media remain retained.</p>}
    {snapshot.result && <details><summary>Exact logical-forget result</summary><pre>{JSON.stringify(snapshot.result,null,2)}</pre></details>}
    {snapshot.receipt && <details><summary>Exact retained forget receipt</summary><pre>{JSON.stringify(snapshot.receipt,null,2)}</pre></details>}
  </div>
}
