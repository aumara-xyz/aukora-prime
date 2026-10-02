import { useSyncExternalStore } from 'react'
import { ActionButton, Panel, SectionHeader } from '@aukora/face-layout/client'
import type { PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import type { Controller } from './controller.mjs'
import { CAPABILITY_LABELS } from './controller.mjs'
import { CAPTURE_METADATA_FIELDS, validateCaptureReview } from '../../../adapters/capture-review.mjs'
import { validateCaptureMetadata } from '../../../adapters/capture-metadata.mjs'
import { validateForgetReview } from '../../../adapters/forget-review.mjs'
import { MemoryCaptureHints } from './MemoryCaptureHints'
import css from './OwnerSurface.module.css'

export function OwnerSurface({ activeSurface, controller }: PropsRuntime<'shell.surface'> & {controller:Controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot)
  const busy = state.phase.endsWith('_pending') || state.approval_action_pending || state.logout_status === 'pending'
  const locked = busy || state.phase === 'outcome_unknown'
  const view = state.presentation
  const memoryAction = view?.operation.action_type === 'memory.save' || view?.operation.action_type === 'memory.forget'
  let memoryReady = !memoryAction
  if (!memoryReady && view?.memory_review) {
    try {
      validateCaptureReview(view.operation.canonical_parameters, {
        statement: view.memory_review.statement, attributed_to: view.memory_review.attributed_to,
        capture_metadata:view.memory_review.capture_metadata, evidence_quote:view.memory_review.evidence_quote,
      })
      memoryReady = view.memory_review.capture_sha256 === (view.operation.canonical_parameters as {capture_sha256:string}).capture_sha256
      const metadata = validateCaptureMetadata(view.capture_metadata)
      memoryReady = memoryReady && CAPTURE_METADATA_FIELDS.every(key => metadata[key] === view.memory_review!.capture_metadata[key])
    } catch { memoryReady = false }
  }
  if (!memoryReady && view?.operation.action_type === 'memory.forget' && view.forget_review) {
    try {
      const {record_id,revision,statement,attributed_to,canonical_sha256} = view.forget_review
      validateForgetReview(view.operation,{record_id,revision,statement,attributed_to})
      memoryReady = canonical_sha256 === (view.operation.canonical_parameters as {canonical_sha256:string}).canonical_sha256
    } catch { memoryReady = false }
  }
  return <section className={css.surface} hidden={activeSurface !== 'prime-owner'} data-prime-owner-surface data-phase={state.phase}>
    <SectionHeader className={css.header}><h1>Owner access and approvals</h1>
      <p>Use an existing credential. Enrollment is unavailable here.</p></SectionHeader>
    {state.fixture && <p role="alert" data-disposable-fixture>Disposable UI fixture. Authentication and approvals below are synthetic; no effect is executed.</p>}
    <Panel className={css.card}><CapabilityDetails controller={controller} /></Panel>
    <Panel className={css.card}>
      <h2>Owner session</h2>
      {state.owner ? <><p data-owner-confirmed>Host-confirmed owner: <code>{state.owner.owner_id}</code></p>
        <p>Session expires: <time>{state.owner.expiry}</time></p></>
        : <label className={css.owner}>Owner ID<input autoComplete="off" value={state.owner_id} disabled={busy}
          onChange={event => controller.setOwnerId(event.target.value)} aria-label="Owner ID" /></label>}
      <div className={css.actions}>
        {!state.owner && state.login_kinds.map(kind => <ActionButton key={kind} disabled={busy || !state.owner_id || !state.authority_available || state.phase === 'unavailable'}
          onClick={() => { void controller.login(kind) }}>{kind === 'passkey' ? 'Sign in with passkey' : 'Sign in with owner key'}</ActionButton>)}
        {state.owner && <ActionButton disabled={busy} onClick={() => { void controller.logout() }}>Sign out</ActionButton>}
      </div>
      {state.logout_status !== 'idle' && <p role="status" data-server-logout-status={state.logout_status}>
        {state.logout_status === 'confirmed' ? 'The host confirmed server logout.'
          : state.logout_status === 'pending' ? 'Local access removed. Server logout is pending.' : 'Local access removed. Server logout is unconfirmed.'}
      </p>}
    </Panel>
    <Panel className={css.card}>
      <h2>Exact operation</h2>
      {!state.operation_available && <p>No operation has been supplied by the host.</p>}
      {state.operation_available && <ActionButton disabled={!state.owner || locked || !state.authority_available || state.phase === 'approved' || state.phase === 'denied'}
        onClick={() => { void controller.prepare() }}>Request fresh review</ActionButton>}
      {view && <>
        {view.operation.action_type === 'memory.save' && <div data-memory-capture-review>
          <h3>Exact memory statement</h3>
          {memoryReady ? <><pre data-memory-statement>{view.memory_review!.statement}</pre>
            <p>Attribution</p><pre data-memory-attribution>{view.memory_review!.attributed_to}</pre>
            <p>Capture hash</p><pre data-memory-capture-hash>{view.memory_review!.capture_sha256}</pre>
            <h3>Exact selected source quotation</h3>
            <pre data-memory-evidence-quote>{view.memory_review!.evidence_quote}</pre>
            <p>The source quotation can differ from the captured statement. The operation digest binds the exact statement, attribution, metadata and quotation. The host verifies the private capture and source.</p>
            <MemoryCaptureHints statement={view.memory_review!.statement} evidenceQuote={view.memory_review!.evidence_quote} metadata={view.capture_metadata} />
            {view.capture_metadata ? <dl data-fixed-capture-dates>
              <dt>Source observed at</dt><dd><time>{view.capture_metadata.observed_at}</time></dd>
              <dt>Valid from</dt><dd><time>{view.capture_metadata.valid_from}</time></dd>
            </dl> : <p data-fixed-capture-dates-unavailable>The host has not supplied the capture dates.</p>}
          </>
            : <p role="alert" data-memory-review-refused>The exact statement, attribution, metadata or source quotation is missing or does not match the independent capture draft. Approval is unavailable.</p>}
        </div>}
        {view.operation.action_type === 'memory.forget' && <div data-memory-forget-review>
          <h3>Exact original record for logical forget</h3>
          {memoryReady ? <><p>Record</p><pre data-forget-record-id>{view.forget_review!.record_id}</pre>
            <p>Revision</p><pre data-forget-revision>{view.forget_review!.revision}</pre>
            <p>Original statement</p><pre data-forget-statement>{view.forget_review!.statement}</pre>
            <p>Original attribution</p><pre data-forget-attribution>{view.forget_review!.attributed_to === null ? 'null' : view.forget_review!.attributed_to}</pre>
            <p>Original canonical bytes hash</p><pre data-forget-canonical-hash>{view.forget_review!.canonical_sha256}</pre>
            <p>Logical forget removes visibility. Canonical payloads, backups, WAL, authority history and physical media are retained.</p></>
            : <p role="alert" data-forget-review-refused>The original record and exact literals are missing or changed. Approval is unavailable.</p>}
        </div>}
        <dl className={css.fields} data-exact-operation>{view.rows.map(row => <div key={row.key} data-operation-field={row.key}>
          <dt>{row.label} <code>({row.key})</code></dt><dd><pre>{row.exact}</pre></dd></div>)}</dl>
        <p>Operation digest</p><pre data-operation-digest>{view.operation_digest}</pre>
        <p>Review expires: <time data-approval-expiry>{view.approval_expiry}</time></p>
        <p>Fresh review challenge</p><pre data-review-challenge>{JSON.stringify(view.review_challenge, null, 2)}</pre>
        <p>Exact canonical operation</p><pre data-canonical-operation>{view.canonical_operation}</pre>
        <div className={css.actions}>
          <ActionButton variant="gold" disabled={state.phase !== 'review_ready' || state.expired || !state.authority_available || !memoryReady || busy ||
              (memoryAction && !state.approval_action_available)}
            onClick={() => { void controller.submitApproval() }}>Approve exact operation</ActionButton>
          <ActionButton variant="red-warning" disabled={state.phase !== 'review_ready' || state.expired || !state.authority_available}
            onClick={() => { void controller.decline() }}>Decline</ActionButton>
        </div>
        {memoryAction && !state.approval_action_available && !state.approval_action_result && !state.forget_action_result &&
          <p role="status" data-memory-action-unavailable>The memory approval workflow is unavailable.</p>}
      </>}
    </Panel>
    {state.approval_action_result && <Panel className={css.card} data-memory-workflow-result>
      <h2>Host memory workflow result</h2>
      <dl className={css.fields}>
        <div><dt>Approval</dt><dd data-memory-approval-status>{state.approval_action_result.approval}</dd></div>
        <div><dt>Save</dt><dd data-memory-save-status>{state.approval_action_result.save}</dd></div>
        <div><dt>Index</dt><dd data-memory-index-status>{state.approval_action_result.index.status}</dd></div>
        <div><dt>Citation</dt><dd data-memory-citation-status>{state.approval_action_result.citation_status}</dd></div>
        <div><dt>Authority settlement</dt><dd data-memory-settlement-status>{state.approval_action_result.authority_settlement ?? 'unconfirmed'}</dd></div>
        <div><dt>Receipt digest</dt><dd><pre data-memory-receipt-digest>{state.approval_action_result.receipt_digest ?? 'unconfirmed'}</pre></dd></div>
      </dl>
      {state.approval_action_result.reconciliation_required && <p role="alert">Reconciliation is required. Do not retry this save.</p>}
      {state.approval_action_result.read_error_code && <p role="status">Index or citation read unavailable: {state.approval_action_result.read_error_code}</p>}
      {state.approval_action_result.saved === true && state.approval_action_result.record &&
        <SavedCaptureContent record={state.approval_action_result.record} />}
      {state.approval_action_result.receipt && <details><summary>Exact host receipt</summary>
        <pre data-memory-effect-receipt>{JSON.stringify(state.approval_action_result.receipt, null, 2)}</pre></details>}
      {state.approval_action_result.citation && <details><summary>Exact citation</summary>
        <pre data-memory-citation>{JSON.stringify(state.approval_action_result.citation, null, 2)}</pre></details>}
    </Panel>}
    {state.forget_action_result && <Panel className={css.card} data-memory-forget-result>
      <h2>Host logical-forget result</h2>
      <dl className={css.fields}>
        <div><dt>Approval</dt><dd>{state.forget_action_result.approval}</dd></div>
        <div><dt>Logical forget</dt><dd data-forget-status>{state.forget_action_result.forget}</dd></div>
        <div><dt>Authority settlement</dt><dd data-forget-settlement>{state.forget_action_result.authority_settlement ?? 'unconfirmed'}</dd></div>
        <div><dt>Receipt digest</dt><dd><pre>{state.forget_action_result.receipt_digest ?? 'unconfirmed'}</pre></dd></div>
      </dl>
      {state.forget_action_result.forgotten && <p>Visibility was removed. Canonical payloads, external backups, WAL and physical media were not erased.</p>}
      {state.forget_action_result.reconciliation_required && <p role="alert">Reconciliation is required. Do not retry this forget operation.</p>}
      {state.forget_action_result.receipt && <details><summary>Exact host forget receipt</summary>
        <pre data-forget-receipt>{JSON.stringify(state.forget_action_result.receipt,null,2)}</pre></details>}
    </Panel>}
    <p role="status" aria-live="polite" data-prime-authority-status>{state.reason}</p>
    {state.error_code && <p role="alert" className={css.error} data-authority-error={state.error_code}>{state.error_code}</p>}
    {state.expired && <p role="alert">This session or review has expired.</p>}
  </section>
}

function SavedCaptureContent({record}:{record:Readonly<Record<string,unknown>>}) {
  const evidence = Array.isArray(record.evidence) ? record.evidence : []
  return <div data-memory-saved-capture-content>
    <h3>Exact saved memory and source evidence</h3>
    <p>The original saved bytes remain unchanged. Source quotations describe the selected source event and can differ from the captured statement.</p>
    <pre data-memory-saved-canonical-bytes>{typeof record.canonical_bytes === 'string' ? record.canonical_bytes : 'Unavailable'}</pre>
    {evidence.map((entry:unknown,index:number) => {
      const quote = entry && typeof entry === 'object' && 'quote' in entry ? entry.quote : null
      return <div key={index} data-memory-saved-evidence>
        {typeof quote === 'string' && <pre data-memory-saved-evidence-quote>{quote}</pre>}
        <pre data-memory-saved-evidence-fields>{JSON.stringify(entry,null,2)}</pre>
      </div>
    })}
    {evidence.length === 0 && <p data-memory-saved-evidence-unavailable>No source evidence was supplied in the saved record.</p>}
  </div>
}

function CapabilityDetails({controller}:{controller:Controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot)
  const value = state.capabilities
  return <div data-prime-capability-status={state.capability_status}>
    <h2>Disposable preview · qualification pending</h2>
    <p>Source metadata does not prove that memory is loaded or a capability is working.</p>
    {!value && <p>{state.fixture ? 'Synthetic fixture only. Runtime capability status is unavailable.'
      : state.capability_status === 'pending' ? 'Waiting for runtime capability status.' : 'Runtime capability status is unavailable.'}</p>}
    {value && <dl className={css.fields}>
      <div><dt>Source commit</dt><dd><code data-source-commit>{value.source_commit}</code></dd></div>
      <div><dt>Runtime PID</dt><dd data-runtime-pid>{value.runtime_pid}</dd></div>
      <div><dt>Release digest</dt><dd><code data-release-digest>{value.release_digest}</code></dd></div>
    </dl>}
    <ul className={css.capabilities}>{Object.entries(CAPABILITY_LABELS).map(([id,label]) => <li key={id} data-capability={id}>
      {label}: <strong>{value?.unavailable_capabilities.includes(id) ? 'Unavailable' : 'Not qualified'}</strong>
    </li>)}</ul>
  </div>
}

export function CapabilityBadge({controller}:{controller:Controller}) {
  return <details className={css.badge} data-prime-capability-badge data-reserves-hot-corners>
    <summary>Disposable preview · pending</summary>
    <div className={css.badgePanel}><CapabilityDetails controller={controller} /></div>
  </details>
}

export function OwnerMenu({activeSurface,openSurface}:PropsRuntime<'shell.menu.system'>) {
  return <ActionButton className={css.menu} aria-current={activeSurface === 'prime-owner' ? 'page' : undefined}
    data-prime-owner-launcher onClick={() => openSurface('prime-owner', undefined, 'contained')}>Owner access</ActionButton>
}
