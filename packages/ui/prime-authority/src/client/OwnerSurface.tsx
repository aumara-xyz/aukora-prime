import { useSyncExternalStore } from 'react'
import { ActionButton, Panel, SectionHeader } from '@aukora/face-layout/client'
import type { PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import type { Controller } from './controller.mjs'
import { CAPABILITY_LABELS } from './controller.mjs'
import css from './OwnerSurface.module.css'

export function OwnerSurface({ activeSurface, controller }: PropsRuntime<'shell.surface'> & {controller:Controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot)
  const busy = state.phase.endsWith('_pending')
  const locked = busy || state.phase === 'outcome_unknown'
  const view = state.presentation
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
        {state.owner && <ActionButton disabled={busy} onClick={() => controller.logout()}>Sign out</ActionButton>}
      </div>
    </Panel>
    <Panel className={css.card}>
      <h2>Exact operation</h2>
      {!state.operation_available && <p>No operation has been supplied by the host.</p>}
      {state.operation_available && <ActionButton disabled={!state.owner || locked || !state.authority_available || state.phase === 'approved' || state.phase === 'denied'}
        onClick={() => { void controller.prepare() }}>Request fresh review</ActionButton>}
      {view && <>
        <dl className={css.fields} data-exact-operation>{view.rows.map(row => <div key={row.key} data-operation-field={row.key}>
          <dt>{row.label} <code>({row.key})</code></dt><dd><pre>{row.exact}</pre></dd></div>)}</dl>
        <p>Operation digest</p><pre data-operation-digest>{view.operation_digest}</pre>
        <p>Review expires: <time data-approval-expiry>{view.approval_expiry}</time></p>
        <p>Fresh review challenge</p><pre data-review-challenge>{JSON.stringify(view.review_challenge, null, 2)}</pre>
        <p>Exact canonical operation</p><pre data-canonical-operation>{view.canonical_operation}</pre>
        <div className={css.actions}>
          <ActionButton variant="gold" disabled={state.phase !== 'review_ready' || state.expired || !state.authority_available}
            onClick={() => { void controller.approve() }}>Approve exact operation</ActionButton>
          <ActionButton variant="red-warning" disabled={state.phase !== 'review_ready' || state.expired || !state.authority_available}
            onClick={() => { void controller.decline() }}>Decline</ActionButton>
        </div>
      </>}
    </Panel>
    <p role="status" aria-live="polite" data-prime-authority-status>{state.reason}</p>
    {state.error_code && <p role="alert" className={css.error} data-authority-error={state.error_code}>{state.error_code}</p>}
    {state.expired && <p role="alert">This session or review has expired.</p>}
  </section>
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
