import { useEffect, useRef, useSyncExternalStore } from 'react'
import type { Controller } from './provider-controller.mjs'
import styles from './PrimeProviderEditor.module.css'

// Exact plain interfaces copied from pinned DSH ui-settings-models store.ts
// and slot-contract.ts (MIT). These do not augment or replace the native SlotMap.
export interface ProviderDirectoryEntry {
  readonly provider:string
  readonly displayName:string
  readonly settingsNs:string
  readonly settingsPath:readonly string[]
  readonly active:boolean
  readonly declared?:boolean
  readonly error?:string
}
export interface ProviderCardExtrasOwnerProps {
  provider:ProviderDirectoryEntry
  configured:boolean
  keyConfigured:boolean
}
export type PrimeProviderEditorProps=ProviderCardExtrasOwnerProps & {controller:Controller}

function ReadOnlyField({label,value}:{label:string;value:string}) {
  return <label className={styles['field']}>
    <span className={styles['fieldLabel']}>{label}</span>
    <input className={styles['input']} value={value} readOnly aria-label={label} />
  </label>
}

export function PrimeProviderEditor({provider,controller}:PrimeProviderEditorProps) {
  const state = useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot)
  const keyInput = useRef<HTMLInputElement>(null)
  const matching = provider.provider === 'externalDeepSeek' && provider.settingsNs === 'prime-inference'
    && provider.settingsPath.length === 2 && provider.settingsPath[0] === 'providers' && provider.settingsPath[1] === 'externalDeepSeek'
  const entryReady = matching && state.entry_status === 'ready' && state.owner_status === 'loaded'
  useEffect(() => { if (matching) void controller.load() },[controller,matching])
  useEffect(() => { if (!entryReady && keyInput.current) keyInput.current.value = '' },[entryReady])
  useEffect(() => { const input = keyInput.current; return () => { if (input) input.value = '' } },[matching])
  if (!matching) return null
  const row = state.row
  const ceiling = row.taskSpendCeiling === null ? 'Not configured'
    : `${row.taskSpendCeiling.amount} ${row.taskSpendCeiling.currency}`
  return <div className={styles['editor']} data-prime-provider-editor data-provider="externalDeepSeek">
    <div className={styles['editorHeader']}>
      <span className={styles['editorTitle']}>DeepSeek</span>
      <span className={styles['editorRoute']}>externalDeepSeek</span>
    </div>
    <ReadOnlyField label="Endpoint" value={row.endpoint} />
    <label className={styles['field']}>
      <span className={styles['fieldLabel']}>Draft model</span>
      <select className={`${styles['input']} ${styles['selectInput']}`} aria-label="Draft model"
        value={state.model_draft === 'deepseek-flash' ? 'deepseek-flash' : ''}
        onChange={event => { if (event.target.value === 'deepseek-flash') controller.setModel(event.target.value) }}>
        <option value="" disabled>Choose a model</option>
        <option value="deepseek-flash">DeepSeek V4.1 Flash (deepseek-flash)</option>
      </select>
      <p className={styles['advancedHint']}>This selection is a local draft. Configuration changes require separate owner approval.</p>
    </label>
    <ReadOnlyField label="Configured model" value={row.model || (state.owner_status === 'loaded' ? 'Not configured' : 'Unconfirmed')} />
    <details className={styles['customized']}>
      <summary className={styles['customizedSummary']}>Current task limits · read-only</summary>
      <div className={styles['customizedBody']}>
        <ReadOnlyField label="Region" value={row.region || 'Not configured'} />
        <ReadOnlyField label="Allowed data classes" value={row.allowedDataClasses.join(', ') || 'None configured'} />
        <ReadOnlyField label="Maximum input tokens" value={String(row.maxInputTokens)} />
        <ReadOnlyField label="Maximum output tokens" value={String(row.maxOutputTokens)} />
        <ReadOnlyField label="Maximum requests" value={String(row.maxRequests)} />
        <ReadOnlyField label="Task spend ceiling" value={ceiling} />
      </div>
    </details>
    <p className={styles['advancedHint']} data-prime-provider-readiness>
      Catalog: {state.catalog_status}. Owner status: {state.owner_status}. Key entry: {state.entry_status}.
    </p>
    <p className={styles['advancedHint']}>
      Credential status: {state.owner_status === 'loaded' && row.credentialConfigured ? 'Owner status reports configured' : 'Not confirmed configured'}.
    </p>
    <form onSubmit={event => {
      event.preventDefault()
      if (entryReady && keyInput.current) void controller.submitCredential(keyInput.current)
    }}>
      <label className={styles['field']}>
        <span className={styles['fieldLabel']}>API key · approved owner handoff</span>
        <input ref={keyInput} className={styles['input']} type="password" autoComplete="off" autoCapitalize="none"
          spellCheck={false} aria-label="DeepSeek API key" disabled={!entryReady} />
      </label>
      <div className={styles['editorActions']}>
        <button type="button" className={styles['secondaryButton']} disabled={state.owner_status === 'pending' || state.entry_status === 'pending'}
          onClick={() => { void controller.refreshOwner() }}>Refresh owner status</button>
        <button type="submit" className={styles['primaryButton']} disabled={!entryReady}>Store key with approved handoff</button>
      </div>
    </form>
    <p className={styles['advancedHint']} role="status" aria-live="polite" data-prime-provider-reason>{state.reason}</p>
  </div>
}
