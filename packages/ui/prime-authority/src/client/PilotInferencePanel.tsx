// SPDX-License-Identifier: AGPL-3.0-or-later
import { useRef, useSyncExternalStore } from 'react'
import { ActionButton, Panel } from '@aukora/face-layout/client'
import type { PilotInferenceController } from './inference-controller.mjs'
import { AumaReplyView } from './AumaReplyView'
import css from './OwnerSurface.module.css'

export function PilotInferencePanel({controller}:{controller?:PilotInferenceController}) {
  if (!controller) return <Panel className={css.card} data-auma-pilot data-auma-pilot-unavailable>
    <h2>One Auma reply</h2><AumaReplyView result={null} />
    <div className={css.actions}><ActionButton disabled>Request one Auma reply</ActionButton></div>
    <p>The host has not supplied an owner-bound reply client. Model choice and a configured key alone do not enable a provider call.</p>
  </Panel>
  return <ConnectedInferencePanel controller={controller} />
}

function ConnectedInferencePanel({controller}:{controller:PilotInferenceController}) {
  const state = useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot)
  const draft = useRef<HTMLTextAreaElement>(null)
  // A new host context or owner lifetime removes the previous transient input.
  return <Panel className={css.card} data-auma-pilot data-auma-pilot-phase={state.phase}>
    <h2>One Auma reply</h2>
    <p role="status">{state.reason}</p>
    {state.mode === 'mock' && <p role="alert" data-auma-synthetic>Explicit synthetic provider flow. This is not live inference.</p>}
    {state.context && <dl className={css.fields}>
      <div><dt>Owner</dt><dd><code>{state.context.owner_id}</code></dd></div>
      <div><dt>Task</dt><dd><code>{state.context.task_id}</code></dd></div>
      <div><dt>Conversation</dt><dd><code>{state.context.conversation_id}</code></dd></div>
    </dl>}
    <label className={css.owner}>Message to Auma<textarea key={state.generation} ref={draft} rows={4} autoComplete="off"
      aria-label="Message to Auma" disabled={!state.available} /></label>
    <div className={css.actions}><ActionButton disabled={!state.available}
      onClick={() => {const text=draft.current?.value;if (text !== undefined) void controller.request(text)}}>Request one Auma reply</ActionButton></div>
    {state.request_uuid && <p>Request: <code>{state.request_uuid}</code></p>}
    {state.phase === 'outcome_unknown' && !state.result && <p role="alert" data-auma-request-unconfirmed>
      The reply is unconfirmed. No reservation or cancellation outcome has been supplied. Do not retry this request.
    </p>}
    <AumaReplyView result={state.result} />
    <p>This request uses the host's existing exact-operation approval flow. It does not sign or approve automatically.</p>
  </Panel>
}
