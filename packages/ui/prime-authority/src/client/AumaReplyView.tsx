// SPDX-License-Identifier: AGPL-3.0-or-later
// Read-only projection of E's existing InferenceResult at frozen fbbb1ae.
// The owner/task-bound transport supplies this result; this view sends nothing.
interface BodyReceipt {
  readonly sessionId:string;readonly line:string;readonly turn:number;readonly spokenAt:number
  readonly request_uuid:string;readonly body_sha256:string
  readonly source_citation:{readonly sessionId:string;readonly turn:number;readonly sha256:string;readonly requestId:string}
  readonly citations:readonly {readonly source_id:string;readonly url:string;readonly captured_at:string;readonly span_sha256:string}[]
}
export type PilotInferenceResult = {
  readonly outcome:'completed'
  readonly request_uuid:string
  readonly mode:'mock'|'production'
  readonly route_id:'externalDeepSeek'
  readonly proposal:{readonly text:string;readonly source_ids:readonly string[];readonly grantsAuthority:false}
  readonly usage:{readonly input_tokens:number;readonly output_tokens:number;readonly cost_microusd:number}
  readonly receipt:BodyReceipt
  readonly omitted:readonly {readonly reason:string}[]
} | {
  readonly outcome:'outcome_unknown';readonly request_uuid:string;readonly receipt:BodyReceipt
  readonly error:string;readonly reservation_retained:true
}

export function AumaReplyView({result}:{result:PilotInferenceResult|null}) {
  if (!result) return <p data-auma-reply-unavailable>No Auma reply has been supplied by the owner-bound provider flow.</p>
  if (result.outcome === 'outcome_unknown') return result.reservation_retained === true ? <div role="alert" data-auma-reply-unknown>
    <p>The provider result is unconfirmed. The request reservation remains held; do not retry it.</p>
    <p>Request: <code>{result.request_uuid}</code></p>
  </div> : <p role="alert" data-auma-reply-invalid>The provider outcome and reservation status are unconfirmed. Do not retry it.</p>
  if (result.outcome !== 'completed' || result.route_id !== 'externalDeepSeek' ||
      !['mock','production'].includes(result.mode ?? '') || result.proposal?.grantsAuthority !== false ||
      typeof result.proposal.text !== 'string' || !result.usage ||
      ![result.usage.input_tokens,result.usage.output_tokens,result.usage.cost_microusd].every(value => Number.isSafeInteger(value) && value >= 0) ||
      !result.receipt || typeof result.receipt !== 'object' || Array.isArray(result.receipt)) {
    return <p role="alert" data-auma-reply-invalid>The provider result cannot be presented as a completed Auma reply.</p>
  }
  return <div data-auma-reply data-provider-mode={result.mode}>
    <h3>{result.mode === 'mock' ? 'Auma reply · synthetic provider' : 'Auma reply · provider result'}</h3>
    <p>Model output is a proposal. It grants no authority and has not been saved as memory.</p>
    <pre data-auma-reply-text>{result.proposal.text}</pre>
    <dl>
      <dt>Request</dt><dd><code>{result.request_uuid}</code></dd>
      <dt>Route</dt><dd>{result.route_id}</dd>
      <dt>Reported input tokens</dt><dd>{result.usage.input_tokens}</dd>
      <dt>Reported output tokens</dt><dd>{result.usage.output_tokens}</dd>
      <dt>Reported cost · micro USD</dt><dd>{result.usage.cost_microusd}</dd>
    </dl>
    <details><summary>Exact provider receipt</summary><pre>{JSON.stringify(result.receipt,null,2)}</pre></details>
  </div>
}
