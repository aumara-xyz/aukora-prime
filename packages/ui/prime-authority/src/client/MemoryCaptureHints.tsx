import { capturePresentationWarnings } from '../../../adapters/capture-presentation.mjs'
import type { CapturePresentationExample } from '../../../adapters/capture-presentation.mjs'
import type {CaptureMetadata} from '../../../adapters/capture-metadata.mjs'
import { CAPTURE_TEXT_POLICY } from '../../../adapters/capture-review.mjs'

const POLICY = Object.freeze([
  ['Privacy', 'local'], ['Scope', 'owner'], ['Links', 'empty'], ['Origin', 'prime.capture/v1'],
  ['Body override', 'none (null)'], ['Evidence', 'derived from the exact selected source event'],
  ['Authority grants', 'none'],
] as const)

function exampleText(example:CapturePresentationExample):string {
  const position = `UTF-16 index ${example.index}`
  if ('code_point' in example) {
    return `${position}: ${example.code_point}${'resembles' in example ? `, ${example.script ?? 'Unicode'} letter resembling ${example.resembles}` : ''}`
  }
  return `${position}, length ${example.length}: ${example.scripts.join(', ')}`
}

// Mount only after main's independent draft pairing and host metadata checks.
// This view supplies text hints and documented policy, never authority or normalization.
export function MemoryCaptureHints({statement,evidenceQuote,metadata}:{statement:string;evidenceQuote:string;metadata:CaptureMetadata|null}) {
  return <div data-memory-capture-hints>
    <h4>Text review hints</h4>
    <p>Hints aid review and preserve the exact text. Examples use UTF-16 indexes and Unicode code points, with up to 16 examples per category.
      Greek and Cyrillic lookalike examples are limited, and script mixing can be legitimate.</p>
    <TextHints text={statement} label="Captured statement" field="statement" />
    <TextHints text={evidenceQuote} label="Source quotation" field="evidence_quote" />
    <div data-new-capture-text-policy>
      <p>New statements and source quotations must already use NFC, with visible nonblank content. Their text is never normalized or replaced.</p>
      <p>Tabs, line feeds, ZWNJ and ZWJ are permitted. Other C0 and C1 controls, DEL, and other Unicode format controls are refused.</p>
      <p>Refused invisible fillers: <code>{CAPTURE_TEXT_POLICY.refused_fillers.join(', ')}</code>.</p>
      <p>Refused line separators: <code>{CAPTURE_TEXT_POLICY.refused_line_separators.join(', ')}</code>. Existing saved bytes retain their original text.</p>
    </div>
    <h4>Fixed new-capture policy</h4>
    {metadata ? <>
    <p>The host supplied these exact metadata values for the reviewed operation.</p>
    <dl data-memory-fixed-capture-policy>{([
      ['Profile',metadata.profile],['Category',metadata.category],['Confidence percent',String(metadata.confidence_percent)],
      ['Sensitivity',metadata.sensitivity],['Observed at',metadata.observed_at],['Valid from',metadata.valid_from],...POLICY,
    ] as const).map(([label,value]) => <div key={label}>
      <dt>{label}</dt><dd>{value}</dd>
    </div>)}</dl>
    <pre data-fixed-capture-metadata>{JSON.stringify(metadata,null,2)}</pre>
    </> : <p data-fixed-capture-metadata-unavailable>The host has not supplied fixed capture metadata. Approval requires all exact metadata fields.</p>}
  </div>
}

function TextHints({text,label,field}:{text:string;label:string;field:'statement'|'evidence_quote'}) {
  const warnings = capturePresentationWarnings(text)
  return <div data-memory-unicode-field={field}><h5>{label}</h5>
    {warnings.length === 0 && <p data-memory-no-presentation-hints>These limited checks produced no hints. Review the exact text above.</p>}
    {warnings.map(warning => <div key={warning.code} data-memory-unicode-hint={warning.code}>
      <p>{warning.text}</p><p>Occurrences: {warning.count}</p>
      <ul>{warning.examples.map((example,index) => <li key={index}><code>{exampleText(example)}</code></li>)}</ul>
    </div>)}
  </div>
}
