import { capturePresentationWarnings } from '../../../adapters/capture-presentation.mjs'
import type { CapturePresentationExample } from '../../../adapters/capture-presentation.mjs'

const POLICY = Object.freeze([
  ['Policy version', '1'], ['Category', 'fact'], ['Confidence', '0.7'], ['Sensitivity', 'none'],
  ['Privacy', 'local'], ['Scope', 'owner'], ['Links', 'empty'], ['Origin', 'prime.capture/v1'],
  ['Body override', 'none (null)'], ['Observed time', 'exact selected source event time'],
  ['Valid from', 'source event calendar date'], ['Evidence', 'derived from the exact selected source event'],
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
export function MemoryCaptureHints({statement}:{statement:string}) {
  const warnings = capturePresentationWarnings(statement)
  return <div data-memory-capture-hints>
    <h4>Text review hints</h4>
    <p>Hints aid review and preserve the exact text. Examples use UTF-16 indexes and Unicode code points, with up to 16 examples per category.
      Greek and Cyrillic lookalike examples are limited, and script mixing can be legitimate.</p>
    {warnings.length === 0 && <p data-memory-no-presentation-hints>These limited checks produced no hints. Review the exact statement above.</p>}
    {warnings.map(warning => <div key={warning.code} data-memory-unicode-hint={warning.code}>
      <p>{warning.text}</p><p>Occurrences: {warning.count}</p>
      <ul>{warning.examples.map((example,index) => <li key={index}><code>{exampleText(example)}</code></li>)}</ul>
    </div>)}
    <h4>Fixed new-capture policy</h4>
    <p>This pilot uses the documented fixed policy for new captures.</p>
    <dl data-memory-fixed-capture-policy>{POLICY.map(([label,value]) => <div key={label}>
      <dt>{label}</dt><dd>{value}</dd>
    </div>)}</dl>
  </div>
}
