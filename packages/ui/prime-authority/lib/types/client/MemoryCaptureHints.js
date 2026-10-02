import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { capturePresentationWarnings } from '../adapters/capture-presentation.mjs';
const POLICY = Object.freeze([
    ['Policy version', '1'], ['Category', 'fact'], ['Confidence', '0.7'], ['Sensitivity', 'none'],
    ['Privacy', 'local'], ['Scope', 'owner'], ['Links', 'empty'], ['Origin', 'prime.capture/v1'],
    ['Body override', 'none (null)'], ['Observed time', 'exact selected source event time'],
    ['Valid from', 'source event calendar date'], ['Evidence', 'derived from the exact selected source event'],
    ['Authority grants', 'none'],
]);
function exampleText(example) {
    const position = `UTF-16 index ${example.index}`;
    if ('code_point' in example) {
        return `${position}: ${example.code_point}${'resembles' in example ? `, ${example.script ?? 'Unicode'} letter resembling ${example.resembles}` : ''}`;
    }
    return `${position}, length ${example.length}: ${example.scripts.join(', ')}`;
}
// Mount only after main's independent draft pairing and host metadata checks.
// This view supplies text hints and documented policy, never authority or normalization.
export function MemoryCaptureHints({ statement }) {
    const warnings = capturePresentationWarnings(statement);
    return _jsxs("div", { "data-memory-capture-hints": true, children: [_jsx("h4", { children: "Text review hints" }), _jsx("p", { children: "Hints aid review and preserve the exact text. Examples use UTF-16 indexes and Unicode code points, with up to 16 examples per category. Greek and Cyrillic lookalike examples are limited, and script mixing can be legitimate." }), warnings.length === 0 && _jsx("p", { "data-memory-no-presentation-hints": true, children: "These limited checks produced no hints. Review the exact statement above." }), warnings.map(warning => _jsxs("div", { "data-memory-unicode-hint": warning.code, children: [_jsx("p", { children: warning.text }), _jsxs("p", { children: ["Occurrences: ", warning.count] }), _jsx("ul", { children: warning.examples.map((example, index) => _jsx("li", { children: _jsx("code", { children: exampleText(example) }) }, index)) })] }, warning.code)), _jsx("h4", { children: "Fixed new-capture policy" }), _jsx("p", { children: "This pilot uses the documented fixed policy for new captures." }), _jsx("dl", { "data-memory-fixed-capture-policy": true, children: POLICY.map(([label, value]) => _jsxs("div", { children: [_jsx("dt", { children: label }), _jsx("dd", { children: value })] }, label)) })] });
}
//# sourceMappingURL=MemoryCaptureHints.js.map