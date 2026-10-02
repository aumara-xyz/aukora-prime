import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { capturePresentationWarnings } from '../adapters/capture-presentation.mjs';
import { CAPTURE_TEXT_POLICY } from '../adapters/capture-review.mjs';
const POLICY = Object.freeze([
    ['Privacy', 'local'], ['Scope', 'owner'], ['Links', 'empty'], ['Origin', 'prime.capture/v1'],
    ['Body override', 'none (null)'], ['Evidence', 'derived from the exact selected source event'],
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
export function MemoryCaptureHints({ statement, evidenceQuote, metadata }) {
    return _jsxs("div", { "data-memory-capture-hints": true, children: [_jsx("h4", { children: "Text review hints" }), _jsx("p", { children: "Hints aid review and preserve the exact text. Examples use UTF-16 indexes and Unicode code points, with up to 16 examples per category. Greek and Cyrillic lookalike examples are limited, and script mixing can be legitimate." }), _jsx(TextHints, { text: statement, label: "Captured statement", field: "statement" }), _jsx(TextHints, { text: evidenceQuote, label: "Source quotation", field: "evidence_quote" }), _jsxs("div", { "data-new-capture-text-policy": true, children: [_jsx("p", { children: "New statements and source quotations must already use NFC, with visible nonblank content. Their text is never normalized or replaced." }), _jsx("p", { children: "Tabs, line feeds, ZWNJ and ZWJ are permitted. Other C0 and C1 controls, DEL, and other Unicode format controls are refused." }), _jsxs("p", { children: ["Refused invisible fillers: ", _jsx("code", { children: CAPTURE_TEXT_POLICY.refused_fillers.join(', ') }), "."] }), _jsxs("p", { children: ["Refused line separators: ", _jsx("code", { children: CAPTURE_TEXT_POLICY.refused_line_separators.join(', ') }), ". Existing saved bytes retain their original text."] })] }), _jsx("h4", { children: "Fixed new-capture policy" }), metadata ? _jsxs(_Fragment, { children: [_jsx("p", { children: "The host supplied these exact metadata values for the reviewed operation." }), _jsx("dl", { "data-memory-fixed-capture-policy": true, children: [
                            ['Profile', metadata.profile], ['Category', metadata.category], ['Confidence percent', String(metadata.confidence_percent)],
                            ['Sensitivity', metadata.sensitivity], ['Observed at', metadata.observed_at], ['Valid from', metadata.valid_from], ...POLICY,
                        ].map(([label, value]) => _jsxs("div", { children: [_jsx("dt", { children: label }), _jsx("dd", { children: value })] }, label)) }), _jsx("pre", { "data-fixed-capture-metadata": true, children: JSON.stringify(metadata, null, 2) })] }) : _jsx("p", { "data-fixed-capture-metadata-unavailable": true, children: "The host has not supplied fixed capture metadata. Approval requires all exact metadata fields." })] });
}
function TextHints({ text, label, field }) {
    const warnings = capturePresentationWarnings(text);
    return _jsxs("div", { "data-memory-unicode-field": field, children: [_jsx("h5", { children: label }), warnings.length === 0 && _jsx("p", { "data-memory-no-presentation-hints": true, children: "These limited checks produced no hints. Review the exact text above." }), warnings.map(warning => _jsxs("div", { "data-memory-unicode-hint": warning.code, children: [_jsx("p", { children: warning.text }), _jsxs("p", { children: ["Occurrences: ", warning.count] }), _jsx("ul", { children: warning.examples.map((example, index) => _jsx("li", { children: _jsx("code", { children: exampleText(example) }) }, index)) })] }, warning.code))] });
}
//# sourceMappingURL=MemoryCaptureHints.js.map