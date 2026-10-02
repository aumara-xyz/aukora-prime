import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
export function AumaReplyView({ result }) {
    if (!result)
        return _jsx("p", { "data-auma-reply-unavailable": true, children: "No Auma reply has been supplied by the owner-bound provider flow." });
    if (result.outcome === 'outcome_unknown')
        return result.reservation_retained === true ? _jsxs("div", { role: "alert", "data-auma-reply-unknown": true, children: [_jsx("p", { children: "The provider result is unconfirmed. The request reservation remains held; do not retry it." }), _jsxs("p", { children: ["Request: ", _jsx("code", { children: result.request_uuid })] })] }) : _jsx("p", { role: "alert", "data-auma-reply-invalid": true, children: "The provider outcome and reservation status are unconfirmed. Do not retry it." });
    if (result.outcome !== 'completed' || result.route_id !== 'externalDeepSeek' ||
        !['mock', 'production'].includes(result.mode ?? '') || result.proposal?.grantsAuthority !== false ||
        typeof result.proposal.text !== 'string' || !result.usage ||
        ![result.usage.input_tokens, result.usage.output_tokens, result.usage.cost_microusd].every(value => Number.isSafeInteger(value) && value >= 0) ||
        !result.receipt || typeof result.receipt !== 'object' || Array.isArray(result.receipt)) {
        return _jsx("p", { role: "alert", "data-auma-reply-invalid": true, children: "The provider result cannot be presented as a completed Auma reply." });
    }
    return _jsxs("div", { "data-auma-reply": true, "data-provider-mode": result.mode, children: [_jsx("h3", { children: result.mode === 'mock' ? 'Auma reply · synthetic provider' : 'Auma reply · provider result' }), _jsx("p", { children: "Model output is a proposal. It grants no authority and has not been saved as memory." }), _jsx("pre", { "data-auma-reply-text": true, children: result.proposal.text }), _jsxs("dl", { children: [_jsx("dt", { children: "Request" }), _jsx("dd", { children: _jsx("code", { children: result.request_uuid }) }), _jsx("dt", { children: "Route" }), _jsx("dd", { children: result.route_id }), _jsx("dt", { children: "Reported input tokens" }), _jsx("dd", { children: result.usage.input_tokens }), _jsx("dt", { children: "Reported output tokens" }), _jsx("dd", { children: result.usage.output_tokens }), _jsx("dt", { children: "Reported cost \u00B7 micro USD" }), _jsx("dd", { children: result.usage.cost_microusd })] }), _jsxs("details", { children: [_jsx("summary", { children: "Exact provider receipt" }), _jsx("pre", { children: JSON.stringify(result.receipt, null, 2) })] })] });
}
//# sourceMappingURL=AumaReplyView.js.map