import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useRef, useSyncExternalStore } from 'react';
import styles from './PrimeProviderEditor.module.css';
function ReadOnlyField({ label, value }) {
    return _jsxs("label", { className: styles['field'], children: [_jsx("span", { className: styles['fieldLabel'], children: label }), _jsx("input", { className: styles['input'], value: value, readOnly: true, "aria-label": label })] });
}
export function PrimeProviderEditor({ provider, controller }) {
    const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
    const keyInput = useRef(null);
    const matching = provider.provider === 'externalDeepSeek' && provider.settingsNs === 'prime-inference'
        && provider.settingsPath.length === 2 && provider.settingsPath[0] === 'providers' && provider.settingsPath[1] === 'externalDeepSeek';
    const entryReady = matching && state.entry_status === 'ready' && state.owner_status === 'loaded';
    useEffect(() => { if (matching)
        void controller.load(); }, [controller, matching]);
    useEffect(() => { if (!entryReady && keyInput.current)
        keyInput.current.value = ''; }, [entryReady]);
    useEffect(() => { const input = keyInput.current; return () => { if (input)
        input.value = ''; }; }, [matching]);
    if (!matching)
        return null;
    const row = state.row;
    const ceiling = row.taskSpendCeiling === null ? 'Not configured'
        : `${row.taskSpendCeiling.amount} ${row.taskSpendCeiling.currency}`;
    return _jsxs("div", { className: styles['editor'], "data-prime-provider-editor": true, "data-provider": "externalDeepSeek", children: [_jsxs("div", { className: styles['editorHeader'], children: [_jsx("span", { className: styles['editorTitle'], children: "DeepSeek" }), _jsx("span", { className: styles['editorRoute'], children: "externalDeepSeek" })] }), _jsx(ReadOnlyField, { label: "Endpoint", value: row.endpoint }), _jsxs("label", { className: styles['field'], children: [_jsx("span", { className: styles['fieldLabel'], children: "Draft model" }), _jsxs("select", { className: `${styles['input']} ${styles['selectInput']}`, "aria-label": "Draft model", value: state.model_draft === 'deepseek-flash' ? 'deepseek-flash' : '', onChange: event => { if (event.target.value === 'deepseek-flash')
                            controller.setModel(event.target.value); }, children: [_jsx("option", { value: "", disabled: true, children: "Choose a model" }), _jsx("option", { value: "deepseek-flash", children: "DeepSeek V4.1 Flash (deepseek-flash)" })] }), _jsx("p", { className: styles['advancedHint'], children: "This selection is a local draft. Configuration changes require separate owner approval." })] }), _jsx(ReadOnlyField, { label: "Configured model", value: row.model || (state.owner_status === 'loaded' ? 'Not configured' : 'Unconfirmed') }), _jsxs("details", { className: styles['customized'], children: [_jsx("summary", { className: styles['customizedSummary'], children: "Current task limits \u00B7 read-only" }), _jsxs("div", { className: styles['customizedBody'], children: [_jsx(ReadOnlyField, { label: "Region", value: row.region || 'Not configured' }), _jsx(ReadOnlyField, { label: "Allowed data classes", value: row.allowedDataClasses.join(', ') || 'None configured' }), _jsx(ReadOnlyField, { label: "Maximum input tokens", value: String(row.maxInputTokens) }), _jsx(ReadOnlyField, { label: "Maximum output tokens", value: String(row.maxOutputTokens) }), _jsx(ReadOnlyField, { label: "Maximum requests", value: String(row.maxRequests) }), _jsx(ReadOnlyField, { label: "Task spend ceiling", value: ceiling })] })] }), _jsxs("p", { className: styles['advancedHint'], "data-prime-provider-readiness": true, children: ["Catalog: ", state.catalog_status, ". Owner status: ", state.owner_status, ". Key entry: ", state.entry_status, "."] }), _jsxs("p", { className: styles['advancedHint'], children: ["Credential status: ", state.owner_status === 'loaded' && row.credentialConfigured ? 'Owner status reports configured' : 'Not confirmed configured', "."] }), _jsxs("form", { onSubmit: event => {
                    event.preventDefault();
                    if (entryReady && keyInput.current)
                        void controller.submitCredential(keyInput.current);
                }, children: [_jsxs("label", { className: styles['field'], children: [_jsx("span", { className: styles['fieldLabel'], children: "API key \u00B7 approved owner handoff" }), _jsx("input", { ref: keyInput, className: styles['input'], type: "password", autoComplete: "off", autoCapitalize: "none", spellCheck: false, "aria-label": "DeepSeek API key", disabled: !entryReady })] }), _jsxs("div", { className: styles['editorActions'], children: [_jsx("button", { type: "button", className: styles['secondaryButton'], disabled: state.owner_status === 'pending' || state.entry_status === 'pending', onClick: () => { void controller.refreshOwner(); }, children: "Refresh owner status" }), _jsx("button", { type: "submit", className: styles['primaryButton'], disabled: !entryReady, children: "Store key with approved handoff" })] })] }), !entryReady && _jsx("p", { className: styles['advancedHint'], "data-prime-provider-entry-help": true, children: "Sign in through Owner access and refresh owner status. Secure key-entry approval must be supplied by the owner/provider flow; its approval control is not mounted in this source preview. The key field stays disabled until a fresh single-use handoff to separate credential storage is supplied. This flow requires its qualified HTTPS origin; the localhost passkey profile does not enable key entry." }), _jsx("p", { className: styles['advancedHint'], role: "status", "aria-live": "polite", "data-prime-provider-reason": true, children: state.reason })] });
}
//# sourceMappingURL=PrimeProviderEditor.js.map