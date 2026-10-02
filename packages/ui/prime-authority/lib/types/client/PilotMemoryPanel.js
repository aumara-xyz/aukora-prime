import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { ActionButton, Panel } from '@aukora/face-layout/client';
import css from './OwnerSurface.module.css';
function currentOwner(controller, binding, expected) {
    const state = controller.getSnapshot();
    const owner = state.owner;
    const ownerId = binding.client.binding?.owner_id;
    if (binding.ownerController !== controller || typeof ownerId !== 'string' || !ownerId
        || !owner || state.owner_id !== ownerId || owner.owner_id !== ownerId
        || expected && owner !== expected || !state.authority_available || state.expired
        || state.logout_status === 'pending' || !Number.isFinite(Date.parse(owner.expiry))
        || Date.parse(owner.expiry) <= Date.now())
        return null;
    return owner;
}
function attached(client) {
    return !!client.workflow && !!client.forgetWorkflow
        && typeof client.workflow.getSnapshot === 'function' && typeof client.workflow.subscribe === 'function'
        && typeof client.forgetWorkflow.getSnapshot === 'function' && typeof client.forgetWorkflow.subscribe === 'function'
        && ['proposeSave', 'refresh', 'recover', 'recoverForget'].every(name => typeof client[name] === 'function');
}
function Unavailable({ reason }) {
    return _jsxs(Panel, { className: css.card, "data-memory-pilot": true, "data-memory-pilot-unavailable": true, children: [_jsx("h2", { children: "Owner-approved memory" }), _jsx("p", { role: "status", children: reason }), _jsxs("div", { className: css.actions, children: [_jsx(ActionButton, { disabled: true, children: "Read memory recovery" }), _jsx(ActionButton, { disabled: true, children: "Read forget recovery" }), _jsx(ActionButton, { disabled: true, children: "Refresh record" }), _jsx(ActionButton, { disabled: true, children: "Prepare memory proposal" })] })] });
}
export function PilotMemoryPanel({ controller, binding }) {
    useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
    const session = useRef({ binding: undefined, owner: null, key: 0 });
    if (!binding)
        return _jsx(Unavailable, { reason: "The host has not supplied an owner memory client." });
    if (binding.ownerController !== controller || binding.client.binding?.owner_id !== controller.getSnapshot().owner_id) {
        return _jsx(Unavailable, { reason: "The memory client does not match this configured owner controller." });
    }
    if (!attached(binding.client))
        return _jsx(Unavailable, { reason: "The host has not attached the owner memory workflows." });
    const owner = currentOwner(controller, binding);
    if (!owner)
        return _jsx(Unavailable, { reason: "Sign in with the configured owner's current, unexpired credential before reading or proposing memory." });
    if (session.current.binding !== binding || session.current.owner !== owner) {
        session.current = { binding, owner, key: session.current.key + 1 };
    }
    return _jsx(AttachedMemoryPanel, { controller: controller, binding: binding, owner: owner, workflow: binding.client.workflow, forgetWorkflow: binding.client.forgetWorkflow }, session.current.key);
}
function AttachedMemoryPanel({ controller, binding, owner, workflow, forgetWorkflow }) {
    const rendered = useRef({ binding, owner, workflow, forgetWorkflow });
    rendered.current = { binding, owner, workflow, forgetWorkflow };
    const mounted = useRef(true);
    const flight = useRef(null);
    const statementInput = useRef(null);
    const [pending, setPending] = useState(null);
    const [reason, setReason] = useState('Recovery reads existing facts and may deliver an already committed settlement receipt. It does not restore data or repeat an effect.');
    const live = useCallback(() => mounted.current && rendered.current.binding === binding
        && rendered.current.owner === owner && rendered.current.workflow === workflow && rendered.current.forgetWorkflow === forgetWorkflow
        && binding.client.workflow === workflow && binding.client.forgetWorkflow === forgetWorkflow
        && currentOwner(controller, binding, owner) !== null, [controller, binding, owner, workflow, forgetWorkflow]);
    const readMemory = useCallback(() => live() ? workflow.getSnapshot() : null, [live, workflow]);
    const readForget = useCallback(() => live() ? forgetWorkflow.getSnapshot() : null, [live, forgetWorkflow]);
    const memory = useSyncExternalStore(workflow.subscribe, readMemory, readMemory);
    const forget = useSyncExternalStore(forgetWorkflow.subscribe, readForget, readForget);
    const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
    useEffect(() => {
        mounted.current = true;
        return () => { mounted.current = false; flight.current = null; };
    }, []);
    useEffect(() => {
        // A draft remains only in this owner's transient DOM input. Changing the
        // owner or composition clears it without normalizing its original text.
        const input = statementInput.current;
        if (input)
            input.value = '';
        setReason('Recovery reads existing facts and may deliver an already committed settlement receipt. It does not restore data or repeat an effect.');
        setPending(null);
        return () => { if (input)
            input.value = ''; };
    }, [binding, owner, workflow, forgetWorkflow]);
    if (!memory || !forget || !live())
        return _jsx(Unavailable, { reason: "The owner session or memory binding has changed." });
    const busy = pending !== null || state.phase.endsWith('_pending') || state.approval_action_pending
        || state.logout_status === 'pending' || memory.phase.endsWith('_pending') || forget.phase.endsWith('_pending')
        || forget.recovery_status === 'pending';
    const uncertain = state.phase === 'outcome_unknown' || state.error_code === 'OUTCOME_UNKNOWN'
        || state.error_code === 'RECONCILIATION_REQUIRED' || memory.reconciliation_required || forget.reconciliation_required
        || memory.phase === 'outcome_unknown' || forget.phase === 'outcome_unknown'
        || memory.save === 'unknown' || forget.forget === 'unknown'
        || state.approval_action_result?.reconciliation_required === true || state.forget_action_result?.reconciliation_required === true;
    const canRefresh = memory.saved === true && memory.record !== null && memory.operation !== null;
    const randomUuid = typeof globalThis.crypto?.randomUUID === 'function';
    async function run(label, action) {
        if (flight.current || busy || !live())
            return;
        const current = controller.getSnapshot();
        const currentMemory = workflow.getSnapshot(), currentForget = forgetWorkflow.getSnapshot();
        if (current.phase.endsWith('_pending') || current.approval_action_pending || current.logout_status === 'pending'
            || currentMemory.phase.endsWith('_pending') || currentForget.phase.endsWith('_pending')
            || currentForget.recovery_status === 'pending')
            return;
        if (label === 'proposal' && (current.phase === 'outcome_unknown' || current.error_code === 'OUTCOME_UNKNOWN'
            || current.error_code === 'RECONCILIATION_REQUIRED' || currentMemory.reconciliation_required || currentForget.reconciliation_required
            || currentMemory.phase === 'outcome_unknown' || currentForget.phase === 'outcome_unknown'
            || currentMemory.save === 'unknown' || currentForget.forget === 'unknown'
            || current.approval_action_result?.reconciliation_required || current.forget_action_result?.reconciliation_required))
            return;
        if (!live())
            return;
        const token = {};
        flight.current = token;
        setPending(label);
        try {
            const result = await action();
            if (flight.current !== token || !live())
                return;
            setReason(result.reconciliation_required
                ? 'The outcome still requires reconciliation. Do not repeat the attempted effect.'
                : result.error_code ? `The memory request was refused or unavailable: ${result.error_code}.`
                    : label === 'proposal' ? 'The proposal is prepared. Use Exact operation to request a fresh review and approve it explicitly.'
                        : 'The current workflow facts are shown below. No effect was retried.');
        }
        catch {
            if (flight.current === token && live())
                setReason('The memory request is unavailable or its outcome is unconfirmed. No effect was retried.');
        }
        finally {
            if (flight.current === token) {
                flight.current = null;
                if (live())
                    setPending(null);
            }
        }
    }
    return _jsxs(Panel, { className: css.card, "data-memory-pilot": true, children: [_jsx("h2", { children: "Owner-approved memory" }), _jsx("p", { children: "Read the current workflow directly, including recovery after a fresh owner session. Storage, indexing, citation and authority settlement remain separate facts." }), _jsxs("div", { className: css.actions, children: [_jsx(ActionButton, { disabled: busy, onClick: () => { void run('memory recovery', () => binding.client.recover({ operation_id: null })); }, children: "Read memory recovery" }), _jsx(ActionButton, { disabled: busy, onClick: () => { void run('forget recovery', () => binding.client.recoverForget({ operation_id: null })); }, children: "Read forget recovery" }), _jsx(ActionButton, { disabled: busy || !canRefresh, onClick: () => { void run('record refresh', () => binding.client.refresh()); }, children: "Refresh record" })] }), !canRefresh && _jsx("p", { "data-memory-refresh-unavailable": true, children: "Refresh requires an active confirmed save. Read recovery to inspect retained facts after a fresh session." }), _jsxs("form", { onSubmit: event => {
                    event.preventDefault();
                    const statement = statementInput.current?.value;
                    if (busy || uncertain || !randomUuid || !live())
                        return;
                    if (typeof statement !== 'string' || !statement.trim() || statement.length > 4096) {
                        setReason('Enter a nonblank literal statement of at most 4,096 characters before preparing a proposal.');
                        return;
                    }
                    // Preserve the complete literal statement. The worker supplies the source,
                    // attribution and fixed metadata; its existing policy admits or refuses it.
                    void run('proposal', () => binding.client.proposeSave({
                        extraction_json: JSON.stringify({ statement }), idempotency_key: globalThis.crypto.randomUUID(),
                    }));
                }, children: [_jsxs("label", { className: css.owner, children: ["Literal memory statement", _jsx("textarea", { ref: statementInput, "aria-label": "Literal memory statement", autoComplete: "off", spellCheck: false, disabled: busy || uncertain, rows: 4 })] }), _jsx("p", { children: "Preparing a proposal does not save memory. Use the existing Exact operation card to request a fresh review, inspect the exact source quotation and approve explicitly. New capture text must already satisfy the worker's text policy." }), _jsx("div", { className: css.actions, children: _jsx(ActionButton, { disabled: busy || uncertain || !randomUuid, onClick: () => { statementInput.current?.form?.requestSubmit(); }, children: "Prepare memory proposal" }) })] }), !randomUuid && _jsx("p", { role: "status", children: "A secure browser UUID is unavailable; proposal preparation is disabled." }), uncertain && _jsx("p", { role: "alert", "data-memory-pilot-uncertain": true, children: "An attempted operation remains unresolved. New memory proposals are disabled; read recovery without repeating the effect." }), _jsx("p", { role: "status", "aria-live": "polite", "data-memory-pilot-status": true, children: pending ? `Reading or preparing ${pending}.` : reason }), _jsx(MemoryFacts, { snapshot: memory }), _jsx(ForgetFacts, { snapshot: forget })] });
}
const booleanFact = (value) => value === null ? 'Unconfirmed' : value ? 'Yes' : 'No';
function MemoryFacts({ snapshot }) {
    const record = snapshot.saved === true ? snapshot.record : null;
    const evidence = record && Array.isArray(record.evidence) ? record.evidence : [];
    return _jsxs("div", { "data-memory-pilot-facts": true, children: [_jsx("h3", { children: "Memory workflow and retained save facts" }), _jsxs("dl", { className: css.fields, children: [_jsxs("div", { children: [_jsx("dt", { children: "Workflow" }), _jsx("dd", { children: snapshot.phase })] }), _jsxs("div", { children: [_jsx("dt", { children: "Approval" }), _jsx("dd", { children: snapshot.approval })] }), _jsxs("div", { children: [_jsx("dt", { children: "Save" }), _jsx("dd", { children: snapshot.save })] }), _jsxs("div", { children: [_jsx("dt", { children: "Saved" }), _jsx("dd", { children: booleanFact(snapshot.saved) })] }), _jsxs("div", { children: [_jsx("dt", { children: "Storage" }), _jsx("dd", { children: typeof record?.storage_status === 'string' ? record.storage_status : 'Unconfirmed' })] }), _jsxs("div", { children: [_jsx("dt", { children: "Index" }), _jsxs("dd", { children: [snapshot.index.status, "; indexed: ", booleanFact(snapshot.index.indexed), "; searchable: ", booleanFact(snapshot.index.searchable)] })] }), _jsxs("div", { children: [_jsx("dt", { children: "Citation" }), _jsx("dd", { children: snapshot.citation_status })] }), _jsxs("div", { children: [_jsx("dt", { children: "Authority settlement" }), _jsx("dd", { children: snapshot.authority_settlement ?? 'Unconfirmed' })] }), _jsxs("div", { children: [_jsx("dt", { children: "Operation digest" }), _jsx("dd", { children: _jsx("pre", { children: snapshot.operation_digest ?? 'Unavailable' }) })] }), _jsxs("div", { children: [_jsx("dt", { children: "Receipt digest" }), _jsx("dd", { children: _jsx("pre", { children: snapshot.receipt_digest ?? 'Unavailable' }) })] })] }), snapshot.error_code && _jsxs("p", { role: "status", children: ["Memory request status: ", snapshot.error_code] }), snapshot.read_error_code && _jsxs("p", { role: "status", children: ["Index or citation read unavailable: ", snapshot.read_error_code] }), record && _jsxs("div", { "data-memory-pilot-saved-content": true, children: [_jsx("h3", { children: "Exact saved canonical bytes" }), _jsx("pre", { children: typeof record.canonical_bytes === 'string' ? record.canonical_bytes : 'Unavailable' }), _jsx("h3", { children: "Exact saved source evidence" }), evidence.map((entry, index) => {
                        const quote = entry && typeof entry === 'object' && 'quote' in entry ? entry.quote : null;
                        return _jsxs("div", { children: [typeof quote === 'string' && _jsx("pre", { "data-memory-pilot-evidence-quote": true, children: quote }), _jsx("pre", { children: JSON.stringify(entry, null, 2) })] }, index);
                    }), evidence.length === 0 && _jsx("p", { children: "No source evidence was supplied in this record." })] }), snapshot.receipt && _jsxs("details", { children: [_jsx("summary", { children: "Exact retained save receipt" }), _jsx("pre", { children: JSON.stringify(snapshot.receipt, null, 2) })] }), snapshot.citation && _jsxs("details", { children: [_jsx("summary", { children: "Exact retained citation" }), _jsx("pre", { children: JSON.stringify(snapshot.citation, null, 2) })] })] });
}
function ForgetFacts({ snapshot }) {
    return _jsxs("div", { "data-memory-pilot-forget-facts": true, children: [_jsx("h3", { children: "Logical-forget recovery facts" }), _jsxs("dl", { className: css.fields, children: [_jsxs("div", { children: [_jsx("dt", { children: "Workflow" }), _jsx("dd", { children: snapshot.phase })] }), _jsxs("div", { children: [_jsx("dt", { children: "Recovery" }), _jsx("dd", { children: snapshot.recovery_status })] }), _jsxs("div", { children: [_jsx("dt", { children: "Approval" }), _jsx("dd", { children: snapshot.approval })] }), _jsxs("div", { children: [_jsx("dt", { children: "Logical forget" }), _jsx("dd", { children: snapshot.forget })] }), _jsxs("div", { children: [_jsx("dt", { children: "Forgotten" }), _jsx("dd", { children: booleanFact(snapshot.forgotten) })] }), _jsxs("div", { children: [_jsx("dt", { children: "Authority settlement" }), _jsx("dd", { children: snapshot.authority_settlement ?? 'Unconfirmed' })] }), _jsxs("div", { children: [_jsx("dt", { children: "Recovery operation" }), _jsx("dd", { children: _jsx("pre", { children: snapshot.recovery_operation_id ?? 'Unavailable' }) })] }), _jsxs("div", { children: [_jsx("dt", { children: "Receipt digest" }), _jsx("dd", { children: _jsx("pre", { children: snapshot.receipt_digest ?? 'Unavailable' }) })] })] }), snapshot.error_code && _jsxs("p", { role: "status", children: ["Forget request status: ", snapshot.error_code] }), snapshot.forgotten === true && _jsx("p", { children: "Logical forget removed visibility. Canonical payloads, authority history, backups, WAL and physical media remain retained." }), snapshot.result && _jsxs("details", { children: [_jsx("summary", { children: "Exact logical-forget result" }), _jsx("pre", { children: JSON.stringify(snapshot.result, null, 2) })] }), snapshot.receipt && _jsxs("details", { children: [_jsx("summary", { children: "Exact retained forget receipt" }), _jsx("pre", { children: JSON.stringify(snapshot.receipt, null, 2) })] })] });
}
//# sourceMappingURL=PilotMemoryPanel.js.map