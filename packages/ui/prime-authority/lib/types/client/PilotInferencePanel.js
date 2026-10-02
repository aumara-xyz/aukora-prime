import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useRef, useSyncExternalStore } from 'react';
import { ActionButton, Panel } from '@aukora/face-layout/client';
import { AumaReplyView } from './AumaReplyView';
import css from './OwnerSurface.module.css';
export function PilotInferencePanel({ controller }) {
    if (!controller)
        return _jsxs(Panel, { className: css.card, "data-auma-pilot": true, "data-auma-pilot-unavailable": true, children: [_jsx("h2", { children: "One Auma reply" }), _jsx(AumaReplyView, { result: null }), _jsx("div", { className: css.actions, children: _jsx(ActionButton, { disabled: true, children: "Request one Auma reply" }) }), _jsx("p", { children: "The host has not supplied an owner-bound reply client. Model choice and a configured key alone do not enable a provider call." })] });
    return _jsx(ConnectedInferencePanel, { controller: controller });
}
function ConnectedInferencePanel({ controller }) {
    const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
    const draft = useRef(null);
    // A new host context or owner lifetime removes the previous transient input.
    return _jsxs(Panel, { className: css.card, "data-auma-pilot": true, "data-auma-pilot-phase": state.phase, children: [_jsx("h2", { children: "One Auma reply" }), _jsx("p", { role: "status", children: state.reason }), state.mode === 'mock' && _jsx("p", { role: "alert", "data-auma-synthetic": true, children: "Explicit synthetic provider flow. This is not live inference." }), state.context && _jsxs("dl", { className: css.fields, children: [_jsxs("div", { children: [_jsx("dt", { children: "Owner" }), _jsx("dd", { children: _jsx("code", { children: state.context.owner_id }) })] }), _jsxs("div", { children: [_jsx("dt", { children: "Task" }), _jsx("dd", { children: _jsx("code", { children: state.context.task_id }) })] }), _jsxs("div", { children: [_jsx("dt", { children: "Conversation" }), _jsx("dd", { children: _jsx("code", { children: state.context.conversation_id }) })] })] }), _jsxs("label", { className: css.owner, children: ["Message to Auma", _jsx("textarea", { ref: draft, rows: 4, autoComplete: "off", "aria-label": "Message to Auma", disabled: !state.available }, state.generation)] }), _jsx("div", { className: css.actions, children: _jsx(ActionButton, { disabled: !state.available, onClick: () => { const text = draft.current?.value; if (text !== undefined)
                        void controller.request(text); }, children: "Request one Auma reply" }) }), state.request_uuid && _jsxs("p", { children: ["Request: ", _jsx("code", { children: state.request_uuid })] }), state.phase === 'outcome_unknown' && !state.result && _jsx("p", { role: "alert", "data-auma-request-unconfirmed": true, children: "The reply is unconfirmed. No reservation or cancellation outcome has been supplied. Do not retry this request." }), _jsx(AumaReplyView, { result: state.result }), _jsx("p", { children: "This request uses the host's existing exact-operation approval flow. It does not sign or approve automatically." })] });
}
//# sourceMappingURL=PilotInferencePanel.js.map