import type { ApprovalActionResult, Controller } from './controller.mjs';
import type { ForgetWorkflowSnapshot } from '../adapters/forget-result.mjs';
interface SnapshotStore<Snapshot> {
    getSnapshot(): Snapshot;
    subscribe(listener: () => void): () => void;
}
/** Structural subset of H's existing, attached createOwnerMemoryClient result.
 * It supplies no route, source context, session, signer or authority itself. */
export interface MemoryPilotBinding {
    readonly ownerController: Controller;
    readonly client: {
        readonly binding: {
            readonly owner_id: string;
        };
        readonly workflow: SnapshotStore<ApprovalActionResult> | undefined;
        readonly forgetWorkflow: SnapshotStore<ForgetWorkflowSnapshot> | undefined;
        proposeSave(draft: {
            extraction_json: string;
            idempotency_key: string;
        }): Promise<ApprovalActionResult>;
        refresh(): Promise<ApprovalActionResult>;
        recover(input?: {
            operation_id: string | null;
        }): Promise<ApprovalActionResult>;
        recoverForget(input?: {
            operation_id: string | null;
        }): Promise<ForgetWorkflowSnapshot>;
    };
}
export declare function PilotMemoryPanel({ controller, binding }: {
    controller: Controller;
    binding?: MemoryPilotBinding;
}): import("react").JSX.Element;
export {};
//# sourceMappingURL=PilotMemoryPanel.d.ts.map