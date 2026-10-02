import type { Context } from '@deepseek-ai/cordis';
import type { Binding, Controller } from './controller.mjs';
import type { ProviderCardExtrasOwnerProps } from './PrimeProviderEditor.tsx';
import type { Controller as ProviderController, ProviderBinding } from './provider-controller.mjs';
import type { MemoryPilotBinding } from './PilotMemoryPanel';
export { createPrimeOwnerController, createHttpAuthority } from './controller.mjs';
export { OwnerSurface, CapabilityBadge } from './OwnerSurface.tsx';
export { AumaReplyView } from './AumaReplyView.tsx';
export type { PilotInferenceResult } from './AumaReplyView.tsx';
export { PilotMemoryPanel } from './PilotMemoryPanel';
export type { MemoryPilotBinding } from './PilotMemoryPanel';
export type { Binding, ConnectionWitness, Controller } from './controller.mjs';
export { createPrimeProviderController, createPublicProviderApi } from './provider-controller.mjs';
export type { ProviderBinding, ProviderController };
/** Trusted native connection ordering only; never an owner or effect grant. */
export interface NativeOwnerConnection {
    readonly controller: Controller;
    readonly isConnected: (binding: Binding) => boolean;
}
declare module '@deepseek-ai/cordis' {
    interface Context {
        primeOwnerUi: Controller;
        primeAuthority: Binding;
        primeProviderUi: ProviderController;
        primeProviderSettings: Omit<ProviderBinding, 'ownerController'>;
        primePilotMemory: MemoryPilotBinding;
        primeOwnerNativeConnection: NativeOwnerConnection;
    }
}
declare module '@deepseek-ai/dsh-client-ui-slots' {
    interface SlotMap {
        'settings.models.provider-card': {
            kind: 'keyed';
            scope: 'root';
            owner: ProviderCardExtrasOwnerProps;
        };
    }
}
export declare const inject: string[];
export declare function apply(ctx: Context): void;
//# sourceMappingURL=index.d.ts.map