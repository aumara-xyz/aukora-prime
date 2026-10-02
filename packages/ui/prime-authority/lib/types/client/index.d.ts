import type { Context } from '@deepseek-ai/cordis';
import type { Binding, Controller } from './controller.mjs';
import type { ProviderCardExtrasOwnerProps } from './PrimeProviderEditor.tsx';
import type { Controller as ProviderController, ProviderBinding } from './provider-controller.mjs';
export { createPrimeOwnerController, createHttpAuthority } from './controller.mjs';
export { OwnerSurface, CapabilityBadge } from './OwnerSurface.tsx';
export type { Binding, Controller } from './controller.mjs';
export { createPrimeProviderController, createPublicProviderApi } from './provider-controller.mjs';
export type { ProviderBinding, ProviderController };
declare module '@deepseek-ai/cordis' {
    interface Context {
        primeOwnerUi: Controller;
        primeAuthority: Binding;
        primeProviderUi: ProviderController;
        primeProviderSettings: Omit<ProviderBinding, 'ownerController'>;
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