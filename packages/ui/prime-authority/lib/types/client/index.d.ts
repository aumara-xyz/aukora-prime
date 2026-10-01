import type { Context } from '@deepseek-ai/cordis';
import type { Binding, Controller } from './controller.mjs';
export { createPrimeOwnerController, createHttpAuthority } from './controller.mjs';
export { OwnerSurface, CapabilityBadge } from './OwnerSurface.tsx';
export type { Binding, Controller } from './controller.mjs';
declare module '@deepseek-ai/cordis' {
    interface Context {
        primeOwnerUi: Controller;
        primeAuthority: Binding;
    }
}
export declare const inject: string[];
export declare function apply(ctx: Context): void;
//# sourceMappingURL=index.d.ts.map