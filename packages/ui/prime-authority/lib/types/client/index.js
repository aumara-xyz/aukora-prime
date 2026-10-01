var __rewriteRelativeImportExtension = (this && this.__rewriteRelativeImportExtension) || function (path, preserveJsx) {
    if (typeof path === "string" && /^\.\.?\//.test(path)) {
        return path.replace(/\.(tsx)$|((?:\.d)?)((?:\.[^./]+?)?)\.([cm]?)ts$/i, function (m, tsx, d, ext, cm) {
            return tsx ? preserveJsx ? ".jsx" : ".js" : d && (!ext || !cm) ? m : (d + ext + "." + cm.toLowerCase() + "js");
        });
    }
    return path;
};
import { createPrimeOwnerController, createHttpAuthority, readHttpCapabilities } from './controller.mjs';
import { OwnerSurface, OwnerMenu, CapabilityBadge } from "./OwnerSurface.js";
export { createPrimeOwnerController, createHttpAuthority } from './controller.mjs';
export { OwnerSurface, CapabilityBadge } from "./OwnerSurface.js";
export const inject = ['slots', 'layout', 'locale'];
export function apply(ctx) {
    const controller = createPrimeOwnerController();
    let supplied = false;
    ctx.effect(() => { const off = ctx.reflect.provide('primeOwnerUi', controller); return () => { controller.dispose(); off(); }; }, 'prime owner UI controller');
    ctx.inject(['primeAuthority'], binding => {
        supplied = true;
        controller.connect(binding.primeAuthority);
        binding.effect(() => () => { supplied = false; controller.disconnect(); }, 'prime authority UI binding');
    });
    ctx.effect(() => {
        let disposed = false;
        // H serves these exact browser-safe contract modules under the guarded module route.
        const load = (url) => import(__rewriteRelativeImportExtension(/* @vite-ignore */ url));
        void load('/prime/contracts/browser.mjs').then(contracts => {
            if (!disposed && !supplied) {
                controller.connect({ authority: createHttpAuthority(undefined, contracts), contracts, requiresCapabilities: true });
                void readHttpCapabilities(undefined, contracts).then(capabilities => {
                    if (!disposed && !supplied)
                        controller.setCapabilities(capabilities);
                }).catch(() => { if (!disposed && !supplied)
                    controller.capabilitiesUnavailable(); });
            }
        }).catch(() => { });
        return () => { disposed = true; };
    }, 'prime browser contract helper');
    ctx.slots.inject('shell.surface', () => ctx.slots.register({ name: 'shell.surface', id: 'prime-owner', order: 70,
        inject: () => ({ controller }) }, OwnerSurface));
    ctx.slots.inject('shell.menu.system', () => ctx.slots.register({ name: 'shell.menu.system', id: 'prime-owner', order: 70 }, OwnerMenu));
    ctx.slots.inject('shell.overlay', () => ctx.slots.register({ name: 'shell.overlay', id: 'prime-capabilities', order: 70,
        inject: () => ({ controller }) }, CapabilityBadge));
}
//# sourceMappingURL=index.js.map