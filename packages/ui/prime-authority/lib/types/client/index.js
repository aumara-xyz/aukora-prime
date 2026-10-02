var __rewriteRelativeImportExtension = (this && this.__rewriteRelativeImportExtension) || function (path, preserveJsx) {
    if (typeof path === "string" && /^\.\.?\//.test(path)) {
        return path.replace(/\.(tsx)$|((?:\.d)?)((?:\.[^./]+?)?)\.([cm]?)ts$/i, function (m, tsx, d, ext, cm) {
            return tsx ? preserveJsx ? ".jsx" : ".js" : d && (!ext || !cm) ? m : (d + ext + "." + cm.toLowerCase() + "js");
        });
    }
    return path;
};
import { createElement, useSyncExternalStore } from 'react';
import { createPrimeOwnerController, createHttpAuthority, readHttpCapabilities } from './controller.mjs';
import { OwnerSurface, OwnerMenu, CapabilityBadge } from "./OwnerSurface.js";
import { PrimeProviderEditor } from "./PrimeProviderEditor.js";
import { createPrimeProviderController, createPublicProviderApi } from './provider-controller.mjs';
export { createPrimeOwnerController, createHttpAuthority } from './controller.mjs';
export { OwnerSurface, CapabilityBadge } from "./OwnerSurface.js";
export { AumaReplyView } from "./AumaReplyView.js";
export { PilotMemoryPanel } from './PilotMemoryPanel';
export { createPrimeProviderController, createPublicProviderApi } from './provider-controller.mjs';
export const inject = ['slots', 'layout', 'locale'];
export function apply(ctx) {
    const controller = createPrimeOwnerController();
    const providers = createPrimeProviderController();
    // Optional UI-only projection of H's already attached owner memory client.
    // Providing this service performs no login, attachment, recovery or effect.
    let memoryPilot;
    const memoryListeners = new Set();
    const memorySnapshot = () => memoryPilot;
    const memorySubscribe = (listener) => { memoryListeners.add(listener); return () => { memoryListeners.delete(listener); }; };
    const setMemoryPilot = (value) => { memoryPilot = value; for (const listener of memoryListeners)
        listener(); };
    function PilotOwnerSurface(props) {
        const current = useSyncExternalStore(memorySubscribe, memorySnapshot, memorySnapshot);
        return createElement(OwnerSurface, { ...props, ...(current ? { memoryPilot: current } : {}) });
    }
    let supplied = false;
    let nativeDisposed = false;
    let nativeConnection;
    const nativeAcknowledgement = Object.freeze({ controller,
        isConnected: (expected) => !nativeDisposed && nativeConnection?.active === true
            && nativeConnection.binding === expected && nativeConnection.witness?.isCurrent() === true,
    });
    let providerSupplied = false;
    let providerContracts;
    const connectPublicProvider = () => {
        if (!providerSupplied && providerContracts) {
            providers.connect({ ownerController: controller, contracts: providerContracts, api: createPublicProviderApi(providerContracts) });
            void providers.load();
        }
    };
    ctx.effect(() => { const off = ctx.reflect.provide('primeOwnerUi', controller); return () => { controller.dispose(); off(); }; }, 'prime owner UI controller');
    ctx.effect(() => {
        const off = ctx.reflect.provide('primeOwnerNativeConnection', nativeAcknowledgement);
        return () => { nativeDisposed = true; if (nativeConnection)
            nativeConnection.active = false; nativeConnection = undefined; off(); };
    }, 'prime native binding acknowledgement');
    ctx.effect(() => { const off = ctx.reflect.provide('primeProviderUi', providers); return () => { providers.dispose(); off(); }; }, 'prime Models card controller');
    ctx.inject(['primePilotMemory'], binding => {
        const selected = binding.primePilotMemory;
        setMemoryPilot(selected);
        binding.effect(() => () => { if (memoryPilot === selected)
            setMemoryPilot(undefined); }, 'prime pilot memory view binding');
    });
    ctx.inject(['primeProviderSettings'], binding => {
        providerSupplied = true;
        providers.connect({ ...binding.primeProviderSettings, ownerController: controller });
        void providers.load();
        binding.effect(() => () => { providerSupplied = false; providers.disconnect(); connectPublicProvider(); }, 'prime owner provider binding');
    });
    ctx.inject(['primeAuthority'], binding => {
        if (nativeDisposed)
            return;
        const selected = binding.primeAuthority;
        const owned = { binding: selected, active: true, witness: null };
        nativeConnection = owned;
        supplied = true;
        // Own cleanup before connect's synchronous notifications can remove or
        // replace this injection. Old cleanup must not disconnect its replacement.
        binding.effect(() => () => {
            owned.active = false;
            const witness = owned.witness;
            owned.witness = null;
            if (nativeConnection !== owned)
                return;
            nativeConnection = undefined;
            supplied = false;
            if (witness)
                void controller.disconnect(witness);
        }, 'prime authority UI binding');
        if (!owned.active || nativeDisposed || nativeConnection !== owned)
            return;
        const witness = controller.connect(selected, { onConnection: current => {
                if (owned.active && !nativeDisposed && nativeConnection === owned)
                    owned.witness = current;
            } });
        if (owned.active && !nativeDisposed && nativeConnection === owned && witness?.isCurrent() === true)
            owned.witness = witness;
    });
    ctx.effect(() => {
        let disposed = false;
        // H serves these exact browser-safe contract modules under the guarded module route.
        const load = (url) => import(__rewriteRelativeImportExtension(/* @vite-ignore */ url));
        void load('/prime/contracts/browser.mjs').then(contracts => {
            if (!disposed) {
                providerContracts = contracts;
                connectPublicProvider();
            }
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
        inject: () => ({ controller }) }, PilotOwnerSurface));
    ctx.slots.inject('shell.menu.system', () => ctx.slots.register({ name: 'shell.menu.system', id: 'prime-owner', order: 70 }, OwnerMenu));
    ctx.slots.inject('shell.overlay', () => ctx.slots.register({ name: 'shell.overlay', id: 'prime-capabilities', order: 70,
        inject: () => ({ controller }) }, CapabilityBadge));
    ctx.slots.inject('settings.models.provider-card', () => ctx.slots.register({ name: 'settings.models.provider-card', key: 'prime-inference',
        inject: () => ({ controller: providers }) }, PrimeProviderEditor));
}
//# sourceMappingURL=index.js.map