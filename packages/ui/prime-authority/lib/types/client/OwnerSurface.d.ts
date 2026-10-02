import type { PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots';
import type { Controller } from './controller.mjs';
import type { MemoryPilotBinding } from './PilotMemoryPanel';
export declare function OwnerSurface({ activeSurface, openSurface, controller, memoryPilot }: PropsRuntime<'shell.surface'> & {
    controller: Controller;
    memoryPilot?: MemoryPilotBinding;
}): import("react").JSX.Element;
export declare function CapabilityBadge({ controller }: {
    controller: Controller;
}): import("react").JSX.Element;
export declare function OwnerMenu({ activeSurface, openSurface }: PropsRuntime<'shell.menu.system'>): import("react").JSX.Element;
//# sourceMappingURL=OwnerSurface.d.ts.map