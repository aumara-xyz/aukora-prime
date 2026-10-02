import type { Controller } from './provider-controller.mjs';
export interface ProviderDirectoryEntry {
    readonly provider: string;
    readonly displayName: string;
    readonly settingsNs: string;
    readonly settingsPath: readonly string[];
    readonly active: boolean;
    readonly declared?: boolean;
    readonly error?: string;
}
export interface ProviderCardExtrasOwnerProps {
    provider: ProviderDirectoryEntry;
    configured: boolean;
    keyConfigured: boolean;
}
export type PrimeProviderEditorProps = ProviderCardExtrasOwnerProps & {
    controller: Controller;
};
export declare function PrimeProviderEditor({ provider, controller }: PrimeProviderEditorProps): import("react").JSX.Element | null;
//# sourceMappingURL=PrimeProviderEditor.d.ts.map