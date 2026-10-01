import type { OwnedExecutor, OwnedExecutorRequest, ExecutionReceipt, OperationProposal, ConsumedGrant } from '../../contracts/src/index.ts'
import type { SdkTransport } from './sdk-transport.ts'
export { SdkTransport, SDK_SOURCE_COMMIT, SDK_PACKAGE_VERSION } from './sdk-transport.ts'
export interface ExecutorSettings {
  workspace: string; logical_workspace_root: string; image_digest: string;
  control_timeout_ms: number; cleanup_timeout_ms: number; poll_ms: number;
}
export class OwnedLedger {
  constructor(root: string)
  withLease<T>(work: () => Promise<T>): Promise<T>
  pending(): unknown[]
  close(): void
}
export class OpenShellOwnedExecutor implements OwnedExecutor {
  constructor(options: { settings: ExecutorSettings; transport: SdkTransport; ledger: OwnedLedger;
    assertConsumed: (operation: OperationProposal, grant: ConsumedGrant) => Promise<boolean>;
    qualification: (settings: Readonly<ExecutorSettings>) => boolean })
  readonly capability: 'unavailable' | 'qualified'
  execute(request: OwnedExecutorRequest): Promise<ExecutionReceipt>
  reconcileOwned(): Promise<readonly ExecutionReceipt[]>
  cancellationCause(requestId: string): 'timeout' | 'caller' | 'dispose' | null
  availability(): { backend: 'openshell-linux'; state: 'unavailable' | 'qualified'; cleanup: 'pending' | 'unprobed'; runtimeEnforcementVerified: boolean }
  dispose(): Promise<void>
}
export function createDshOpenShellExecutor(options: {
  ShellExecutor: abstract new (...args: any[]) => any;
  resolveSpec: (request: any) => any;
  executor: OwnedExecutor;
  resolveOperation: (spec: any) => Promise<OwnedExecutorRequest>;
}): new (...args: any[]) => any
export function installOwnedBash(ctx: any, options: Parameters<typeof createDshOpenShellExecutor>[0]): Promise<any>
export function policyDigest(mode: 'read-only' | 'workspace-write'): `sha256:${string}`
export function wirePolicy(mode: 'read-only' | 'workspace-write'): import('./sdk-transport.ts').Policy
export function loadPinnedSdk(sdkRoot: string, connectOptions: { gateway: string; [key: string]: unknown }): Promise<{ client: unknown; transport: SdkTransport }>
export { validateSpec, guestEnvironment, guestPolicy, refused } from './policy.mjs'
