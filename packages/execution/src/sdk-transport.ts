// SPDX-License-Identifier: AGPL-3.0-or-later
// Wire fields are source-derived from OpenShell 6648bd0, not CLI stdout.
import { Buffer } from 'node:buffer'
import { refused } from './policy.mjs'
import { createProfileDigest, assertCreateTemplate, guestWorkdir } from './create-profile.mjs'
import type { CreateTemplate } from './create-profile.mjs'

export const SDK_SOURCE_COMMIT = '6648bd0c290efbc41ba131ee9831ee45cd431f94'
export const SDK_PACKAGE_VERSION = '0.0.0'
export type Policy = {
  version: number; filesystem: { includeWorkdir: boolean; readOnly: string[]; readWrite: string[] };
  landlock: { compatibility: string }; process: { runAsUser: string; runAsGroup: string };
  networkPolicies: Record<string, never>; networkMiddlewares: Record<string, never>;
}
type ObservedPolicy = {
  version: number; filesystem?: Policy['filesystem']; landlock?: Policy['landlock']; process?: Policy['process'];
  networkPolicies: Record<string, unknown>; networkMiddlewares: Record<string, unknown>;
}
export type Sandbox = {
  metadata?: { id: string; name: string; workspace: string; labels: Record<string, string> };
  spec?: { template?: { image: string; resources?: Record<string,unknown>; driverConfig?: Record<string,unknown>;
    runtimeClassName?: string; agentSocket?: string; labels?: Record<string,string>; annotations?: Record<string,string>;
    environment?: Record<string,string>; userNamespaces?: boolean }; policy?: ObservedPolicy; providers: string[]; environment: Record<string, string>; command: string[]; tty: boolean; providerAttachmentEpoch?: string };
  status?: { phase: number; configurationAdmission?: { instanceId: string; state: number; policyVersion: number; policyHash: string; configRevision: bigint; providerEnvRevision: bigint; error: string } };
}
/** Exact pinned raw readback. Revisions stay bigint until the durable boundary. */
export type EffectiveConfiguration = {
  policy?: ObservedPolicy; version: number; policyHash: string;
  settings: Record<string, {scope: number; value?: unknown}>;
  configRevision: bigint; policySource: number; globalPolicyVersion: number;
  providerEnvRevision: bigint; supervisorMiddlewareServices: unknown[];
  workspace: string; policyValidationFailureMode: string;
  extensionAuthenticationEnabled: boolean; providerAttachmentEpoch: string;
  configurationAdmitted: boolean; configurationError: string; configurationInstanceId: string;
}
type Scope = { selection: { case: 'workspace'; value: string } }
type Options = { signal?: AbortSignal; timeoutMs?: number }
type Target = { workspaceScope: Scope; name: string }
type Job = { name: string; token: string; create_request_id: string; delete_request_id: string; request_id: string;
  create_template: CreateTemplate; create_profile_digest: string; guest_workdir: string }
type Settings = { workspace: string; image_digest: string; logical_workspace_root: string }
type Spec = { timeoutMs: number; command: string; workdir: string; stdin?: string }
export type ExecRequest = {
  workspaceScope: Scope; sandbox: string; command: string[]; workdir: string;
  environment: Record<string, string>; executionTimeout: { seconds: bigint; nanos: number };
  stdin: Uint8Array; tty: false; noLoginShell: true; requestId: string;
}
type CreateRequest = Target & { requestId: string; labels: Record<string, string>; spec: {
  template: CreateTemplate; policy: Policy; providers: []; environment: Record<string, string>;
  command: string[]; tty: false;
} }
export type WireEvent = { payload: { case: 'stdout' | 'stderr'; value: { data: Uint8Array } }
  | { case: 'exit'; value: { exitCode: number } } | { case: undefined; value?: undefined } }
/** Structural subset of the generated SDK Client<OpenShell>. Pass OpenShellClient.raw.
 * The actual built SDK remains the connection/TLS/auth owner. No host execution. */
export interface RawSdkClient {
  createSandbox(request: CreateRequest, options?: Options): Promise<{ sandbox?: Sandbox }>;
  getSandbox(request: Target, options?: Options): Promise<{ sandbox?: Sandbox }>;
  getSandboxConfig(request: Target, options?: Options): Promise<EffectiveConfiguration>;
  listSandboxes(request: { workspaceScope: Scope; pageSize: number; pageToken: string; labelSelector: string }, options?: Options): Promise<{ sandboxes: Sandbox[]; nextPageToken: string }>;
  deleteSandbox(request: Target & { requestId: string; allowMissing: true }, options?: Options): Promise<{ outcome: number; sandboxId: string }>;
  execSandbox(request: ExecRequest, options?: Options): AsyncIterable<WireEvent>;
}
export type TypedEvent = { type: 'exit'; exitCode: number }
  | { type: 'ambiguous_exit'; exitCode: 124 }
  | { type: 'rpc_complete' }
  | { stream: 'stdout' | 'stderr'; data: Buffer }
export class SdkTransport {
  readonly sourceCommit = SDK_SOURCE_COMMIT
  readonly packageVersion = SDK_PACKAGE_VERSION
  readonly raw: RawSdkClient
  readonly gatewayIdentity: string | null
  constructor(raw: RawSdkClient, options: {gatewayIdentity?: string} = {}) {
    if (!raw || (['createSandbox','getSandbox','getSandboxConfig','listSandboxes','deleteSandbox','execSandbox'] as const).some(k => typeof raw[k] !== 'function')) {
      throw refused('built OpenShell SDK raw lifecycle surface required', 'UNAVAILABLE')
    }
    this.raw = raw
    this.gatewayIdentity=options.gatewayIdentity??null
  }
  scope(workspace: string): Scope { return { selection: { case: 'workspace', value: workspace } } }
  async create(job: Job, settings: Settings, policy: Policy, environment: Record<string, string>, options: Options) {
    if (job.create_profile_digest !== createProfileDigest(settings.image_digest)
      || job.guest_workdir !== guestWorkdir(settings.logical_workspace_root, settings.logical_workspace_root)) {
      throw refused('durable create profile differs', 'UNAVAILABLE')
    }
    const template = assertCreateTemplate(job.create_template, settings.image_digest)
    const response = await this.raw.createSandbox({ workspaceScope: this.scope(settings.workspace), name: job.name,
      requestId: job.create_request_id, labels: { 'aukora.openshell/owner': job.token },
      spec: { template, policy, providers: [], environment,
        command: ['/bin/sleep', 'infinity'], tty: false } }, options)
    return response.sandbox
  }
  async get(job: Job, settings: Settings, options: Options) {
    return (await this.raw.getSandbox({ workspaceScope: this.scope(settings.workspace), name: job.name }, options)).sandbox
  }
  async configuration(job: Job, settings: Settings, options: Options) {
    return this.raw.getSandboxConfig({ workspaceScope: this.scope(settings.workspace), name: job.name }, options)
  }
  async inventory(settings: Settings, pageToken: string, options: Options) {
    return this.raw.listSandboxes({ workspaceScope: this.scope(settings.workspace), pageSize: 100,
      pageToken, labelSelector: '' }, options)
  }
  async delete(job: Job, settings: Settings, options: Options) {
    // This API has no expected-ID condition. Identity is rechecked by the owner.
    return this.raw.deleteSandbox({ workspaceScope: this.scope(settings.workspace), name: job.name,
      requestId: job.delete_request_id, allowMissing: true }, options)
  }
  async *execStream(job: Job, settings: Settings, spec: Spec, environment: Record<string, string>, signal: AbortSignal): AsyncGenerator<TypedEvent> {
    const timeout = spec.timeoutMs
    const workdir = guestWorkdir(spec.workdir, settings.logical_workspace_root)
    if (job.guest_workdir !== workdir || job.create_profile_digest !== createProfileDigest(settings.image_digest)) {
      throw refused('durable execution profile differs', 'UNAVAILABLE')
    }
    const stream = this.raw.execSandbox({ workspaceScope: this.scope(settings.workspace), sandbox: job.name,
      command: ['bash', '-c', spec.command], workdir, environment,
      executionTimeout: { seconds: BigInt(Math.floor(timeout / 1000)), nanos: (timeout % 1000) * 1_000_000 },
      stdin: Buffer.from(spec.stdin ?? '', 'utf8'), tty: false, noLoginShell: true, requestId: job.request_id }, { signal })
    let sawExit = false
    for await (const event of stream) {
      const payload = event.payload
      if (payload?.case === 'stdout' || payload?.case === 'stderr') {
        if (sawExit) throw refused('output followed typed terminal event', 'OUTCOME_UNKNOWN')
        yield { stream: payload.case, data: Buffer.from(payload.value.data) }
      } else if (payload?.case === 'exit') {
        if (sawExit || !Number.isInteger(payload.value.exitCode) || payload.value.exitCode < 0 || payload.value.exitCode > 2147483647) {
          throw refused('invalid or duplicate typed command exit', 'OUTCOME_UNKNOWN')
        }
        sawExit = true
        // Pinned gateway also emits synthetic124 on its timeout path, without
        // terminalizing the durable command launch. The wire has no provenance;
        // a genuine command124 is indistinguishable and remains unknown too.
        yield payload.value.exitCode === 124
          ? { type: 'ambiguous_exit', exitCode: 124 }
          : { type: 'exit', exitCode: payload.value.exitCode }
      } else throw refused('unknown exec protocol event', 'OUTCOME_UNKNOWN')
    }
    // Exhaustion drains Connect's final RPC status. Seeing exit alone is insufficient.
    yield { type: 'rpc_complete' }
    if (!sawExit) throw refused('SDK stream completed without typed exit', 'OUTCOME_UNKNOWN')
  }
}
