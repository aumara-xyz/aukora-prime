// SPDX-License-Identifier: AGPL-3.0-or-later
// Linux service adapter for Genesis's mandatory-agent-confinement interface.
// Supported file effects are guest workspace-write only. A missing applied
// hard policy refuses preparation; there is no host execution fallback.
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  prepareLabTransport, readConfinementInfo, readSettings, unavailable, validateRequest,
} from './transport.mjs';

export const name = 'aukora-openshell-confinement';
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

/** SandboxProvider.confine(argv, policy, signal): Promise<ConfinedArgv>. */
export function createConfinement(settings, boundary) {
  const layout = boundary.resolveLayout();
  return Object.freeze({
    async confine(argv, policy, signal) {
      if (process.platform !== 'linux') {
        throw unavailable('PLATFORM', 'this provider is Linux-only');
      }
      validateRequest(argv, policy, settings, signal);
      const transport = prepareLabTransport(argv, policy, settings,
        boundary.sandboxArgv, layout, signal);
      await readConfinementInfo(layout, signal);
      signal?.throwIfAborted();
      // The root-owned wrapper repeats the policy check under its execution
      // lock before launch. No environment flag can substitute for readback.
      return Object.freeze({ ...transport, enforcement: 'full' });
    },
  });
}

/** Keep native foreground mechanics, replacing only the transport workdir. */
export function guestBashExecutor(Executor, settings) {
  return class GuestBashExecutor extends Executor {
    resolve(request) {
      if (request.stdin !== undefined || request.env !== undefined) {
        throw unavailable('TRANSPORT', 'stdin and caller environment transport are unsupported');
      }
      const spec = super.resolve(request);
      validateRequest(['bash', '-c', spec.command], spec.sandboxPolicy, settings, spec.signal);
      if (spec.workdir !== settings.workspaceRoot) {
        throw unavailable('WORKSPACE', 'only the exact guest workdir /sandbox is supported');
      }
      return spec;
    }
    async run(spec) {
      validateRequest(['bash', '-c', spec.command], spec.sandboxPolicy, settings, spec.signal);
      if (spec.workdir !== settings.workspaceRoot || spec.stdin !== undefined || spec.env !== undefined) {
        throw unavailable('TRANSPORT', 'unsupported guest workdir, stdin or caller environment');
      }
      // dshEnv is a trusted host-plugin snapshot. This guest profile intentionally
      // has no host environment transport; the root-owned wrapper sets guest env.
      // Keep the policy's guest root unchanged while spawning sudo at host '/'.
      return super.run({ ...spec, workdir: '/', dshEnv: undefined });
    }
    async start() {
      throw unavailable('BACKGROUND', 'background execution is unsupported by this guest profile');
    }
  };
}

export async function apply(ctx, config) {
  const settings = readSettings(config);
  if (process.platform !== 'linux') {
    throw unavailable('PLATFORM', 'this provider is Linux-only');
  }
  if (ctx.get('sandbox') !== undefined || ctx.get('aukoraConfinement') !== undefined ||
      ctx.get('shell') !== undefined) {
    throw unavailable('SERVICE_CONFLICT', 'disable the existing sandbox, Seatbelt and Bash providers before mounting');
  }
  // Source checkout and Prime release layouts. No sibling repository, PATH
  // discovery or host fallback is used. Grok owns carrying these source files.
  const candidates = ['packages', 'prime-packages'].map(prefix => ({
    sandbox: join(ROOT, prefix, 'boundary-gate/src/sandbox.mjs'),
    layout: join(ROOT, prefix, 'boundary-gate/src/layout.mjs'),
  }));
  const selected = candidates.find(candidate =>
    existsSync(candidate.sandbox) && existsSync(candidate.layout));
  if (!selected) throw unavailable('BACKEND', 'the selected release does not carry boundary-gate');
  const sandbox = await import(pathToFileURL(selected.sandbox).href);
  const layout = await import(pathToFileURL(selected.layout).href);
  if (typeof sandbox.sandboxArgv !== 'function' || typeof layout.resolveLayout !== 'function') {
    throw unavailable('BACKEND', 'boundary-gate does not expose the selected transport contract');
  }
  const executorModule = [
    join(ROOT, 'packages/shell/bash-sandbox/lib/index.js'),
    join(ROOT, 'vendor/dsh/packages/shell/bash-sandbox/lib/index.js'),
  ].find(candidate => existsSync(candidate));
  if (!executorModule) throw unavailable('BACKEND', 'the selected release does not carry the native Bash executor');
  const loaded = await import(pathToFileURL(executorModule).href);
  const Executor = loaded.SandboxBashExecutor ?? loaded.default;
  if (typeof Executor !== 'function') throw unavailable('BACKEND', 'the native Bash executor class is unavailable');
  const provider = createConfinement(settings, {
    sandboxArgv: sandbox.sandboxArgv, resolveLayout: layout.resolveLayout,
  });
  // The existing Bash executor injects sandbox; requiredConfinement gets the
  // separate aukoraConfinement service. Both names must belong to one provider.
  ctx.provide('sandbox', provider);
  ctx.provide('aukoraConfinement', provider);
  await ctx.plugin(guestBashExecutor(Executor, settings), {
    cwd: settings.workspaceRoot,
    timeoutMs: settings.timeoutSeconds * 1000,
    maxTimeoutMs: settings.timeoutSeconds * 1000,
  });
}
