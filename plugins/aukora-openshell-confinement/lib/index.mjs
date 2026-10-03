// SPDX-License-Identifier: AGPL-3.0-or-later
// Linux service adapter for Genesis's mandatory-agent-confinement interface.
// Current boundary-gate sbx-exec cannot satisfy complete file/lifecycle policy;
// mounting this plugin registers refusing services, never a host fallback.
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  prepareLabTransport, readSettings, unavailable, validateRequest, WRAPPER_LIMITS,
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
      // Prepare the exact existing runner without launching it. The partial
      // transport is retained as source for the wrapper owner's review only.
      prepareLabTransport(argv, policy, settings, boundary.sandboxArgv, layout, signal);
      signal?.throwIfAborted();
      // Never return partial enforcement to a consumer that would launch it.
      // No operator flag, environment variable or callback can waive this fence.
      throw unavailable('WRAPPER_POLICY_AND_LIFECYCLE', WRAPPER_LIMITS.join('; '));
    },
  });
}

export async function apply(ctx, config) {
  const settings = readSettings(config);
  if (process.platform !== 'linux') {
    throw unavailable('PLATFORM', 'this provider is Linux-only');
  }
  if (ctx.get('sandbox') !== undefined || ctx.get('aukoraConfinement') !== undefined) {
    throw unavailable('SERVICE_CONFLICT', 'disable the existing sandbox and Seatbelt providers before mounting');
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
  const provider = createConfinement(settings, {
    sandboxArgv: sandbox.sandboxArgv, resolveLayout: layout.resolveLayout,
  });
  // The existing Bash executor injects sandbox; requiredConfinement gets the
  // separate aukoraConfinement service. Both names must belong to one provider.
  ctx.provide('sandbox', provider);
  ctx.provide('aukoraConfinement', provider);
}
