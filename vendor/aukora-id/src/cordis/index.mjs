import { Context } from 'cordis';
import manifest from 'cordis/package.json' with { type: 'json' };
import { snapshotBytes } from '../bytes/index.mjs';
import { startLocalService } from '../host/client.mjs';
import { startLocalTransportPair } from '../transport/index.mjs';
import { createProposalBridge } from './bridge.mjs';
import { plainFields } from '../pentora/bytes.mjs';
import { confinementStatus, requireUntrustedConfinement, startUntrustedPlugin } from './confinement.mjs';

export { encodeProposal } from './bridge.mjs';
export { confinementStatus, startUntrustedPlugin } from './confinement.mjs';
export const CORDIS_PIN = Object.freeze({ name: 'cordis', version: '4.0.0-rc.10', license: 'MIT',
  repository: 'git+https://github.com/cordiverse/cordis.git', directory: 'packages/core' });

function requireCordiversePackage() {
  if (manifest.name !== CORDIS_PIN.name || manifest.version !== CORDIS_PIN.version || manifest.license !== CORDIS_PIN.license ||
      manifest.repository?.url !== CORDIS_PIN.repository || manifest.repository?.directory !== CORDIS_PIN.directory) {
    throw new Error('Cordis package identity/pin mismatch');
  }
}

// Trusted host entry point. Only these locally authored integration plugins run
// inside Cordis. The returned controller MUST NOT be passed to untrusted code.
export async function startCordisHost({ configBytes, observerConfigBytes = null, transport = null, execArgv = [], barrier = null, untrustedPluginBytes = null }) {
  requireCordiversePackage();
  // Refuse before W3 startup or any plugin evaluation/resource acquisition.
  if (untrustedPluginBytes !== null) requireUntrustedConfinement();
  const config = snapshotBytes(configBytes);
  const context = new Context(), fibers = [];
  let service, bridge, pair, pulse, observerConfig, closing = false, closePromise;
  const status = { cordis: CORDIS_PIN, trusted_plugins: [], untrusted_plugins_running: 0,
    os_confinement: confinementStatus(), installed_application: 'NOT_VERIFIED' };
  try {
    observerConfig = observerConfigBytes === null ? null : snapshotBytes(observerConfigBytes);
    // Cordis owns resource acquisition and asynchronous disposal. Its plugin
    // lifecycle is exercised; it does not confer security authority on a plugin.
    fibers.push(await context.plugin({ name: 'aukora-local-aperture', async apply() {
      service = await startLocalService({ configBytes: config, observerConfigBytes: observerConfig, barrier, execArgv });
      status.trusted_plugins.push('aukora-local-aperture');
      return async () => { await service.close(); };
    } }));
    fibers.push(await context.plugin({ name: 'aukora-proposal-bridge', apply() {
      bridge = createProposalBridge(service.proposal);
      status.trusted_plugins.push('aukora-proposal-bridge');
      return () => bridge.close();
    } }));
    fibers.push(await context.plugin({ name: 'aukora-durable-activity', apply() {
      // W2 prefix verification and raw bundles stay in the host child. This
      // controller receives only pulse data; no caller selects history/live mode.
      const take = typeof service.takePulse === 'function' ? () => service.takePulse() : null;
      let stopped = false;
      pulse = Object.freeze({
        async take() {
          if (stopped || take === null) return null;
          try {
            const value = await take();
            if (stopped || value === null) return null;
            const fields = plainFields(value, ['schema', 'event_id', 'record_digest', 'sequence', 'grants_authority']);
            if (fields === null || fields.schema !== 'aukora.aura.pulse.v1' || fields.grants_authority !== false ||
                typeof fields.event_id !== 'string' || !/^[0-9a-f]{64}$/.test(fields.event_id) ||
                typeof fields.record_digest !== 'string' || !/^[0-9a-f]{64}$/.test(fields.record_digest) ||
                typeof fields.sequence !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(fields.sequence) ||
                BigInt(fields.sequence) > 18446744073709551615n) return null;
            return Object.freeze({ ...fields });
          } catch { return null; }
        },
        close() { stopped = true; },
      });
      status.trusted_plugins.push('aukora-durable-activity');
      status.live_pulse_source = take === null ? 'UNAVAILABLE' : 'AVAILABLE';
      return () => pulse.close();
    } }));
    if (transport !== null) fibers.push(await context.plugin({ name: 'aukora-signed-data-transport', async apply() {
      pair = await startLocalTransportPair({ ...transport, execArgv });
      status.trusted_plugins.push('aukora-signed-data-transport');
      return async () => { await pair.close(); };
    } }));
  } catch (error) {
    // A failing application can have acquired a resource before its fiber was
    // returned. Close all concrete handles as well as any completed fibers.
    bridge?.close(); pulse?.close();
    await Promise.allSettled([pair?.close(), service?.close()]);
    for (const fiber of fibers.reverse()) { try { await fiber.dispose(); } catch { /* concrete handles closed above */ } }
    throw error;
  } finally { config.fill(0); observerConfig?.fill(0); }
  return Object.freeze({
    // Trusted diagnostics and fault-injection, absent from the proposal bridge.
    notices: service.notices, serviceProcess: service.process, exited: service.exited,
    async inspect() { return { ...status, trusted_plugins: [...status.trusted_plugins], aperture: await service.inspect(),
      transport_pids: pair?.processes.map(child => child.pid) ?? [] }; },
    submitProposal: frame => bridge.submit(frame),
    takePulse: () => closing ? Promise.resolve(null) : pulse.take(),
    transferData(from, event, evidence) {
      if (closing || !pair) throw new Error('LOCAL data transport unavailable');
      return pair.transfer(from, event, evidence);
    },
    startUntrustedPlugin,
    close() {
      if (closePromise) return closePromise;
      closing = true; bridge.close(); pulse.close();
      closePromise = (async () => {
        const errors = [];
        for (const fiber of [...fibers].reverse()) {
          try { await fiber.dispose(); } catch (error) { errors.push(error); }
        }
        // Check concrete cleanup even if a library disposer logs/throws a failure.
        const cleanup = await Promise.allSettled([pair?.close(), service.close()]);
        for (const result of cleanup) if (result.status === 'rejected') errors.push(result.reason);
        if (errors.length) throw new AggregateError(errors, 'Cordis resource disposal failed');
        return cleanup[1].value;
      })();
      return closePromise;
    },
  });
}
