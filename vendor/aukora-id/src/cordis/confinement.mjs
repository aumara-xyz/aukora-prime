// No OS backend has been admitted in this build. A same-user Node child, Cordis
// Context isolation, frozen JS object or node:vm is not a security sandbox.
export function confinementStatus() {
  return Object.freeze({ status: 'BLOCKED', execution_allowed: false,
    backend: null, reason: 'OS_CONFINEMENT_UNAVAILABLE' });
}

export function requireUntrustedConfinement() {
  throw Object.assign(new Error('Untrusted plugin launch requires an admitted OS confinement backend'), {
    code: 'MISSING_EVIDENCE', blocker: 'OS_CONFINEMENT_UNAVAILABLE',
  });
}

// Deliberately no module loader, spawn call, caller-provided launcher, environment
// override or unsafe fallback. The blocked request has zero execution effects.
export async function startUntrustedPlugin(_pluginBytes) {
  requireUntrustedConfinement();
}
