import { readFileSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { exactObject, requireCondition } from './contract.mjs';
import { checkPrivateFile } from './custody.mjs';

export const POST_RATE_POLICY = Object.freeze({
  version: 1,
  authorScope: 'all_authenticated',
  admissionScope: 'validated_new_post_attempt',
  gapMs: 30000,
  windowMs: 3600000,
  maxAttempts: 20,
  windowStart: 'exclusive',
  replay: 'completed_exact_no_attempt',
  reservation: 'commit_before_message',
  retention: 'no_prune_no_refund',
  clock: 'nondecreasing',
});

export function validatePostRatePolicy(value) {
  exactObject(value, Object.keys(POST_RATE_POLICY));
  requireCondition(Object.entries(POST_RATE_POLICY).every(([key, expected]) => value[key] === expected), 503, 'post_rate_policy_unavailable');
  return POST_RATE_POLICY;
}

export const POST_RATE_POLICY_JSON = JSON.stringify(POST_RATE_POLICY);

// Only the executable's trusted host configuration selects this external file.
// It is never a request field, and no absence or parse failure supplies a default.
export function loadPostRatePolicy(path) {
  const sourceRoot = dirname(dirname(fileURLToPath(import.meta.url)));
  requireCondition(typeof path === 'string' && resolve(path) !== sourceRoot && !resolve(path).startsWith(sourceRoot + sep), 503, 'post_rate_policy_must_be_external');
  const identity = checkPrivateFile(path, 4096);
  const bytes = readFileSync(path);
  const checked = checkPrivateFile(path, 4096);
  requireCondition(identity.dev === checked.dev && identity.ino === checked.ino, 503, 'post_rate_policy_identity_changed');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  // The approved policy's canonical spelling is closed; duplicate JSON keys and
  // extra values cannot be accepted by JSON.parse's last-key-wins behavior.
  const value = JSON.parse(text);
  validatePostRatePolicy(value);
  requireCondition(text.trim() === POST_RATE_POLICY_JSON, 503, 'post_rate_policy_unavailable');
  return POST_RATE_POLICY;
}
