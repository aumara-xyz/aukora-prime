// Plain-data proposal only. No enrollment, biometrics, phrase KDF or recovery.
import { readFileSync } from 'node:fs';
import { createHash, randomBytes, randomInt } from 'node:crypto';
import { canonicalBytes, closed, fail, parseBytes } from '../bytes/index.mjs';

export const WORDLIST_SHA256 = 'addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e';
export const WORDLIST_PROFILE = 'eff.long.english.2016.sha256.' + WORDLIST_SHA256;
const demand = (ok, code = 'CLOSED_SCHEMA') => { if (!ok) fail(code); };
const plain = value => parseBytes(Buffer.from(JSON.stringify(value)));
let cached;
function english() {
  if (cached) return cached;
  const bytes = readFileSync(new URL('./data/eff_large_wordlist.txt', import.meta.url));
  demand(bytes.length === 108800, 'CLOSED_SCHEMA');
  demand(createHash('sha256').update(bytes).digest('hex') === WORDLIST_SHA256, 'BAD_SIGNATURE');
  const lines = new TextDecoder('utf-8', { fatal: true }).decode(bytes).split('\n');
  demand(lines.pop() === '' && lines.length === 7776);
  const buckets = new Map(), seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    const match = /^([1-6]{5})\t([a-z]+(?:-[a-z]+)?)$/.exec(lines[i]);
    demand(match !== null);
    const expected = i.toString(6).padStart(5, '0').replace(/[0-5]/g, digit => String(Number(digit) + 1));
    demand(match[1] === expected && !seen.has(match[2]));
    const word = match[2], initial = word[0]; seen.add(word);
    if (!buckets.has(initial)) buckets.set(initial, []);
    buckets.get(initial).push(word);
  }
  for (const words of buckets.values()) Object.freeze(words);
  cached = buckets;
  return cached;
}
export function supportedLanguages() {
  const buckets = english();
  return plain([{ language: 'en', wordlist_profile: WORDLIST_PROFILE, entries: 7776,
    initial_counts: Object.fromEntries([...buckets].map(([initial, words]) => [initial, words.length])),
    license: 'CC-BY-4.0', supported_acrostic: 'exactly seven lowercase ASCII letters', themes: false }]);
}
export function proposeBind(requestBytes) {
  const request = parseBytes(requestBytes, { maxBytes: 1024 });
  closed(request, { schema: value => demand(value === 'aukora.bind.request.v1'),
    language: value => demand(value === 'en', 'UNSUPPORTED_PROFILE'),
    acrostic: value => demand(typeof value === 'string' && /^[a-z]{7}$/.test(value)) });
  const buckets = english();
  const words = [...request.acrostic].map(initial => {
    const choices = buckets.get(initial);
    demand(choices !== undefined && choices.length > 0, 'UNSUPPORTED_PROFILE');
    return choices[randomInt(choices.length)];
  });
  // Random identifiers do not depend on words, initials, language or display.
  // No secret/private key or public phrase check is constructed here.
  return plain({ public_proposal: { schema: 'aukora.bind.proposal.v1', status: 'proposal_only', mode: 'LOCAL_TEST',
    proposal_id: randomBytes(32).toString('hex'), subject_id: randomBytes(32).toString('hex'),
    chain_id: randomBytes(32).toString('hex'), language: request.language, wordlist_profile: WORDLIST_PROFILE,
    enrolled: false, biometric_verified: false, recovery_available: false, grants_authority: false },
  private_phrase: { visibility: 'private_local_display_only', acrostic: request.acrostic, words,
    key_material: false, recoverable: false } });
}
export function proposeBindBytes(requestBytes) { return canonicalBytes(proposeBind(requestBytes)); }
export function recover(_requestBytes) {
  return Object.freeze({ verdict: 'UNKNOWN', reason_codes: Object.freeze(['RECOVERY_UNREVIEWED']) });
}
