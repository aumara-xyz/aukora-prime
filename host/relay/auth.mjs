import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync, statSync, realpathSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AUTHORS, exactObject, requireCondition } from './contract.mjs';

export function tokenDigest(token) { return createHash('sha256').update(token).digest('hex'); }
export function createAuthenticator(config) {
  exactObject(config, ['version', 'tokenDigests']);
  requireCondition(config.version === 1 && config.tokenDigests && typeof config.tokenDigests === 'object' && !Array.isArray(config.tokenDigests), 500, 'invalid_auth_config');
  const entries = Object.entries(config.tokenDigests);
  requireCondition(entries.length > 0 && entries.length <= AUTHORS.length, 500, 'invalid_auth_config');
  const seen = new Set();
  const bindings = entries.map(([author, digest]) => {
    requireCondition(AUTHORS.includes(author) && typeof digest === 'string' && /^[a-f0-9]{64}$/.test(digest) && !seen.has(digest), 500, 'invalid_auth_config');
    seen.add(digest); return [author, Buffer.from(digest, 'hex')];
  });
  return function authenticate(header) {
    requireCondition(typeof header === 'string' && /^Bearer [A-Za-z0-9_-]{32,512}$/.test(header), 401, 'authentication_required');
    const digest = Buffer.from(tokenDigest(header.slice(7)), 'hex'); let matched;
    for (const [author, expected] of bindings) if (timingSafeEqual(digest, expected)) matched = author;
    requireCondition(matched !== undefined, 401, 'authentication_required'); return matched;
  };
}
export function loadAuthenticator(path) {
  requireCondition(typeof path === 'string' && path.length > 0, 500, 'auth_config_required');
  const full = realpathSync(path); const source = dirname(fileURLToPath(import.meta.url));
  requireCondition(full !== source && !full.startsWith(source + sep), 500, 'auth_config_must_be_external');
  const stat = statSync(full);
  requireCondition(stat.isFile() && stat.size <= 8192 && (stat.mode & 0o077) === 0 && stat.uid === process.getuid(), 500, 'auth_config_must_be_private');
  return createAuthenticator(JSON.parse(readFileSync(resolve(full), 'utf8')));
}
