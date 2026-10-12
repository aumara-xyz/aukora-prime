#!/usr/bin/env node
// Recomputes the CSP hashes for the inline <style> and <script> blocks of portal/index.html
// and rewrites the policy in place. Not a build step: the committed page is already stamped.
// Run after editing the page:  node tests/stamp-csp.mjs        (check only: --check)
import fs from 'node:fs';
import crypto from 'node:crypto';
import { PORTAL_HTML } from './load-core.mjs';

const b64 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('base64');
let html = fs.readFileSync(PORTAL_HTML, 'utf8');
const scripts = [...html.matchAll(/<script id="[^"]+">([\s\S]*?)<\/script>/g)].map((m) => `'sha256-${b64(m[1])}'`);
const styles = [...html.matchAll(/<style>([\s\S]*?)<\/style>/g)].map((m) => `'sha256-${b64(m[1])}'`);
// The socket allow-list is exactly the relay list in the page.
const relays = (html.match(/const RELAYS = \[([^\]]*)\]/) || ['', ''])[1].split(',').map((x) => x.trim().replace(/'/g, '')).filter(Boolean);
if (relays.length === 0 || relays.some((r) => !/^wss:\/\/[a-z0-9.-]+$/.test(r))) { console.log('RELAYS constant not found or malformed'); process.exit(1); }
export const policy = [
  "default-src 'none'",
  `script-src 'self' ${scripts.join(' ')}`,
  `style-src ${styles.join(' ')}`,
  'img-src data: blob:',
  'media-src blob: mediastream:',
  "connect-src 'self' " + relays.join(' '),
  'worker-src blob:',
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');
const re = /(<meta http-equiv="Content-Security-Policy" content=")([^"]*)(">)/;
const current = (html.match(re) || [])[2];
if (process.argv.includes('--check')) {
  if (current !== policy) { console.log('CSP STALE: run node tests/stamp-csp.mjs'); process.exit(1); }
  console.log('CSP current'); process.exit(0);
}
if (current === undefined) { console.log('no CSP meta tag found'); process.exit(1); }
fs.writeFileSync(PORTAL_HTML, html.replace(re, (_, a, __, c) => a + policy + c));
console.log(current === policy ? 'CSP already current' : 'CSP stamped');
