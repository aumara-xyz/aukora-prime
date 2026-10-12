// Shared loader for the portal gates. Evaluates the exact bytes of the
// <script id="portal-core"> block from portal/index.html in this process,
// so the gates exercise the shipped logic, not a copy of it.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const PORTAL_DIR = path.join(here, '..', 'portal');
export const PORTAL_HTML = path.join(PORTAL_DIR, 'index.html');
export const VERIFY_MJS = path.join(here, '..', '..', 'verify.mjs');
export const VECTORS_DIR = path.join(here, '..', '..', 'vectors');
export const VENDOR_DIR = path.join(here, '..', 'vendor');

export function readPortalHtml() {
  return fs.readFileSync(PORTAL_HTML, 'utf8');
}

export function extractScript(html, id) {
  const m = html.match(new RegExp(`<script id="${id}">([\\s\\S]*?)</script>`));
  if (!m) throw new Error(`<script id="${id}"> not found in portal/index.html`);
  return m[1];
}

let cached = null;
export function loadCore() {
  if (cached) return cached;
  const code = extractScript(readPortalHtml(), 'portal-core');
  (0, eval)(code);
  if (!globalThis.PortalCore) throw new Error('portal-core did not define globalThis.PortalCore');
  cached = globalThis.PortalCore;
  return cached;
}

// The two pinned vendor libraries, loaded from the same files the page uses.
export function loadQr() {
  (0, eval)(fs.readFileSync(path.join(VENDOR_DIR, 'qrcode.min.js'), 'utf8') + '\n;globalThis.__qrcode = qrcode;');
  const jsQR = createRequire(import.meta.url)(path.join(VENDOR_DIR, 'jsQR.min.js'));
  return { qrcode: globalThis.__qrcode, jsQR };
}
