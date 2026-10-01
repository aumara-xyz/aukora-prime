// SPDX-License-Identifier: AGPL-3.0-or-later
// Exact selected SECRET_PATTERNS block from Genesis645 compaction-export.mjs.
export const SECRET_PATTERNS = Object.freeze([
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/u,
  /\bnsec1[02-9ac-hj-np-z]{20,}\b/iu,
  /\bsk-[A-Za-z0-9_-]{20,}\b/u,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u,
  /\b[0-9a-f]{64}\b/iu,
])
