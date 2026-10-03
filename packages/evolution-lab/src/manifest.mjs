// SPDX-License-Identifier: AGPL-3.0-or-later

export const EVIDENCE_CLASSES = Object.freeze([
  'measured', 'synthetic', 'historical-reported', 'proposed', 'unperformed',
]);
export const EVIDENCE_LABELS = Object.freeze({
  measured: 'Measured',
  synthetic: 'Synthetic',
  'historical-reported': 'Historical reported',
  proposed: 'Proposed',
  unperformed: 'Unperformed',
});
export const EXECUTIONS = Object.freeze(['RAN', 'SOURCE-ONLY', 'RECORDED', 'UNPERFORMED']);
export const CLASS_EXECUTIONS = Object.freeze({
  measured: Object.freeze(['RAN']),
  synthetic: Object.freeze(['RAN', 'SOURCE-ONLY', 'RECORDED']),
  'historical-reported': Object.freeze(['RECORDED']),
  proposed: Object.freeze(['UNPERFORMED']),
  unperformed: Object.freeze(['UNPERFORMED']),
});
export const MANIFEST_MAX_BYTES = 64 * 1024;
export const MANIFEST_MAX_DEPTH = 12;

const ERROR_MESSAGES = Object.freeze({
  'invalid-input': 'Evolution Lab requires JSON text.',
  'too-large': 'Evolution Lab manifest exceeds its size limit.',
  'too-deep': 'Evolution Lab manifest exceeds its nesting limit.',
  'invalid-json': 'Evolution Lab manifest is not valid JSON.',
  'duplicate-key': 'Evolution Lab manifest contains duplicate JSON keys.',
  'invalid-schema': 'Evolution Lab manifest does not match its closed schema.',
  'unsafe-text': 'Evolution Lab manifest contains disallowed text.',
  'invalid-lineage': 'Evolution Lab manifest has invalid artifact or entry lineage.',
  'inconsistent-state': 'Evolution Lab manifest contains inconsistent evidence states.',
});

export class ManifestError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES['invalid-schema']);
    this.name = 'ManifestError';
    this.code = Object.hasOwn(ERROR_MESSAGES, code) ? code : 'invalid-schema';
  }
}

function reject(code = 'invalid-schema') {
  throw new ManifestError(code);
}

const ROOT_KEYS = Object.freeze([
  'schemaVersion', 'title', 'availability', 'mode', 'reason', 'limits', 'entries',
]);
const ENTRY_KEYS = Object.freeze([
  'id', 'kind', 'title', 'parentIds', 'evidenceClass', 'execution', 'sourcePin',
  'command', 'costUsd', 'wallTimeSeconds', 'modelProvenance', 'artifacts',
  'prediction', 'outcome', 'failures', 'limits',
]);
const ARTIFACT_KEYS = Object.freeze(['id', 'parentIds', 'title', 'evidenceClass', 'sha256', 'receipt']);
const SLUG = /^[a-z0-9](?:[a-z0-9_-]{0,63})$/;
const REVISION = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const UTC_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const RECEIPT_PATH = /^(?:docs|research)\/evidence\/(?:[A-Za-z0-9][A-Za-z0-9_-]*\/)*[A-Za-z0-9][A-Za-z0-9_-]*\.(?:json|md|txt)$/;
const DISALLOWED_CHARACTERS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const PRIVATE_PATH = /(?:\/Users\/|\/home\/|\/root\/|\/private\/|\/tmp\/|\/var\/folders\/|\/(?:workspace|workspaces|workdir)\/|\/mnt\/data\/|(?:^|[\s"'=])~[\/\\]|[A-Za-z]:[\\/]Users[\\/]|Documents[\\/]Codex|(?:^|[\s"'=])(?:\.runtime|\.codex|\.aws)[\/\\]|(?:^|[\s"'=])(?:workspace|workspaces)[\/\\])/i;
const IPV4 = /(?:^|[^0-9])(?:\d{1,3}\.){3}\d{1,3}(?:$|[^0-9])/;
const CREDENTIAL = /(?:-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bBearer\s+[A-Za-z0-9._~+/-]{8,}|\bAuthorization\s*:\s*Basic\s+\S{8,}|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|\b(?:api[_ -]?key|access[_ -]?token|client[_ -]?secret|password|passwd|secret|token)\s*[:=]\s*["']?[^\s"']{4,}|\b[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s/@:]+:[^\s/@]+@)/i;

// These narrow checks supplement upstream owner sanitation; they are not DLP.
function hasIPv6(text) {
  for (const match of text.matchAll(/[0-9a-f:]+/gi)) {
    const candidate = match[0];
    if (!candidate.includes(':')) continue;
    const halves = candidate.split('::');
    if (halves.length > 2) continue;
    const groups = halves.flatMap(part => part === '' ? [] : part.split(':'));
    if (!groups.every(group => /^[0-9a-f]{1,4}$/i.test(group))) continue;
    if ((halves.length === 1 && groups.length === 8)
      || (halves.length === 2 && groups.length < 8)) return true;
  }
  return false;
}

function text(value, max, min = 1) {
  if (typeof value !== 'string' || [...value].length < min || [...value].length > max
    || (min > 0 && value.trim().length === 0)) reject();
  if (DISALLOWED_CHARACTERS.test(value) || PRIVATE_PATH.test(value)
    || IPV4.test(value) || hasIPv6(value) || CREDENTIAL.test(value)) reject('unsafe-text');
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) reject('unsafe-text');
    } else if (unit >= 0xdc00 && unit <= 0xdfff) reject('unsafe-text');
  }
}

function closed(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) reject();
  const actual = Object.keys(value);
  if (actual.length !== keys.length || !keys.every(key => Object.hasOwn(value, key))) reject();
}

function member(value, values) {
  if (!values.includes(value)) reject();
}

function slug(value) {
  if (typeof value !== 'string' || !SLUG.test(value)) reject();
}

function nullableMatch(value, pattern) {
  if (value !== null && (typeof value !== 'string' || !pattern.test(value))) reject();
}

function boundedArray(value, max, validate) {
  if (!Array.isArray(value) || value.length > max) reject();
  for (const item of value) validate(item);
}

function textList(value) {
  boundedArray(value, 16, item => text(item, 1000));
}

function parents(value) {
  boundedArray(value, 8, slug);
  if (new Set(value).size !== value.length) reject('invalid-lineage');
}

function receipt(value) {
  if (value === null) return;
  closed(value, ['path', 'revision']);
  text(value.path, 240);
  if (!RECEIPT_PATH.test(value.path)) reject();
  nullableMatch(value.revision, REVISION);
  if (value.revision === null) reject();
}

function utcDate(value) {
  nullableMatch(value, UTC_DATE);
  if (value === null) return;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) reject();
  const canonical = value.includes('.') ? value : value.replace('Z', '.000Z');
  if (parsed.toISOString() !== canonical) reject();
}

function metric(value) {
  if (value !== null && (typeof value !== 'number' || !Number.isFinite(value)
    || value < 0 || value > 1e9 || Object.is(value, -0))) reject();
}

function evidence(value) {
  member(value, EVIDENCE_CLASSES);
}

function artifact(value) {
  closed(value, ARTIFACT_KEYS);
  slug(value.id);
  parents(value.parentIds);
  text(value.title, 120);
  evidence(value.evidenceClass);
  nullableMatch(value.sha256, SHA256);
  receipt(value.receipt);
}

function prediction(value) {
  if (value === null) return;
  closed(value, ['evidenceClass', 'preregisteredAt', 'sourcePin', 'statement', 'receipt']);
  evidence(value.evidenceClass);
  utcDate(value.preregisteredAt);
  nullableMatch(value.sourcePin, REVISION);
  text(value.statement, 1000);
  receipt(value.receipt);
}

function outcome(value) {
  if (value === null) return;
  closed(value, ['evidenceClass', 'observedAt', 'summary']);
  evidence(value.evidenceClass);
  utcDate(value.observedAt);
  text(value.summary, 1000);
}

function entry(value) {
  closed(value, ENTRY_KEYS);
  slug(value.id);
  member(value.kind, ['generation', 'experiment', 'source-check']);
  text(value.title, 120);
  parents(value.parentIds);
  evidence(value.evidenceClass);
  member(value.execution, EXECUTIONS);
  if (!CLASS_EXECUTIONS[value.evidenceClass].includes(value.execution)) reject('inconsistent-state');
  nullableMatch(value.sourcePin, REVISION);
  if (value.command !== null) text(value.command, 256);
  metric(value.costUsd);
  metric(value.wallTimeSeconds);
  if (value.modelProvenance !== null) {
    closed(value.modelProvenance, ['model', 'registration', 'evidenceClass']);
    text(value.modelProvenance.model, 120);
    text(value.modelProvenance.registration, 240);
    evidence(value.modelProvenance.evidenceClass);
  }
  boundedArray(value.artifacts, 16, artifact);
  prediction(value.prediction);
  outcome(value.outcome);
  if (value.prediction?.preregisteredAt && value.outcome?.observedAt
    && new Date(value.prediction.preregisteredAt).getTime() >= new Date(value.outcome.observedAt).getTime()) {
    reject('inconsistent-state');
  }
  textList(value.failures);
  textList(value.limits);
  if (['proposed', 'unperformed'].includes(value.evidenceClass)
    && (value.costUsd !== null || value.wallTimeSeconds !== null
      || value.execution !== 'UNPERFORMED')) reject('inconsistent-state');
}

function checkLineage(items) {
  const byId = new Map();
  for (const item of items) {
    if (byId.has(item.id)) reject('invalid-lineage');
    byId.set(item.id, item);
  }
  const visited = new Set();
  const pending = new Set();
  function visit(id) {
    if (pending.has(id) || !byId.has(id)) reject('invalid-lineage');
    if (visited.has(id)) return;
    pending.add(id);
    for (const parentId of byId.get(id).parentIds) visit(parentId);
    pending.delete(id);
    visited.add(id);
  }
  for (const id of byId.keys()) visit(id);
}

function checkState(value) {
  if ((value.availability === 'available') !== (value.entries.length > 0)
    || (value.availability === 'unavailable' && value.reason === null)) reject('inconsistent-state');
  if (value.mode === 'synthetic-fixture') {
    for (const item of value.entries) {
      const labeled = [item, ...item.artifacts, item.modelProvenance, item.prediction, item.outcome];
      if (labeled.some(part => part !== null && part.evidenceClass !== 'synthetic')) reject('inconsistent-state');
    }
  }
  checkLineage(value.entries);
  checkLineage(value.entries.flatMap(item => item.artifacts));
}

// Inspect raw JSON before JSON.parse can discard duplicate decoded keys.
function inspectJson(source) {
  let cursor = 0;
  function whitespace() {
    while (cursor < source.length && /[ \t\n\r]/.test(source[cursor])) cursor += 1;
  }
  function stringToken() {
    const start = cursor;
    if (source[cursor++] !== '"') reject('invalid-json');
    while (cursor < source.length) {
      const character = source[cursor++];
      if (character === '"') return source.slice(start, cursor);
      if (character === '\\') cursor += 1;
    }
    reject('invalid-json');
  }
  function value(depth) {
    if (depth > MANIFEST_MAX_DEPTH) reject('too-deep');
    whitespace();
    const opening = source[cursor];
    if (opening === '{' || opening === '[') {
      cursor += 1;
      whitespace();
      const closing = opening === '{' ? '}' : ']';
      const keys = new Set();
      if (source[cursor] === closing) { cursor += 1; return; }
      while (cursor < source.length) {
        if (opening === '{') {
          let key;
          try { key = JSON.parse(stringToken()); } catch (error) {
            if (error instanceof ManifestError) throw error;
            reject('invalid-json');
          }
          if (keys.has(key)) reject('duplicate-key');
          keys.add(key);
          whitespace();
          if (source[cursor++] !== ':') reject('invalid-json');
        }
        value(depth + 1);
        whitespace();
        if (source[cursor] === closing) { cursor += 1; return; }
        if (source[cursor++] !== ',') reject('invalid-json');
        whitespace();
      }
      reject('invalid-json');
    } else if (opening === '"') {
      stringToken();
    } else {
      const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(source.slice(cursor));
      if (token === null) reject('invalid-json');
      cursor += token[0].length;
    }
  }
  value(0);
  whitespace();
  if (cursor !== source.length) reject('invalid-json');
}

function freeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
}

/** Recognize inert, owner-sanitized evidence JSON. Does not fetch or execute it. */
export function parseManifest(jsonText) {
  if (typeof jsonText !== 'string') reject('invalid-input');
  if (jsonText.length > MANIFEST_MAX_BYTES
    || new TextEncoder().encode(jsonText).byteLength > MANIFEST_MAX_BYTES) reject('too-large');
  inspectJson(jsonText);
  let value;
  try { value = JSON.parse(jsonText); } catch { reject('invalid-json'); }
  closed(value, ROOT_KEYS);
  if (value.schemaVersion !== 1) reject();
  text(value.title, 80);
  member(value.availability, ['unavailable', 'empty', 'available']);
  member(value.mode, ['synthetic-fixture', 'sanitized-reference']);
  if (value.reason !== null) text(value.reason, 240);
  textList(value.limits);
  boundedArray(value.entries, 32, entry);
  checkState(value);
  return freeze(value);
}

export const EMPTY_MANIFEST_JSON = JSON.stringify({
  schemaVersion: 1,
  title: 'Evolution Lab',
  availability: 'unavailable',
  mode: 'sanitized-reference',
  reason: 'No approved sanitized evidence manifest has been supplied.',
  limits: [
    'No generation metrics have been measured or loaded.',
    'Registration and model provenance are not safety certification.',
    'Evidence must be sanitized upstream by its owner; text checks are not complete data loss prevention.',
  ],
  entries: [],
});
