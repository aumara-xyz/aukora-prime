export const AUTHORS = Object.freeze(['peter', 'gpt', 'grok', 'claudecode_cloud', 'claudecode_local', 'muse', 'dot', 'claude', 'auma']);
// AUMA is advisory and narrow: she may read and post plain chat, nothing else (no claims, reviews,
// decisions or status writes), at her own lower rate and body size. Every other agent keeps the full agent scopes.
export const NARROW_AUTHORS = Object.freeze({ auma: Object.freeze({ scopes: Object.freeze(['messages:read', 'messages:post:chat']), requestsPerMinute: 12, bodyBytes: 2000 }) });
export function scopesFor(author) {
  if (Object.hasOwn(NARROW_AUTHORS, author)) return [...NARROW_AUTHORS[author].scopes];
  return ['messages:read', 'messages:post:chat', 'messages:post:claim', 'messages:post:review', 'status:read', 'status:write:self', ...(author === 'peter' ? ['messages:post:decision'] : [])];
}
export function requestsPerMinuteFor(author) { return Object.hasOwn(NARROW_AUTHORS, author) ? NARROW_AUTHORS[author].requestsPerMinute : LIMITS.requestsPerMinute; }
export function bodyBytesFor(author) { return Object.hasOwn(NARROW_AUTHORS, author) ? NARROW_AUTHORS[author].bodyBytes : LIMITS.bodyBytes; }
export function requireScope(author, scope) { requireCondition(scopesFor(author).includes(scope), 403, 'scope_denied'); }
export const KINDS = Object.freeze(['chat', 'claim', 'review', 'decision']);
export const LIMITS = Object.freeze({ requestBytes: 32768, bodyBytes: 16384, refs: 32, refBytes: 512, doingBytes: 1024, pageSize: 100, tail: 20, requestsPerMinute: 120, maxCursor: 9223372036854775807n });
export const STORAGE = Object.freeze({ agentQuotaBytes: 16 * 1024 * 1024, peterQuotaBytes: 32 * 1024 * 1024, maxPages: 65536, reservedPeterPages: 16384, rowOverheadBytes: 512 });

export class RelayError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
export function requireCondition(condition, status, code) {
  if (!condition) throw new RelayError(status, code);
}
export function exactObject(value, keys) {
  requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value), 400, 'invalid_object');
  requireCondition(Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k)), 400, 'invalid_fields');
}
function boundedString(value, bytes, allowEmpty = false) {
  requireCondition(typeof value === 'string' && (allowEmpty || value.trim().length > 0) && Buffer.byteLength(value, 'utf8') <= bytes && value.isWellFormed() && !value.includes('\u0000'), 400, 'invalid_string');
}
export function validateMessage(value) {
  exactObject(value, ['clientRequestId', 'kind', 'body', 'refs']);
  requireCondition(typeof value.clientRequestId === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value.clientRequestId), 400, 'invalid_request_id');
  requireCondition(KINDS.includes(value.kind), 400, 'invalid_kind');
  boundedString(value.body, LIMITS.bodyBytes);
  requireCondition(Array.isArray(value.refs) && value.refs.length <= LIMITS.refs, 400, 'invalid_refs');
  for (const ref of value.refs) boundedString(ref, LIMITS.refBytes);
  return value;
}
export function validateStatus(value) {
  exactObject(value, ['doing']); boundedString(value.doing, LIMITS.doingBytes, true); return value;
}
export function parsePage(params) {
  // tail=N (1..20) alone returns the newest N messages in ascending order, so a narrow reader needs one request.
  if (params.has('tail')) {
    requireCondition([...params.keys()].length === 1 && params.getAll('tail').length === 1, 400, 'invalid_query');
    const tail = params.get('tail'); requireCondition(/^[1-9][0-9]?$/.test(tail) && Number(tail) <= LIMITS.tail, 400, 'invalid_tail');
    return { tail: Number(tail) };
  }
  requireCondition([...params.keys()].every(k => ['after', 'limit'].includes(k)) && params.getAll('after').length <= 1 && params.getAll('limit').length <= 1, 400, 'invalid_query');
  const after = params.get('after') ?? '0'; const limit = params.get('limit') ?? '50';
  requireCondition(/^(0|[1-9][0-9]{0,18})$/.test(after) && BigInt(after) <= LIMITS.maxCursor, 400, 'invalid_cursor');
  requireCondition(/^[1-9][0-9]{0,2}$/.test(limit) && Number(limit) <= LIMITS.pageSize, 400, 'invalid_limit');
  return { after, limit: Number(limit) };
}
