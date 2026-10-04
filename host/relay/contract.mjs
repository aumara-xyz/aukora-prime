export const AUTHORS = Object.freeze(['peter', 'gpt', 'grok', 'claudecode_cloud', 'claudecode_local', 'muse', 'dot']);
export function scopesFor(author) {
  return ['messages:read', 'messages:post:chat', 'messages:post:claim', 'messages:post:review', 'status:read', 'status:write:self', ...(author === 'peter' ? ['messages:post:decision'] : [])];
}
export const KINDS = Object.freeze(['chat', 'claim', 'review', 'decision']);
export const LIMITS = Object.freeze({ requestBytes: 32768, bodyBytes: 16384, refs: 32, refBytes: 512, doingBytes: 1024, pageSize: 100, requestsPerMinute: 120, maxCursor: 9223372036854775807n });
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
  requireCondition([...params.keys()].every(k => ['after', 'limit'].includes(k)) && params.getAll('after').length <= 1 && params.getAll('limit').length <= 1, 400, 'invalid_query');
  const after = params.get('after') ?? '0'; const limit = params.get('limit') ?? '50';
  requireCondition(/^(0|[1-9][0-9]{0,18})$/.test(after) && BigInt(after) <= LIMITS.maxCursor, 400, 'invalid_cursor');
  requireCondition(/^[1-9][0-9]{0,2}$/.test(limit) && Number(limit) <= LIMITS.pageSize, 400, 'invalid_limit');
  return { after, limit: Number(limit) };
}
