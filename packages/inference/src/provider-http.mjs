import { InferenceRefusal, integer, refuse } from './policy.mjs';
import { parseStrictJson } from '../../contracts/src/json.mjs';

const PREFIX = '/api/prime/inference';
const PUBLIC_ERRORS = new Set(['OWNER_AUTH_UNAVAILABLE','OWNER_AUTH_REQUIRED','OWNER_APPROVAL_UNAVAILABLE','OWNER_APPROVAL_REQUIRED',
  'CREDENTIAL_SERVICE_UNAVAILABLE','INVALID_PROVIDER_CONFIG','INVALID_CREDENTIAL_ENTRY','CREDENTIAL_TICKET_INVALID',
  'CREDENTIAL_GENERATION_CHANGED','SECRET_REQUIRES_SEPARATED_OWNER_ENTRY','SECURE_OWNER_ORIGIN_REQUIRED','INVALID_HTTP_REQUEST']);
function send(res, status, value) {
  res.writeHead(status,{ 'content-type': 'application/json', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' });
  res.end(JSON.stringify(value));
}
function secureOrigin(req, origin) {
  if (!origin || new URL(origin).protocol !== 'https:' || req.headers.origin !== origin) refuse('SECURE_OWNER_ORIGIN_REQUIRED');
  // The reverse proxy must terminate authenticated HTTPS and route the entry path directly to the worker UID.
  if (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin') refuse('SECURE_OWNER_ORIGIN_REQUIRED');
}
async function readBody(req, maxBytes) {
  if (!/^application\/json(?:\s*;.*)?$/iu.test(req.headers['content-type'] ?? '')) refuse('INVALID_HTTP_REQUEST');
  let size = 0; const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) refuse('INVALID_HTTP_REQUEST');
    chunks.push(Buffer.from(chunk));
  }
  let value;
  try {
    // Retain a leading BOM so the strict JSON parser rejects it instead of silently stripping it.
    const text = new TextDecoder('utf-8',{ fatal:true,ignoreBOM:true }).decode(Buffer.concat(chunks));
    value = parseStrictJson(text,{ maxBytes });
  } catch { refuse('INVALID_HTTP_REQUEST'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) refuse('INVALID_HTTP_REQUEST');
  return value;
}
const closed = (value, keys) => {
  if (Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) refuse('INVALID_HTTP_REQUEST');
};
function errorResponse(res, error) {
  const code = error instanceof InferenceRefusal && PUBLIC_ERRORS.has(error.code) ? error.code : 'UNAVAILABLE';
  send(res,code.includes('REQUIRED') ? 401 : code.startsWith('INVALID') ? 400 : 503,{ error: code });
}

/** H mounts this in the application host. It never receives the owner's API-key field. */
export function createProviderSettingsHandler({ settings, owner_origin, ownerContext }) {
  return async (req,res) => {
    const path = new URL(req.url,'https://route.invalid').pathname;
    if (!path.startsWith(PREFIX + '/')) return false;
    // Reserved for direct worker routing. A generic app host must refuse this path without reading its body.
    if (path === PREFIX + '/credential-entry') { send(res,503,{ error: 'SECRET_REQUIRES_SEPARATED_OWNER_ENTRY' }); return true; }
    try {
      if (req.method === 'GET' && path === PREFIX + '/catalog') { send(res,200,settings.catalog()); return true; }
      if (typeof ownerContext !== 'function') refuse('OWNER_AUTH_UNAVAILABLE');
      const context = await ownerContext(req);
      if (req.method === 'GET' && path === PREFIX + '/providers/externalDeepSeek') {
        send(res,200,await settings.status(context)); return true;
      }
      secureOrigin(req,owner_origin);
      if (req.method === 'PUT' && path === PREFIX + '/providers/externalDeepSeek') {
        const body = await readBody(req,32768); closed(body,['config','approval_proof']);
        send(res,200,await settings.configure(context,body.config,body.approval_proof)); return true;
      }
      if (req.method === 'POST' && path === PREFIX + '/credential-handoff') {
        const body = await readBody(req,32768); closed(body,['expected_generation','approval_proof']);
        send(res,200,await settings.credentialHandoff(context,body)); return true;
      }
      send(res,405,{ error: 'METHOD_UNAVAILABLE' });
    } catch (error) { errorResponse(res,error); }
    return true;
  };
}

/** Mount only in the separate credential process, with direct same-origin HTTPS routing and C-backed owner auth. */
export function createCredentialEntryHandler({ service, owner_origin, ownerContext }) {
  return async (req,res) => {
    if (new URL(req.url,'https://route.invalid').pathname !== PREFIX + '/credential-entry') return false;
    try {
      if (req.method !== 'POST') refuse('INVALID_HTTP_REQUEST');
      secureOrigin(req,owner_origin);
      if (typeof ownerContext !== 'function') refuse('OWNER_AUTH_UNAVAILABLE');
      const context = await ownerContext(req);
      const body = await readBody(req,6144); closed(body,['ticket','secret']);
      try {
        const result = await service.submitEntry(context,body);
        if (result?.configured !== true || !integer(result.generation,1)) refuse('CREDENTIAL_SERVICE_UNAVAILABLE');
        send(res,200,{ configured: true, generation: result.generation });
      }
      finally { body.secret = ''; }
    } catch (error) { errorResponse(res,error); }
    return true;
  };
}
