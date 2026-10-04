import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { resolve, isAbsolute, dirname } from 'node:path';
import { mkdirSync, statSync } from 'node:fs';
import { loadAuthenticator } from './auth.mjs';
import { createStore } from './store.mjs';
import { LIMITS, RelayError, requireCondition, validateMessage, validateStatus, parsePage, scopesFor, requestsPerMinuteFor, bodyBytesFor, requireScope } from './contract.mjs';

async function readJson(req) {
  requireCondition(req.headers['content-type']?.split(';')[0].trim().toLowerCase() === 'application/json', 415, 'json_required');
  requireCondition(!req.headers['content-encoding'], 415, 'content_encoding_unsupported');
  const length = req.headers['content-length'];
  requireCondition(length === undefined || (/^[0-9]+$/.test(length) && Number(length) <= LIMITS.requestBytes), 413, 'request_too_large');
  let bytes = 0; const chunks = [];
  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    bytes += chunk.length;
    requireCondition(bytes <= LIMITS.requestBytes, 413, 'request_too_large'); chunks.push(chunk);
  }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
  catch { throw new RelayError(400, 'invalid_json'); }
}
function json(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...(status >= 400 ? { Connection: 'close' } : {}) }); res.end(JSON.stringify(value));
}
export function createRelay({ authenticate, store }) {
  const rates = new Map();
  const server = http.createServer({ maxHeaderSize: 8192, connectionsCheckingInterval: 1000 }, async (req, res) => {
    try {
      // An API for authenticated headless clients. No browser CORS or forwarded identity trust.
      requireCondition(!req.headers.origin, 403, 'browser_origin_unsupported');
      const author = authenticate(req.headers.authorization);
      const now = Date.now(); const priorRate = rates.get(author);
      const rate = !priorRate || now - priorRate.started >= 60000 ? { started: now, count: 0 } : priorRate;
      rate.count += 1; rates.set(author, rate);
      requireCondition(rate.count <= requestsPerMinuteFor(author), 429, 'rate_limited');
      requireCondition(req.url.length <= 2048, 414, 'url_too_long');
      const url = new URL(req.url, 'http://localhost');
      if (req.method === 'GET' && url.pathname === '/v1/messages') { requireScope(author, 'messages:read'); return json(res, 200, store.read(parsePage(url.searchParams))); }
      if (req.method === 'POST' && url.pathname === '/v1/messages') {
        requireCondition(url.search === '', 400, 'invalid_query');
        const input = validateMessage(await readJson(req));
        requireCondition(input.kind !== 'decision' || author === 'peter', 403, 'peter_only_decision');
        requireScope(author, `messages:post:${input.kind}`);
        requireCondition(Buffer.byteLength(input.body, 'utf8') <= bodyBytesFor(author), 413, 'body_too_large_for_author');
        const result = store.post(author, input); return json(res, result.replayed ? 200 : 201, result);
      }
      if (req.method === 'GET' && url.pathname === '/v1/status') {
        requireCondition(url.search === '', 400, 'invalid_query'); requireScope(author, 'status:read'); return json(res, 200, store.status());
      }
      if (req.method === 'PUT' && url.pathname === '/v1/status') {
        requireCondition(url.search === '', 400, 'invalid_query'); requireScope(author, 'status:write:self');
        const input = validateStatus(await readJson(req)); return json(res, 200, store.setStatus(author, input.doing));
      }
      if (req.method === 'GET' && url.pathname === '/v1/whoami' && url.search === '') return json(res, 200, { author, scopes: scopesFor(author) });
      throw new RelayError(404, 'not_found');
    } catch (error) {
      // Never echo payloads, headers, tokens, paths, or SQLite details.
      if (!res.destroyed && !res.headersSent) json(res, error instanceof RelayError ? error.status : 500, { error: error instanceof RelayError ? error.code : 'internal_error' });
    }
  });
  server.requestTimeout = 10000; server.headersTimeout = 10000; server.keepAliveTimeout = 2000;
  server.maxRequestsPerSocket = 100;
  server.maxConnections = 64;
  return server;
}
export async function start() {
  const authenticate = loadAuthenticator(process.env.RELAY_AUTH_FILE);
  const dbPath = process.env.RELAY_DB_FILE;
  requireCondition(typeof dbPath === 'string' && isAbsolute(dbPath), 500, 'absolute_db_path_required');
  const parent = dirname(dbPath); mkdirSync(parent, { recursive: true, mode: 0o700 });
  const stat = statSync(parent);
  requireCondition((stat.mode & 0o077) === 0 && stat.uid === process.getuid(), 500, 'db_directory_must_be_private');
  const port = process.env.RELAY_PORT ?? '8787';
  requireCondition(/^[0-9]{1,5}$/.test(port) && Number(port) >= 1024 && Number(port) <= 65535, 500, 'invalid_port');
  process.umask(0o077);
  const store = createStore(dbPath); const server = createRelay({ authenticate, store });
  await new Promise((done, fail) => { server.once('error', fail); server.listen(Number(port), '127.0.0.1', done); });
  console.log('Relay listening on loopback. External deployment and participant connectivity are not established.');
  let shuttingDown = false;
  const stop = () => {
    if (shuttingDown) return; shuttingDown = true;
    server.close(() => { store.close(); }); server.closeIdleConnections();
    setTimeout(() => server.closeAllConnections(), 11000).unref();
  };
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  return { server, store };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  start().catch(() => { console.error('Relay startup refused. Check private external configuration and runtime prerequisites.'); process.exitCode = 1; });
}
