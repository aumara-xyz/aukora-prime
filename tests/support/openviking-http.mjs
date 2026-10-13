// The stand-in serves OpenViking requests over loopback, with opt-in injected transport for listen refusals.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'

export const loopbackListenUnavailable = error => error?.syscall === 'listen' && ['EPERM', 'EACCES'].includes(error?.code)

export async function createOpenVikingHttpFixture({ statement, question, semanticMatch = (content, query) => content === statement && query.endsWith(question), allowTransportFallback = false } = {}) {
  const files = new Map(), vectors = new Set(), calls = []
  const controls = { embeddingDown: false, vectorStatus: 'complete', slow: false, writeFailures: new Map(), maxContentBytes: Infinity }
  // Shapes from vendor/openviking/upstream-openviking.json's v0.4.21 source:
  // server/routers/{content,search,filesystem}.py and storage/content_write.py.
  // Scores are deterministic fixtures, never an embedding benchmark.
  const dispatch = async request => {
    const url = new URL(request.url), body = request.body ? JSON.parse(request.body) : {}, uri = url.searchParams.get('uri')
    calls.push({ path: url.pathname, method: request.method, uri: body.uri ?? uri, query: body.query,
      ...(url.pathname === '/api/v1/content/write' ? { timeout: body.timeout, bytes: Buffer.byteLength(body.content, 'utf8') } : {}) })
    const ok = result => ({ status: 200, body: { status: 'ok', result } })
    const error = (status, code) => ({ status, body: { status: 'error', error: { code, message: 'synthetic detail' } } })
    if (url.pathname === '/health') return { status: 200, body: { healthy: true } }
    if (request.headers?.['x-api-key'] !== 'synthetic-key') return error(401, 'UNAUTHENTICATED')
    assert.equal(request.headers['x-openviking-account'], 'aukora')
    assert.equal(request.headers['x-openviking-user'], 'owner')
    if (url.pathname === '/api/v1/content/write') {
      assert.equal(request.method, 'POST'); assert.equal(body.mode, 'replace'); assert.equal(body.wait, true)
      assert.ok(body.uri.startsWith('viking://user/owner/memories/kira/content/'))
      const refusal = controls.writeFailures.get(body.uri)
      if (refusal?.httpStatus) return error(refusal.httpStatus, 'SYNTHETIC-WRITE-REFUSED')
      if (Buffer.byteLength(body.content, 'utf8') > controls.maxContentBytes) return error(413, 'CONTENT_TOO_LARGE')
      files.set(body.uri, body.content)
      if (controls.slow) await new Promise(resolve => setTimeout(resolve, 150))
      const status = refusal && Object.hasOwn(refusal, 'vectorStatus') ? refusal.vectorStatus : controls.embeddingDown ? 'failed' : controls.vectorStatus
      if (status === 'complete') vectors.add(body.uri)
      return ok({ uri: body.uri, semantic_status: 'skipped', vector_status: status })
    }
    if (url.pathname === '/api/v1/search/find') {
      if (controls.embeddingDown) return error(500, 'INTERNAL')
      assert.equal(body.target_uri, 'viking://user/owner/memories/kira/content')
      return ok({ memories: [...vectors].filter(uri => semanticMatch(files.get(uri), body.query))
        .map(uri => ({ uri, score: 0.91, abstract: 'untrusted summary' })), resources: [], skills: [], total: vectors.size })
    }
    if (url.pathname === '/api/v1/content/read') return files.has(uri) ? ok(files.get(uri)) : error(404, 'NOT_FOUND')
    if (url.pathname === '/api/v1/fs' && request.method === 'DELETE') { files.delete(uri); vectors.delete(uri); return ok({}) }
    throw Error(`unexpected fixture endpoint ${url.pathname}`)
  }
  const server = createServer(async (req, res) => {
    try {
      let body = ''; for await (const chunk of req) body += chunk
      const reply = await dispatch({ url: `http://127.0.0.1${req.url}`, method: req.method, headers: req.headers, body })
      res.writeHead(reply.status, { 'content-type': 'application/json' }); res.end(JSON.stringify(reply.body))
    } catch { res.writeHead(500); res.end('{}') }
  })
  const injectedFetch = async (url, options = {}) => {
    options.signal?.throwIfAborted()
    const headers = Object.fromEntries(new Headers(options.headers).entries())
    const response = dispatch({ url: String(url), method: options.method ?? 'GET', headers, body: options.body })
      .then(reply => Response.json(reply.body, { status: reply.status }))
    if (!options.signal) return response
    let abort
    const aborted = new Promise((_, reject) => {
      abort = () => reject(options.signal.reason)
      options.signal.addEventListener('abort', abort, { once: true })
    })
    try { return await Promise.race([response, aborted]) }
    finally { options.signal.removeEventListener('abort', abort) }
  }
  try { await new Promise((resolve, reject) => {
    const fail = error => { server.removeListener('listening', ready); reject(error) }
    const ready = () => { server.removeListener('error', fail); resolve() }
    server.once('error', fail); server.once('listening', ready); server.listen(0, '127.0.0.1')
  }) } catch (error) {
    if (!allowTransportFallback || !loopbackListenUnavailable(error)) throw error
    return { url: 'http://127.0.0.1:49671', files, vectors, calls, controls, fetch: injectedFetch,
      transport: 'injected', listenRefusal: error.code, close: async () => {} }
  }
  return { url: `http://127.0.0.1:${server.address().port}`, files, vectors, calls, controls, fetch: globalThis.fetch, transport: 'http',
    close: async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)) } }
}
