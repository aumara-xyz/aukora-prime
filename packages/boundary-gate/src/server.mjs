// Socket and HTTP front of the gate. One JSON request per line, one JSON reply, connection closed.
//   PROPOSE socket: 0660, group = the shared group (harness + gate). proposeOps only.
//   OWNER socket:   0600, gate user only (root can still connect). ownerOps; the approver principal is fixed here.
//   OWNER HTTP:     OFF by default (ownerPage: true / gate.mjs --owner-page to serve it). Loopback only; bearer-protected
//                   page whose approval runs the same review -> decide_review ceremony as the popup.
import net from 'node:net'
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import { createOwnerPage } from './owner-page.mjs'

export const OWNER_SOCKET_APPROVER = 'owner via owner.sock (local; 0600 gate user/root only)'

export function lineServer(opmap, approverFor) {
  return net.createServer((c) => {
    let buf = ''; c.setTimeout(30000, () => c.destroy())
    c.on('data', (d) => {
      buf += d; if (buf.length > 1 << 20) { c.destroy(); return }
      const nl = buf.indexOf('\n'); if (nl < 0) return
      let res
      try {
        const req = JSON.parse(buf.slice(0, nl)); const fn = typeof req?.op === 'string' && Object.hasOwn(opmap, req.op) ? opmap[req.op] : null
        if (!fn) throw new Error('unknown op')
        const args = req.args && typeof req.args === 'object' && !Array.isArray(req.args) ? req.args : {}
        res = { ok: true, result: fn(args, approverFor ? approverFor(c) : undefined) }
      } catch (e) { res = { ok: false, error: String(e?.message ?? e) } }
      c.end(JSON.stringify(res) + '\n')
    })
    c.on('error', () => {})
  })
}

const listen = (srv, ...a) => new Promise((res, rej) => { srv.once('error', rej); srv.listen(...a, () => { srv.off('error', rej); res(srv) }) })

export async function serveGate(gate, { runDir, gid = 0, ownerHttpPort = 17792, timeZone = 'UTC', ownerPage = false }) {
  fs.mkdirSync(runDir, { recursive: true })
  const proposeSocket = path.join(runDir, 'gate.sock'), ownerSocket = path.join(runDir, 'owner.sock')
  for (const s of [proposeSocket, ownerSocket]) { try { fs.unlinkSync(s) } catch {} }
  const proposeServer = await listen(lineServer(gate.proposeOps), proposeSocket)
  if (gid) fs.chownSync(proposeSocket, process.getuid(), gid)
  fs.chmodSync(proposeSocket, 0o660)
  fs.writeFileSync(path.join(runDir, 'receipt-ed25519.pub'), gate.pubPem, { mode: 0o644 })
  const ownerServer = await listen(lineServer(gate.ownerOps, () => OWNER_SOCKET_APPROVER), ownerSocket)
  fs.chmodSync(ownerSocket, 0o600)
  try { fs.unlinkSync(path.join(runDir, 'owner-http.port')) } catch {}
  const page = ownerPage ? createOwnerPage(gate, { timeZone }) : null
  const ownerHttp = page ? await listen(http.createServer(page.handler), ownerHttpPort, '127.0.0.1') : null
  const port = ownerHttp ? ownerHttp.address().port : null
  if (ownerHttp) fs.writeFileSync(path.join(runDir, 'owner-http.port'), String(port), { mode: 0o644 })
  return {
    proposeSocket, ownerSocket, port, page,
    close: () => Promise.all([proposeServer, ownerServer, ownerHttp].filter(Boolean).map(s => new Promise(r => s.close(() => r())))),
  }
}

// Minimal client for one request on a gate socket. Fails closed on timeout, bad reply or connection error.
export function call(sockPath, op, args = {}, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const c = net.createConnection(sockPath); let buf = ''
    const t = setTimeout(() => { c.destroy(); reject(new Error('gate timeout (fail closed)')) }, timeoutMs)
    c.on('connect', () => c.write(JSON.stringify({ op, args }) + '\n'))
    c.on('data', d => { buf += d })
    c.on('end', () => { clearTimeout(t); let r; try { r = JSON.parse(buf) } catch { return reject(new Error('gate: bad reply (fail closed)')) } r.ok ? resolve(r.result) : reject(new Error(r.error)) })
    c.on('error', e => { clearTimeout(t); reject(Object.assign(new Error(`gate unavailable (${e.code}); fail closed`), { code: e.code })) })
  })
}
