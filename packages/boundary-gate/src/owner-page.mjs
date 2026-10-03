// Owner approval page, served by the gate itself (never through the harness), protected by the owner bearer
// (rotated on every gate start, 12 h expiry). Approve is two-step: Reject comes first in tab order; "Approve…
// (step 1 of 2)" is out of the tab order and only opens step 2, where the result must be TYPED before
// "Confirm apply" works (single-use nonce, 2 min). Tab/Enter/Space alone cannot approve. Every POST must echo
// the exact base and result sha256 the page showed, or it is refused.
import { randomBytes } from 'node:crypto'
import { bearerOk } from './secrets.mjs'
import { colorName, isHex } from './card.mjs'

export const CONFIRM_TTL_MS = 2 * 60 * 1000
export const PAGE_APPROVER = 'owner via gate approval page (bearer token, typed 2-step confirm)'
export const PAGE_REJECTER = 'owner via gate approval page (bearer token)'
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
const chip = (h) => isHex(h) ? `<span class=chip style="background:${esc(h.toUpperCase())}"></span>` : `<span class="chip dflt" title="app default: stock accent, unknown colour"></span>`
const CSS = 'body{font:15px/1.5 system-ui;margin:0;background:#111;color:#eee;padding:16px}.card{background:#1b1b1b;border:1px solid #444;border-radius:10px;padding:12px;margin:12px 0}.h{color:#6cf;font-weight:700;font-size:12px}.plain{font-size:18px;margin:6px 0}.after{font-weight:700;color:#fd6}.sw{margin:8px 0;font-size:16px}.chip{display:inline-block;width:44px;height:28px;border-radius:6px;border:2px solid #fff;vertical-align:middle;margin:0 4px}.chip.dflt{background:repeating-linear-gradient(45deg,#555 0 6px,#999 6px 12px)}.swt{font-size:12px;color:#aaa}.warn{background:#3a1010;border:2px solid #f44;border-radius:8px;padding:6px 10px;margin:8px 0}.wh{color:#f88;font-weight:700}.warn li{margin:2px 0}.nowarn{color:#888;font-size:12px}.note{background:#2a2a1a;border:1px dashed #776;border-radius:8px;padding:8px;margin:8px 0;white-space:pre-wrap}.nh{color:#cc6;font-size:12px;font-weight:700}.hex{font:12px monospace;color:#bbb;margin-top:4px}.btns form{display:inline}button{font-size:16px;padding:10px 18px;border-radius:8px;border:0;margin-top:8px}.ap,.ap1{background:#2a7;color:#fff}.ap1{opacity:.8}.rj{background:#a33;color:#fff}.confirm{margin-top:10px;padding:8px;border:1px solid #2a7;border-radius:8px}.confirm input{font:16px monospace;padding:6px;margin:6px 0}div{word-break:break-all}.msg{color:#6f6}'

export function createOwnerPage(gate, { timeZone = 'UTC', confirmTtlMs = CONFIRM_TTL_MS } = {}) {
  const { owner, now } = gate
  const confirms = new Map()   // nonce -> { id, base, new, exp } (single use; memory only)
  const resultLabel = (v) => v.new_accent === 'default' ? 'default' : '#' + String(v.new_accent ?? '').replace(/^#/, '')

  function pageHtml(msg, confirmFor) {
    const items = gate.pendingRows().map(p => {
      const v = gate.cardView(p)
      const hid = `<input type=hidden name=k value="${esc(owner.bearer)}"><input type=hidden name=id value="${esc(p.id)}"><input type=hidden name=base value="${esc(p.base_sha)}"><input type=hidden name=new value="${esc(p.new_sha)}">`
      let step2 = ''
      if (confirmFor && confirmFor.id === p.id) step2 = `<form method=POST action=/act class=confirm>${hid}<input type=hidden name=nonce value="${esc(confirmFor.nonce)}">
      <div><b>Step 2 of 2.</b> Type the result <b>${esc(resultLabel(v))}</b> exactly to confirm (Enter/Space/Tab alone cannot approve):</div>
      <input name=typed autocomplete=off spellcheck=false placeholder="type ${esc(resultLabel(v).replace(/^#/, ''))}" aria-label="type the result colour to confirm">
      <button name=a value=confirm class=ap tabindex=-1>Confirm apply ${esc(resultLabel(v))}</button></form>`
      return `<div class=card data-id="${esc(p.id)}"><div class=h>HOST-VERIFIED (gate)</div>
      <div class=plain>${esc(v.plain)}</div>
      <div class=after>${esc(v.after_apply)}</div>
      <div class=sw>${chip(v.base_accent)} BEFORE ${esc(v.base_accent ?? '?')} ${esc(colorName(v.base_accent))} <span class=arr>&rarr;</span> ${chip(v.new_accent)} AFTER ${esc(v.new_accent ?? '?')} ${esc(colorName(v.new_accent))}</div>
      <div class=swt>${esc(v.swatch ?? '')}</div>
      ${v.warnings.length ? `<div class=warn><div class=wh>GATE WARNINGS (${v.warnings.length})</div><ul>${v.warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul></div>` : '<div class=nowarn>gate warnings: none</div>'}
      <div>target: <b>${esc(p.target)}</b></div>
      <div>proposal ${esc(p.id)} · expires ${esc(new Date(p.expires).toLocaleTimeString('en-GB', { timeZone }))} ${esc(timeZone)}</div>
      <div>current sha256 ${esc(p.base_sha)}</div><div>result&nbsp; sha256 ${esc(p.new_sha)}</div>
      <div class=note><div class=nh>MODEL NOTE (unverified)</div>${esc(v.note_display)}${v.note_meta?.hexdump ? `<div class=hex>raw note bytes (${esc(v.note_meta.raw_bytes)}): ${esc(v.note_meta.hexdump)}</div>` : ''}</div>
      <div class=btns><form method=POST action=/act class=rjf>${hid}<button name=a value=reject class=rj>Reject</button></form>
      <form method=POST action=/act class=apf>${hid}<button name=a value=approve-step1 class=ap1 tabindex=-1>Approve&hellip; (step 1 of 2)</button></form></div>${step2}</div>`
    }).join('\n')
    return `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>Boundary gate — owner approval</title>
  <style>${CSS}</style>
  <h2>Boundary gate — owner approval</h2><p>This page is served directly by the gate, not by the harness. Only items below are gate-verified. Approve takes two steps and a typed confirmation.</p>
  ${msg ? `<p class=msg>${esc(msg)}</p>` : ''}${items || '<p>No pending proposals.</p>'}`
  }

  // Pure form handler (used by the HTTP server and by checks). Returns { status, body }.
  function act(form) {
    const f = form instanceof URLSearchParams ? form : new URLSearchParams(form)
    if (!bearerOk(owner, f.get('k'), now)) return { status: 401, body: unauthorized() }
    const id = String(f.get('id')), a = f.get('a')
    const p = gate.db.prepare('SELECT base_sha,new_sha,target,state FROM proposals WHERE id=?').get(id)
    let msg, confirmFor = null
    for (const [k, v] of confirms) if (now() > v.exp) confirms.delete(k)
    if (!p) msg = 'proposal not found'
    else if (p.base_sha !== f.get('base') || p.new_sha !== f.get('new')) msg = 'refused: proposal changed since the page was shown; reload and re-check.'
    else if (a === 'reject') { const r = gate.ownerOps.reject({ id }, PAGE_REJECTER); msg = `rejected: ${r.message}` }
    else if (a === 'approve-step1') {
      if (p.state !== 'pending') msg = `proposal is ${p.state}`
      else { const nonce = randomBytes(16).toString('base64url'); confirms.set(nonce, { id, base: p.base_sha, new: p.new_sha, exp: now() + confirmTtlMs }); confirmFor = { id, nonce }; msg = 'Step 2: type the result colour below to confirm. Nothing has been applied.' }
    } else if (a === 'confirm') {
      const n = String(f.get('nonce')); const c = confirms.get(n); confirms.delete(n)
      const s = gate.targets[p.target]
      const want = (s?.accentOf?.(gate.blobText(p.new_sha)) ?? '').replace(/^#/, '').toUpperCase(), typed = String(f.get('typed') ?? '').trim().replace(/^#/, '').toUpperCase()
      if (!c || c.id !== id || c.base !== p.base_sha || c.new !== p.new_sha || now() > c.exp) msg = 'not applied: confirmation expired or invalid - start again with Approve (step 1).'
      else if (!want || typed !== want) msg = `not applied: typed confirmation "${typed.slice(0, 20)}" does not match the result. Nothing changed.`
      else { const r = gate.ownerOps.approve({ id }, PAGE_APPROVER); msg = r.applied ? `APPLIED ${p.target} — ledger #${r.ledger_seq}` : `not applied: ${r.message}` }
    } else msg = 'unknown action; nothing done'
    return { status: 200, body: pageHtml(msg, confirmFor) }
  }
  const unauthorized = () => owner.bearer_expires && now() > owner.bearer_expires ? 'unauthorized: owner link expired (12 h). Rotate the bearer (owner socket rotate_bearer) or restart the gate for a new link.' : 'unauthorized'

  function handler(req, res) {
    const u = new URL(req.url, 'http://gate.invalid')
    const send = (status, body, type = 'text/html; charset=utf-8') => { res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'" }); res.end(body) }
    if (req.method === 'GET' && u.pathname === '/') return bearerOk(owner, u.searchParams.get('k'), now) ? send(200, pageHtml('')) : send(401, unauthorized(), 'text/plain')
    if (req.method === 'POST' && u.pathname === '/act') {
      let body = ''; req.on('data', d => { body += d; if (body.length > 1e5) req.destroy() })
      req.on('end', () => { const r = act(body); send(r.status, r.body, r.status === 401 ? 'text/plain' : undefined) })
      return
    }
    send(404, 'not found', 'text/plain')
  }
  return { pageHtml, act, handler, confirms }
}
