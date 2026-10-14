// Owner approval page, served by the gate itself (never through the harness), protected by the owner bearer
// (rotated on every gate start, 12 h expiry). Approve is two-step: Reject comes first in tab order; "Approve…
// (step 1 of 2)" is out of the tab order and only opens step 2, where the result must be TYPED before
// "Confirm apply" works (single-use nonce, 2 min). Tab/Enter/Space alone cannot approve. Every POST must echo
// the exact base and result sha256 the page showed, or it is refused.
import { createHash, randomBytes } from 'node:crypto'
import fs from 'node:fs'
import { bearerOk } from './secrets.mjs'
import { colorName, isHex } from './card.mjs'
import { OWNER_PASSKEY_SCRIPT } from './owner-passkey-script.mjs'
import { readProtectedJson } from './owner-state.mjs'

export const CONFIRM_TTL_MS = 2 * 60 * 1000
export const PAGE_APPROVER = 'owner via gate approval page (bearer token, typed 2-step confirm)'
export const PAGE_REJECTER = 'owner via gate approval page (bearer token)'
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
const chip = (h) => isHex(h) ? `<span class=chip style="background:${esc(h.toUpperCase())}"></span>` : `<span class="chip dflt" title="app default: stock accent, unknown colour"></span>`
const CSS = ':root{color-scheme:dark;--bg:#0b0d18;--surface:rgba(38,43,54,.72);--border:rgba(255,255,255,.1);--text:#e8eaed;--secondary:#b8bcc4;--muted:#8b9099;--cyan:#96b4ff;--gold:#e0b76a;--mint:#81d4b4;--violet:#c4aaff;--red:#f2555a;--radius:14px}*{box-sizing:border-box}body{font:15px/1.55 system-ui;margin:0;min-height:100vh;padding:clamp(20px,5vw,64px) 18px;background:radial-gradient(900px 620px at 20% -10%,rgba(129,212,180,.1),transparent 60%),radial-gradient(850px 620px at 90% 105%,rgba(196,170,255,.12),transparent 60%),var(--bg);color:var(--text)}main{width:min(760px,100%);margin:auto}.mast{margin:0 0 24px}.brand{display:inline-block;margin:0;background:linear-gradient(90deg,var(--mint),var(--cyan),var(--violet),var(--gold));background-clip:text;-webkit-background-clip:text;color:transparent;font-size:clamp(30px,7vw,52px);letter-spacing:.12em;line-height:1}.mast p{margin:8px 0 0;color:var(--secondary)}.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:clamp(20px,4vw,32px);margin:16px 0;box-shadow:0 24px 80px #0005,inset 0 1px #ffffff08;backdrop-filter:blur(18px)}.card h2{margin:0 0 8px;font-size:clamp(23px,4vw,31px);line-height:1.2;letter-spacing:-.025em}.h{color:var(--cyan);font-weight:700;font-size:12px;letter-spacing:.08em}.plain{color:var(--secondary);margin:14px 0}.after{font-weight:650;color:var(--gold);margin:12px 0}.sw{margin:12px 0;font-size:16px}.chip{display:inline-block;width:44px;height:28px;border-radius:8px;border:2px solid #fff;vertical-align:middle;margin:0 4px}.chip.dflt{background:repeating-linear-gradient(45deg,#555 0 6px,#999 6px 12px)}.swt{font-size:12px;color:var(--muted)}.warn{background:rgba(242,85,90,.08);border:1px solid rgba(242,85,90,.48);border-radius:var(--radius);padding:10px 14px;margin:14px 0}.wh{color:#f98b8f;font-weight:700}.warn li{margin:4px 0}.nowarn{color:var(--muted);font-size:12px}.fingerprints{margin:16px 0;padding:14px;border:1px solid var(--border);border-radius:var(--radius);background:#08091070;color:var(--secondary);font:12px/1.65 ui-monospace,SFMono-Regular,Menlo,monospace;cursor:text;user-select:all}.fingerprints div{display:grid;grid-template-columns:minmax(92px,auto) 1fr;gap:12px}.fingerprints b{color:var(--gold);font-weight:600}.fingerprints code{font:inherit;color:var(--text);overflow-wrap:anywhere}.meta{color:var(--muted);font-size:12px}.note{background:rgba(224,183,106,.05);border:1px solid rgba(224,183,106,.25);border-radius:var(--radius);padding:12px 14px;margin:14px 0;white-space:pre-wrap;overflow-wrap:anywhere}.nh{color:var(--gold);font-size:12px;font-weight:700}.hex{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--secondary);margin-top:6px}.btns{display:flex;flex-wrap:wrap;gap:10px}.btns form{display:inline}button{font:600 15px system-ui;padding:10px 18px;border-radius:var(--radius);border:1px solid transparent;margin-top:8px;cursor:pointer}.ap,.ap1{background:rgba(150,180,255,.12);border-color:rgba(150,180,255,.45);color:var(--cyan)}.ap1{opacity:.88}.rj{background:transparent;border-color:rgba(242,85,90,.42);color:#f98b8f}button:focus-visible,input:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}.confirm{margin-top:16px;padding:16px;border:1px solid rgba(150,180,255,.45);border-radius:var(--radius);background:rgba(150,180,255,.05)}.confirm label{display:block}.confirm input{display:block;width:100%;font:16px ui-monospace,SFMono-Regular,Menlo,monospace;padding:10px 12px;margin:10px 0 4px;border:1px solid var(--border);border-radius:10px;background:#08091080;color:var(--text)}.ttl{color:var(--gold);font-size:12px}.msg{padding:12px 14px;border:1px solid rgba(129,212,180,.34);border-radius:var(--radius);background:rgba(129,212,180,.07);color:var(--mint)}.empty{color:var(--secondary)}@media(max-width:520px){.fingerprints div{display:block}.fingerprints b{display:block;margin-top:6px}.btns form,.btns button{width:100%}}'

export function createOwnerPage(gate, { timeZone = 'UTC', confirmTtlMs = CONFIRM_TTL_MS } = {}) {
  const { owner, now } = gate
  const confirms = new Map()   // nonce -> { id, base, new, exp } (single use; memory only)
  const accentTarget = (p) => typeof gate.targets[p.target]?.accentOf === 'function'
  const resultLabel = (p, v) => accentTarget(p)
    ? v.new_accent === 'default' ? 'default' : '#' + String(v.new_accent ?? '').replace(/^#/, '') : p.new_sha
  const resultKind = (p) => accentTarget(p) ? 'result colour' : 'result SHA-256'
  const releaseCard = (p) => {
    if (p.target !== 'plugins/aukora-plugin-set/approval.json') return null
    try {
      const value = JSON.parse(gate.blobText(p.new_sha))
      if (value?.kind !== 'aukora-plugin-set-approval/v1' || !/^[0-9a-f]{40}$/.test(value.release) ||
        !/^[0-9a-f]{64}$/.test(value.plugin_set) || !/^[0-9a-f]{64}$/.test(value.operation) || !/^[0-9a-f]{64}$/.test(value.record)) return null
      return value
    } catch { return null }
  }
  const fingerprintHtml = (p, release) => {
    const rows = release ? [['release', release.release], ['plugin set', release.plugin_set], ['operation', release.operation], ['release record', release.record]] : []
    rows.push(['current SHA-256', p.base_sha], ['result SHA-256', p.new_sha])
    return `<div class=fingerprints tabindex=0 title="Click once to select these exact fingerprints" aria-label="Exact fingerprints; click once to select all">${rows.map(([label, value]) => `<div><b>${label}</b><code>${esc(value)}</code></div>`).join('')}</div>`
  }
  const appliedNext = (p) => {
    const release = releaseCard(p)
    return release ? `Release ${release.release.slice(0, 7)} is approved. Next, the operator installs this exact approval and starts the node; this page did not start it.` : 'The exact change is now applied; its signed receipt is in the gate ledger.'
  }

  function pageHtml(msg, confirmFor) {
    const items = gate.pendingRows().map(p => {
      const v = gate.cardView(p)
      const release = releaseCard(p)
      const heading = release ? `Start release ${release.release.slice(0, 7)} on this node` : v.plain
      const hid = `<input type=hidden name=k value="${esc(owner.bearer)}"><input type=hidden name=id value="${esc(p.id)}"><input type=hidden name=base value="${esc(p.base_sha)}"><input type=hidden name=new value="${esc(p.new_sha)}">`
      let step2 = ''
      if (confirmFor && confirmFor.id === p.id) step2 = `<form method=POST action=/act class=confirm>${hid}<input type=hidden name=nonce value="${esc(confirmFor.nonce)}">
      <label for=typed-confirm><b>Step 2 of 2.</b> Paste the ${resultKind(p)} <b>${esc(resultLabel(p, v))}</b> into the box below; this step expires in 2 minutes.</label>
      <input id=typed-confirm name=typed autocomplete=off spellcheck=false placeholder="paste ${esc(resultLabel(p, v).replace(/^#/, ''))}" aria-label="paste the ${resultKind(p)} to confirm" aria-describedby=confirm-limit>
      <div class=ttl id=confirm-limit>2-minute limit from the start of step 2. Enter, Space, or Tab alone cannot approve.</div>
      <button name=a value=confirm class=ap tabindex=-1>Confirm apply ${esc(resultLabel(p, v))}</button></form>`
      return `<div class=card data-id="${esc(p.id)}"><h2>${esc(heading)}</h2><div class=h>HOST-VERIFIED BY THE BOUNDARY GATE</div>
      ${release ? `<div class=plain>${esc(v.plain)}</div>` : ''}
      <div class=after>${esc(v.after_apply)}</div>
      ${accentTarget(p) ? `<div class=sw>${chip(v.base_accent)} BEFORE ${esc(v.base_accent ?? '?')} ${esc(colorName(v.base_accent))} <span class=arr>&rarr;</span> ${chip(v.new_accent)} AFTER ${esc(v.new_accent ?? '?')} ${esc(colorName(v.new_accent))}</div>` : ''}
      <div class=swt>${esc(v.swatch ?? '')}</div>
      ${v.warnings.length ? `<div class=warn><div class=wh>GATE WARNINGS (${v.warnings.length})</div><ul>${v.warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul></div>` : '<div class=nowarn>gate warnings: none</div>'}
      ${fingerprintHtml(p, release)}
      <div class=meta>Target <b>${esc(p.target)}</b> · proposal ${esc(p.id)} · expires ${esc(new Date(p.expires).toLocaleTimeString('en-GB', { timeZone }))} ${esc(timeZone)}</div>
      <div class=note><div class=nh>MODEL NOTE (unverified)</div>${esc(v.note_display)}${v.note_meta?.hexdump ? `<div class=hex>raw note bytes (${esc(v.note_meta.raw_bytes)}): ${esc(v.note_meta.hexdump)}</div>` : ''}</div>
      <div class=btns><form method=POST action=/act class=rjf>${hid}<button name=a value=reject class=rj>Reject</button></form>
      <form method=POST action=/act class=apf>${hid}<button name=a value=approve-step1 class=ap1 tabindex=-1>Approve&hellip; (step 1 of 2)</button></form></div>${step2}</div>`
    }).join('\n')
    return `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>Boundary gate — owner approval</title>
  <style>${CSS}</style>
  <main><header class=mast><h1 class=brand>AUKORA</h1><p>Boundary gate · owner approval</p></header>
  ${msg ? `<p class=msg role=status>${esc(msg)}</p>` : ''}${items || '<p class=empty>No pending proposals.</p>'}</main>`
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
      else { const nonce = randomBytes(16).toString('base64url'); confirms.set(nonce, { id, base: p.base_sha, new: p.new_sha, exp: now() + confirmTtlMs }); confirmFor = { id, nonce }; msg = `Step 2: type the ${resultKind(p)} below to confirm. Nothing has been applied.` }
    } else if (a === 'confirm') {
      const n = String(f.get('nonce')); const c = confirms.get(n); confirms.delete(n)
      const s = gate.targets[p.target]
      const color = typeof s?.accentOf === 'function'
      const want = color ? (s.accentOf(gate.blobText(p.new_sha)) ?? '').replace(/^#/, '').toUpperCase() : p.new_sha
      const input = String(f.get('typed') ?? '').trim(), typed = color ? input.replace(/^#/, '').toUpperCase() : input
      if (!c || c.id !== id || c.base !== p.base_sha || c.new !== p.new_sha || now() > c.exp) msg = 'not applied: confirmation expired or invalid - start again with Approve (step 1).'
      else if (!want || typed !== want) msg = `not applied: typed confirmation "${typed.slice(0, 20)}" does not match the result. Nothing changed.`
      else {
        // The one ceremony: a fresh review challenge over the exact base/new, then decide_review (no direct approve).
        try {
          const rv = gate.ownerOps.review({ id })
          const r = gate.ownerOps.decide_review({ id, base_sha: rv.base_sha, new_sha: rv.new_sha, review_challenge: rv.review_challenge, outcome: 'allowed-once' }, PAGE_APPROVER)
          msg = r.applied ? `APPLIED ${p.target} — ledger #${r.ledger_seq}. ${appliedNext(p)}` : `not applied: ${r.message}`
        } catch (e) { msg = `not applied: ${String(e?.message ?? e).slice(0, 200)}` }
      }
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

// Only a protected root designation enables the enrollment page's rehearsal marker.
export function readRehearsalMarker() {
  let value
  try {
    fs.lstatSync('/etc/aukora-boundary-gate/rehearsal.json')
    value = readProtectedJson('/etc/aukora-boundary-gate/rehearsal.json')
  }
  catch (error) {
    if (error.code === 'ENOENT') return false
    throw new Error('OWNER_PASSKEY_REHEARSAL_MARKER_REFUSED')
  }
  if (!value || typeof value !== 'object' || Object.keys(value).length !== 2
    || value.version !== 1 || value.kind !== 'aukora-passkey-rehearsal/v1')
    throw new Error('OWNER_PASSKEY_REHEARSAL_MARKER_REFUSED')
  return true
}

// Passkey routes accept only the configured HTTPS owner origin and bounded same-origin JSON.
export function createPasskeyOwnerHandler(gate, { origin, rpId, appOrigin, node, gateId } = {}) {
  const fail = code => { throw new Error(code) }
  let configured
  try { configured = new URL(origin) } catch { fail('OWNER_PASSKEY_ORIGIN_REQUIRED') }
  if (configured.protocol !== 'https:' || configured.origin !== origin || configured.hostname !== rpId ||
    !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(rpId) ||
    /^\d+(?:\.\d+){3}$/.test(rpId)) fail('OWNER_PASSKEY_ORIGIN_REQUIRED')
  const css = 'body{font:16px/1.5 system-ui;margin:2rem auto;padding:1rem;max-width:70rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid;padding:1rem}button,input{font:inherit;padding:.5rem;margin:.5rem 0}article{border-top:2px solid;margin-top:2rem}#status{white-space:pre-wrap}'
  const hash = text => createHash('sha256').update(text).digest('base64')
  const scriptHash = hash(OWNER_PASSKEY_SCRIPT)
  const headers = { 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff', 'permissions-policy': 'publickey-credentials-create=(self), publickey-credentials-get=(self)',
    'content-security-policy': `default-src 'none'; script-src 'sha256-${scriptHash}'; style-src 'sha256-${hash(css)}'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` }
  const html = (mode, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">${mode === 'enroll' && readRehearsalMarker() ? '<meta name="aukora-node-mode" content="rehearsal">' : ''}<title>Boundary gate — owner passkey</title><style>${css}</style><script defer src="/owner/passkey.js" integrity="sha256-${scriptHash}"></script></head><body data-owner-passkey data-origin="${esc(origin)}" data-rp-id="${esc(rpId)}" data-app-origin="${esc(appOrigin ?? '')}" data-node="${esc(node ?? '')}" data-gate="${esc(gateId ?? '')}" data-mode="${mode}"><h1>Boundary gate — owner passkey</h1><p>This page is served by the gate. A browser session alone cannot approve an effect.</p><p>A passkey signs exact card bytes after the device’s local user check. It does not prove a unique person; synced passkeys can leave the device.</p><p id="status" role="status"></p>${body}</body></html>`
  const send = (res, status, body, type = 'application/json; charset=utf-8') => { res.writeHead(status, { ...headers, 'content-type': type }); res.end(type.startsWith('application/json') ? JSON.stringify(body) : body) }
  const closed = (body, keys) => body && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).length === keys.length && keys.every(key => Object.hasOwn(body, key))
  const readBody = req => new Promise((resolve, reject) => {
    let bytes = 0, chunks = [], settled = false, timer
    const stop = (error, body) => { if (settled) return; settled = true; clearTimeout(timer); req.setTimeout?.(0); error ? reject(error) : resolve(body) }
    const timedOut = () => stop(new Error('OWNER_PASSKEY_BODY_TIMEOUT'))
    timer = setTimeout(timedOut, 10000); timer.unref?.()
    req.setTimeout?.(10000, timedOut)
    req.on('data', chunk => {
      if (settled) return
      bytes += Buffer.byteLength(chunk)
      if (bytes > 65536) { chunks = []; stop(new Error('OWNER_PASSKEY_BODY_TOO_LARGE')); return }
      chunks.push(Buffer.from(chunk))
    })
    req.on('error', () => stop(new Error('OWNER_PASSKEY_BODY_INVALID')))
    req.on('aborted', () => stop(new Error('OWNER_PASSKEY_BODY_INVALID')))
    req.on('end', () => {
      if (settled) return
      try { stop(null, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))) }
      catch { stop(new Error('OWNER_PASSKEY_BODY_INVALID')) }
    })
  })
  async function handler(req, res) {
    try {
      if (req.headers.host !== configured.host) fail('OWNER_PASSKEY_HOST_REFUSED')
      if (typeof req.url !== 'string' || !req.url.startsWith('/') || req.url.startsWith('//') || req.url.length > 4096 || req.url.includes('#')) fail('OWNER_PASSKEY_PATH_REFUSED')
      const url = new URL(req.url, origin), script = url.pathname === '/owner/passkey.js'
      if (req.method === 'GET') {
        const publicNavigation = ['/owner/signin', '/owner/binding'].includes(url.pathname) && !url.search
          && ['same-site', 'cross-site'].includes(req.headers['sec-fetch-site'])
        if (script ? req.headers['sec-fetch-site'] !== 'same-origin' || req.headers['sec-fetch-mode'] !== 'no-cors' || req.headers['sec-fetch-dest'] !== 'script'
          : (!['same-origin', 'none'].includes(req.headers['sec-fetch-site']) && !publicNavigation) || req.headers['sec-fetch-mode'] !== 'navigate' || req.headers['sec-fetch-dest'] !== 'document') fail('OWNER_PASSKEY_FETCH_METADATA_REFUSED')
        if (script) {
          if (url.search) fail('OWNER_PASSKEY_PATH_REFUSED')
          return send(res, 200, OWNER_PASSKEY_SCRIPT, 'text/javascript; charset=utf-8')
        }
        if (url.pathname === '/owner/enroll' && !url.search) return send(res, 200, html('enroll', '<p>Use your authenticator once to enroll, then again to prove possession.</p><form id="enroll-form" hidden><input id="claim-code" type="hidden" autocomplete="off"><button type="submit">Resume owner enrollment</button></form>'), 'text/html; charset=utf-8')
        if (['/owner/signin', '/owner/binding'].includes(url.pathname) && !url.search) {
          if (!gate.ownerBrowser || !appOrigin || !node || !gateId) fail('OWNER_BROWSER_JOIN_REQUIRED')
          const mode = url.pathname === '/owner/signin' ? 'signin' : 'binding'
          return send(res, 200, html(mode, `<p>${mode === 'signin' ? 'Sign in to your node with the enrolled passkey.' : 'After the app binding ceremony, review the exact subject and node below.'}</p><button id="owner-start">Prepare ${mode === 'signin' ? 'sign-in' : 'subject binding'}</button><pre data-owner-statement hidden></pre><button id="owner-confirm" hidden>${mode === 'signin' ? 'Sign in' : 'Bind this exact subject and node'} with passkey</button>`), 'text/html; charset=utf-8')
        }
        if (url.pathname === '/owner/cards') {
          if ([...url.searchParams.keys()].join(',') !== 'bearer') fail('OWNER_PASSKEY_PATH_REFUSED')
          const bearer = url.searchParams.get('bearer')
          if (!bearerOk(gate.owner, bearer, gate.now)) return send(res, 401, { ok: false, error: 'OWNER_PASSKEY_BEARER_REFUSED' })
          const pending = await gate.ownerOps.pending({})
          const cards = pending.pending.map(card => `<article data-card data-id="${esc(card.id)}"><h2>Proposal ${esc(card.id)}</h2><pre data-card-text>${esc(JSON.stringify(card, null, 2))}</pre><pre data-authorization hidden></pre><button type="button" data-review>Review exact card</button><button type="button" data-approve hidden>Approve once with passkey</button></article>`).join('')
          return send(res, 200, html('cards', `<input id="owner-bearer" type="hidden" value="${esc(bearer)}">${cards || '<p>No pending proposals.</p>'}`), 'text/html; charset=utf-8')
        }
        return send(res, 404, { ok: false, error: 'OWNER_PASSKEY_PATH_REFUSED' })
      }
      if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'OWNER_PASSKEY_METHOD_REFUSED' })
      if (req.headers.origin !== origin) fail('OWNER_PASSKEY_ORIGIN_REFUSED')
      if (req.headers['sec-fetch-site'] !== 'same-origin' || !['cors', 'same-origin'].includes(req.headers['sec-fetch-mode']) || !['', 'empty'].includes(req.headers['sec-fetch-dest'])) fail('OWNER_PASSKEY_FETCH_METADATA_REFUSED')
      if (req.headers['content-type'] !== 'application/json') fail('OWNER_PASSKEY_CONTENT_TYPE_REFUSED')
      if (url.search) fail('OWNER_PASSKEY_PATH_REFUSED')
      const body = await readBody(req)
      const browser = { '/owner/signin/start': ['startSignin', []], '/owner/signin/finish': ['finishSignin', ['challenge_id', 'assertion']],
        '/owner/signin/redeem': ['redeemSignin', ['code', 'app_origin']], '/owner/binding/start': ['startBinding', []],
        '/owner/binding/finish': ['finishBinding', ['challenge_id', 'assertion']] }
      if (Object.hasOwn(browser, url.pathname)) {
        if (!gate.ownerBrowser) fail('OWNER_BROWSER_JOIN_REQUIRED')
        const [operation, fields] = browser[url.pathname]
        if (!closed(body, fields)) fail('OWNER_BROWSER_FIELDS_REFUSED')
        return send(res, 200, { ok: true, result: gate.ownerBrowser[operation](body) })
      }
      const enroll = { '/owner/enroll/start': ['claim_code'], '/owner/enroll/register': ['enrollment_id', 'registration'], '/owner/enroll/finish': ['enrollment_id', 'assertion'] }
      if (Object.hasOwn(enroll, url.pathname)) {
        if (!closed(body, enroll[url.pathname])) fail('OWNER_PASSKEY_FIELDS_REFUSED')
        const operation = { '/owner/enroll/start': 'startPasskeyEnrollment', '/owner/enroll/register': 'registerPasskeyEnrollment', '/owner/enroll/finish': 'finishPasskeyEnrollment' }[url.pathname]
        return send(res, 200, { ok: true, result: await gate[operation](body) })
      }
      const keys = url.pathname === '/owner/review' ? ['bearer', 'id']
        : url.pathname === '/owner/approve' ? ['bearer', 'id', 'base_sha', 'new_sha', 'review_challenge', 'owner_authorization_proof'] : null
      if (!keys) return send(res, 404, { ok: false, error: 'OWNER_PASSKEY_PATH_REFUSED' })
      if (!closed(body, keys)) fail('OWNER_PASSKEY_FIELDS_REFUSED')
      if (!bearerOk(gate.owner, body.bearer, gate.now)) return send(res, 401, { ok: false, error: 'OWNER_PASSKEY_BEARER_REFUSED' })
      const { bearer, ...args } = body
      const result = url.pathname === '/owner/review' ? await gate.ownerOps.review(args)
        : await gate.ownerOps.decide_review({ ...args, outcome: 'allowed-once' }, 'owner via gate passkey page')
      send(res, 200, { ok: true, result })
    } catch (error) {
      const code = /^(?:[A-Z][A-Z0-9_]+|owner-browser:[a-z-]+|passkey:[a-z-]+)$/.test(error?.message) ? error.message : 'OWNER_PASSKEY_REFUSED'
      send(res, code === 'OWNER_PASSKEY_BODY_TOO_LARGE' ? 413 : 403, { ok: false, error: code })
      if (code === 'OWNER_PASSKEY_BODY_TOO_LARGE' || code === 'OWNER_PASSKEY_BODY_TIMEOUT') req.destroy?.()
    }
  }
  return { handler }
}
