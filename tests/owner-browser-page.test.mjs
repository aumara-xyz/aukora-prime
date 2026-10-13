// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic browser requests exercise the gate page; no real authenticator or HTTPS listener.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import { EventEmitter } from 'node:events'
import fs from 'node:fs'
import { createPasskeyOwnerHandler } from '../packages/boundary-gate/src/owner-page.mjs'
import { passkeyOwnerScript } from '../packages/boundary-gate/src/owner-passkey-script.mjs'
const origin = 'https://owner.example.test', app = 'https://app.example.test', node = 'a'.repeat(64), gateId = 'b'.repeat(64)
const hash = text => createHash('sha256').update(text).digest('base64url')
function fakeGate() {
  const calls = [], ownerBrowser = Object.fromEntries(['startSignin','finishSignin','redeemSignin','startBinding','finishBinding'].map(name => [name, body => { calls.push([name,body]); return {} }]))
  return { calls, ownerBrowser }
}
async function request(factory, gate, url, body, method = 'POST', headers = {}) {
  const req = new EventEmitter(), res = { writeHead(status, headers) { this.status = status; this.headers = headers }, end(body) { this.body = body } }
  Object.assign(req, { method, url, headers: { host: new URL(origin).host, origin, 'sec-fetch-site': 'same-origin',
    'sec-fetch-mode': method === 'GET' ? 'navigate' : 'cors', 'sec-fetch-dest': method === 'GET' ? 'document' : 'empty', 'content-type': 'application/json', ...headers } })
  const work = factory(gate, { origin, rpId: new URL(origin).hostname, appOrigin: app, node, gateId }).handler(req,res)
  req.emit('data', Buffer.from(JSON.stringify(body))); req.emit('end'); await work; return res
}
async function routeChecks(factory) {
  const gate = fakeGate()
  for (const [path,body,name] of [['signin/start',{},'startSignin'],['signin/finish',{challenge_id:'id',assertion:{}},'finishSignin'],
    ['signin/redeem',{code:'code',app_origin:app},'redeemSignin'],['binding/start',{},'startBinding'],['binding/finish',{challenge_id:'id',assertion:{}},'finishBinding']]) {
    assert.equal((await request(factory,gate,'/owner/'+path,body)).status,200)
    assert.deepEqual(gate.calls.at(-1),[name,body])
    const before = gate.calls.length
    assert.equal((await request(factory,gate,'/owner/'+path,{...body,subject:'browser-selected'})).status,403)
    assert.equal(gate.calls.length,before)
  }
  for (const mode of ['signin','binding']) {
    const page = await request(factory,gate,'/owner/'+mode,{},'GET')
    assert.equal(page.status,200); assert.ok(page.body.includes(`data-app-origin="${app}"`)); assert.match(page.headers['content-security-policy'],/script-src 'sha256-/)
    for (const site of ['same-site','cross-site']) {
      assert.equal((await request(factory,gate,'/owner/'+mode,{},'GET',{'sec-fetch-site':site})).status,200)
      assert.equal((await request(factory,gate,'/owner/'+mode,{},'GET',{'sec-fetch-site':site,'sec-fetch-dest':'iframe'})).status,403)
    }
  }
  assert.equal((await request(factory,gate,'/owner/enroll',{},'GET',{'sec-fetch-site':'cross-site'})).status,403)
  assert.equal((await request(factory,{},'/owner/signin/start',{})).status,403)
}
test('browser join routes use real Fetch Metadata and closed passkey-only stages',()=>routeChecks(createPasskeyOwnerHandler))
function element(dataset={}) { return {dataset,hidden:false,disabled:false,listeners:{},addEventListener(name,run){this.listeners[name]=run}, async click(){await(this.listeners.click||this.onclick)?.({preventDefault(){}})} } }
function browser({kind='signin',change=()=>{},finishChange=()=>{}}={}) {
  const root=element({origin,rpId:new URL(origin).hostname,appOrigin:app,node,gate:gateId,mode:kind}), status=element(),start=element(),confirm=element(),text=element()
  const statement={version:1,kind:`aukora-owner-browser-${kind}/v1`,gate:gateId,node,origin,rp_id:root.dataset.rpId,app_origin:app,nonce:'c'.repeat(64),
    ...(kind==='binding'?{subject:'aukora:1:'+'d'.repeat(64),rootId:'e'.repeat(64)}:{})}
  change(statement)
  const statement_text=JSON.stringify(statement), calls=[],gets=[],redirects=[]
  const public_key={challenge:hash(statement_text),rpId:root.dataset.rpId,allowCredentials:[{type:'public-key',id:'AQ'}],userVerification:'required'}
  const started={challenge_id:'c'.repeat(64),statement_text,public_key}
  if(statement.badChallenge){delete statement.badChallenge;started.public_key.challenge='AQ'}
  const elements={'[data-owner-passkey]':root,'#status':status,'#owner-start':start,'#owner-confirm':confirm,'[data-owner-statement]':text}
  const environment={document:{querySelector:s=>elements[s]},location:{origin,replace:value=>redirects.push(value)},isSecureContext:true,PublicKeyCredential:function(){},btoa,atob,crypto:webcrypto,
    navigator:{credentials:{create(){},async get(options){gets.push(options);return {type:'public-key',rawId:Uint8Array.of(1),response:{clientDataJSON:Uint8Array.of(2),authenticatorData:Uint8Array.of(3),signature:Uint8Array.of(4),userHandle:null}}}}},
    async fetch(path,options){calls.push([path,JSON.parse(options.body)]);const result=path.endsWith('/start')?started:{code:'x'.repeat(43),app_origin:app,bound:true};if(path.endsWith('/finish'))finishChange(result);return{ok:true,json:async()=>({ok:true,result})}}}
  return{environment,status,start,confirm,text,calls,gets,redirects}
}
async function runBrowser(run,options={}) { const b=browser(options);run(b.environment);await b.start.click();await b.confirm.click();return b }
test('owner page displays then signs statement; returns only fixed app fragment or binding success',async()=>{
  for(const kind of ['signin','binding']){
    const b=browser({kind});passkeyOwnerScript(b.environment);await b.start.click();assert.equal(b.gets.length,0);assert.equal(b.text.hidden,false)
    await b.confirm.click();assert.equal(b.gets.length,1);assert.deepEqual(b.calls.map(c=>c[0]),[`/owner/${kind}/start`,`/owner/${kind}/finish`]);assert.equal(b.confirm.hidden,true)
    if(kind==='signin')assert.deepEqual(b.redirects,[app+'/__aukora/signin#'+'x'.repeat(43)])
    else assert.match(b.status.textContent,/exact subject and node/)
  }
})
const scriptUrl=new URL('../packages/boundary-gate/src/owner-passkey-script.mjs',import.meta.url),pageUrl=new URL('../packages/boundary-gate/src/owner-page.mjs',import.meta.url)
const load=(source,url)=>import('data:text/javascript;base64,'+Buffer.from(source.replace(/from '(\.\/[^']+)'/g,(_,p)=>`from '${new URL(p,url).href}'`)).toString('base64'))
test('browser join page and script protections fail when removed',async t=>{
  const page=fs.readFileSync(pageUrl,'utf8')
  const mutant=await load(page.replace("if (!closed(body, fields)) fail('OWNER_BROWSER_FIELDS_REFUSED')",''),pageUrl)
  await assert.rejects(()=>routeChecks(mutant.createPasskeyOwnerHandler),assert.AssertionError)
  const openNavigation=await load(page.replace("['/owner/signin', '/owner/binding'].includes(url.pathname) && !url.search",'true'),pageUrl)
  await assert.rejects(()=>routeChecks(openNavigation.createPasskeyOwnerHandler),assert.AssertionError)
  const source=fs.readFileSync(scriptUrl,'utf8'), mutations=[
    ['node','statement.node !== root.dataset.node',{change:s=>{s.node='f'.repeat(64)}}],
    ['gate','statement.gate !== root.dataset.gate',{change:s=>{s.gate='f'.repeat(64)}}],
    ['origin','statement.origin !== profile.origin',{change:s=>{s.origin='https://evil.example.test'}}],
    ['rp','statement.rp_id !== profile.rpId',{change:s=>{s.rp_id='evil.example.test'}}],
    ['audience','statement.app_origin !== root.dataset.appOrigin',{change:s=>{s.app_origin='https://evil.example.test'}}],
    ['nonce','statement.nonce !== started.challenge_id',{change:s=>{s.nonce='f'.repeat(64)}}],
    ['kind','statement.kind !== `aukora-owner-browser-${kind}/v1`',{change:s=>{s.kind='different'}}],
    ['version','statement.version !== 1',{change:s=>{s.version=2}}],
    ['subject','!/^aukora:1:[a-f0-9]{64}$/.test(statement.subject)',{kind:'binding',change:s=>{s.subject='wrong'}}],
    ['root','!/^[a-f0-9]{64}$/.test(statement.rootId)',{kind:'binding',change:s=>{s.rootId='wrong'}}],
    ['challenge','encode(digest) !== started.public_key?.challenge',{change:s=>{s.badChallenge=true}}],
    ['redirect','result.app_origin !== root.dataset.appOrigin',{finishChange:r=>{r.app_origin='https://evil.example.test'},redirect:true}],
    ['code','!/^[A-Za-z0-9_-]{43}$/.test(result.code)',{finishChange:r=>{r.code='short'},redirect:true}],
  ]
  for(const[name,before,options]of mutations)await t.test(name,async()=>{
    const check=async run=>{const b=await runBrowser(run,options);assert.equal(options.redirect?b.redirects.length:b.gets.length,0)}
    await check(passkeyOwnerScript);assert.equal(source.split(before).length,2)
    const changed=await load(source.replace(before,'false'),scriptUrl)
    await assert.rejects(()=>check(changed.passkeyOwnerScript),assert.AssertionError)
  })
  t.diagnostic(`SOURCE-ONLY browser page mutations: ${mutations.length+2}/${mutations.length+2} killed`)
})
