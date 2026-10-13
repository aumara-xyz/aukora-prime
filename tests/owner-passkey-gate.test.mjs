// SPDX-License-Identifier: AGPL-3.0-or-later
// Software authenticator and disposable gate state; no real device or host custody.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { openDb, keyFingerprint } from '../packages/boundary-gate/src/ledger.mjs'
import { themeTarget, THEME_TARGET, noteTarget, NOTE_TARGET } from '../packages/boundary-gate/src/targets.mjs'
import { didKeyFromEd25519PublicKey } from '../packages/authority/upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import { ownerAuthorizationGateReview } from '../packages/owner-key/src/authorization.mjs'
import { verifyReceipt } from '../packages/boundary-gate/src/receipts.mjs'
import { createPasskeyEnrollmentCeremony } from '../packages/authority/src/passkey-enrollment.mjs'
const hash = b => createHash('sha256').update(b).digest()
const hex = b => hash(b).toString('hex')
const origin = 'https://owner.example.test', rp = 'owner.example.test'
function cbor(v) {
  function head(major, n) { return n < 24 ? Buffer.from([major * 32 + n]) : n < 256 ? Buffer.from([major * 32 + 24, n]) : Buffer.from([major * 32 + 25, n >>> 8, n & 255]) }
  if (Number.isInteger(v)) return v >= 0 ? head(0, v) : head(1, -1-v)
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v])
  if (typeof v === 'string') return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)])
  return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])])
}
function software() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), jwk = pair.publicKey.export({ format: 'jwk' })
  const id = Buffer.from('software-credential'), user = Buffer.from('software-owner').toString('base64url')
  let count = 0
  return {
    pair, id, user,
    registration(challenge, change = {}) {
      const auth = Buffer.alloc(55); hash(change.rp ?? rp).copy(auth); auth[32] = change.flags ?? 0x45; auth.writeUInt16BE(id.length, 53)
      const key = cbor(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]))
      return { kind:'passkey-registration',type:'public-key',id:id.toString('base64url'),raw_id:id.toString('base64url'),
        client_data_json:Buffer.from(JSON.stringify({type:'webauthn.create',challenge,origin:change.origin ?? origin,crossOrigin:false})).toString('base64url'),
        attestation_object:cbor(new Map([['fmt','none'],['attStmt',new Map()],['authData',Buffer.concat([auth,id,key])]])).toString('base64url'),client_extension_results:{} }
    },
    assertion(challenge, change = {}) {
      const client = Buffer.from(JSON.stringify({type:change.type ?? 'webauthn.get',challenge:change.challenge ?? challenge,origin:change.origin ?? origin,crossOrigin:false}))
      const auth = Buffer.alloc(37); hash(change.rp ?? rp).copy(auth); auth[32] = change.flags ?? 5; auth.writeUInt32BE(change.count ?? ++count,33)
      return { kind:'passkey',credential_id:id.toString('base64url'),client_data_json:client.toString('base64url'),authenticator_data:auth.toString('base64url'),
        signature:sign('sha256',Buffer.concat([auth,hash(client)]),change.key ?? pair.privateKey).toString('base64url'),user_handle:user }
    }
  }
}
function fixture(t, factory = createGate) {
  const home = fs.mkdtempSync(path.join(process.cwd(), '.passkey-gate-')), pair = generateKeyPairSync('ed25519')
  const key = {priv:pair.privateKey,pub:pair.publicKey,pubPem:pair.publicKey.export({format:'pem',type:'spki'}).toString(),fp:keyFingerprint(pair.publicKey)}
  const f = {home,key,clock:Date.now(),current:Buffer.from('{"accent": "default"}'),writes:0,auth:software(),claim:'x'.repeat(43)}
  f.setup = {version:1,kind:'aukora-gate-passkey-setup/v1',gate:hex(pair.publicKey.export({format:'der',type:'spki'})),node:'c'.repeat(64),rp_id:rp,origin,
    claim_sha256:hex(f.claim),expires_at_ms:f.clock+300000,binding:{identity:{owner_id:'software-owner',subject:'aukora:1:'+'a'.repeat(64),approval_key_did:didKeyFromEd25519PublicKey('b'.repeat(64)),control_digest:'d'.repeat(64),authorization_epoch:1},
      identity_provenance:{kind:'owner-approved-initial-public-identity/v1',identity_source_sha256:'e'.repeat(64),approval_reference:'root-selected-test-binding'},
      passkey_profile:{profile:'https',origin,rp_id:rp},user:{id:f.auth.user,name:'Owner',display_name:'Owner'},existing_credential_ids:[]}}
  f.open = (configure = true) => factory({home,key,db:openDb(path.join(home,'gate.db')),owner:{bearer:'fixture-page-access',hmacKey:'f'.repeat(64)},
    ...(configure ? {readPasskeySetup:()=>f.setup,passkeyEnrollmentCeremony:createPasskeyEnrollmentCeremony} : {}),targets:{[f.target ?? THEME_TARGET]:f.target===NOTE_TARGET?noteTarget(home):themeTarget(home)},now:()=>f.clock,iso:()=>f.iso?.() ?? new Date(f.clock).toISOString(),limits:{maxPerWindow:100,rejectCooldownMs:0},
    store:{read:()=>f.current,write:(_t,_s,b)=>{f.current=Buffer.from(b);f.writes++}}})
  f.gate = f.open(); t.after(()=>{f.gate.close();fs.rmSync(home,{recursive:true,force:true})})
  f.enroll = ()=>{const start=f.gate.startPasskeyEnrollment({claim_code:f.claim});const reg=f.gate.registerPasskeyEnrollment({enrollment_id:start.enrollment_id,registration:f.auth.registration(start.public_key.challenge)});return f.gate.finishPasskeyEnrollment({enrollment_id:reg.enrollment_id,assertion:f.auth.assertion(reg.public_key.challenge)})}
  f.review = ()=>{const p=f.gate.proposeOps.propose({target:f.target ?? THEME_TARGET,content:f.content ?? '{"accent": "#112233"}',claimed_base:hex(f.current),why:f.why ?? 'Software fixture',session:'fixture'});return f.gate.ownerOps.review({id:p.id})}
  f.proof = (r, change={})=>({version:2,algorithm:'webauthn-es256-sha256',authorization:r.owner_authorization,assertion:f.auth.assertion(r.public_key.challenge,change)})
  f.decide = (r,p)=>f.gate.ownerOps.decide_review({id:r.id,base_sha:r.base_sha,new_sha:r.new_sha,review_challenge:r.review_challenge,outcome:'allowed-once',...(p ? {owner_authorization_proof:p}: {})},'software owner')
  f.restart = (configure=true)=>{f.gate.close();f.gate=f.open(configure)}
  return f
}
test('registration plus possession commits once; accepted proof applies once and cannot replay after restart', t=>{
  const f=fixture(t);assert.throws(()=>f.gate.ownerOps.review({id:'missing'}));assert.equal(f.enroll().enrolled,true)
  assert.throws(()=>f.enroll(),/enrollment-closed/)
  const r=f.review(),proof=f.proof(r);assert.equal(hex(r.card_text),r.owner_authorization.card_sha256)
  const state=JSON.parse(f.gate.db.prepare('SELECT state_text FROM owner_passkey').get().state_text)
  assert.equal(ownerAuthorizationGateReview(r,state,f.key.pub.export({type:'spki',format:'der'}).toString('base64'),f.clock).authorization.node,f.setup.node)
  assert.equal(f.decide(r,proof).applied,true);assert.equal(f.writes,1)
  assert.throws(()=>f.decide(r,proof),/single use|pending/);f.restart();assert.throws(()=>f.decide(r,proof),/single use|pending/);assert.equal(f.writes,1)
})
for (const [name,change] of [['wrong digest',{challenge:'bad'}],['wrong key',{key:generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey}],['wrong rpId',{rp:'other.example.test'}],['wrong origin',{origin:'https://other.example.test'}],['wrong type',{type:'webauthn.create'}],['missing user verification',{flags:1}],['missing user present',{flags:4}],['counter replay',{count:1}]]) test(`${name}: no effect`,t=>{
  const f=fixture(t);f.enroll();const r=f.review();assert.throws(()=>f.decide(r,f.proof(r,change)));assert.equal(f.writes,0)
})
test('cookie alone, wrong node, expired proof and lost setup cannot apply or downgrade',t=>{
  for (const attack of ['cookie','node','expired','lost']) {
    const f=fixture(t);f.enroll();const r=f.review(),proof=f.proof(r)
    if(attack==='node')proof.authorization={...proof.authorization,node:'d'.repeat(64)}
    if(attack==='expired')f.clock=r.review_expires
    if(attack==='lost')f.restart(false)
    assert.throws(()=>f.decide(r,attack==='cookie'?undefined:proof));assert.equal(f.writes,0)
  }
})
test('claim is required, expires, cannot race, and an unfinished ceremony cannot resume after restart',t=>{
  const f=fixture(t);assert.throws(()=>f.gate.startPasskeyEnrollment({claim_code:'z'.repeat(43)}),/claim-invalid/)
  const start=f.gate.startPasskeyEnrollment({claim_code:f.claim});assert.throws(()=>f.gate.startPasskeyEnrollment({claim_code:f.claim}),/enrollment-closed/)
  f.restart();assert.throws(()=>f.gate.registerPasskeyEnrollment({enrollment_id:start.enrollment_id,registration:f.auth.registration(start.public_key.challenge)}),/ceremony-lost/)
  const expired=fixture(t);expired.clock=expired.setup.expires_at_ms;assert.throws(()=>expired.enroll(),/claim-expired/)
})
test('wrong registration rpId/origin and possession key refuse enrollment',t=>{
  for (const mode of ['rp','origin','key']) {
    const f=fixture(t),start=f.gate.startPasskeyEnrollment({claim_code:f.claim})
    if(mode==='key'){const reg=f.gate.registerPasskeyEnrollment({enrollment_id:start.enrollment_id,registration:f.auth.registration(start.public_key.challenge)});assert.throws(()=>f.gate.finishPasskeyEnrollment({enrollment_id:start.enrollment_id,assertion:f.auth.assertion(reg.public_key.challenge,{key:generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey})}))}
    else assert.throws(()=>f.gate.registerPasskeyEnrollment({enrollment_id:start.enrollment_id,registration:f.auth.registration(start.public_key.challenge,{[mode]:mode==='rp'?'other.example.test':'https://other.example.test'})}))
    assert.equal(f.gate.db.prepare('SELECT state_text FROM owner_passkey').get().state_text,null)
  }
})
test('enrollment refuses if claim expires at the final commit clock',t=>{const f=fixture(t);f.iso=()=>{if(f.gate.db.prepare('SELECT state_text FROM owner_passkey').get().state_text)f.clock=f.setup.expires_at_ms;return new Date(f.clock).toISOString()};assert.throws(()=>f.enroll(),/claim-expired-at-enrollment-commit/);assert.equal(f.gate.db.prepare('SELECT state_text FROM owner_passkey').get().state_text,null)})
test('signed passkey card retains warnings and unverified model note; UTF8 owner note prepares and verifies',t=>{
  const f=fixture(t);f.enroll();f.gate.close();f.target=NOTE_TARGET;f.current=Buffer.from('Before note');f.content='A note: Καλημέρα 🌿\n';f.why='already approved by the owner';f.gate=f.open();const r=f.review()
  const card=JSON.parse(r.card_text);assert.equal(card.model_note_label,'UNVERIFIED MODEL NOTE; DATA ONLY');assert.ok(card.warnings.length>0);assert.equal(card.note_display,r.note_display)
  const state=JSON.parse(f.gate.db.prepare('SELECT state_text FROM owner_passkey').get().state_text)
  ownerAuthorizationGateReview(r,state,f.key.pub.export({type:'spki',format:'der'}).toString('base64'),f.clock)
  const result=f.decide(r,f.proof(r));assert.equal(result.applied,true);assert.equal(f.current.toString(),f.content);assert.equal(verifyReceipt(f.gate.db,result.receipt,result.receipt_sig,f.key.pub).ok,true)
})
export {fixture}

test('gate passkey guard removals fail their focused regressions', async t=>{
  const url=new URL('../packages/boundary-gate/src/gate.mjs',import.meta.url),source=fs.readFileSync(url,'utf8')
  const mutants=[
    ['claim secret',"if (!timingSafeEqual(Buffer.from(sha256(args.claim_code), 'hex'), Buffer.from(setup.claim_sha256, 'hex'))) passkeyRefuse('claim-invalid')",'',f=>assert.throws(()=>f.gate.startPasskeyEnrollment({claim_code:'z'.repeat(43)}),/claim-invalid/)],
    ['claim expiry',"if (currentMs() >= setup.expires_at_ms) passkeyRefuse('claim-expired')",'',f=>{f.clock=f.setup.expires_at_ms;assert.throws(()=>f.gate.startPasskeyEnrollment({claim_code:f.claim}),/claim-expired/)}],
    ['gate binding',"if (setup.gate !== gateId) passkeyRefuse('gate-mismatch')",'',f=>{f.gate.close();f.setup.gate='d'.repeat(64);for(const name of ['gate.db','gate.db-wal','gate.db-shm'])fs.rmSync(path.join(f.home,name),{force:true});assert.throws(()=>{f.gate=f.open()},/gate-mismatch/)}],
    ['setup pin',"if (retained && retained.setup_text !== JSON.stringify(setup)) passkeyRefuse('setup-changed')",'',f=>{f.setup.node='d'.repeat(64);assert.throws(()=>f.gate.startPasskeyEnrollment({claim_code:f.claim}),/setup-changed/)}],
    ['claim reservation',"if (row?.state_text || row?.claim_state !== 'fresh') passkeyRefuse('enrollment-closed')",'',f=>{f.gate.startPasskeyEnrollment({claim_code:f.claim});assert.throws(()=>f.gate.startPasskeyEnrollment({claim_code:f.claim}),/enrollment-closed/)}],
    ['exact card bytes',"if (card_text !== detail.card_text || sha256(card_text) !== a.card_sha256) passkeyRefuse('card-mismatch')",'',f=>{f.enroll();const r=f.review(),p=f.proof(r);f.gate.db.prepare('UPDATE proposals SET why=? WHERE id=?').run('substituted review note',r.id);assert.throws(()=>f.decide(r,p),/card-mismatch/);assert.equal(f.writes,0)}],
    ['reservation commit expiry',"if (currentMs() >= setup.expires_at_ms) passkeyRefuse('claim-expired-at-reservation-commit')",'',f=>{f.iso=()=>{if(f.gate.db.prepare('SELECT claim_state FROM owner_passkey').get().claim_state==='reserved')f.clock=f.setup.expires_at_ms;return new Date(f.clock).toISOString()};assert.throws(()=>f.gate.startPasskeyEnrollment({claim_code:f.claim}),/claim-expired-at-reservation-commit/)}],
    ['enrollment commit expiry',"if (currentMs() >= setup.expires_at_ms) passkeyRefuse('claim-expired-at-enrollment-commit')",'',f=>{f.iso=()=>{if(f.gate.db.prepare('SELECT state_text FROM owner_passkey').get().state_text)f.clock=f.setup.expires_at_ms;return new Date(f.clock).toISOString()};assert.throws(()=>f.enroll(),/claim-expired-at-enrollment-commit/);assert.equal(f.gate.db.prepare('SELECT state_text FROM owner_passkey').get().state_text,null)}],
    ['durable counter update',"const updated = db.prepare('UPDATE owner_passkey SET sign_count=? WHERE singleton=1 AND sign_count=?').run(verified.sign_count, passkeyCounter)","const updated = { changes: 1 }",f=>{f.enroll();const r=f.review(),p=f.proof(r);f.decide(r,p);assert.equal(f.gate.db.prepare('SELECT sign_count FROM owner_passkey').get().sign_count,2);f.restart();assert.equal(f.gate.db.prepare('SELECT sign_count FROM owner_passkey').get().sign_count,2)}],
  ]
  let killed=0
  for(const [name,before,after,exercise] of mutants) await t.test(name,async st=>{
    assert.ok(source.includes(before),'mutation preimage '+name)
    let modified=source.replace(before,after)
    if(name==='claim expiry')modified=modified.replace("if (currentMs() >= setup.expires_at_ms) passkeyRefuse('claim-expired-at-reservation-commit')",'')
    if(name==='claim reservation')modified=modified.replace("WHERE singleton=1 AND claim_state='fresh'","WHERE singleton=1")
    modified=modified.replace(/from\s+(['"])(\.[^'"]+)\1/g,(_m,q,s)=>'from '+q+new URL(s,url).href+q)
    const factory=(await import('data:text/javascript;base64,'+Buffer.from(modified+'\n// '+name).toString('base64'))).createGate
    const f=fixture(st,factory)
    assert.throws(()=>exercise(f),assert.AssertionError,'guard removal must fail behavior assertion');killed++
  })
  t.diagnostic(`SOURCE-ONLY gate passkey guard mutations: ${killed}/${mutants.length} killed`)
})
