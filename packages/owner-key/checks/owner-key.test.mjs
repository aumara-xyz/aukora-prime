// SPDX-License-Identifier: AGPL-3.0-or-later
// Published RFC6979 A.2.5 fixture only; no generated/production key or Keychain access.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { ownerKeyRequest, ownerKeyRequestText, ownerKeyRequestDigest, ownerKeySigningBytes,
  ownerRootPin, parseOwnerKeyRequest, verifyOwnerKeyBinding, consumeOwnerKeyBinding } from '../src/index.mjs'
import { createOwnerKeyBridge } from '../../../apps/aukora-desktop/owner-key-bridge.mjs'

const b64url = h => Buffer.from(h, 'hex').toString('base64url')
const fixture = createPrivateKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
  d: b64url('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'),
  x: b64url('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'),
  y: b64url('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299') } })
const spki = createPublicKey(fixture).export({ type: 'spki', format: 'der' }).toString('base64')
const pin = ownerRootPin(spki)
const draft = () => ({ version: 1, action: 'bind-scoped-nostr', audience: 'aukora:aura',
  scope: 'owner-recipient', owner_subject: `aukora:1:${'1'.repeat(64)}`, owner_root_id: pin.owner_root_id,
  request_id: '2'.repeat(64), nonce: '3'.repeat(64), scoped_nostr_pubkey_hex: '4'.repeat(64),
  previous_binding_digest: null, previous_nostr_pubkey_hex: null, epoch: 1, issued_at: 100, expires_at: 200 })
const pins = r => ({ owner_root_spki_base64: spki, request_digest: ownerKeyRequestDigest(r), ...Object.fromEntries(['owner_subject','audience','scope','epoch',
  'previous_binding_digest','previous_nostr_pubkey_hex','scoped_nostr_pubkey_hex','request_id','nonce'].map(k => [k,r[k]])) })
const signed = r => ({ algorithm: 'p256-ecdsa-sha256', request: r,
  signature_base64: sign('sha256', ownerKeySigningBytes(r), fixture).toString('base64') })

test('exact root certificate verifies without claiming custody, attendance or authority', () => {
  const r = draft(), proof = signed(r), result = verifyOwnerKeyBinding(proof, pins(r), 150)
  assert.equal(result.status, 'verified-binding'); assert.equal(result.grants_authority, false)
  assert.equal(result.custody, 'independent-enrollment-required'); assert.equal(result.activation, 'UNPERFORMED')
  assert.equal(result.binding_digest, ownerKeyRequestDigest(r))
  assert(!JSON.stringify(result).includes('signature_base64'))
})

test('wire ambiguity, accessors, unsafe integers and unknown approval flags refuse', () => {
  const r = draft(), text = ownerKeyRequestText(r)
  assert.equal(ownerKeyRequestText(parseOwnerKeyRequest(text)), text)
  assert.throws(() => parseOwnerKeyRequest(text.replace('"version":1', '"version":1,"version":1')))
  assert.throws(() => parseOwnerKeyRequest(' '+text))
  for (const altered of [{...r, approved:true}, {...r, epoch:-0}, {...r, expires_at:221}, {...r, nonce:['3'.repeat(64)]},
    {...r, nonce:r.nonce+'\n'}, {...r, owner_subject:r.owner_subject+'\n'},
    {...r, scope:'arbitrary-action'}, {...r, action:'sign-anything'}]) assert.throws(() => ownerKeyRequest(altered))
  let getterCalls = 0
  const accessor = {...r}; Object.defineProperty(accessor,'nonce',{enumerable:true,get(){getterCalls++;return r.nonce}})
  assert.throws(() => ownerKeyRequest(accessor)); assert.equal(getterCalls,0)
})

test('changed complete body, digest, root, subject, service, epoch and nonce refuse', () => {
  const r = draft(), original = signed(r)
  for (const [key,value] of [['owner_subject',`aukora:1:${'5'.repeat(64)}`],['audience','aukora:recall'],
    ['scope','aura-author'],['scoped_nostr_pubkey_hex','6'.repeat(64)],['nonce','7'.repeat(64)],
    ['request_id','8'.repeat(64)],['owner_root_id','9'.repeat(64)],['issued_at',101]]) {
    assert.throws(() => verifyOwnerKeyBinding({...original,request:{...r,[key]:value}},pins(r),150), key)
  }
  assert.throws(() => verifyOwnerKeyBinding({...original,algorithm:'software-approved'},pins(r),150))
  assert.throws(() => verifyOwnerKeyBinding({...original,touch_id:true},pins(r),150))
  const corrupt = Buffer.from(original.signature_base64,'base64'); corrupt[corrupt.length-1]^=1
  assert.throws(() => verifyOwnerKeyBinding({...original,signature_base64:corrupt.toString('base64')},pins(r),150))
  const alteredTime={...r,issued_at:101};assert.throws(()=>verifyOwnerKeyBinding(signed(alteredTime),pins(r),150))
  for(const [key,value] of [['owner_subject',`aukora:1:${'e'.repeat(64)}`],['audience','aukora:recall'],
    ['scope','aura-author'],['scoped_nostr_pubkey_hex','f'.repeat(64)]])
    assert.throws(()=>verifyOwnerKeyBinding(original,{...pins(r),[key]:value},150),`expected ${key}`)
  assert.throws(() => verifyOwnerKeyBinding(original,pins(r),200))
  assert.throws(() => verifyOwnerKeyBinding(original,pins(r),99))
  assert.throws(() => ownerRootPin('invalid'))
})

test('rotation binds predecessor, distinct recipient and exact epoch', () => {
  const initial = draft()
  const r = {...initial,action:'rotate-scoped-nostr',epoch:2,previous_binding_digest:ownerKeyRequestDigest(initial),
    previous_nostr_pubkey_hex:initial.scoped_nostr_pubkey_hex,scoped_nostr_pubkey_hex:'a'.repeat(64)}
  assert.equal(verifyOwnerKeyBinding(signed(r),pins(r),150).request.epoch,2)
  assert.throws(() => verifyOwnerKeyBinding(signed(r),{...pins(r),epoch:3},150))
  assert.throws(() => verifyOwnerKeyBinding(signed(r),{...pins(r),previous_binding_digest:'b'.repeat(64)},150))
  assert.throws(() => ownerKeyRequest({...r,scoped_nostr_pubkey_hex:r.previous_nostr_pubkey_hex}))
})

test('atomic consumption rejects replay, concurrent duplicate and uncertain settlement', async () => {
  const r=draft(), proof=signed(r), seen=new Set()
  const consumeOnce=async c=>{assert.equal(c.request.audience,r.audience);assert.equal(c.request.expires_at,r.expires_at)
    assert.equal(c.binding_digest,ownerKeyRequestDigest(c.request));assert(Object.isFrozen(c.request))
    const key=c.owner_root_id+':'+c.request.nonce;if(seen.has(key))return false;seen.add(key);return true}
  const results=await Promise.allSettled([consumeOwnerKeyBinding(proof,pins(r),{nowSeconds:150,consumeOnce}),
    consumeOwnerKeyBinding(proof,pins(r),{nowSeconds:150,consumeOnce})])
  assert.equal(results.filter(x=>x.status==='fulfilled').length,1)
  assert.equal(results.filter(x=>x.status==='rejected').length,1)
  await assert.rejects(consumeOwnerKeyBinding(proof,pins(r),{nowSeconds:150}))
  await assert.rejects(consumeOwnerKeyBinding(proof,pins(r),{nowSeconds:150,consumeOnce:async()=>undefined}))
})

test('native presentation freezes action; concurrency, cancellation, fallback and substitutions refuse', async () => {
  const r=draft(); let finish; let presented
  const bridge=createOwnerKeyBridge({expectations:pins(r),nowSeconds:()=>150,
    presentOwnerAction:value=>{presented=value;return new Promise(resolve=>{finish=resolve})}})
  const waiting=bridge.requestBinding(r)
  assert.equal((await bridge.requestBinding(r)).reason,'owner-key:busy')
  const original=parseOwnerKeyRequest(presented.wire);r.scoped_nostr_pubkey_hex='c'.repeat(64)
  finish({status:'signed',proof:signed(original)})
  assert.equal((await waiting).status,'signed-binding')
  assert.equal(presented.preview.to_nostr_pubkey_hex,original.scoped_nostr_pubkey_hex)
  for(const response of [{status:'cancelled'},{approved:true},{status:'signed',proof:signed({...draft(),nonce:'d'.repeat(64)})}]){
    const one=createOwnerKeyBridge({expectations:pins(draft()),nowSeconds:()=>150,presentOwnerAction:async()=>response})
    const result=await one.requestBinding(draft());assert.notEqual(result.status,'signed-binding');assert.equal(result.grants_authority,false)
  }
  assert.throws(()=>createOwnerKeyBridge({expectations:pins(draft())}))
  const expired=createOwnerKeyBridge({expectations:pins(draft()),nowSeconds:()=>200,
    presentOwnerAction:async()=>({status:'signed',proof:signed(draft())})})
  assert.equal((await expired.requestBinding(draft())).reason,'owner-key:expired')
})
