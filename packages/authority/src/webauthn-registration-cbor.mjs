// SPDX-License-Identifier: AGPL-3.0-or-later
// Bounded WebAuthn none-attestation and ES256 COSE decoding only.
import {types} from 'node:util'
import {p256} from '../upstream/vendor/authority/deps/@noble/curves@2.2.0/nist.js'

const MAX_BYTES=16*1024,MAX_DEPTH=4,MAX_MAP_ENTRIES=16,MAX_ITEMS=128
const MAX_SAFE=BigInt(Number.MAX_SAFE_INTEGER)
const typedArrayPrototype=Object.getPrototypeOf(Uint8Array.prototype)
const viewGetters=Object.fromEntries(['buffer','byteOffset','byteLength'].map(key=>
 [key,Object.getOwnPropertyDescriptor(typedArrayPrototype,key).get]))
const fail=reason=>{throw Object.assign(new Error(reason),{error_code:'UNAUTHORIZED'})}
const invalid=()=>fail('WEBAUTHN_REGISTRATION_CBOR_INVALID')

function snapshot(input) {
 if(!types.isUint8Array(input))invalid()
 // Use intrinsic accessors rather than caller-defined view properties/iterators.
 const buffer=viewGetters.buffer.call(input),offset=viewGetters.byteOffset.call(input),length=viewGetters.byteLength.call(input)
 if(types.isSharedArrayBuffer(buffer)||length===0||length>MAX_BYTES)invalid()
 try {return Buffer.from(new Uint8Array(buffer,offset,length))} catch {invalid()}
}
function decode(input) {
 const bytes=snapshot(input)
 let offset=0,items=0
 function argument(additional) {
  if(additional<24)return additional
  const size=additional===24?1:additional===25?2:additional===26?4:additional===27?8:0
  if(size===0||offset+size>bytes.length)invalid()
  let value
  if(size===1)value=BigInt(bytes[offset])
  else if(size===2)value=BigInt(bytes.readUInt16BE(offset))
  else if(size===4)value=BigInt(bytes.readUInt32BE(offset))
  else value=bytes.readBigUInt64BE(offset)
  offset+=size
  const minimum=size===1?24n:size===2?256n:size===4?65536n:4294967296n
  if(value<minimum||value>MAX_SAFE)invalid()
  return Number(value)
 }
 function item(depth) {
  if(depth>MAX_DEPTH||++items>MAX_ITEMS||offset>=bytes.length)invalid()
  const initial=bytes[offset++],major=initial>>>5,additional=initial&31
  // Arrays, tags, simple values, floats and indefinite forms are outside this profile.
  if(![0,1,2,3,5].includes(major))invalid()
  const value=argument(additional)
  if(major===0)return value
  if(major===1) {
   const negative=-1-value
   if(!Number.isSafeInteger(negative))invalid()
   return negative
  }
  if(major===2||major===3) {
   if(value>MAX_BYTES||value>bytes.length-offset)invalid()
   const part=bytes.subarray(offset,offset+value);offset+=value
   if(major===2)return Buffer.from(part)
   try {return new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(part)} catch {invalid()}
  }
  if(value>MAX_MAP_ENTRIES)invalid()
  const map=new Map()
  for(let n=0;n<value;n++) {
   const key=item(depth+1)
   if((typeof key!=='string'&&!Number.isSafeInteger(key))||map.has(key))invalid()
   map.set(key,item(depth+1))
  }
  return map
 }
 const result=item(0)
 if(offset!==bytes.length)invalid()
 return result
}
function exactMap(value,keys,reason) {
 if(!(value instanceof Map)||value.size!==keys.length||!keys.every(key=>value.has(key)))fail(reason)
 return value
}

export function parseNoneAttestation(bytes) {
 const value=exactMap(decode(bytes),['fmt','authData','attStmt'],'WEBAUTHN_REGISTRATION_ATTESTATION_INVALID')
 const authData=value.get('authData'),statement=value.get('attStmt')
 if(value.get('fmt')!=='none'||!Buffer.isBuffer(authData)||authData.length===0
  ||!(statement instanceof Map)||statement.size!==0)fail('WEBAUTHN_REGISTRATION_ATTESTATION_INVALID')
 // This parser establishes syntax only; the registration controller verifies authData.
 return authData
}

export function parseES256CredentialKey(bytes) {
 const keys=[1,3,-1,-2,-3]
 const value=exactMap(decode(bytes),keys,'WEBAUTHN_REGISTRATION_KEY_INVALID')
 // Minimal encodings plus this fixed order give CTAP2 canonical ES256 COSE_Key.
 if([...value.keys()].some((key,index)=>key!==keys[index])||value.get(1)!==2||value.get(3)!==-7||value.get(-1)!==1)
  fail('WEBAUTHN_REGISTRATION_KEY_INVALID')
 const x=value.get(-2),y=value.get(-3)
 if(!Buffer.isBuffer(x)||x.length!==32||!Buffer.isBuffer(y)||y.length!==32)fail('WEBAUTHN_REGISTRATION_KEY_INVALID')
 const key=Buffer.concat([Buffer.from([4]),x,y])
 try {p256.Point.fromBytes(key).assertValidity()} catch {fail('WEBAUTHN_REGISTRATION_KEY_INVALID')}
 return key.toString('hex')
}
