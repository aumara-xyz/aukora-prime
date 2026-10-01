import { createHash, timingSafeEqual } from 'node:crypto'
import { p256 } from '../upstream/vendor/authority/deps/@noble/curves@2.2.0/nist.js'
import { parseStrictText } from '../upstream/plugins/aukora-kira/lib/strict-read.mjs'
import { readClosedDataRecord } from '../upstream/plugins/aukora-aumlok/lib/validation.mjs'
import { assertData } from './operation.mjs'
const hash = bytes => createHash('sha256').update(bytes).digest()
const fault = reason => { throw Object.assign(new Error(reason),{error_code:'UNAUTHORIZED'}) }
export function decodeBase64url(value, max=65536) {
  if(typeof value!=='string'||value.length===0||value.length>max*2||!/^[A-Za-z0-9_-]+$/.test(value)) fault('WEBAUTHN_ENCODING_INVALID')
  const bytes=Buffer.from(value,'base64url')
  if(bytes.length>max||bytes.toString('base64url')!==value) fault('WEBAUTHN_ENCODING_INVALID')
  return bytes
}
export function webauthnChallenge(bytes) { return hash(bytes).toString('base64url') }
export function prepareWebauthnConfig(input) {
  if(input===undefined) return null
  assertData(input)
  const c=readClosedDataRecord(input,['rp_id','origins','credentials'],'WebAuthn trusted configuration')
  if(typeof c.rp_id!=='string'||!/^[a-z0-9]+([.-][a-z0-9]+)*$/.test(c.rp_id)||!Array.isArray(c.origins)||!c.origins.length||!Array.isArray(c.credentials)) throw new TypeError('INVALID: WebAuthn RP/origin config')
  for(const origin of c.origins) {
    const url=new URL(origin)
    if(url.protocol!=='https:'||url.origin!==origin||!(url.hostname===c.rp_id||url.hostname.endsWith('.'+c.rp_id))) throw new TypeError('INVALID: exact HTTPS WebAuthn origin')
  }
  const ids=new Set()
  for(const cred of c.credentials) {
    readClosedDataRecord(cred,['owner_id','credential_id','public_key_hex','user_handle','sign_count','backup_eligible'],'enrolled ES256 credential')
    decodeBase64url(cred.credential_id,1024);decodeBase64url(cred.user_handle,64)
    if(typeof cred.owner_id!=='string'||!cred.owner_id||typeof cred.public_key_hex!=='string'||!/^04[a-f0-9]{128}$/.test(cred.public_key_hex)||!Number.isSafeInteger(cred.sign_count)||cred.sign_count<0||cred.sign_count>0xffffffff||typeof cred.backup_eligible!=='boolean'||ids.has(cred.credential_id)) throw new TypeError('INVALID: enrolled ES256 credential')
    p256.Point.fromBytes(Buffer.from(cred.public_key_hex,'hex')).assertValidity()
    ids.add(cred.credential_id)
  }
  return JSON.parse(JSON.stringify(c))
}
export function webauthnOptions(config, ownerId, challenge) {
  const credentials=config?.credentials.filter(c=>c.owner_id===ownerId) ?? []
  if(!credentials.length) throw Object.assign(new Error('PASSKEY_OWNER_CREDENTIAL_NOT_ENROLLED'),{error_code:'UNAVAILABLE'})
  return {challenge,rpId:config.rp_id,allowCredentials:credentials.map(c=>({type:'public-key',id:c.credential_id})),userVerification:'required',timeout:60000}
}
// ES256 assertion verification only. No registration, attestation claim or signing.
// W3C WebAuthn §7.2; crypto is pinned @noble/curves 2.2.0, not a new curve implementation.
export function verifyWebauthnAssertion({material,config,ownerId,challenge,counter,checkCounter=true}) {
  if(!config) throw Object.assign(new Error('PASSKEY_VERIFIER_NOT_CONFIGURED'),{error_code:'UNAVAILABLE'})
  assertData(material)
  const m=readClosedDataRecord(material,['kind','credential_id','client_data_json','authenticator_data','signature','user_handle'],'WebAuthn assertion')
  if(m.kind!=='passkey') fault('WEBAUTHN_MATERIAL_KIND')
  const credential=config.credentials.find(c=>c.credential_id===m.credential_id&&c.owner_id===ownerId)
  if(!credential) fault('WEBAUTHN_CREDENTIAL_NOT_PINNED')
  decodeBase64url(m.credential_id,1024)
  if(m.user_handle!==null && (!timingSafeEqualSafe(decodeBase64url(m.user_handle,64),decodeBase64url(credential.user_handle,64)))) fault('WEBAUTHN_USER_HANDLE_MISMATCH')
  const clientBytes=decodeBase64url(m.client_data_json,16384),auth=decodeBase64url(m.authenticator_data,4096),signature=decodeBase64url(m.signature,128)
  let client
  try {client=parseStrictText(new TextDecoder('utf-8',{fatal:true}).decode(clientBytes),'WebAuthn clientDataJSON')} catch {fault('WEBAUTHN_CLIENT_DATA_INVALID')}
  if(!client||typeof client!=='object'||Array.isArray(client)) fault('WEBAUTHN_CLIENT_DATA_INVALID')
  if(client.type!=='webauthn.get'||client.challenge!==challenge||!config.origins.includes(client.origin)||client.crossOrigin===true||Object.hasOwn(client,'topOrigin')) fault('WEBAUTHN_CHALLENGE_OR_ORIGIN_MISMATCH')
  if(client.crossOrigin!==undefined&&client.crossOrigin!==false) fault('WEBAUTHN_CROSS_ORIGIN_REFUSED')
  // No authenticator extensions were requested. Refuse AT/ED and unexpected trailing bytes.
  if(auth.length!==37||!timingSafeEqual(auth.subarray(0,32),hash(config.rp_id))) fault('WEBAUTHN_RP_ID_MISMATCH')
  const flags=auth[32]
  if((flags&1)===0||(flags&4)===0||(flags&0xe2)!==0) fault('WEBAUTHN_UP_UV_OR_FLAGS_REFUSED')
  const backupEligible=(flags&8)!==0,backupState=(flags&16)!==0
  if(backupEligible!==credential.backup_eligible||(backupState&&!backupEligible)) fault('WEBAUTHN_BACKUP_ELIGIBILITY_CHANGED')
  const signCount=auth.readUInt32BE(33),prior=counter??credential.sign_count
  if(checkCounter&&(signCount!==0||prior!==0)&&signCount<=prior) fault('WEBAUTHN_COUNTER_REPLAYED')
  const signed=Buffer.concat([auth,hash(clientBytes)])
  if(!p256.verify(signature,signed,Buffer.from(credential.public_key_hex,'hex'),{format:'der',prehash:true,lowS:false})) fault('WEBAUTHN_SIGNATURE_INVALID')
  return {credential_id:credential.credential_id,sign_count:signCount,backup_eligible:backupEligible,backup_state:backupState,signed_bytes_digest:hash(signed).toString('hex'),user_present:true,user_verified:true,comprehension:'not-proven'}
}
function timingSafeEqualSafe(a,b) { return a.length===b.length && timingSafeEqual(a,b) }
