// SPDX-License-Identifier: AGPL-3.0-or-later
// Setup-only source. No route, private key, store creation or configuration writer.
import { createHash, randomBytes } from 'node:crypto'
import { types } from 'node:util'
import { canonicalJson } from '../../contracts/src/runtime.mjs'
import { readClosedDataRecord } from '../upstream/plugins/aukora-aumlok/lib/validation.mjs'
import { ed25519PublicKeyFromDidKey, didKeyFromEd25519PublicKey } from '../upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import { parseStrictText } from '../upstream/plugins/aukora-kira/lib/strict-read.mjs'
import { assertData, deepFreeze } from './operation.mjs'
import { decodeBase64url, prepareWebauthnConfig, webauthnChallenge, webauthnOptions, verifyWebauthnAssertion } from './webauthn.mjs'
import { parseNoneAttestation, parseES256CredentialKey } from './webauthn-registration-cbor.mjs'

const hex=/^[a-f0-9]{64}$/
const hash=bytes=>createHash('sha256').update(bytes).digest()
const digest=(domain,value)=>{boundedData(value);return 'sha256:'+hash(Buffer.from(domain+'\0'+canonicalJson(value),'utf8')).toString('hex')}
const fail=(reason,code='UNAUTHORIZED')=>{throw Object.assign(new Error(reason),{error_code:code})}
function boundedData(value) {
  let nodes=0,characters=0
  function visit(v,depth) {
    if(++nodes>4096||depth>32)fail('PASSKEY_BOOTSTRAP_DATA_BUDGET','INVALID')
    if(typeof v==='string'){characters+=v.length;if(characters>262144)fail('PASSKEY_BOOTSTRAP_DATA_BUDGET','INVALID');return}
    if(v===null||typeof v==='boolean')return
    if(typeof v==='number'){if(!Number.isSafeInteger(v)||Object.is(v,-0))fail('PASSKEY_BOOTSTRAP_DATA_INVALID','INVALID');return}
    if(typeof v!=='object'||types.isProxy(v)||(!Array.isArray(v)&&![null,Object.prototype].includes(Object.getPrototypeOf(v))))fail('PASSKEY_BOOTSTRAP_DATA_INVALID','INVALID')
    const keys=Reflect.ownKeys(v)
    if(keys.length>512)fail('PASSKEY_BOOTSTRAP_DATA_BUDGET','INVALID')
    for(const key of keys){const d=Object.getOwnPropertyDescriptor(v,key);if(typeof key!=='string'||!d||!Object.hasOwn(d,'value'))fail('PASSKEY_BOOTSTRAP_DATA_INVALID','INVALID');characters+=key.length;if(characters>262144)fail('PASSKEY_BOOTSTRAP_DATA_BUDGET','INVALID');visit(d.value,depth+1)}
  }
  visit(value,0)
}
const closed=(value,keys)=>{boundedData(value);assertData(value);return readClosedDataRecord(value,keys,'setup-only passkey enrollment')}
const rawHex=value=>typeof value==='string'&&hex.test(value)
const snapshot=value=>deepFreeze(JSON.parse(canonicalJson(value)))
const equal=(a,b)=>canonicalJson(a)===canonicalJson(b)
const text=value=>typeof value==='string'&&value.length>0&&value.length<=1024&&!/[\u0000-\u001f\u007f]/u.test(value)&&!/[\ud800-\udfff]/u.test(value.replace(/[\ud800-\udbff][\udc00-\udfff]/gu,''))
const iso=value=>typeof value==='string'&&Number.isFinite(Date.parse(value))&&new Date(Date.parse(value)).toISOString()===value

export const PASSKEY_PILOT_GUARANTEE=deepFreeze({
  profile:'reduced-guarantee-samehost-pilot/v1',
  missing:['independent-state-witness','second-host-anchor','hardware-hash-display'],
  authenticator_provenance:'not-proven',hardware_custody:'not-proven',comprehension:'not-proven',
  full_qualification:false
})

// These are immutable provisioner selections, never guest identity claims. The
// provenance metadata does not itself prove the source/projection relationship.
export function validatePasskeyEnrollmentBinding(input) {
  const b=closed(input,['identity','identity_provenance','passkey_profile','user','existing_credential_ids'])
  const id=closed(b.identity,['owner_id','subject','approval_key_did','control_digest','authorization_epoch'])
  if(!text(id.owner_id)||typeof id.subject!=='string'||!/^aukora:1:[a-f0-9]{64}$/.test(id.subject)||!rawHex(id.control_digest)||!Number.isSafeInteger(id.authorization_epoch)||id.authorization_epoch<0||typeof id.approval_key_did!=='string'||id.approval_key_did.length>96)fail('PASSKEY_BOOTSTRAP_IDENTITY_INVALID','INVALID')
  if(didKeyFromEd25519PublicKey(ed25519PublicKeyFromDidKey(id.approval_key_did))!==id.approval_key_did)fail('PASSKEY_BOOTSTRAP_DID_NONCANONICAL','INVALID')
  const provenance=closed(b.identity_provenance,['kind','identity_source_sha256','approval_reference'])
  if(provenance.kind!=='owner-approved-initial-public-identity/v1'||!rawHex(provenance.identity_source_sha256)||!text(provenance.approval_reference))fail('PASSKEY_BOOTSTRAP_PROVENANCE_REQUIRED','INVALID')
  const profile=closed(b.passkey_profile,['profile','origin','rp_id'])
  if(!['https','localhost-pilot-v1'].includes(profile.profile)||typeof profile.rp_id!=='string'||profile.rp_id.length>253||typeof profile.origin!=='string'||profile.origin.length>2048)fail('PASSKEY_BOOTSTRAP_PROFILE_REQUIRED','INVALID')
  prepareWebauthnConfig({profile:profile.profile,rp_id:profile.rp_id,origins:[profile.origin],credentials:[]})
  const user=closed(b.user,['id','name','display_name'])
  decodeBase64url(user.id,64)
  if(!text(user.name)||!text(user.display_name))fail('PASSKEY_BOOTSTRAP_USER_INVALID','INVALID')
  if(!Array.isArray(b.existing_credential_ids)||b.existing_credential_ids.length>256||new Set(b.existing_credential_ids).size!==b.existing_credential_ids.length)fail('PASSKEY_BOOTSTRAP_CREDENTIAL_INVENTORY_INVALID','INVALID')
  for(const credentialId of b.existing_credential_ids)decodeBase64url(credentialId,1023)
  if(Buffer.byteLength(canonicalJson(b))>65536)fail('PASSKEY_BOOTSTRAP_BINDING_TOO_LARGE','INVALID')
  return snapshot(b)
}
function request(input,possession=false) {
  const r=closed(input,possession?['version','ceremony_id','binding','issued_at','expiry','candidate_digest']:['version','ceremony_id','binding','issued_at','expiry'])
  if(r.version!==1||!rawHex(r.ceremony_id)||!iso(r.issued_at)||!iso(r.expiry)||Date.parse(r.expiry)<=Date.parse(r.issued_at)||Date.parse(r.expiry)-Date.parse(r.issued_at)>300000||(possession&&(typeof r.candidate_digest!=='string'||!/^sha256:[a-f0-9]{64}$/.test(r.candidate_digest))))fail('PASSKEY_BOOTSTRAP_REQUEST_INVALID','INVALID')
  return snapshot({...r,binding:validatePasskeyEnrollmentBinding(r.binding)})
}
export function passkeyRegistrationSigningBytes(input) {
  return Buffer.from('aukora-prime.passkey-registration.v1\0'+canonicalJson(request(input)),'utf8')
}
export function passkeyPossessionSigningBytes(input) {
  return Buffer.from('aukora-prime.passkey-bootstrap-possession.v1\0'+canonicalJson(request(input,true)),'utf8')
}
export function passkeyRegistrationCandidateDigest(candidate) {
  return digest('aukora-prime.passkey-registration-candidate.v1',candidate)
}
export function passkeyBootstrapEvidenceDigest(evidence) {
  return digest('aukora-prime.passkey-bootstrap-evidence.v1',evidence)
}
export function passkeyBootstrapBindingDigest(binding,credential) {
  const b=validatePasskeyEnrollmentBinding(binding)
  const c=closed(credential,['owner_id','credential_id','public_key_hex','user_handle','sign_count','backup_eligible'])
  prepareWebauthnConfig(config(b,c))
  if(c.owner_id!==b.identity.owner_id||c.user_handle!==b.user.id)fail('PASSKEY_BOOTSTRAP_OWNER_BINDING_MISMATCH','INVALID')
  const {sign_count,...stableCredential}=c
  return digest('aukora-prime.passkey-bootstrap-binding.v1',{binding:b,credential:stableCredential})
}
function config(binding,credential) {
  return {profile:binding.passkey_profile.profile,rp_id:binding.passkey_profile.rp_id,origins:[binding.passkey_profile.origin],credentials:[credential]}
}

// A none-attestation candidate is not an enrollment or proof of key possession.
export function verifyPasskeyRegistration({material,binding,challenge}) {
  const b=validatePasskeyEnrollmentBinding(binding)
  if(decodeBase64url(challenge,32).length!==32)fail('PASSKEY_REGISTRATION_CHALLENGE_INVALID')
  const m=closed(material,['kind','type','id','raw_id','client_data_json','attestation_object','client_extension_results'])
  if(m.kind!=='passkey-registration'||m.type!=='public-key'||m.id!==m.raw_id)fail('PASSKEY_REGISTRATION_TYPE_OR_ID_INVALID')
  closed(m.client_extension_results,[])
  const credentialId=decodeBase64url(m.raw_id,1023)
  if(b.existing_credential_ids.includes(m.raw_id))fail('PASSKEY_REGISTRATION_CREDENTIAL_ALREADY_KNOWN','REPLAYED')
  const clientBytes=decodeBase64url(m.client_data_json,16384)
  let client
  try{client=parseStrictText(new TextDecoder('utf-8',{fatal:true}).decode(clientBytes),'registration clientDataJSON')}catch{fail('PASSKEY_REGISTRATION_CLIENT_DATA_INVALID')}
  if(!client||typeof client!=='object'||Array.isArray(client)||client.type!=='webauthn.create'||client.challenge!==challenge||client.origin!==b.passkey_profile.origin||Object.hasOwn(client,'topOrigin')||(client.crossOrigin!==undefined&&client.crossOrigin!==false))fail('PASSKEY_REGISTRATION_CHALLENGE_OR_ORIGIN_MISMATCH')
  const attestation=decodeBase64url(m.attestation_object,16384),auth=parseNoneAttestation(attestation)
  if(auth.length<56||!auth.subarray(0,32).equals(hash(b.passkey_profile.rp_id)))fail('PASSKEY_REGISTRATION_RP_ID_MISMATCH')
  const flags=auth[32]
  if((flags&0x45)!==0x45||(flags&0xa2)!==0)fail('PASSKEY_REGISTRATION_UP_UV_AT_OR_FLAGS_REFUSED')
  const backupEligible=(flags&8)!==0,backupState=(flags&16)!==0
  if(backupState&&!backupEligible)fail('PASSKEY_REGISTRATION_BACKUP_FLAGS_INVALID')
  const idLength=auth.readUInt16BE(53)
  if(idLength<1||idLength>1023||auth.length<=55+idLength||!auth.subarray(55,55+idLength).equals(credentialId))fail('PASSKEY_REGISTRATION_CREDENTIAL_ID_MISMATCH')
  const publicKeyHex=parseES256CredentialKey(auth.subarray(55+idLength))
  const credential={owner_id:b.identity.owner_id,credential_id:m.raw_id,public_key_hex:publicKeyHex,user_handle:b.user.id,sign_count:auth.readUInt32BE(33),backup_eligible:backupEligible}
  prepareWebauthnConfig(config(b,credential))
  return snapshot({credential,registration_client_data_sha256:hash(clientBytes).toString('hex'),attestation_object_sha256:hash(attestation).toString('hex'),aaguid_hex:auth.subarray(37,53).toString('hex'),backup_state:backupState,attestation:'none',key_possession:'not-yet-verified',grants_authority:false})
}
function creationOptions(r) {
  const b=r.binding
  return snapshot({challenge:webauthnChallenge(passkeyRegistrationSigningBytes(r)),rp:{id:b.passkey_profile.rp_id,name:'AUKORA Prime'},user:{id:b.user.id,name:b.user.name,displayName:b.user.display_name},pubKeyCredParams:[{type:'public-key',alg:-7}],timeout:60000,excludeCredentials:b.existing_credential_ids.map(id=>({type:'public-key',id})),authenticatorSelection:{residentKey:'preferred',userVerification:'required'},attestation:'none',extensions:{}})
}

// Pure stage decision used by the local controller. No wire clock or externally
// supplied stage is ever used by createPasskeyEnrollmentCeremony.
export function assertPasskeyEnrollmentStage(input) {
  const v=closed(input,['status','expiry','now','expected'])
  if(!['AWAITING_REGISTRATION','REGISTRATION_ATTEMPTED','AWAITING_POSSESSION','POSSESSION_ATTEMPTED','POSSESSION_VERIFIED','DECLINED','EXPIRED','FAILED'].includes(v.status)||!['AWAITING_REGISTRATION','AWAITING_POSSESSION'].includes(v.expected)||!iso(v.expiry)||!Number.isSafeInteger(v.now)||v.now<0)fail('PASSKEY_BOOTSTRAP_STAGE_INVALID','INVALID')
  const state=['AWAITING_REGISTRATION','AWAITING_POSSESSION'].includes(v.status)&&v.now>=Date.parse(v.expiry)?'EXPIRED':v.status
  if(state!==v.expected)fail(state==='DECLINED'?'OWNER_DECLINED_PASSKEY_BOOTSTRAP':state==='EXPIRED'?'PASSKEY_BOOTSTRAP_EXPIRED':'PASSKEY_BOOTSTRAP_STAGE_REFUSED',state==='DECLINED'?'CANCELLED':state==='EXPIRED'?'EXPIRED':'REPLAYED')
  return state
}

// An unfinished ceremony is deliberately process-local and never resumes after a
// restart. Only a protected setup host may construct it after explicit owner action.
export function createPasskeyEnrollmentCeremony(trustedBinding) {
  const binding=validatePasskeyEnrollmentBinding(trustedBinding),stamp=Date.now()
  const registrationRequest=request({version:1,ceremony_id:randomBytes(32).toString('hex'),binding,issued_at:new Date(stamp).toISOString(),expiry:new Date(stamp+300000).toISOString()})
  const publicKey=creationOptions(registrationRequest)
  let state='AWAITING_REGISTRATION',candidate=null,registrationMaterial=null,possessionRequest=null,evidence=null,reason=null
  function refresh() {
    if(Date.now()>=Date.parse(registrationRequest.expiry)&&['AWAITING_REGISTRATION','AWAITING_POSSESSION'].includes(state)){state='EXPIRED';reason='PASSKEY_BOOTSTRAP_EXPIRED'}
  }
  const status=()=>{refresh();return snapshot({status:state,ceremony_id:registrationRequest.ceremony_id,expiry:registrationRequest.expiry,passkey_profile:binding.passkey_profile,guarantee:PASSKEY_PILOT_GUARANTEE,identity_provenance_verified:false,grants_authority:false,owner_enrollment:false,reason})}
  function live(expected) {refresh();assertPasskeyEnrollmentStage({status:state,expiry:registrationRequest.expiry,now:Date.now(),expected})}
  return Object.freeze({
    status,
    creationRequest(){live('AWAITING_REGISTRATION');return snapshot({request:registrationRequest,public_key:publicKey,guarantee:PASSKEY_PILOT_GUARANTEE,identity_provenance_verified:false,owner_enrollment:false,grants_authority:false})},
    acceptRegistration(material){
      live('AWAITING_REGISTRATION');state='REGISTRATION_ATTEMPTED'
      try{
        candidate=verifyPasskeyRegistration({material,binding,challenge:publicKey.challenge})
        if(Date.now()>=Date.parse(registrationRequest.expiry))fail('PASSKEY_BOOTSTRAP_EXPIRED','EXPIRED')
        registrationMaterial=snapshot(material)
        possessionRequest=request({...registrationRequest,candidate_digest:passkeyRegistrationCandidateDigest(candidate)},true)
        state='AWAITING_POSSESSION'
        return snapshot({candidate,request:possessionRequest,public_key:webauthnOptions(config(binding,candidate.credential),binding.identity.owner_id,webauthnChallenge(passkeyPossessionSigningBytes(possessionRequest))),guarantee:PASSKEY_PILOT_GUARANTEE,identity_provenance_verified:false,owner_enrollment:false,grants_authority:false})
      }catch(error){state=error.error_code==='EXPIRED'?'EXPIRED':'FAILED';reason=error.message;throw error}
    },
    confirmPossession(material){
      live('AWAITING_POSSESSION');state='POSSESSION_ATTEMPTED'
      try{
        const assertion=closed(material,['kind','credential_id','client_data_json','authenticator_data','signature','user_handle'])
        const verified=verifyWebauthnAssertion({material:assertion,config:config(binding,candidate.credential),ownerId:binding.identity.owner_id,challenge:webauthnChallenge(passkeyPossessionSigningBytes(possessionRequest)),counter:candidate.credential.sign_count})
        if(Date.now()>=Date.parse(registrationRequest.expiry))fail('PASSKEY_BOOTSTRAP_EXPIRED','EXPIRED')
        evidence=snapshot({version:1,kind:'prime-passkey-bootstrap/v1',registration_request:registrationRequest,registration_material:registrationMaterial,candidate,possession_request:possessionRequest,possession_material:snapshot(assertion),credential:{...candidate.credential,sign_count:verified.sign_count},verified_at:new Date().toISOString(),guarantee:PASSKEY_PILOT_GUARANTEE,identity_provenance_verified:false,owner_enrollment:false,grants_authority:false})
        state='POSSESSION_VERIFIED'
        return snapshot({status:state,evidence,evidence_digest:passkeyBootstrapEvidenceDigest(evidence),requires_protected_setup_commit:true,guarantee:PASSKEY_PILOT_GUARANTEE,identity_provenance_verified:false,grants_authority:false,owner_enrollment:false})
      }catch(error){state=error.error_code==='EXPIRED'?'EXPIRED':'FAILED';reason=error.message;throw error}
    },
    decline(){
      refresh()
      if(!['AWAITING_REGISTRATION','AWAITING_POSSESSION'].includes(state))fail('PASSKEY_BOOTSTRAP_DECLINE_STAGE_REFUSED','REPLAYED')
      state='DECLINED';reason='OWNER_DECLINED_PASSKEY_BOOTSTRAP';return status()
    }
  })
}

// Historical public evidence verification, not live enrollment or authentication.
// expected_binding and expected_digest must come from H's independently protected
// setup manifest; a caller's self-reported expected values confer no trust.
export function validatePasskeyBootstrapEvidence({evidence,expected_binding,expected_digest}) {
  const e=closed(evidence,['version','kind','registration_request','registration_material','candidate','possession_request','possession_material','credential','verified_at','guarantee','identity_provenance_verified','owner_enrollment','grants_authority'])
  if(Buffer.byteLength(canonicalJson(e))>262144)fail('PASSKEY_BOOTSTRAP_EVIDENCE_TOO_LARGE','INVALID')
  if(e.version!==1||e.kind!=='prime-passkey-bootstrap/v1'||e.identity_provenance_verified!==false||e.owner_enrollment!==false||e.grants_authority!==false||!equal(e.guarantee,PASSKEY_PILOT_GUARANTEE)||typeof expected_digest!=='string'||!/^sha256:[a-f0-9]{64}$/.test(expected_digest)||passkeyBootstrapEvidenceDigest(e)!==expected_digest)fail('PASSKEY_BOOTSTRAP_EVIDENCE_PIN_MISMATCH','RECONCILIATION_REQUIRED')
  const binding=validatePasskeyEnrollmentBinding(expected_binding),r=request(e.registration_request),p=request(e.possession_request,true)
  if(!equal(r.binding,binding)||!equal({...r,candidate_digest:p.candidate_digest},p)||!iso(e.verified_at)||Date.parse(e.verified_at)<Date.parse(r.issued_at)||Date.parse(e.verified_at)>=Date.parse(r.expiry))fail('PASSKEY_BOOTSTRAP_EVIDENCE_BINDING_MISMATCH','RECONCILIATION_REQUIRED')
  const candidate=verifyPasskeyRegistration({material:e.registration_material,binding,challenge:webauthnChallenge(passkeyRegistrationSigningBytes(r))})
  if(!equal(candidate,e.candidate)||passkeyRegistrationCandidateDigest(candidate)!==p.candidate_digest)fail('PASSKEY_BOOTSTRAP_CANDIDATE_MISMATCH','RECONCILIATION_REQUIRED')
  const checked=verifyWebauthnAssertion({material:e.possession_material,config:config(binding,candidate.credential),ownerId:binding.identity.owner_id,challenge:webauthnChallenge(passkeyPossessionSigningBytes(p)),counter:candidate.credential.sign_count})
  const credential={...candidate.credential,sign_count:checked.sign_count}
  if(!equal(e.credential,credential))fail('PASSKEY_BOOTSTRAP_CREDENTIAL_MISMATCH','RECONCILIATION_REQUIRED')
  return snapshot({identity:binding.identity,webauthn:config(binding,credential),evidence_digest:expected_digest,guarantee:PASSKEY_PILOT_GUARANTEE,identity_provenance_verified:false,owner_enrollment:false,grants_authority:false})
}

// Optional normal-service input, taken only from the protected setup manifest.
// This selects pin enforcement; it cannot upgrade provenance or provision state.
export function preparePasskeyBootstrap(input,{identities,webauthn,loginKinds}) {
  if(input===undefined)return null
  const selected=closed(input,['evidence','expected_binding','expected_digest'])
  const verified=validatePasskeyBootstrapEvidence(selected)
  if(!Array.isArray(identities)||!identities.some(id=>equal(id,verified.identity))||!equal(webauthn,verified.webauthn)||!equal(loginKinds,['passkey']))fail('PASSKEY_BOOTSTRAP_CONFIG_BINDING_MISMATCH','RECONCILIATION_REQUIRED')
  return snapshot({owner_id:verified.identity.owner_id,binding_digest:passkeyBootstrapBindingDigest(selected.expected_binding,verified.webauthn.credentials[0]),evidence_digest:verified.evidence_digest,guarantee:PASSKEY_PILOT_GUARANTEE})
}
// Called on the actual loaded owner row. Absence on both sides preserves v1;
// every one-sided, changed or removed selection refuses without rebaselining.
export function assertPasskeyBootstrapOwnerPin(owner,bootstrap) {
  const expected=bootstrap?.owner_id===owner.owner_id?bootstrap.binding_digest:undefined
  if(owner.passkey_bootstrap_digest!==expected)fail('PASSKEY_BOOTSTRAP_PIN_CHANGED_OR_MISSING','RECONCILIATION_REQUIRED')
}
