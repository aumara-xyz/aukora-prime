// SPDX-License-Identifier: AGPL-3.0-or-later
// Test ONLY: disposable synthetic authenticator keys, actual C verification/stores.
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto'
import {mkdirSync} from 'node:fs'
import {join} from 'node:path'
import {createAuthorityService} from '../../authority/src/index.mjs'
import {didKeyFromEd25519PublicKey} from '../../authority/upstream/plugins/aukora-aumlok/lib/did-key.mjs'
const hash=value=>createHash('sha256').update(value).digest()
export function authorityFixture({root,audience,authorizeTask,observeTarget,actions=['memory.save']}={}) {
  mkdirSync(join(root,'state'),{mode:0o700})
  const ed=generateKeyPairSync('ed25519'),ec=generateKeyPairSync('ec',{namedCurve:'prime256v1'})
  const jwk=ec.publicKey.export({format:'jwk'}),raw=Buffer.from(ed.publicKey.export({format:'jwk'}).x,'base64url').toString('hex')
  const identity={owner_id:'synthetic-owner',subject:'aukora:1:'+'a'.repeat(64),approval_key_did:didKeyFromEd25519PublicKey(raw),control_digest:'2'.repeat(64),authorization_epoch:0}
  const credential={owner_id:identity.owner_id,credential_id:randomBytes(32).toString('base64url'),public_key_hex:'04'+Buffer.from(jwk.x,'base64url').toString('hex')+Buffer.from(jwk.y,'base64url').toString('hex'),user_handle:Buffer.from('synthetic-owner').toString('base64url'),sign_count:0,backup_eligible:false}
  const webauthn={rp_id:'prime.example.test',origins:['https://prime.example.test'],credentials:[credential]}
  const config={statePath:join(root,'state','authority.json'),stateRoot:join(root,'state'),witnessDir:join(root,'witness'),audience,identities:[identity],webauthn,
    policy:{version:'synthetic-policy',actions,agents:['synthetic-agent'],data_scope:['synthetic'],maximum_cost:{currency:'USD',amount:'0'}},provisionTrustedState:true,authorizeTask,observeTarget}
  let counter=0
  function assertion(challenge) {
    const client=Buffer.from(JSON.stringify({type:'webauthn.get',challenge,origin:webauthn.origins[0],crossOrigin:false}))
    const auth=Buffer.alloc(37);hash(webauthn.rp_id).copy(auth);auth[32]=5;auth.writeUInt32BE(++counter,33)
    return {kind:'passkey',credential_id:credential.credential_id,client_data_json:client.toString('base64url'),authenticator_data:auth.toString('base64url'),signature:sign('sha256',Buffer.concat([auth,hash(client)]),ec.privateKey).toString('base64url'),user_handle:credential.user_handle}
  }
  return {identity,config,service:createAuthorityService(config),assertion,restart:()=>createAuthorityService({...config,provisionTrustedState:false})}
}
