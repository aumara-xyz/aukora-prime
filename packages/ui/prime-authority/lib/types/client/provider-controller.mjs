// SPDX-License-Identifier: AGPL-3.0-or-later
// Separate Models card. No generic credentials/settings mutations, signer,
// model request, ambient key or private token getter exists in this controller.
import {validateProviderNamespace} from '../adapters/provider-settings.mjs'
const MODEL='deepseek-flash',ENTRY='/api/prime/inference/credential-entry'
const EMPTY={endpoint:'https://api.deepseek.com',model:'',region:'',allowedDataClasses:[],maxInputTokens:0,maxOutputTokens:0,
  maxRequests:0,enabled:false,credentialConfigured:false,taskSpendCeiling:null}
const frozen=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))frozen(child);Object.freeze(value)}return value}
const closed=(value,fields)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...fields].sort().join(',')
const refusal=()=>{throw new TypeError('Prime provider operation unavailable')}

/** Default source binding exposes the owned PUBLIC catalog only. Owner APIs
 * require H's injected, C-authenticated context and independent worker join. */
export function createPublicProviderApi(contracts,fetcher=globalThis.fetch) {
  return Object.freeze({async catalog(){
    const response=await fetcher('/api/prime/inference/catalog',{method:'GET',credentials:'same-origin',redirect:'error',cache:'no-store'})
    if(!response.ok)refusal()
    return contracts.parseStrictJson(await response.text(),{maxBytes:65536,maxDepth:32})
  }})
}

export function createPrimeProviderController({now=Date.now,fetcher=globalThis.fetch,schedule=setTimeout,unschedule=clearTimeout,browser=()=>({origin:globalThis.location?.origin,isSecureContext:globalThis.isSecureContext})}={}) {
  const listeners=new Set()
  let binding=null,offOwner,revision=0,statusRevision=0,ownerMetadataLoaded=false,owner=null,flight=null,ticket=null,generation=null,disposed=false,expiryTimer
  const usedApprovals=new Set()
  let state=frozen({model_draft:MODEL,catalog_status:'pending',owner_status:'unavailable',row:{...EMPTY},entry_status:'unavailable',
    reason:'Owner configuration and secure key entry are unavailable.'})
  const notify=patch=>{if(disposed)return;state=frozen({...state,...patch});for(const listener of listeners)listener()}
  const current=entry=>!disposed&&binding===entry.binding&&revision===entry.revision&&owner===entry.owner
  function ownerReady(){
    const observed=binding?.ownerController?.getSnapshot()
    if(!owner||observed?.owner!==owner||observed.authority_available!==true||observed.expired===true||
      typeof owner.owner_id!=='string'||!owner.owner_id||!Number.isFinite(Date.parse(owner.expiry))||Date.parse(owner.expiry)<=now())refusal()
    return owner
  }
  function secureEntry(){
    const profile=binding?.entryProfile,support=browser()
    if(!closed(profile,['origin','qualified_separate_worker'])||profile.qualified_separate_worker!==true||
      typeof profile.origin!=='string'||new URL(profile.origin).protocol!=='https:'||new URL(profile.origin).origin!==profile.origin||
      support.origin!==profile.origin||support.isSecureContext!==true)refusal()
  }
  function stopExpiry(){if(expiryTimer!==undefined)unschedule(expiryTimer);expiryTimer=undefined}
  function clearPrivate(){revision++;statusRevision++;ownerMetadataLoaded=false;ticket=null;generation=null;flight=null;usedApprovals.clear();stopExpiry()}
  function rowOf(namespace){return validateProviderNamespace(namespace,binding.contracts).section.providers.externalDeepSeek}
  const api={
    getSnapshot:()=>state,
    subscribe(listener){listeners.add(listener);return()=>listeners.delete(listener)},
    connect(next){
      offOwner?.();clearPrivate();binding=next;owner=next?.ownerController?.getSnapshot().owner??null
      notify({catalog_status:'pending',owner_status:'unavailable',row:{...EMPTY},entry_status:'unavailable',reason:'Loading the nonsecret provider catalog. Secure entry remains unavailable.'})
      offOwner=next?.ownerController?.subscribe(()=>{
        const snapshot=next.ownerController.getSnapshot(),observed=snapshot.owner
        if(observed===owner&&(!owner||snapshot.authority_available===true&&snapshot.expired!==true&&Date.parse(owner.expiry)>now()))return
        clearPrivate();owner=observed
        notify({owner_status:'unavailable',row:{...EMPTY},entry_status:'unavailable',reason:'Owner access changed. Configuration and key entry need a fresh owner check.'})
      })
    },
    setModel(value){if(value!==MODEL)refusal();notify({model_draft:value,reason:'Model choice is a local draft. No configuration was saved and no model request was sent.'})},
    async load(){
      const entry={binding,revision,owner}
      try{
        if(typeof binding?.api?.catalog!=='function')refusal()
        const catalog=await binding.api.catalog()
        if(!current(entry))return null
        if(!closed(catalog,['version','providers','namespace'])||catalog.version!==1||!Array.isArray(catalog.providers)||catalog.providers.length!==1)refusal()
        const provider=catalog.providers[0]
        if(!closed(provider,['provider','displayName','settingsNs','settingsPath','declared','active','endpoint','credential_entry','paid_requests_enabled','models','credential_status','pending'])||
          provider.provider!=='externalDeepSeek'||provider.settingsNs!=='prime-inference'||provider.endpoint!=='https://api.deepseek.com'||
          !Array.isArray(provider.settingsPath)||provider.settingsPath.join('/')!=='providers/externalDeepSeek'||provider.credential_entry!=='separated_owner_handoff')refusal()
        const row=rowOf(catalog.namespace)
        notify({catalog_status:'loaded',...(ownerMetadataLoaded?{}:{row,
          reason:'DeepSeek V4.1 Flash uses deepseek-flash. Model choice is a local draft; secure owner entry remains unavailable.'})})
        return state
      }catch{if(current(entry))notify({catalog_status:'unavailable',reason:'The provider catalog is unavailable. Owner access and key entry are shown separately.'});return null}
    },
    async refreshOwner(){
      const entry={binding,revision,owner}
      const statusRead=++statusRevision
      try{
        ownerReady();if(typeof binding?.api?.status!=='function')refusal()
        notify({owner_status:'pending'})
        if(!current(entry)||statusRead!==statusRevision)return null
        ownerReady()
        const result=await binding.api.status()
        if(!current(entry)||statusRead!==statusRevision)return null
        ownerReady()
        if(!closed(result,['version','provider','configured','config_digest','profile','credential','paid_requests_enabled','pending','namespace'])||
          result.version!==1||result.provider!=='externalDeepSeek'||typeof result.configured!=='boolean'||typeof result.paid_requests_enabled!=='boolean'||
          !closed(result.credential,['configured','generation'])||typeof result.credential.configured!=='boolean'||
          !(result.credential.generation===null||Number.isSafeInteger(result.credential.generation)&&result.credential.generation>0))refusal()
        const row=rowOf(result.namespace)
        if(row.credentialConfigured!==result.credential.configured||row.enabled!==result.paid_requests_enabled)refusal()
        generation=result.credential.generation??0
        ownerMetadataLoaded=true
        notify({owner_status:'loaded',row,...(['unknown','pending','ready','configured'].includes(state.entry_status)?{}:{entry_status:'review_required',
          reason:'Owner metadata loaded. Key entry requires fresh owner approval and secure credential storage.'})})
        return state
      }catch{if(current(entry)&&statusRead===statusRevision)notify({owner_status:'unavailable',...(['unknown','pending','ready','configured'].includes(state.entry_status)?{}:{entry_status:'unavailable'}),reason:'Owner provider configuration is unavailable. Key entry remains disabled.'});return null}
    },
    /** H supplies the signed proof from the existing exact-operation approval
     * UI. C/worker authenticate and authorize provider+generation independently. */
    prepareCredentialEntry(input){
      if(flight)return flight
      if(state.entry_status==='unknown'||state.entry_status==='pending'||state.entry_status==='ready')return Promise.resolve(null)
      const entry={binding,revision,owner}
      flight=Promise.resolve().then(async()=>{
        let invoked=false
        try{
          if(!current(entry))return null
          ownerReady();secureEntry()
          if(state.owner_status!=='loaded'||!closed(input,['expected_generation','approval_proof'])||
            input.expected_generation!==generation||!Number.isSafeInteger(generation)||generation<0||typeof binding.api.credentialHandoff!=='function')refusal()
          binding.contracts.validateContract('ApprovalProof',input.approval_proof)
          if(input.approval_proof.owner_id!==owner.owner_id||Date.parse(input.approval_proof.expiry)<=now())refusal()
          const proofRef=input.approval_proof.operation_id+'\0'+input.approval_proof.operation_digest+'\0'+input.approval_proof.nonce
          if(usedApprovals.has(proofRef)||usedApprovals.size>=16)refusal()
          const request=binding.contracts.parseStrictJson(binding.contracts.canonicalJson(input))
          notify({entry_status:'pending',reason:'Waiting for approved single-use key entry. No key was sent.'})
          if(!current(entry))return null
          ownerReady();secureEntry();usedApprovals.add(proofRef);invoked=true
          const descriptor=await binding.api.credentialHandoff(request)
          if(!current(entry))return null
          ownerReady();secureEntry()
          if(!closed(descriptor,['provider','method','path','ticket','expires_at'])||descriptor.provider!=='externalDeepSeek'||descriptor.method!=='POST'||
            descriptor.path!==ENTRY||typeof descriptor.ticket!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(descriptor.ticket)||
            typeof descriptor.expires_at!=='string'||!Number.isFinite(Date.parse(descriptor.expires_at))||Date.parse(descriptor.expires_at)<=now()||
            Date.parse(descriptor.expires_at)>Math.min(now()+60000,Date.parse(owner.expiry)))refusal()
          ticket=frozen({...descriptor,expected_generation:request.expected_generation})
          const prepared=ticket
          stopExpiry()
          expiryTimer=schedule(()=>{
            if(current(entry)&&ticket===prepared){ticket=null;notify({entry_status:'unavailable',reason:'The one-use credential handoff expired. Key entry is disabled; no key was sent.'})}
          },Date.parse(prepared.expires_at)-now())
          expiryTimer?.unref?.()
          notify({entry_status:'ready',reason:'Approved key entry is ready. The key goes directly to secure credential storage.'})
          return {ready:true}
        }catch{if(current(entry)){ticket=null;notify({entry_status:invoked?'unknown':'unavailable',reason:invoked
          ? 'The credential handoff result is unconfirmed. No key was sent and no retry was made.' : 'Secure owner handoff is unavailable. No key was sent.'})}return null}
        finally{if(current(entry))flight=null}
      })
      return flight
    },
    async submitCredential(input){
      const entry={binding,revision,owner},descriptor=ticket
      let secret,body,dispatched=false
      try{
        if(state.entry_status==='unknown'||state.entry_status==='pending')return null
        ownerReady();secureEntry()
        if(state.entry_status!=='ready'||!descriptor||Date.parse(descriptor.expires_at)<=now()||typeof input?.value!=='string')refusal()
        secret=input.value
        if(!secret||secret.length>4096)refusal()
        // Consume before dispatch. Never cache a secret or retry a lost reply.
        ticket=null;stopExpiry();input.value=''
        body=binding.contracts.canonicalJson({ticket:descriptor.ticket,secret});secret=undefined
        notify({entry_status:'pending',reason:'Sending the key to secure credential storage. Its result is unconfirmed.'})
        if(!current(entry))return null
        ownerReady();secureEntry();dispatched=true
        const response=await fetcher(ENTRY,{method:'POST',credentials:'same-origin',redirect:'error',cache:'no-store',
          headers:{'content-type':'application/json'},body})
        body=undefined
        if(!current(entry))return null
        ownerReady();secureEntry()
        const result=binding.contracts.parseStrictJson(await response.text(),{maxBytes:4096,maxDepth:8})
        if(!current(entry))return null
        ownerReady()
        if(!response.ok||!closed(result,['configured','generation'])||result.configured!==true||result.generation!==descriptor.expected_generation+1)refusal()
        generation=result.generation
        statusRevision++
        ownerMetadataLoaded=true
        notify({owner_status:'loaded',entry_status:'configured',row:{...state.row,credentialConfigured:true},reason:'Credential storage was acknowledged. Paid inference still requires an approved route and task limits.'})
        return {configured:true,generation:result.generation}
      }catch{
        if(current(entry))notify({entry_status:dispatched?'unknown':'unavailable',reason:dispatched
          ? 'Credential storage is unconfirmed. The one-use handoff was consumed; no retry was sent.' : 'Secure key entry is unavailable.'})
        return null
      }finally{secret=undefined;body=undefined;if(input&&typeof input.value==='string')input.value=''}
    },
    disconnect(){offOwner?.();offOwner=undefined;clearPrivate();binding=null;owner=null;notify({owner_status:'unavailable',row:{...EMPTY},entry_status:'unavailable',reason:'Owner provider binding unavailable. Key entry disabled.'})},
    dispose(){api.disconnect();disposed=true;listeners.clear()},
  }
  return Object.freeze(api)
}
