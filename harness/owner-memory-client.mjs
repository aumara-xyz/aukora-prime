// SPDX-License-Identifier: AGPL-3.0-or-later
// Unmounted browser composition for the separate native owner controller.
// These own-package imports are rewritten to prime-packages by compose.py.
import {createUiAdapters} from '../packages/runtime-bridge/src/ui-adapter.mjs';
import {createOwnerMemoryWorkflow} from '../packages/runtime-bridge/src/owner-memory-workflow.mjs';
import {createOwnerForgetWorkflow} from '../packages/runtime-bridge/src/owner-forget-workflow.mjs';
import {createOwnerMemoryHttpCall} from './owner-memory-browser.mjs';

/** The owner binding and signer are trusted composition inputs. This factory
 * creates no identity, credential, session, listener or accepted host record.
 * Existing capability status must separately enable the native controller. */
export function createOwnerMemoryClient({controller,contracts,ownerBinding,fetcher,passkeySigner,isCurrentConnection}={}) {
 if(['connect','getSnapshot','subscribe','setApprovalAction','setForgetAction','submitApproval','reconcileApprovalAction','logout','disconnect','setCapabilities','capabilitiesUnavailable'].some(name=>typeof controller?.[name]!=='function'))throw new TypeError('UNAVAILABLE: native owner controller required');
 if(typeof isCurrentConnection!=='function')throw new TypeError('UNAVAILABLE: exact native connection observer required');
 if(!ownerBinding||Object.getPrototypeOf(ownerBinding)!==Object.prototype
  ||Object.keys(ownerBinding).sort().join(',')!=='owner_id,passkeyProfile'
  ||typeof ownerBinding.owner_id!=='string'||!ownerBinding.owner_id.length
  ||passkeySigner!==undefined&&typeof passkeySigner!=='function')throw new TypeError('INVALID: trusted owner binding required');
 const owner=contracts.parseStrictJson(contracts.canonicalJson(ownerBinding),{maxBytes:4096,maxDepth:8});
 if(!owner.passkeyProfile||Object.keys(owner.passkeyProfile).sort().join(',')!=='origin,profile,rp_id')throw new TypeError('INVALID: exact passkey profile required');
 Object.freeze(owner.passkeyProfile);
 // B's existing signer validates the profile and actual secure browser origin
 // before an assertion. Missing/unqualified capabilities keep login disabled.
 const adapters=createUiAdapters({call:createOwnerMemoryHttpCall({contracts,fetcher})});
 // Old B controllers notify local sign-out; newer controllers also call the
 // authority logout method. Keep the same actual server result for both paths,
 // including lost replies, until a fresh login attempt starts a new generation.
 let logoutFlight=null;
 const revoke=()=>logoutFlight??=adapters.logout();
 const authority=Object.freeze({...adapters.authority,logout:revoke,
  loginChallenge(input){logoutFlight=null;return adapters.authority.loginChallenge(input);},
 });
 const memory=Object.freeze({...adapters.memory,logout:revoke});
 const binding=Object.freeze({...owner,authority,contracts,loginKinds:Object.freeze(['passkey']),requiresCapabilities:true,
  ...(passkeySigner?{passkeySigner}:{})});
 const ownsConnection=()=>{try{return isCurrentConnection(binding)===true;}catch{return false;}};
 const requireConnection=()=>{if(!ownsConnection())throw new TypeError('UNAVAILABLE: exact native connection is not current');};
 let disposed=false,attaching=false,workflow,forgetWorkflow,off,pilotRegistration;
 const attached=()=>{if(disposed||attaching||!workflow)throw new TypeError('UNAVAILABLE: owner client is not attached');requireConnection();return workflow;};
 const attachedForget=()=>{attached();return forgetWorkflow;};
 const recoveryCurrent=owner=>{
  attached();const state=controller.getSnapshot();
  if(state.owner!==owner||owner&&(state.authority_available!==true||state.expired===true
   ||!Number.isFinite(Date.parse(owner.expiry))||Date.parse(owner.expiry)<=Date.now()))
   throw new TypeError('UNAVAILABLE: recovery owner is no longer current');
 };
 const client=Object.freeze({
  binding,
  // Native composition first provides binding as Cordis primeAuthority, waits
  // for B's controller.connect, and then attaches. Its supplied flag prevents
  // the default async HTTP binding from reconnecting and clearing this hook.
  attach(){if(disposed)throw new TypeError('UNAVAILABLE: owner client disposed');if(attaching)throw new TypeError('UNAVAILABLE: owner client attachment in progress');requireConnection();if(workflow)return workflow;
   if(controller.getSnapshot().owner_id!==binding.owner_id)throw new TypeError('UNAVAILABLE: native owner binding must connect before attach');
   attaching=true;
   try{
    workflow=createOwnerMemoryWorkflow({controller,memory,contracts});
    forgetWorkflow=createOwnerForgetWorkflow({controller,memory,contracts});
    off=controller.subscribe(()=>{const state=controller.getSnapshot();
     // Replacement invalidates the witness before its notifications. Dispose
     // only our stores/adapter; ownership checks below protect the new hooks.
     if(!ownsConnection()){try{client.dispose();}catch{}return;}
     // Also fences a logout before a pending login has established an owner.
     if(!state.owner&&['logged_out','unavailable','expired'].includes(state.phase))revoke();
    });
    requireConnection();
    controller.setApprovalAction((_view,options)=>attached().approveAndSave(options));
    // Hook installation synchronously notifies B observers, which may dispose
    // the native composition. Never install the next hook after that teardown.
    if(disposed)throw new TypeError('UNAVAILABLE: owner client disposed during attachment');
    requireConnection();
    controller.setForgetAction((_view,options)=>attachedForget().approveAndForget(options));
    if(disposed)throw new TypeError('UNAVAILABLE: owner client disposed during attachment');
    requireConnection();
    return workflow;
   }catch(error){client.dispose();throw error;}
   finally{attaching=false;}
  },
  get workflow(){return disposed||ownsConnection()?workflow:undefined;},
  get forgetWorkflow(){return disposed||ownsConnection()?forgetWorkflow:undefined;},
  proposeSave:draft=>attached().proposeSave(draft),
  refresh:()=>attached().refresh(),
  recall:input=>attached().recall(input),
  getRecallSnapshot:()=>attached().getRecallSnapshot(),
  // Call inside the browser composition's own effect, only after native
  // primeAuthority connection and attach(). This does not connect, authenticate
  // or supply capability evidence; B still checks the current owner session.
  providePilotMemory(scope){
   attached();
   if(scope?.primeOwnerUi!==controller||typeof scope?.reflect?.provide!=='function')throw new TypeError('UNAVAILABLE: matching native owner UI scope required');
   if(pilotRegistration)throw new TypeError('UNAVAILABLE: pilot memory projection already provided');
   let remove,active=true,providing=true,removing=false;
   const release=()=>{
    active=false;
    // Reentrant disposal cannot relinquish ownership before native provision
    // returns its remover, or while a remover that may fail is still running.
    if(providing||removing)return;
    if(remove){removing=true;try{remove();remove=undefined;}finally{removing=false;}}
    if(pilotRegistration===release)pilotRegistration=undefined;
   };
   pilotRegistration=release;
   try {
    const disposer=scope.reflect.provide('primePilotMemory',Object.freeze({ownerController:controller,client}));
    if(typeof disposer!=='function')throw new TypeError('UNAVAILABLE: owned pilot projection disposer required');
    remove=disposer;providing=false;
    // Native service observers may dispose the client during provision.
    if(!active||disposed)release();
    return release;
   } catch(error){providing=false;release();throw error;}
  },
  // An explicit call after a fresh authenticated binding. Recovery reads C/D
  // facts and may deliver an already committed receipt; never replays an effect.
  recover:async input=>{
   const owner=controller.getSnapshot().owner;
   const snapshot=await attached().recover(input);
   // B accepts only the exact retained, already approved operation and its
   // completed receipt. A null result keeps its unresolved-action fence.
   recoveryCurrent(owner);await controller.reconcileApprovalAction(snapshot);recoveryCurrent(owner);
   return snapshot;
  },
  proposeForget:input=>attachedForget().proposeForget(input),
  approveAndForget:()=>{
   attachedForget();
   if(controller.getSnapshot().presentation?.operation?.action_type!=='memory.forget')throw new TypeError('UNAVAILABLE: exact logical-forget review required');
   return controller.submitApproval();
  },
  recoverForget:async input=>{
   const owner=controller.getSnapshot().owner;
   const snapshot=await attachedForget().recover(input);
   recoveryCurrent(owner);await controller.reconcileApprovalAction(snapshot);recoveryCurrent(owner);
   return snapshot;
  },
  setCapabilities:value=>{attached();controller.setCapabilities(value);},
  capabilitiesUnavailable:()=>{attached();controller.capabilitiesUnavailable();},
  logout:()=>attached().logout(),
  dispose(){if(disposed){pilotRegistration?.();return;}disposed=true;
   // Remove B's read projection before disposing its stores or owner binding.
   try{pilotRegistration?.();}
   finally{
    try{if(workflow){workflow.dispose();forgetWorkflow?.dispose();off?.();revoke();
     // Each hook clear may synchronously establish another binding. Old
     // teardown must neither clear that binding's hooks nor disconnect it.
     if(ownsConnection())controller.setApprovalAction(null);
     if(ownsConnection())controller.setForgetAction(null);
     if(ownsConnection())controller.disconnect();}}
    finally{off?.();revoke();}
   }
  },
 });
 return client;
}
