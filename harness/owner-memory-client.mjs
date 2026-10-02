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
export function createOwnerMemoryClient({controller,contracts,ownerBinding,fetcher,passkeySigner}={}) {
 if(['connect','getSnapshot','subscribe','setApprovalAction','setForgetAction','logout','disconnect','setCapabilities','capabilitiesUnavailable'].some(name=>typeof controller?.[name]!=='function'))throw new TypeError('UNAVAILABLE: native owner controller required');
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
 let disposed=false,workflow,forgetWorkflow,off;
 const attached=()=>{if(disposed||!workflow)throw new TypeError('UNAVAILABLE: owner client is not attached');return workflow;};
 const attachedForget=()=>{attached();return forgetWorkflow;};
 return Object.freeze({
  binding,
  // Native composition first provides binding as Cordis primeAuthority, waits
  // for B's controller.connect, and then attaches. Its supplied flag prevents
  // the default async HTTP binding from reconnecting and clearing this hook.
  attach(){if(disposed)throw new TypeError('UNAVAILABLE: owner client disposed');if(workflow)return workflow;
   if(controller.getSnapshot().owner_id!==binding.owner_id)throw new TypeError('UNAVAILABLE: native owner binding must connect before attach');
   workflow=createOwnerMemoryWorkflow({controller,memory,contracts});
   forgetWorkflow=createOwnerForgetWorkflow({controller,memory,contracts});
   off=controller.subscribe(()=>{const state=controller.getSnapshot();
    // Also fences a logout before a pending login has established an owner.
    if(!state.owner&&['logged_out','unavailable','expired'].includes(state.phase))revoke();
   });
   controller.setApprovalAction(()=>workflow.approveAndSave());
   controller.setForgetAction(()=>forgetWorkflow.approveAndForget());return workflow;
  },
  get workflow(){return workflow;},
  get forgetWorkflow(){return forgetWorkflow;},
  proposeSave:draft=>attached().proposeSave(draft),
  refresh:()=>attached().refresh(),
  // An explicit call after a fresh authenticated binding. Recovery reads C/D
  // facts and may deliver an already committed receipt; never replays an effect.
  recover:input=>attached().recover(input),
  proposeForget:input=>attachedForget().proposeForget(input),
  approveAndForget:()=>attachedForget().approveAndForget(),
  recoverForget:input=>attachedForget().recover(input),
  setCapabilities:value=>{attached();controller.setCapabilities(value);},
  capabilitiesUnavailable:()=>{attached();controller.capabilitiesUnavailable();},
  logout:()=>attached().logout(),
  dispose(){if(disposed)return;disposed=true;
   try{if(workflow){workflow.dispose();forgetWorkflow.dispose();off?.();revoke();controller.setApprovalAction(null);controller.setForgetAction(null);controller.disconnect();}}
   finally{off?.();revoke();}
  },
 });
}
