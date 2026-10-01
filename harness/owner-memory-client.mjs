// SPDX-License-Identifier: AGPL-3.0-or-later
// Unmounted browser composition for the separate native owner controller.
// These two own-package imports are rewritten to prime-packages by compose.py.
import {createUiAdapters} from '../packages/runtime-bridge/src/ui-adapter.mjs';
import {createOwnerMemoryWorkflow} from '../packages/runtime-bridge/src/owner-memory-workflow.mjs';
import {createOwnerMemoryHttpCall} from './owner-memory-browser.mjs';

/** The owner binding and signer are trusted composition inputs. This factory
 * creates no identity, credential, session, listener or accepted host record.
 * Existing capability status must separately enable the native controller. */
export function createOwnerMemoryClient({controller,contracts,ownerBinding,fetcher,passkeySigner}={}) {
 if(['connect','getSnapshot','subscribe','setApprovalAction','logout','disconnect','setCapabilities','capabilitiesUnavailable'].some(name=>typeof controller?.[name]!=='function'))throw new TypeError('UNAVAILABLE: native owner controller required');
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
 const binding=Object.freeze({...owner,authority:adapters.authority,contracts,loginKinds:Object.freeze(['passkey']),requiresCapabilities:true,
  ...(passkeySigner?{passkeySigner}:{})});
 let disposed=false,workflow,off;
 const attached=()=>{if(disposed||!workflow)throw new TypeError('UNAVAILABLE: owner client is not attached');return workflow;};
 return Object.freeze({
  binding,
  // Native composition first provides binding as Cordis primeAuthority, waits
  // for B's controller.connect, and then attaches. Its supplied flag prevents
  // the default async HTTP binding from reconnecting and clearing this hook.
  attach(){if(disposed)throw new TypeError('UNAVAILABLE: owner client disposed');if(workflow)return workflow;
   if(controller.getSnapshot().owner_id!==binding.owner_id)throw new TypeError('UNAVAILABLE: native owner binding must connect before attach');
   workflow=createOwnerMemoryWorkflow({controller,memory:adapters.memory,contracts});
   off=controller.subscribe(()=>{const state=controller.getSnapshot();
    // Also fences a logout before a pending login has established an owner.
    if(!state.owner&&['logged_out','unavailable','expired'].includes(state.phase))adapters.logout();
   });
   controller.setApprovalAction(()=>workflow.approveAndSave());return workflow;
  },
  get workflow(){return workflow;},
  proposeSave:draft=>attached().proposeSave(draft),
  refresh:()=>attached().refresh(),
  setCapabilities:value=>{attached();controller.setCapabilities(value);},
  capabilitiesUnavailable:()=>{attached();controller.capabilitiesUnavailable();},
  logout(){attached();controller.logout();adapters.logout();},
  dispose(){if(disposed)return;disposed=true;
   try{if(workflow){workflow.dispose();controller.setApprovalAction(null);controller.disconnect();}}
   finally{off?.();adapters.logout();}
  },
 });
}
