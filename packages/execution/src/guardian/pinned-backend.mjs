// SPDX-License-Identifier: AGPL-3.0-or-later
import { refused } from '../policy.mjs'
/** Concrete pinned SDK observation. No delete/stop guess: public name-addressed
 * RPC cannot bind the caller's previously observed UID or terminalize create.
 * Metadata supplies no public original-create request corroboration either. */
export class PinnedGuardianBackend {
  constructor(transport,scope){this.transport=transport;this.scope=scope}
  async observe(registration,{signal}) {
    let token='';const seen=new Set(),sandboxes=[]
    for(let page=0;page<100;page++) {
      const result=await this.transport.inventory(this.scope,token,{signal})
      if(!Array.isArray(result.sandboxes)||typeof result.nextPageToken!=='string')throw refused('pinned guardian inventory incomplete','RECONCILIATION_REQUIRED')
      for(const sandbox of result.sandboxes)if(sandbox.metadata?.name===registration.name) {
        const m=sandbox.metadata
        sandboxes.push({uid:m.id,name:m.name,workspace:m.workspace,owner_token:m.labels?.['aukora.openshell/owner']??null,origin_request_id:null})
      }
      token=result.nextPageToken
      if(!token)return {sandboxes,inventory_complete:true}
      if(seen.has(token))throw refused('pinned guardian inventory cycle','RECONCILIATION_REQUIRED');seen.add(token)
    }
    throw refused('pinned guardian inventory bound exceeded','RECONCILIATION_REQUIRED')
  }
  async reclaim(){throw refused('pinned gateway has no caller-bound expected-UID reclamation or terminal late-create fence','UNAVAILABLE')}
}
