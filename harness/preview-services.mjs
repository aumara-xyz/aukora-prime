// Restricted first-party adapters; no environment credentials, YAML, file intake or host spawning.
import {CredentialProvider} from '../packages/credentials/credentials/lib/index.js';
import {SettingsProvider} from '../packages/settings/settings/lib/index.js';
import {TypertGatewayService} from '../packages/api/gateway/lib/index.js';
import {Service} from '../vendor/cordis/lib/index.js';
const unavailable=()=>{throw Object.assign(new Error('UNAVAILABLE: preview capability not qualified'),{code:'UNAVAILABLE'});};
const browserKey='client-connection/browser-session';
export class PreviewCredentials extends CredentialProvider {
 #record;
 resolve(){return Promise.resolve(undefined);}
 describe(){return Promise.resolve({configured:false,writable:false});}
 set(){return unavailable();} unset(){return unavailable();}
 readRecord=key=>{if(key!==browserKey)return unavailable();return Promise.resolve(structuredClone(this.#record));};
 describeRecord(){return unavailable();}listRecords(){return unavailable();}deleteRecord(){return unavailable();}
 modifyRecord=async(key,mutate)=>{if(key!==browserKey||this.#record!==undefined)return unavailable();const next=await mutate(undefined);if(next?.kind!=='grant'||next?.payload?.version!==1||typeof next.payload.secret!=='string')return unavailable();this.#record=structuredClone(next);return structuredClone(this.#record);};
}
export class PreviewSettings extends SettingsProvider {
 writable=true;#document={};
 load=()=>Promise.resolve(structuredClone(this.#document));
 persist=(ns,section)=>{if(!['ui-onboarding','ui-theme','locale'].includes(ns))return unavailable();this.#document[ns]=structuredClone(section);return Promise.resolve();};
}
export class UnavailableUploads extends Service {
 constructor(ctx){super(ctx,'fileUploads');}
 registerAgentResolver(){return ()=>{};}
 resolve(){return unavailable();}bindPrompt(){return unavailable();}retirePrompt(){return unavailable();}
}
export const previewReads=new Set(['session/list','session/search','session/modelCatalog','session/page','session/canOpenWorkspacePath','settings/describe','settings/canOpenAgentPresetDirectory','settings/canOpenDocument','llm/listProviders','llm/listConfigurableProviders','credentials/describe']);
export function previewRpcAllowed(endpoint,payload) {
 if(previewReads.has(endpoint))return true;
 if(endpoint==='settings/update')return ['ui-onboarding','ui-theme','locale'].includes(payload?.ns);
 return false;
}
export class PreviewGateway extends TypertGatewayService {
 dispatchRpc(endpoint,payload,signal){if(!previewRpcAllowed(endpoint,payload))return Promise.resolve({ok:false,error:{code:'UNAVAILABLE',message:'Prime preview effect route is unavailable',details:{}}});return super.dispatchRpc(endpoint,payload,signal);}
 openWireStream(endpoint,payload,signal){if(!['$events','session/control','session/follow'].includes(endpoint))return unavailable();return super.openWireStream(endpoint,payload,signal);}
}
