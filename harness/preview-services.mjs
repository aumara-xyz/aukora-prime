import {createRequire} from 'node:module';
import {installStrictGatewayWebSocketIngress} from './ingress.mjs';
import {parseStrictJson} from '../prime-packages/contracts/src/runtime.mjs';
// Restricted first-party adapters; no environment credentials, YAML, file intake or host spawning.
import {CredentialProvider} from '../packages/credentials/credentials/lib/index.js';
import {SettingsProvider} from '../packages/settings/settings/lib/index.js';
import {TypertGatewayService} from '../packages/api/gateway/lib/index.js';
import {Service} from '../vendor/cordis/lib/index.js';
import {resolvePilotCredential,describePilotCredential} from './deepseek-pilot.mjs';
const require=createRequire(new URL('../packages/api/gateway/package.json',import.meta.url));
installStrictGatewayWebSocketIngress(require('ws').WebSocketServer,parseStrictJson);
const unavailable=()=>{throw Object.assign(new Error('UNAVAILABLE: preview capability not qualified'),{code:'UNAVAILABLE'});};
const browserKey='client-connection/browser-session';
export class PreviewCredentials extends CredentialProvider {
 #record;
 resolve(ref){return Promise.resolve(resolvePilotCredential(ref));}
 describe(ref){return Promise.resolve(describePilotCredential(ref));}
 set(){return unavailable();} unset(){return unavailable();}
 readRecord=key=>{if(key!==browserKey)return unavailable();return Promise.resolve(structuredClone(this.#record));};
 describeRecord(){return unavailable();}listRecords(){return unavailable();}deleteRecord(){return unavailable();}
 modifyRecord=async(key,mutate)=>{if(key!==browserKey||this.#record!==undefined)return unavailable();const next=await mutate(undefined);if(next?.kind!=='grant'||next?.payload?.version!==1||typeof next.payload.secret!=='string')return unavailable();this.#record=structuredClone(next);return structuredClone(this.#record);};
}
export class PreviewSettings extends SettingsProvider {
 writable=true;#document={'ui-theme':{preference:'dark',fontSize:14}};
 load=()=>Promise.resolve(structuredClone(this.#document));
 persist=(ns,section)=>{
  if(!['ui-onboarding','ui-theme','locale','llm-deepseek','agent-default-model'].includes(ns))return unavailable();
  if(ns==='agent-default-model'&&(section.provider!=='deepseek-official'||section.model!=='deepseek-flash'||section.reasoningEffort!==undefined&&section.reasoningEffort!=='off'))return unavailable();
  if(ns==='llm-deepseek'){
   const fixed={protocol:'chat-completions',baseURL:'https://api.deepseek.com',apiKeyEnv:'DEEPSEEK_API_KEY',thinking:'disabled',reasoningEffort:'off'};
   for(const [key,value]of Object.entries(fixed))if(section[key]!==undefined&&section[key]!==value)return unavailable();
   if(section.maxTokens!==undefined&&(!Number.isSafeInteger(section.maxTokens)||section.maxTokens<1||section.maxTokens>1024))return unavailable();
   if(section.retryPolicy!==undefined&&(section.retryPolicy.mode!=='normal'||section.retryPolicy.maxRetries!==0))return unavailable();
   if(section.models!==undefined&&(!Array.isArray(section.models)||section.models.some(model=>model.id!=='deepseek-flash'||model.maxTokens!==undefined&&model.maxTokens>1024||model.inputModalities?.some(mode=>mode!=='text'))))return unavailable();
  }
  this.#document[ns]=structuredClone(section);return Promise.resolve();
 };
}
export class UnavailableUploads extends Service {
 constructor(ctx){super(ctx,'fileUploads');}
 registerAgentResolver(){return ()=>{};}
 resolve(){return unavailable();}
 bindPrompt(_agent,receiptIds){if(!Array.isArray(receiptIds)||receiptIds.length)return unavailable();return {commit(){},[Symbol.dispose](){}};}
 retirePrompt(){}
}
export const previewReads=new Set(['session/list','session/search','session/modelCatalog','session/page','session/canOpenWorkspacePath','settings/describe','settings/canOpenAgentPresetDirectory','settings/canOpenDocument','llm/listProviders','llm/listConfigurableProviders','credentials/describe']);
export function previewRpcAllowed(endpoint,payload) {
 if(previewReads.has(endpoint))return true;
 if(['session/create','session/selectModel','session/prompt','session/cancel','session/updateQueue','session/rename'].includes(endpoint))return true;
 if(['settings/update','settings/mutate'].includes(endpoint))return ['ui-onboarding','ui-theme','locale','llm-deepseek','agent-default-model'].includes(payload?.args?.ns);
 return false;
}
export class PreviewGateway extends TypertGatewayService {
 dispatchRpc(endpoint,payload,signal){if(!previewRpcAllowed(endpoint,payload))return Promise.resolve({ok:false,error:{code:'UNAVAILABLE',message:'Prime preview effect route is unavailable',details:{}}});return super.dispatchRpc(endpoint,payload,signal);}
 openWireStream(endpoint,payload,signal){if(!['$events','session/control','session/follow'].includes(endpoint))return unavailable();return super.openWireStream(endpoint,payload,signal);}
}
