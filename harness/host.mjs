import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
import {apply as registerWelcomeSettings} from '../packages/client/ui-settings-general/lib/index.js';
import {createStaticAppRoutes} from '../prime-packages/ui/adapters/static-assets.mjs';
import {buildStaticHtmlCsp,createPrimeStaticAppHandler} from './static-csp.mjs';
import {providerCatalog,providerNamespace,mountDshCatalog} from '../prime-packages/inference/src/provider-settings.mjs';
import {providerNamespaceView} from '../prime-packages/ui/adapters/provider-settings.mjs';
import * as contracts from '../prime-packages/contracts/src/runtime.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const Schema=createRequire(resolve(root,'packages/api/settings-controller/package.json'))('@deepseek-ai/schemastery');
export function apply(ctx){
 registerWelcomeSettings(ctx);
 ctx.inject(['llm','settings'],host=>{
  mountDshCatalog(host);
  const view=providerNamespaceView(providerNamespace(),{Schema,contracts});
  host.settings.register(view.ns,new Schema(view.schema),{base:view.base,applies:'live'});
 });
 ctx.inject(['webServer','connection'], web=>{
  const guarded=work=>async(req,res)=>{
   const reject=web.connection?.requestRejection?.(req);
   if(!web.connection||typeof web.connection.requestRejection!=='function'||reject!==undefined){res.writeHead(reject??403);res.end();return;}
   await work(req,res);
  };
  const send=(res,status,body)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(body));};
  const release=JSON.parse(readFileSync(resolve(root,'prime-release.json')));
  web.effect(()=>web.webServer.register({kind:'exact',path:'/api/prime/capabilities',handler:guarded((req,res)=>{
   if(req.method!=='GET'){send(res,405,{ok:false,error_code:'INVALID'});return;}
   send(res,200,{version:1,source_commit:release.source_commit,runtime_pid:process.pid,release_digest:'sha256:'+process.env.PRIME_RELEASE_DIGEST,unavailable_capabilities:release.unavailable_capabilities,phase:'disposable-preview',qualification:'PENDING'});
  })}),'prime observed preview capabilities');
  web.effect(()=>web.webServer.register({kind:'exact',path:'/api/prime/inference/catalog',handler:guarded((req,res)=>{
   if(req.method!=='GET'){send(res,405,{ok:false,error_code:'INVALID'});return;}
   send(res,200,providerCatalog());
  })}),'prime unavailable provider read catalog');
  for(const filename of ['browser.mjs','shared.mjs','json.mjs'])web.effect(()=>web.webServer.register({kind:'exact',path:'/prime/contracts/'+filename,handler:guarded((req,res)=>{
   if(!['GET','HEAD'].includes(req.method)){send(res,405,{ok:false,error_code:'INVALID'});return;}
   res.writeHead(200,{'content-type':'text/javascript; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});
   res.end(req.method==='HEAD'?undefined:readFileSync(resolve(root,'prime-packages/contracts/src',filename)));
  })}),'prime closed browser contracts');
  for(const path of ['/api/kira','/aukora-messages','/aukora-documents'])web.effect(()=>web.webServer.register({kind:'prefix',path,handler:guarded((req,res)=>send(res,503,{ok:false,error_code:'UNAVAILABLE',reason:'Prime owner service join not qualified'}))}),'prime retained service refusal');
  web.effect(()=>web.webServer.register({kind:'prefix',path:'/api/prime',handler:guarded((req,res)=>send(res,503,{ok:false,error_code:'UNAVAILABLE',reason:'Owner passkey verifier/enrollment, broker boundary and service composition pending'}))}),'prime owner route');
  web.effect(()=>web.webServer.register({kind:'prefix',path:'/api/aukora',handler:guarded((req,res)=>send(res,503,{ok:false,error_code:'UNAVAILABLE',reason:'Prime backend capability not configured'}))}),'prime retained route refusal');
  web.effect(()=>web.webServer.register({kind:'prefix',path:'/api/auma-live',handler:guarded((req,res)=>send(res,503,{ok:false,error_code:'UNAVAILABLE',reason:'Embedded live runtime not configured'}))}),'prime embedded runtime refusal');
  web.effect(async()=>{
   const manifest=JSON.parse(readFileSync(resolve(root,'prime-packages/ui/baseline-manifest.json')));
   const appRoot=resolve(root,'plugins/aukora-face-apps');
   const routes=await createStaticAppRoutes({appRoot,manifest});
   const policies=await buildStaticHtmlCsp({appRoot,manifest});
   const disposers=routes.map(route=>web.webServer.register({...route,handler:guarded(createPrimeStaticAppHandler({route,policies}))}));
   return ()=>{for(const dispose of disposers)dispose();};
  },'prime frozen embedded Apps routes');
 });
}
