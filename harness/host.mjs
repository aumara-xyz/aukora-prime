import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {apply as registerWelcomeSettings} from '../packages/client/ui-settings-general/lib/index.js';
import {createStaticAppRoutes} from '../prime-packages/ui/adapters/static-assets.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
export function apply(ctx){
 registerWelcomeSettings(ctx);
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
   const routes=await createStaticAppRoutes({appRoot:resolve(root,'plugins/aukora-face-apps'),manifest});
   const disposers=routes.map(route=>web.webServer.register({...route,handler:guarded(route.handler)}));
   return ()=>{for(const dispose of disposers)dispose();};
  },'prime frozen embedded Apps routes');
 });
}
