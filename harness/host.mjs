import {readFileSync, existsSync, realpathSync} from 'node:fs';
import {resolve,relative,extname,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {apply as registerWelcomeSettings} from '../packages/client/ui-settings-general/lib/index.js';
import {createStaticAppRoutes} from '../prime-packages/ui/adapters/static-assets.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const faces=['layout','sidebar','threads','apps','messages','memory','aumlok','documents','settings'];
const mime={'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.png':'image/png','.svg':'image/svg+xml','.woff2':'font/woff2'};
export function apply(ctx){
 registerWelcomeSettings(ctx);
 ctx.inject(['webServer','connection'], web=>{
  const guarded=work=>async(req,res)=>{
   const reject=web.connection?.requestRejection?.(req);
   if(!web.connection||typeof web.connection.requestRejection!=='function'||reject!==undefined){res.writeHead(reject??403);res.end();return;}
   await work(req,res);
  };
  const send=(res,status,body)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(body));};
  web.effect(()=>web.webServer.register({kind:'prefix',path:'/api/prime',handler:guarded((req,res)=>send(res,503,{ok:false,error_code:'UNAVAILABLE',reason:'Owner passkey verifier/enrollment, broker boundary and service composition pending'}))}),'prime owner route');
  web.effect(()=>web.webServer.register({kind:'prefix',path:'/api/aukora',handler:guarded((req,res)=>send(res,503,{ok:false,error_code:'UNAVAILABLE',reason:'Prime backend capability not configured'}))}),'prime retained route refusal');
  web.effect(()=>web.webServer.register({kind:'prefix',path:'/api/auma-live',handler:guarded((req,res)=>send(res,503,{ok:false,error_code:'UNAVAILABLE',reason:'Embedded live runtime not configured'}))}),'prime embedded runtime refusal');
  web.effect(async()=>{
   const manifest=JSON.parse(readFileSync(resolve(root,'prime-packages/ui/baseline-manifest.json')));
   const routes=await createStaticAppRoutes({appRoot:resolve(root,'plugins/aukora-face-apps'),manifest});
   const disposers=routes.map(route=>web.webServer.register({...route,handler:guarded(route.handler)}));
   return ()=>{for(const dispose of disposers)dispose();};
  },'prime frozen embedded Apps routes');
  web.effect(()=>web.webServer.register({kind:'prefix',path:'/aukora',handler:guarded((req,res)=>{
   let path;try{path=decodeURIComponent(new URL(req.url,'http://localhost').pathname)}catch{res.writeHead(400);res.end();return;}
   const match=/^\/aukora\/([^/]+)\/(.*)$/.exec(path);
   if(!match||!faces.includes(match[1])){res.writeHead(404);res.end();return;}
   const base=resolve(root,'plugins','aukora-face-'+match[1],'assets');
   const file=resolve(base,match[2]);
   if(relative(base,file).startsWith('..')||!existsSync(file)){res.writeHead(404);res.end();return;}
   if(relative(base,realpathSync(file)).startsWith('..')){res.writeHead(403);res.end();return;}
   if(!['GET','HEAD'].includes(req.method)){res.writeHead(405);res.end();return;}
   res.writeHead(200,{'content-type':mime[extname(file)]??'application/octet-stream','x-content-type-options':'nosniff'});
   res.end(req.method==='HEAD'?undefined:readFileSync(file));
  })}),'prime selected assets');
 });
}
