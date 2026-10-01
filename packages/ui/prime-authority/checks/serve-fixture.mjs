import {createServer} from 'node:http'
import {readFile,readdir} from 'node:fs/promises'
import {resolve,join,extname} from 'node:path'
const root=resolve(process.argv[2]),files=new Map()
async function load(directory,prefix=''){for(const item of await readdir(directory,{withFileTypes:true})){if(item.isSymbolicLink())throw new Error('Fixture symlink refused');const path=join(directory,item.name),route=prefix+'/'+item.name;if(item.isDirectory())await load(path,route);else if(item.isFile())files.set(route,await readFile(path))}}
await load(root);files.set('/',files.get('/index.html'))
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.json':'application/json'}
const server=createServer((req,res)=>{if(!['GET','HEAD'].includes(req.method)){res.writeHead(405);res.end();return}let path;try{path=decodeURIComponent(new URL(req.url,'http://fixture.local').pathname)}catch{res.writeHead(400);res.end();return}const body=files.get(path);if(!body){res.writeHead(404);res.end();return}res.writeHead(200,{'content-type':mime[extname(path)]??(path==='/'?'text/html; charset=utf-8':'application/octet-stream'),'cache-control':'no-store','x-content-type-options':'nosniff'});res.end(req.method==='HEAD'?undefined:body)})
server.listen(0,'127.0.0.1',()=>console.log(JSON.stringify({result:'DISPOSABLE_FIXTURE_RUNNING',pid:process.pid,url:'http://127.0.0.1:'+server.address().port+'/',real_credentials:false,effects:false})))
process.on('SIGTERM',()=>server.close(()=>process.exit(0)))
