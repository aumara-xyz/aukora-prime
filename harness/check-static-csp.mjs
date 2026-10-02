import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {readFile,mkdtemp,mkdir,writeFile,rm,realpath} from 'node:fs/promises'
import {dirname,join,resolve} from 'node:path'
import {tmpdir} from 'node:os'
import {fileURLToPath} from 'node:url'
import {buildStaticHtmlCsp,graphStaticCsp,selectedStaticHtml,createPrimeStaticAppHandler} from './static-csp.mjs'
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),ui=join(root,'packages/ui')
const manifest=JSON.parse(await readFile(join(ui,'baseline-manifest.json'),'utf8'))
const source=join(ui,'faces/apps'),temporary=await realpath(await mkdtemp(join(tmpdir(),'prime-static-csp-')))
const sha=bytes=>createHash('sha256').update(bytes).digest('hex')
const refused=reason=>error=>error.code==='PRIME_STATIC_CSP'&&error.reason===reason
let assertions=0
try{
 let donorCalls=0
 const served=[]
 const handler=createPrimeStaticAppHandler({route:{handler:async(req,res)=>{donorCalls++;res.writeHead(200);res.end('preserved donor bytes')}},policies:{'/stock-apps/human-graph/index.html':graphStaticCsp}})
 async function request(url,method='GET'){const response={headers:{},setHeader(name,value){this.headers[name]=value},writeHead(status,headers={}){this.status=status;Object.assign(this.headers,headers)},end(body){this.body=body}};await handler({url,method},response);served.push(response);return response}
 for(const path of ['/stock-apps/auma-lingwa.html','/app/auma/auma.js','/stock-apps/auma-live.html','/stock-apps/auma-live.html?mode=voice','/stock-apps/auma%2dlive.html','/app/aumalive.js','/app/aumalive-audio.js','/app/aumalive-duplex.js']){
  const response=await request(path);assert.equal(response.status,503);assert.equal(JSON.parse(response.body).error_code,'UNAVAILABLE');assert.equal(donorCalls,0);assert.equal(response.headers['x-content-type-options'],'nosniff');assert.ok(response.headers['content-security-policy'].includes("default-src 'none'"));assertions+=5
 }
 const head=await request('/stock-apps/auma-live.html','HEAD');assert.equal(head.status,503);assert.equal(head.body,undefined);assert.equal(donorCalls,0);assertions+=3
 const normal=await request('/stock-apps/human-graph/index.html');assert.equal(normal.status,200);assert.equal(normal.body,'preserved donor bytes');assert.equal(normal.headers['content-security-policy'],graphStaticCsp);assert.equal(donorCalls,1);assertions+=4
 const invalid=await request('/%zz');assert.equal(invalid.status,400);assert.equal(donorCalls,1);assertions+=2
 const actual=await buildStaticHtmlCsp({manifest,appRoot:source})
 assert.equal(Object.keys(actual).length,6);assertions++
 for(const [route,path] of Object.entries(selectedStaticHtml)){
  const html=await readFile(join(source,path),'utf8'),policy=actual[route]
  assert.ok(policy.startsWith("default-src 'none';"));assertions++
  const scripts=policy.split(';').filter(directive=>directive.trim().startsWith('script-src'))
  assert.ok(scripts.every(directive=>!directive.includes("'unsafe-inline'")&&!directive.includes("'unsafe-eval'")));assertions++
  assert.ok(!/https?:|\*|blob:/.test(policy));assertions++
  for(const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)){
   if(/\bsrc\s*=/.test(match[1]))continue
   const hash=createHash('sha256').update(match[2],'utf8').digest('base64')
   assert.ok(policy.includes(`'sha256-${hash}'`));assertions++
  }
  await mkdir(dirname(join(temporary,path)),{recursive:true});await writeFile(join(temporary,path),html)
 }
 assert.equal(actual['/stock-apps/human-graph/index.html'],graphStaticCsp);assertions++
 assert.ok(!actual['/stock-apps/human-graph/index.html'].includes('unsafe-inline'));assertions++
 const foldRoute='/stock-apps/zeta-harp/fold.html',foldPath=selectedStaticHtml[foldRoute],foldHtml=await readFile(join(source,foldPath),'utf8')
 const foldScripts=[...foldHtml.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)]
 assert.equal(foldScripts.length,2);assertions++
 assert.ok(foldScripts.every(match=>!match[1].includes('src')));assertions++
 assert.ok(foldHtml.includes('href="https://github.com/aumara-xyz/zeta-harp"'));assertions++
 const foldHashes=foldScripts.map(match=>`'sha256-${createHash('sha256').update(match[2],'utf8').digest('base64')}'`)
 assert.equal(actual[foldRoute].split(';').find(directive=>directive.trim().startsWith('script-src ')).trim(),"script-src 'self' "+foldHashes.join(' '));assertions++
 const missingFold=structuredClone(manifest);missingFold.files=missingFold.files.filter(item=>item.path!=='faces/apps/'+foldPath)
 await assert.rejects(buildStaticHtmlCsp({manifest:missingFold,appRoot:temporary}),refused('served-html-coverage'));assertions++
 const extraHtml=structuredClone(manifest);extraHtml.files.push({...extraHtml.files.find(item=>item.path==='faces/apps/'+foldPath),path:'faces/apps/vendor/zeta-harp/extra.html'})
 await assert.rejects(buildStaticHtmlCsp({manifest:extraHtml,appRoot:temporary}),refused('served-html-coverage'));assertions++
 async function foldRefusal(html,reason){const bytes=Buffer.from(html),fixture=structuredClone(manifest),entry=fixture.files.find(item=>item.path==='faces/apps/'+foldPath);entry.bytes=bytes.length;entry.sha256=sha(bytes);await writeFile(join(temporary,foldPath),bytes);await assert.rejects(buildStaticHtmlCsp({manifest:fixture,appRoot:temporary}),refused(reason));assertions++;await writeFile(join(temporary,foldPath),foldHtml)}
 await foldRefusal(foldHtml.replace('</head>','<script src="https://github.com/aumara-xyz/zeta-harp"></script></head>'),'external-resource-refused')
 await foldRefusal(foldHtml.replace('</head>','<iframe src="https://github.com/aumara-xyz/zeta-harp"></iframe></head>'),'embedded-resource-unhandled')
 await foldRefusal(foldHtml.replace('href="https://github.com/aumara-xyz/zeta-harp"','href="https://external.invalid/"'),'external-resource-refused')
 const path=selectedStaticHtml['/stock-apps/auma-lingwa.html'],file=join(temporary,path),original=await readFile(file)
 await writeFile(file,Buffer.concat([original,Buffer.from('\n<!-- tampered -->')]))
 await assert.rejects(buildStaticHtmlCsp({manifest,appRoot:temporary}),refused('baseline-changed'));assertions++
 async function fixtureRefusal(html,reason){const bytes=Buffer.from(html),fixture=structuredClone(manifest),entry=fixture.files.find(item=>item.path==='faces/apps/'+path);entry.bytes=bytes.length;entry.sha256=sha(bytes);await writeFile(file,bytes);await assert.rejects(buildStaticHtmlCsp({manifest:fixture,appRoot:temporary}),refused(reason));assertions++}
 await fixtureRefusal(original.toString().replace('<main ','<main onclick="alert(1)" '),'inline-event-handler-refused')
 await fixtureRefusal(original.toString().replace("'/app/auma/auma.js'","'https://external.invalid/app.js'").replace('</head>','<script src="https://external.invalid/code.js"></script></head>'),'external-resource-refused')
 await fixtureRefusal(original.toString().replace('<main ','<main oncl&#105;ck="alert(1)" '),'html-attribute-unhandled')
 await fixtureRefusal(original.toString().replace('</head>','<script src="&#104;ttps://external.invalid/code.js"></script></head>'),'external-resource-refused')
 console.log(JSON.stringify({result:'PASS',assertions,verified_html_routes:6,literal_inline_scripts_hashed:4,exact_fold_document_link_preserved:true,script_unsafe_inline:false,script_unsafe_eval:false,graph_policy_unchanged:true,live_voice_page:'UNAVAILABLE_BEFORE_DONOR_HANDLER',browser_parity:'UNPERFORMED'}))
}finally{await rm(temporary,{recursive:true,force:true})}
