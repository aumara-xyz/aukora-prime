import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createHash} from 'node:crypto'
import {runInNewContext} from 'node:vm'
import {fileURLToPath} from 'node:url'
import {foundationFileRecords,verifyFoundationAdaptation} from '../../../harness/release-integrity.mjs'
const root=new URL('../foundation/',import.meta.url)
const manifest=JSON.parse(await readFile(new URL('prime-import-manifest.json',root),'utf8'))
const sha=bytes=>createHash('sha256').update(bytes).digest('hex')
for(const item of foundationFileRecords(manifest)){const bytes=await readFile(new URL(item.path,root));assert.equal(bytes.length,item.bytes);assert.equal(sha(bytes),item.sha256)}
assert.equal(manifest.copied_exact.length,6)
assert.equal(manifest.adapted.length,1)
await verifyFoundationAdaptation({foundationRoot:fileURLToPath(root),manifest})
const donorReceipt=JSON.parse(await readFile(new URL('lib/build-manifest.json',root),'utf8'))
assert.equal(sha(await readFile(new URL('lib/client.js',root))),donorReceipt.outputs['lib/client.js'])
assert.equal(sha(await readFile(new URL('src/client/index.tsx',root))),donorReceipt.source['src/client/index.tsx'])
await readFile(new URL('licenses/genesis/LICENSE',root));await readFile(new URL('licenses/genesis/NOTICE',root))
let factory,override
runInNewContext(await readFile(new URL('lib/client.js',root),'utf8'),{window:{__ModuleLoader__:{load:entry=>{assert.equal(entry.id,manifest.client_id);factory=entry.factory}}}})
const client=factory(name=>{assert.equal(name,'react/jsx-runtime');return {jsx:()=>null}})
assert.deepEqual([...client.inject],['slots','theme'])
const ctx={slots:{inject:(_name,callback)=>{const result=callback();if(result?.[Symbol.iterator])for(const unused of result)void unused},register:()=>()=>{}},effect:callback=>callback(),theme:{overrideTokens:(name,tokens)=>{override={name,tokens};return ()=>{}}}}
client.apply(ctx)
assert.equal(override.name,'@aukora/dsh-plugin-foundation')
for(const [token,value] of Object.entries({'--dsw-alias-bg-base':'#111520','--dsw-alias-bg-layer-1':'#1B1F2A','--dsw-alias-bg-layer-2':'#1F232E','--dsw-alias-bg-layer-3':'#252834'}))assert.equal(override.tokens[token].dark,value)
const host=await import(new URL('lib/index.js',root));assert.equal(host.apply(),undefined)
console.log(JSON.stringify({result:'PASS',exact_files:manifest.copied_exact.length,adapted_files:manifest.adapted.length,adaptation:'license-only; original donor bytes verified',donor:manifest.commit,native_theme_registration:true,host_effects:false,build_qualification:'historical donor receipt; no new compilation',runtime_render:'PENDING H composition'}))
