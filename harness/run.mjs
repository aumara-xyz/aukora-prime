import {readFileSync,realpathSync} from 'node:fs';
import {resolve,dirname,relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {assertEntrySet} from './composition-policy.mjs';
import {privateDirectory,writePrivateJson} from './private-state.mjs';
import {pathToFileURL} from 'node:url';
import {verifyReleaseUi} from './release-integrity.mjs';
import {readPreviewDeploymentManifest} from './deployment-manifest.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const anchor=readPreviewDeploymentManifest({manifestPath:process.argv[4],releaseRoot:root,expectedManifestSha256:process.argv[5]});
const expected=anchor.manifest.release_digest;
const {fullTreeDigest}=await import(pathToFileURL(process.argv[6]));
if((await fullTreeDigest(root)).digest!==expected)throw new Error('PRIME_RELEASE_DIGEST_MISMATCH');
await verifyReleaseUi({releaseRoot:root,expectedSnapshotSha256:anchor.manifest.ui_integrity_sha256});
const {boot}=await import('../packages/boot/app-boot/lib/index.js');
const {provideCmdline}=await import('../packages/boot/cmdline/lib/index.js');
const {createLaunchEnvironmentSnapshot,DSH_LAUNCH_ENVIRONMENT_KEY}=await import('../packages/util/launch-environment/lib/index.js');
const {default:PrimeShell}=await import('./shell-unavailable.mjs');
const state=privateDirectory(process.argv[2]);
const port=Number(process.argv[3]);if(!Number.isSafeInteger(port)||port<1||port>65535)throw new Error('INVALID_PORT');
const composition=JSON.parse(readFileSync(resolve(root,'prime-composition.json')));
if(composition.version!==1||composition.hmr!==false||composition.user_config_sources.length||composition.shell!=='prime-shell')throw new Error('PRIME_COMPOSITION_REFUSED');
assertEntrySet(composition.entries);
for(const item of composition.inputs){const path=resolve(root,item.path),physical=realpathSync(path);if(relative(root,physical).startsWith('..')||createHash('sha256').update(readFileSync(path)).digest('hex')!==item.sha256)throw new Error('PRIME_PLUGIN_BYTES_CHANGED');}
const expand=value=>{
 if(Array.isArray(value))return value.map(expand);
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,expand(v)]));
 if(value==='$PRIME_PORT')return port;
 if(typeof value==='string'&&value.startsWith('$PRIME_STATE/'))return resolve(state,value.slice(13));
 return value;
};
const entries=expand(composition.entries);
// Absolute resolved module paths remove every home/workspace/package fallback source.
for(const e of entries)e.name=resolve(root,composition.inputs.find(i=>i.id===e.id).path);
const config=resolve(state,'composition.json');writePrivateJson(config,entries);
let ctx;
const exit=async code=>{await ctx?.fiber.dispose();process.exitCode=code;};
ctx=await boot('prime',config,[],host=>{
 host.provide(DSH_LAUNCH_ENVIRONMENT_KEY,createLaunchEnvironmentSnapshot([{source:'process',values:{...process.env}}]));
 provideCmdline(host,{args:[],exit});
});
const actual=[...ctx.loader.entries()].filter(e=>e.options.id!=='include');
const expectedEntries=new Map(entries.map(e=>[e.id,e.name]));
if(actual.length!==entries.length||actual.some(e=>expectedEntries.get(e.options.id)!==e.options.name)||!(ctx.get('shell') instanceof PrimeShell)||ctx.get('hmr')||ctx.get('subprocess')){await ctx.fiber.dispose();throw new Error('PRIME_RUNTIME_PLUGIN_SET_REFUSED');}
const create=ctx.loader.create.bind(ctx.loader);
ctx.loader.create=async options=>{if(expectedEntries.get(options.id)!==options.name)throw new Error('PRIME_DYNAMIC_PLUGIN_REFUSED');return create(options);};
if(!ctx.get('connection')||!ctx.get('webServer'))throw new Error('PRIME_UI_SERVICES_MISSING');
const origin=`http://127.0.0.1:${ctx.webServer.port}/`;
if(!process.send)throw new Error('PRIVATE_READY_CHANNEL_REQUIRED');
process.send({type:'prime-ready',url:ctx.connection.authenticatedUrl(origin),pid:process.pid});
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{void exit(0);});
