import {createHash} from 'node:crypto'
import {constants} from 'node:fs'
import {lstat, open, readdir, realpath, writeFile} from 'node:fs/promises'
import {isAbsolute, join, resolve} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'

const DONOR='645d3213b8aede3b544269b4224ae09df06b0a42'
const DSH='0d1f50007f9bca3f52b06e1c3074fa14d5fb0720'
const LOCK='ca131858949bd12b2acfc227b1af7dfa3c8d65e74b234824d5c741e6421010a1'
const FACES=['layout','sidebar','threads','apps','messages','memory','aumlok','documents','settings']
const HEX=/^[a-f0-9]{64}$/
const fail=(reason,path='')=>{const error=new Error(`PRIME_UI_INTEGRITY:${reason}${path?':'+path:''}`);error.code='PRIME_UI_INTEGRITY';error.reason=reason;throw error}
const sha=bytes=>createHash('sha256').update(bytes).digest('hex')
function keys(value,required,optional=[]){if(!value||typeof value!=='object'||Array.isArray(value)||required.some(k=>!Object.hasOwn(value,k))||Object.keys(value).some(k=>!required.includes(k)&&!optional.includes(k)))fail('manifest-shape')}
function pathName(path){if(typeof path!=='string'||!path||isAbsolute(path)||path.includes('\\')||path.includes('\0')||path.split('/').some(p=>!p||p==='.'||p==='..'))fail('path-refused');return path}
function item(value){keys(value,['path','bytes','sha256'],['face','source_path','id','source','role','output_path']);pathName(value.path);if(!Number.isSafeInteger(value.bytes)||value.bytes<0||!HEX.test(value.sha256))fail('file-pin-invalid',value.path);return {path:value.path,bytes:value.bytes,sha256:value.sha256}}
function items(values){if(!Array.isArray(values)||!values.length||values.length>10000)fail('file-list-invalid');const result=values.map(item);if(new Set(result.map(x=>x.path)).size!==result.length)fail('duplicate-path');return result}
// A package-license adaptation carries current pins separately from original
// donor attribution. Historical exact-only manifests remain readable.
export function foundationFileRecords(manifest){
 const exact=items(manifest.copied_exact),adapted=manifest.adapted??[]
 if(!Array.isArray(adapted)||adapted.length>1)fail('foundation-adaptation-set')
 const records=[...exact]
 if(adapted.length){
  const adaptation=adapted[0]
  keys(adaptation,['path','bytes','sha256','kind','license','donor'])
  keys(adaptation.donor,['source_path','bytes','sha256'])
  if(adaptation.path!=='package.json'||adaptation.kind!=='owned-license-declaration'||adaptation.license!=='AGPL-3.0-or-later'
   ||adaptation.donor.source_path!=='plugins/aukora-foundation/package.json'||adaptation.donor.bytes!==808
   ||adaptation.donor.sha256!=='4c38609d2e1dae4f1032e24edd3a493c5c66e37c8f0a8e658458c51b0ed06337')fail('foundation-adaptation-pin')
  records.push(item({path:adaptation.path,bytes:adaptation.bytes,sha256:adaptation.sha256}))
 }
 if(JSON.stringify(records.map(x=>x.path).sort())!==JSON.stringify(['src/client/index.tsx','lib/client.js','lib/build-manifest.json','package.json','tsdown.config.ts','assets/AUMARA-FULL-TRANSPARENT-ICON.png','assets/AUMARA-ICON-96.png'].sort()))fail('foundation-file-set')
 return records
}
export async function verifyFoundationAdaptation({foundationRoot,manifest}){
 if(!manifest.adapted?.length)return
 const adaptation=manifest.adapted[0],bytes=await pinned(foundationRoot,item({path:adaptation.path,bytes:adaptation.bytes,sha256:adaptation.sha256}))
 const line='  "license": "AGPL-3.0-or-later",\n',text=bytes.toString('utf8')
 if(!Buffer.from(text).equals(bytes)||text.split(line).length!==2||json(bytes).license!==adaptation.license)fail('foundation-license-adaptation')
 const donorBytes=Buffer.from(text.replace(line,''))
 if(donorBytes.length!==adaptation.donor.bytes||sha(donorBytes)!==adaptation.donor.sha256)fail('foundation-license-adaptation')
}
async function rootPath(root){const path=resolve(root);if((await lstat(path)).isSymbolicLink())fail('root-symlink');return realpath(path)}
async function subRoot(root,path){pathName(path);let location=root;for(const part of path.split('/')){location=join(location,part);const stat=await lstat(location);if(stat.isSymbolicLink()||!stat.isDirectory())fail('directory-refused',path)}return location}
async function bytesAt(root,path){pathName(path);let location=root;for(const part of path.split('/')){location=join(location,part);if((await lstat(location)).isSymbolicLink())fail('file-symlink',path)}const before=await lstat(location);if(!before.isFile())fail('not-regular-file',path);const handle=await open(location,constants.O_RDONLY|constants.O_NOFOLLOW);try{const after=await handle.stat();if(!after.isFile()||before.dev!==after.dev||before.ino!==after.ino)fail('file-replaced',path);return await handle.readFile()}finally{await handle.close()}}
async function pinned(root,entry){const bytes=await bytesAt(root,entry.path);if(bytes.length!==entry.bytes||sha(bytes)!==entry.sha256)fail('file-changed',entry.path);return bytes}
async function pin(root,path){const bytes=await bytesAt(root,path);return {path,bytes:bytes.length,sha256:sha(bytes)}}
// Manifest JSON is bounded and duplicate keys are refused before JSON.parse.
function json(bytes){if(bytes.length>8388608)fail('manifest-too-large');const text=bytes.toString('utf8');if(!Buffer.from(text).equals(bytes))fail('manifest-utf8');let i=0;const ws=()=>{while(/\s/.test(text[i]??'')&&i<text.length)i++};function string(){const start=i++;while(i<text.length){const char=text[i++];if(char==='\\'){i++;continue}if(char==='"')return JSON.parse(text.slice(start,i))}fail('manifest-json')};function value(depth=0){if(depth>64)fail('manifest-depth');ws();if(text[i]==='"'){string();return}if(text[i]==='{'){i++;ws();const seen=new Set();if(text[i]==='}'){i++;return}while(true){ws();if(text[i]!=='"')fail('manifest-json');const name=string();if(seen.has(name))fail('manifest-duplicate-key');seen.add(name);ws();if(text[i++]!==':')fail('manifest-json');value(depth+1);ws();if(text[i]==='}'){i++;return}if(text[i++]!==',')fail('manifest-json')}}if(text[i]==='['){i++;ws();if(text[i]===']'){i++;return}while(true){value(depth+1);ws();if(text[i]===']'){i++;return}if(text[i++]!==',')fail('manifest-json')}}const match=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));if(!match)fail('manifest-json');i+=match[0].length}try{value();ws();if(i!==text.length)fail('manifest-json');return JSON.parse(text)}catch(error){if(error.code==='PRIME_UI_INTEGRITY')throw error;fail('manifest-json')}}
export function baselineFileRecords(manifest){
 const records=items(manifest.files),adaptations=manifest.source_adaptations??[]
 if(!Array.isArray(adaptations)||adaptations.length>1)fail('baseline-adaptation-set')
 const original=records.find(entry=>entry.path==='faces/apps/src/vendor/organism.ts')
 if(!adaptations.length&&original&&(original.bytes!==33076||original.sha256!=='a2c2de1e4599f68b01712cb2aaec0bf7d51bddd216326611030997fbaad61a6c'))fail('baseline-adaptation-missing')
 if(adaptations.length){
  const adaptation=adaptations[0]
  keys(adaptation,['path','kind','donor','current','scope','build_qualification'])
  keys(adaptation.donor,['bytes','sha256','git_blob_sha1']);keys(adaptation.current,['bytes','sha256'])
  if(adaptation.path!=='faces/apps/src/vendor/organism.ts'||adaptation.kind!=='private-comment-redaction'
   ||adaptation.donor.bytes!==33076||adaptation.donor.sha256!=='a2c2de1e4599f68b01712cb2aaec0bf7d51bddd216326611030997fbaad61a6c'
   ||adaptation.donor.git_blob_sha1!=='7000e803d7ddc9dbb8570f60bdf75e1537d717d5'
   ||adaptation.current.bytes!==32882||adaptation.current.sha256!=='e88fd0cfa5496aa02fe617b3a1ac039a94d4ae1889e36f298c27c0837817e810'
   ||typeof adaptation.scope!=='string'||!adaptation.scope||typeof adaptation.build_qualification!=='string'||!adaptation.build_qualification)fail('baseline-adaptation-pin')
  const current=records.find(entry=>entry.path===adaptation.path)
  if(!current||current.bytes!==adaptation.current.bytes||current.sha256!==adaptation.current.sha256
   ||manifest.files.find(entry=>entry.path===adaptation.path).role!=='source')fail('baseline-adaptation-binding')
 }
 return records
}
function servedFaces(manifest){if(manifest.schema_version!==1||manifest.commit!==DONOR||JSON.stringify(manifest.faces)!==JSON.stringify(FACES))fail('donor-pin');const all=baselineFileRecords(manifest);const served=all.filter(entry=>{const parts=entry.path.split('/');return parts[0]==='faces'&&FACES.includes(parts[1])&&['package.json','lib','assets','vendor'].includes(parts[2])});for(const face of FACES)if(!served.some(x=>x.path===`faces/${face}/lib/client.js`))fail('face-client-missing',face);return {all,served}}
function faceReleasePath(path){const [,face,...rest]=path.split('/');return `plugins/aukora-face-${face}/${rest.join('/')}`}
async function walk(root,prefix){await subRoot(root,prefix);const result=[];for(const dirent of await readdir(join(root,prefix),{withFileTypes:true})){const path=prefix+'/'+dirent.name;if(dirent.isSymbolicLink())fail('file-symlink',path);if(dirent.isDirectory())result.push(...await walk(root,path));else if(dirent.isFile())result.push(path);else fail('not-regular-file',path)}return result.sort()}
function sameList(left,right){return JSON.stringify(left.map(item).sort((a,b)=>a.path.localeCompare(b.path)))===JSON.stringify(right.map(item).sort((a,b)=>a.path.localeCompare(b.path)))}
const OWNER_ID='@aukora/prime-authority-ui'
// Exact reviewed B df7d173 generated input, reproduced by B 8237dc9 and H.
// Keep an independent runtime pin: receipt fields never choose this configuration.
const OWNER_CONFIG= String.raw`import { clientBundle } from '../tsdown.client.ts'
import { readFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { basename, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
const { transform } = createRequire(new URL('../tsdown.client.ts', import.meta.url))('lightningcss')
const id = ${JSON.stringify(OWNER_ID)}
const ownerRoot = dirname(fileURLToPath(import.meta.url))
const projectRoot = resolve(ownerRoot, '../../..')
const ownedCss = new Set(['OwnerSurface.module.css', 'PrimeProviderEditor.module.css']
  .map(name => resolve(ownerRoot, 'src/client', name)))
const prefix = '\0dsh-css:'
const suffix = '.mjs'
// Style injector and sorted class map follow the pinned DSH MIT preset
// packages/client/tsdown.client.ts at 0d1f50007f9bca3f52b06e1c3074fa14d5fb0720.
// Prime preserves its notice in licenses/DSH-MIT-LICENSE.
function styleModule(fileId, css, classMap) {
  return [
    'const css = ' + JSON.stringify(css) + ';',
    'const tagId = ' + JSON.stringify(id + '/' + basename(fileId)) + ';',
    'if (typeof document !== \'undefined\' && document.querySelector(\'style[data-plugin-css=\' + JSON.stringify(tagId) + \']\') === null) {',
    '  const tag = document.createElement(\'style\');',
    '  tag.dataset.plugin = ' + JSON.stringify(id) + ';',
    '  tag.dataset.pluginCss = tagId;',
    '  tag.textContent = css;',
    '  document.head.appendChild(tag);',
    '}',
    'export default ' + JSON.stringify(classMap) + ';',
  ].join('\n')
}
const upstream = clientBundle(id, [], { hostPhase: true })
export default options => upstream(options).map(config => {
  if (config.name !== id + '/client') return config
  const matches = config.plugins.filter(plugin => plugin?.name === 'dsh-css-modules-inline')
  if (matches.length !== 1 || typeof matches[0].load !== 'function') throw new Error('ui-build:css-preset-shape-mismatch')
  const original = matches[0]
  return { ...config, plugins: config.plugins.map(plugin => plugin !== original ? plugin : {
    ...plugin,
    async load(virtualId) {
      const fileId = virtualId.startsWith(prefix) && virtualId.endsWith(suffix)
        ? virtualId.slice(prefix.length, -suffix.length) : null
      if (!ownedCss.has(fileId)) return original.load.call(this, virtualId)
      this.addWatchFile(fileId)
      const { code, exports: cssExports } = transform({
        filename: fileId, projectRoot, code: await readFile(fileId),
        cssModules: { pattern: '[hash]_[local]' }, minify: true,
      })
      const classMap = {}
      const exportEntries = Object.entries(cssExports ?? {})
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      for (const [local, exp] of exportEntries) classMap[local] = exp.name
      return styleModule(fileId, code.toString(), classMap)
    },
  }) }
})
`
const HARNESS_IDENTITY_PATH='.dsh-build/pinned-harness-identity.json'
const HARNESS_IDENTITY_ALGORITHM='aukora-prime:pinned-harness-identity:v1'
const HARNESS_IDENTITY_DOMAIN='aukora-prime.pinned-harness-identity.v1\0'
const BUILD_PATHS=['pnpm-lock.yaml','tsconfig.base.json','tsconfig.base.client.json','packages/client/tsdown.client.ts','packages/client/modules/src/client/manifest.ts','packages/client/web/src/platform.ts','scripts/client-build-environment.ts','scripts/bundle-input-isolation.ts'].sort((a,b)=>a.localeCompare(b,'en'))
function identityJson(value){
 if(value===null||typeof value==='string'||typeof value==='boolean')return JSON.stringify(value)
 if(typeof value==='number'&&Number.isSafeInteger(value))return JSON.stringify(value)
 if(Array.isArray(value))return '['+value.map(identityJson).join(',')+']'
 if(value&&Object.getPrototypeOf(value)===Object.prototype)return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+identityJson(value[key])).join(',')+'}'
 fail('owner-harness-identity-data')
}
function harnessBinding(binding){
 keys(binding,['path','algorithm','sha256'])
 if(binding.path!==HARNESS_IDENTITY_PATH||binding.algorithm!==HARNESS_IDENTITY_ALGORITHM||!HEX.test(binding.sha256))fail('owner-harness-identity-binding')
 return binding
}
function harnessDocument(bytes,binding){
 const document=json(bytes);keys(document,['formatVersion','kind','algorithm','identity','sha256'])
 if(document.formatVersion!==1||document.kind!=='pinned-harness-identity'||document.algorithm!==HARNESS_IDENTITY_ALGORITHM||!HEX.test(document.sha256))fail('owner-harness-identity-document')
 const identity=document.identity;keys(identity,['upstream','localPatches','compilerInputs','coverage','host','client'])
 keys(identity.upstream,['commit','archiveSha256','lockfileSha256','packageManager','cordisVersion'])
 if(identity.upstream.commit!==DSH||identity.upstream.archiveSha256!=='ae0968314dcd5e3c9d7e8f1f5748bbd289afc4ef5668187e0ef6524a7c64c87e'||identity.upstream.lockfileSha256!==LOCK||identity.upstream.packageManager!=='pnpm@11.7.0'||identity.upstream.cordisVersion!=='4.0.2')fail('owner-harness-upstream-pin')
 if(!Array.isArray(identity.localPatches)||identity.localPatches.length!==4)fail('owner-harness-patch-set')
 const patchNames=new Set()
 for(const patch of identity.localPatches){keys(patch,['file','sha256']);pathName(patch.file);if(!HEX.test(patch.sha256)||patchNames.has(patch.file))fail('owner-harness-patch-set');patchNames.add(patch.file)}
 items(identity.compilerInputs)
 keys(identity.coverage,['hostPatterns','clientPatterns','requiredEntries','excluded','sourceLockfile'])
 for(const key of ['hostPatterns','clientPatterns','requiredEntries','excluded'])if(!Array.isArray(identity.coverage[key])||identity.coverage[key].some(value=>typeof value!=='string'||!value))fail('owner-harness-coverage')
 if(identity.coverage.sourceLockfile!=='pnpm-lock.yaml')fail('owner-harness-coverage')
 for(const field of ['host','client']){keys(identity[field],['entries','sha256']);items(identity[field].entries);if(!HEX.test(identity[field].sha256))fail('owner-harness-output-digest')}
 if(!bytes.equals(Buffer.from(identityJson(document)+'\n'))||sha(Buffer.from(HARNESS_IDENTITY_DOMAIN+identityJson(identity)))!==document.sha256)fail('owner-harness-identity-digest')
 if(document.sha256!==harnessBinding(binding).sha256)fail('owner-harness-identity-mismatch')
 return document
}
// Independent package identities, not receipt-authored resolution hints. Workspace
// seats/versions come from DSH 0d1f50007f9bca3f52b06e1c3074fa14d5fb0720
// (archive ae0968314dcd5e3c9d7e8f1f5748bbd289afc4ef5668187e0ef6524a7c64c87e).
// Registry versions and pnpm peer-qualified seats come from that archive's exact
// ca131858949bd12b2acfc227b1af7dfa3c8d65e74b234824d5c741e6421010a1 lock.
// The layout seat is the unchanged Genesis 645d3213b8aede3b544269b4224ae09df06b0a42
// plugins/aukora-face/layout/package.json copied into Prime faces/layout. Exact
// declared ranges are the reviewed Prime owner package's seven declarations;
// ranges never substitute for the independently fixed resolved versions below.
const OWNER_DEPENDENCIES={
 declared_dependencies:[
  ['@aukora/face-layout','workspace:^','0.1.1-rc.2','prime-ui','faces/layout/package.json'],
  ['@deepseek-ai/cordis','workspace:^','4.0.2','pinned-harness','vendor/cordis/package.json'],
  ['@deepseek-ai/dsh-client-locale','workspace:^','0.1.6-alpha.1','pinned-harness','packages/client/locale/package.json'],
  ['@deepseek-ai/dsh-client-ui-renderer','workspace:^','0.1.6-alpha.1','pinned-harness','packages/client/ui-renderer/package.json'],
  ['@deepseek-ai/dsh-client-ui-slots','workspace:^','0.1.6-alpha.1','pinned-harness','packages/client/ui-slots/package.json'],
  ['@types/react','~18.3.1','18.3.31','pinned-harness','node_modules/.pnpm/@types+react@18.3.31/node_modules/@types/react/package.json'],
  ['react','^18.2.0','18.3.1','pinned-harness','node_modules/.pnpm/react@18.3.1/node_modules/react/package.json'],
 ],
 build_dependencies:[
  ['typescript',null,'6.0.3','pinned-harness','node_modules/.pnpm/typescript@6.0.3/node_modules/typescript/package.json'],
  ['tsdown',null,'0.22.2','pinned-harness','node_modules/.pnpm/tsdown@0.22.2_oxc-resolver@11.20.0_publint@0.3.21_tsx@4.22.4_typescript@6.0.3/node_modules/tsdown/package.json'],
  ['lightningcss',null,'1.32.0','pinned-harness','node_modules/.pnpm/lightningcss@1.32.0/node_modules/lightningcss/package.json'],
 ],
}
function ownerDependencies(buildInputs){
 for(const [field,expected] of Object.entries(OWNER_DEPENDENCIES)){
  const dependencies=buildInputs[field]
  if(!Array.isArray(dependencies)||dependencies.length!==expected.length)fail('owner-dependency-set',field)
  for(let i=0;i<expected.length;i++){
   const dependency=dependencies[i]
   keys(dependency,['name','declared','version','origin','path','bytes','sha256'])
   pathName(dependency.path)
   if(!Number.isSafeInteger(dependency.bytes)||dependency.bytes<1||!HEX.test(dependency.sha256))fail('owner-dependency-pin')
   const identity=['name','declared','version','origin','path'].map(key=>dependency[key])
   if(JSON.stringify(identity)!==JSON.stringify(expected[i]))fail('owner-dependency-identity',expected[i][0])
  }
 }
}
async function ownerDependencyMetadata(buildInputs,{ui,dsh,release}){
 // Shape/identity validation also precedes every actual metadata read. A changed
 // receipt digest can never redirect the consumer to another package or root.
 ownerDependencies(buildInputs)
 for(const dependencies of Object.values(OWNER_DEPENDENCIES))for(const [name,,version,origin,path] of dependencies){
  const entry=[...buildInputs.declared_dependencies,...buildInputs.build_dependencies].find(item=>item.name===name)
  const root=release??(origin==='prime-ui'?ui:dsh)
  const actualPath=release&&origin==='prime-ui'?faceReleasePath(path):path
  const metadata=json(await pinned(root,{...entry,path:actualPath}))
  if(metadata.name!==name||metadata.version!==version)fail('owner-dependency-metadata',name)
 }
}
function ownerReceipt(receipt){
 if(receipt.version!==3||receipt.owner_build?.version!==2)fail('owner-source-receipt-missing')
 keys(receipt,['version','source_commit','source_commit_attribution','upstream_commit','provenance','source_lock_sha256','overlay_lock_sha256','dependency_versions','mode','legacy_hosts_mounted','artifacts','owner_build'])
 if(receipt.upstream_commit!==DSH||receipt.source_commit!==DSH||receipt.source_commit_attribution!=='pinned-dsh-upstream; not Prime/UI source proof'||receipt.mode!=='client-only'||receipt.legacy_hosts_mounted!==false||receipt.source_lock_sha256!==LOCK||receipt.overlay_lock_sha256!==LOCK)fail('owner-build-pin')
 keys(receipt.provenance,['harness_build_receipt'])
 keys(receipt.provenance.harness_build_receipt,['path','bytes','sha256'])
 const historical=item(receipt.provenance.harness_build_receipt)
 if(historical.path!=='.dsh-build/pinned-harness-build.json')fail('owner-provenance-path')
 // The producer's raw receipt is retained attribution, not a compiler input or
 // stable identity. Never compare it with a later producer's volatile bytes.
 if(!receipt.dependency_versions||typeof receipt.dependency_versions!=='object'||Array.isArray(receipt.dependency_versions)||Object.values(receipt.dependency_versions).some(value=>typeof value!=='string'||!value))fail('owner-dependency-versions')
 items(receipt.artifacts)
 const owner=receipt.owner_build
 keys(owner,['version','package_id','source_inputs','source_inputs_before_sha256','source_inputs_after_sha256','build_inputs','build_inputs_before_sha256','build_inputs_after_sha256','output_artifacts'])
 if(owner.package_id!==OWNER_ID)fail('owner-package-pin')
 const sources=items(owner.source_inputs),outputs=items(owner.output_artifacts)
 const sourceDigest=sha(Buffer.from(JSON.stringify(owner.source_inputs))),buildDigest=sha(Buffer.from(JSON.stringify(owner.build_inputs)))
 if(owner.source_inputs_before_sha256!==sourceDigest||owner.source_inputs_after_sha256!==sourceDigest)fail('owner-source-digest-binding')
 if(owner.build_inputs_before_sha256!==buildDigest||owner.build_inputs_after_sha256!==buildDigest)fail('owner-build-digest-binding')
 keys(owner.build_inputs,['harness_identity','pinned','generated','declared_dependencies','build_dependencies'])
 const identity=harnessBinding(owner.build_inputs.harness_identity)
 const pins=items(owner.build_inputs.pinned)
 if(JSON.stringify(pins.map(x=>x.path))!==JSON.stringify(BUILD_PATHS))fail('owner-pinned-build-set')
 const generated=item(owner.build_inputs.generated)
 if(generated.path!=='packages/client/aukora-prime-authority/.prime-client.config.ts'||generated.bytes!==Buffer.byteLength(OWNER_CONFIG)||generated.sha256!==sha(Buffer.from(OWNER_CONFIG)))fail('owner-generated-config')
 ownerDependencies(owner.build_inputs)
 for(const output of owner.output_artifacts){if(!output.path.startsWith('prime-authority/lib/')||output.output_path!==output.path.replace('prime-authority/lib/','prime-authority/'))fail('owner-output-path')}
 for(const path of ['prime-authority/lib/client.js','prime-authority/lib/client.js.map','prime-authority/lib/index.js','prime-authority/lib/types/client/index.d.ts','prime-authority/lib/types/client/controller.d.mts','prime-authority/lib/types/client/controller.mjs'])if(!outputs.some(x=>x.path===path))fail('owner-output-missing',path)
 const publication=sources.find(x=>x.path==='scripts/publish-owner-types.mjs')
 if(publication){
  // The reviewed publication recipe rebases only the known adapter import seat.
  // Compose rederives these bytes from source below; boot checks their sealed
  // snapshot and the independently retained full deployment release digest.
  if(publication.sha256!=='56388dee0becca5c75a95b1374325db505c7adf0b0517c6c9721fb6ad0734a1e')fail('owner-type-publication-profile')
  for(const source of sources.filter(x=>/^prime-authority\/src\/client\/[^/]+\.(?:mjs|d\.mts)$/.test(x.path))){
   const path=source.path.replace('prime-authority/src/client/','prime-authority/lib/types/client/')
   if(!outputs.some(x=>x.path===path))fail('owner-type-publication-output',path)
  }
 }else for(const extension of ['mjs','d.mts']){const source=sources.find(x=>x.path==='prime-authority/src/client/controller.'+extension),output=outputs.find(x=>x.path==='prime-authority/lib/types/client/controller.'+extension);if(!source||source.bytes!==output.bytes||source.sha256!==output.sha256)fail('owner-copied-controller-binding')}
 for(const output of owner.output_artifacts.filter(x=>/\/client\.js(?:\.map)?$/.test(x.path))){const compiled=receipt.artifacts?.find(x=>x.id===OWNER_ID&&x.path===output.output_path);if(!compiled||compiled.bytes!==output.bytes||compiled.sha256!==output.sha256)fail('owner-output-artifact-binding',output.path)}
 return {sources,outputs,buildInputs:owner.build_inputs,harnessIdentity:identity}
}

/** Verify owned source before copying. Owner builds must carry genuine input pins. */
export async function verifyUiSource({sourceRoot}){
 const root=await rootPath(sourceRoot),ui=await subRoot(root,'packages/ui')
 const baselineBytes=await bytesAt(ui,'baseline-manifest.json'),baseline=json(baselineBytes),faces=servedFaces(baseline)
 for(const entry of faces.all)await pinned(ui,entry)
 const foundationBytes=await bytesAt(ui,'foundation/prime-import-manifest.json'),foundation=json(foundationBytes)
 if(foundation.version!==1||foundation.commit!==DONOR||foundation.client_id!=='@aukora/dsh-plugin-foundation'||foundation.baseline_face_diff!==0)fail('foundation-pin')
 const foundationFiles=foundationFileRecords(foundation)
 const foundationRoot=await subRoot(ui,'foundation')
 for(const entry of foundationFiles)await pinned(foundationRoot,entry)
 await verifyFoundationAdaptation({foundationRoot,manifest:foundation})
 const foundationReceipt=json(await bytesAt(ui,'foundation/lib/build-manifest.json'))
 for(const path of ['src/client/index.tsx','tsdown.config.ts'])if(foundationReceipt.source?.[path]!==foundationFiles.find(x=>x.path===path)?.sha256)fail('foundation-source-binding',path)
 if(foundationReceipt.outputs?.['lib/client.js']!==foundationFiles.find(x=>x.path==='lib/client.js')?.sha256)fail('foundation-output-binding')
 const ownerBytes=await bytesAt(ui,'prime-authority/lib/build.json'),owner=json(ownerBytes)
 const binding=ownerReceipt(owner),ownerSources=binding.sources,ownerOutputs=binding.outputs
 await ownerDependencyMetadata(binding.buildInputs,{ui,dsh:await subRoot(root,'vendor/dsh')})
 for(const entry of ownerSources)await pinned(ui,entry)
 for(const entry of ownerOutputs)await pinned(ui,entry)
 if(ownerSources.some(x=>x.path==='scripts/publish-owner-types.mjs')){
  const copySources=ownerSources.filter(x=>/^prime-authority\/src\/client\/[^/]+\.(?:mjs|d\.mts)$/.test(x.path)
   || /^adapters\/(?:capture-metadata|capture-presentation|capture-review|forget-result|forget-review|passkey|provider-settings|save-recovery|transport)\.(?:mjs|d\.mts)$/.test(x.path))
  for(const entry of copySources){
   const client=entry.path.startsWith('prime-authority/src/client/')
   const path=client?entry.path.replace('prime-authority/src/client/','prime-authority/lib/types/client/'):'prime-authority/lib/types/'+entry.path
   const copied=ownerOutputs.find(x=>x.path===path);if(!copied)fail('owner-type-publication-output',path)
   const original=await pinned(ui,entry),expected=client?Buffer.from(original.toString('utf8').replaceAll('../../../adapters/','../adapters/')):original
   if(expected.length!==copied.bytes||sha(expected)!==copied.sha256)fail('owner-type-publication-binding',path)
  }
 }
 // Use B's actual verifier for the complete current source/dependency/output closure.
 // Dynamic import is compose-only. verifyReleaseUi has no B/runtime source dependency.
 await bytesAt(ui,'scripts/verify-owner-build.mjs')
 const {verifyOwnerBuild}=await import(pathToFileURL(join(ui,'scripts/verify-owner-build.mjs')).href)
 if(typeof verifyOwnerBuild!=='function')fail('owner-verifier-export')
 const dsh=await subRoot(root,'vendor/dsh')
 const verified=await verifyOwnerBuild({uiRoot:ui,receiptPath:join(ui,'prime-authority/lib/build.json'),dsh,primeRoot:root})
 if(verified?.result!=='PASS'||verified.source_output_binding!=='MATCH'||verified.pinned_build_inputs!=='MATCH')fail('owner-verifier-refused')
 const identityBytes=await bytesAt(dsh,HARNESS_IDENTITY_PATH)
 harnessDocument(identityBytes,binding.harnessIdentity)
 const sourceRecords=[await pin(ui,'baseline-manifest.json'),await pin(ui,'foundation/prime-import-manifest.json'),await pin(ui,'prime-authority/lib/build.json')]
 return {version:1,donor:DONOR,baseline,served:faces.served,foundation,foundationFiles,owner,ownerSources,ownerOutputs,sourceRecords,harnessIdentity:binding.harnessIdentity,harnessIdentityFile:{path:HARNESS_IDENTITY_PATH,bytes:identityBytes.length,sha256:sha(identityBytes)}}
}

/** Compose seam: call after copying and before final release digest calculation. */
export async function writeUiIntegritySnapshot({sourceRoot,releaseRoot}){
 const source=await verifyUiSource({sourceRoot}),root=await rootPath(releaseRoot),files=[]
 const add=entry=>{const existing=files.find(x=>x.path===entry.path);if(existing){if(existing.bytes!==entry.bytes||existing.sha256!==entry.sha256)fail('duplicate-release-path');return}files.push(entry)}
 for(const entry of source.served)add({...entry,path:faceReleasePath(entry.path)})
 add({...source.sourceRecords[0],path:'prime-packages/ui/baseline-manifest.json'})
 const baseline=json(await bytesAt(root,'prime-served-baseline.json'))
 if(baseline.version!==1||baseline.donor!==DONOR||baseline.rebuilt_substitutions!==false||!sameList(baseline.files,source.served))fail('served-baseline-pin')
 add(await pin(root,'prime-served-baseline.json'))
 for(const entry of source.foundationFiles.filter(x=>!x.path.startsWith('src/')))add({...entry,path:'plugins/aukora-foundation/'+entry.path})
 add({...source.sourceRecords[1],path:'plugins/aukora-foundation/prime-import-manifest.json'})
 add({...source.sourceRecords[2],path:'plugins/prime-authority/lib/build.json'})
 for(const entry of source.ownerOutputs)add({...entry,path:'plugins/'+entry.path})
 add(source.harnessIdentityFile)
 // Additional owned host/package/type bytes are pinned to the reviewed source.
 const ui=await subRoot(await rootPath(sourceRoot),'packages/ui')
 for(const [sourcePath,target] of [['foundation/lib/index.js','plugins/aukora-foundation/lib/index.js'],['prime-authority/package.json','plugins/prime-authority/package.json'],['prime-authority/lib/index.js','plugins/prime-authority/lib/index.js'],...((await walk(ui,'prime-authority/lib/types')).map(path=>[path,'plugins/'+path]))])add({...await pin(ui,sourcePath),path:target})
 for(const entry of files)await pinned(root,entry)
 const snapshot={version:2,kind:'aukora-prime-ui-integrity/v2',donor:DONOR,source_records:source.sourceRecords,owner_source_files:source.ownerSources,owner_harness_identity:source.harnessIdentity,files:files.sort((a,b)=>a.path.localeCompare(b.path))}
 const bytes=Buffer.from(JSON.stringify(snapshot,null,2)+'\n'),path='prime-ui-integrity.json'
 try{await writeFile(join(root,path),bytes,{flag:'wx',mode:0o644})}catch(error){if(error.code==='EEXIST')fail('snapshot-already-exists');throw error}
 return {result:'PASS',snapshot:path,snapshot_sha256:sha(bytes),served_files:files.length,owner_source_build_binding:'VERIFIED_RECEIPT_INPUTS'}
}

/** Boot seam: run before importing any served plugin. Trust the deployment digest separately. */
export async function verifyReleaseUi({releaseRoot,expectedSnapshotSha256}){
 const root=await rootPath(releaseRoot),bytes=await bytesAt(root,'prime-ui-integrity.json')
 if(expectedSnapshotSha256!==undefined&&(!HEX.test(expectedSnapshotSha256)||sha(bytes)!==expectedSnapshotSha256))fail('snapshot-trusted-pin-mismatch')
 const snapshot=json(bytes);keys(snapshot,['version','kind','donor','source_records','owner_source_files','owner_harness_identity','files'])
 if(snapshot.version!==2||snapshot.kind!=='aukora-prime-ui-integrity/v2'||snapshot.donor!==DONOR)fail('snapshot-pin')
 const identity=harnessBinding(snapshot.owner_harness_identity)
 const files=items(snapshot.files);items(snapshot.owner_source_files);const sourceRecords=items(snapshot.source_records)
 const records=[['baseline-manifest.json','prime-packages/ui/baseline-manifest.json'],['foundation/prime-import-manifest.json','plugins/aukora-foundation/prime-import-manifest.json'],['prime-authority/lib/build.json','plugins/prime-authority/lib/build.json']]
 if(sourceRecords.length!==records.length)fail('source-record-set')
 for(const [sourcePath,path] of records){const original=sourceRecords.find(x=>x.path===sourcePath),copied=files.find(x=>x.path===path);if(!original||!copied||original.sha256!==copied.sha256||original.bytes!==copied.bytes)fail('source-record-snapshot-mismatch',path)}
 for(const entry of files)await pinned(root,entry)
 const baseline=json(await bytesAt(root,'prime-packages/ui/baseline-manifest.json')),served=servedFaces(baseline).served
 const servedSnapshot=json(await bytesAt(root,'prime-served-baseline.json'))
 if(servedSnapshot.version!==1||servedSnapshot.donor!==DONOR||servedSnapshot.rebuilt_substitutions!==false||!sameList(servedSnapshot.files,served))fail('served-baseline-pin')
 for(const entry of served){const copied=files.find(x=>x.path===faceReleasePath(entry.path));if(!copied||copied.sha256!==entry.sha256||copied.bytes!==entry.bytes)fail('served-snapshot-omission',entry.path)}
 const foundation=json(await bytesAt(root,'plugins/aukora-foundation/prime-import-manifest.json'))
 if(foundation.version!==1||foundation.commit!==DONOR||foundation.client_id!=='@aukora/dsh-plugin-foundation')fail('foundation-pin')
 for(const entry of foundationFileRecords(foundation).filter(x=>!x.path.startsWith('src/'))){const copied=files.find(x=>x.path==='plugins/aukora-foundation/'+entry.path);if(!copied||copied.sha256!==entry.sha256||copied.bytes!==entry.bytes)fail('foundation-snapshot-omission',entry.path)}
 await verifyFoundationAdaptation({foundationRoot:await subRoot(root,'plugins/aukora-foundation'),manifest:foundation})
 const owner=json(await bytesAt(root,'plugins/prime-authority/lib/build.json'))
 const binding=ownerReceipt(owner)
 if(identityJson(binding.harnessIdentity)!==identityJson(identity))fail('owner-harness-snapshot-mismatch')
 if(!files.some(entry=>entry.path===HARNESS_IDENTITY_PATH))fail('owner-harness-snapshot-omission')
 // Composition adds Prime modules and host shims. The original pure harness
 // was independently rederived by verifyUiSource; boot verifies its preserved
 // document under the protected UI snapshot and full deployment release pin.
 harnessDocument(await bytesAt(root,HARNESS_IDENTITY_PATH),identity)
 for(const entry of binding.buildInputs.pinned)await pinned(root,entry)
 await ownerDependencyMetadata(binding.buildInputs,{release:root})
 if(!sameList(binding.sources,snapshot.owner_source_files))fail('owner-source-snapshot-mismatch')
 for(const entry of binding.outputs){const path='plugins/'+entry.path,copied=files.find(x=>x.path===path);if(!copied||copied.sha256!==entry.sha256||copied.bytes!==entry.bytes)fail('owner-snapshot-omission',path)}
 return {result:'PASS',snapshot_sha256:sha(bytes),served_files:files.length,external_trust_pin:expectedSnapshotSha256!==undefined}
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const [action,...argv]=process.argv.slice(2)
 if(action==='source'&&argv.length===1)console.log(JSON.stringify({result:'PASS',donor:(await verifyUiSource({sourceRoot:argv[0]})).donor}))
 else if(action==='snapshot'&&argv.length===2)console.log(JSON.stringify(await writeUiIntegritySnapshot({sourceRoot:argv[0],releaseRoot:argv[1]})))
 else if(action==='verify'&&(argv.length===1||argv.length===2))console.log(JSON.stringify(await verifyReleaseUi({releaseRoot:argv[0],expectedSnapshotSha256:argv[1]})))
 else throw new Error('usage: release-integrity.mjs source SOURCE_ROOT | snapshot SOURCE_ROOT RELEASE_ROOT | verify RELEASE_ROOT [TRUSTED_SNAPSHOT_SHA256]')
}
