import assert from 'node:assert/strict'
import {mkdtemp,mkdir,readFile,writeFile,readdir,rm,symlink,rename} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join,dirname} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {publishOwnerTypeSources,verifyOwnerTypeSources} from './publish-owner-types.mjs'

const ui=fileURLToPath(new URL('../',import.meta.url)),root=await mkdtemp(join(tmpdir(),'prime-owner-type-check-'))
const sourceClient=join(ui,'prime-authority/src/client'),adapterRoot=join(ui,'adapters'),typeRoot=join(root,'lib/types')
const options={sourceClient,adapterRoot,typeRoot}
let groups=0,refusals=0
try {
  await mkdir(join(typeRoot,'client'),{recursive:true})
  // A synthetic stand-in tests the compiler output's known import rebase;
  // this is not a compiler build or a genuine build receipt.
  await writeFile(join(typeRoot,'client','synthetic.js'),"import '../../../adapters/capture-review.mjs'\n")
  await writeFile(join(typeRoot,'client','synthetic.d.ts'),"import type {CaptureMetadata} from '../../../adapters/capture-metadata.mjs'\n")
  const published=await publishOwnerTypeSources(options)
  await verifyOwnerTypeSources(options)
  for(const required of ['client/controller.mjs','client/controller.d.mts','client/provider-controller.mjs','client/provider-controller.d.mts',
    'adapters/transport.mjs','adapters/provider-settings.mjs','adapters/forget-result.mjs','adapters/forget-result.d.mts'])assert(published.includes(required))
  assert(!published.some(path=>/static-assets|mount-plan/.test(path)))
  for(const name of ['synthetic.js','synthetic.d.ts'])assert((await readFile(join(typeRoot,'client',name),'utf8')).includes('../adapters/'))
  groups++
  // Resolve the actual published source modules from a detached tree, with no
  // access to a donor checkout or a source-directory adapter import fallback.
  const owner=await import(pathToFileURL(join(typeRoot,'client/controller.mjs')))
  const provider=await import(pathToFileURL(join(typeRoot,'client/provider-controller.mjs')))
  assert.equal(typeof owner.createPrimeOwnerController,'function')
  assert.equal(provider.createPrimeProviderController().getSnapshot().entry_status,'unavailable')
  for(const folder of ['client','adapters'])for(const name of await readdir(join(typeRoot,folder))) {
    if(!name.endsWith('.mjs')&&!name.endsWith('.d.mts'))continue
    const path=join(typeRoot,folder,name),text=await readFile(path,'utf8')
    for(const [,relative] of text.matchAll(/(?:from\s+|import\s*)['"](\.[^'"]+)['"]/g))await readFile(join(dirname(path),relative))
  }
  groups++
  const controller=join(typeRoot,'client/provider-controller.mjs'),declaration=join(typeRoot,'client/controller.d.mts'),adapter=join(typeRoot,'adapters/forget-result.mjs')
  for(const path of [controller,declaration,adapter]) {
    const bytes=await readFile(path)
    await writeFile(path,Buffer.concat([bytes,Buffer.from('\n// mutation\n')]))
    await assert.rejects(verifyOwnerTypeSources(options));refusals++
    await writeFile(path,bytes)
  }
  const bytes=await readFile(controller)
  await rm(controller);await assert.rejects(verifyOwnerTypeSources(options));refusals++
  await writeFile(controller,bytes)
  const extra=join(typeRoot,'client/unexpected.mjs')
  await writeFile(extra,'export {}\n');await assert.rejects(verifyOwnerTypeSources(options));refusals++
  await rm(extra)
  await rm(controller);await symlink(join(sourceClient,'provider-controller.mjs'),controller)
  await assert.rejects(verifyOwnerTypeSources(options));refusals++
  await rm(controller);await writeFile(controller,bytes)
  for(const seat of [join(typeRoot,'client'),join(typeRoot,'adapters'),typeRoot]) {
    const saved=seat+'.saved'
    await rename(seat,saved);await symlink(saved,seat,'dir')
    await assert.rejects(verifyOwnerTypeSources(options));refusals++
    await assert.rejects(publishOwnerTypeSources(options))
    await rm(seat);await rename(saved,seat)
  }
  for(const [field,source] of [['sourceClient',sourceClient],['adapterRoot',adapterRoot]]) {
    const alias=join(root,field+'.alias')
    await symlink(source,alias,'dir')
    await assert.rejects(verifyOwnerTypeSources({...options,[field]:alias}));refusals++
    await assert.rejects(publishOwnerTypeSources({...options,[field]:alias}))
    await rm(alias)
  }
  await verifyOwnerTypeSources(options)
  groups++
  console.log(JSON.stringify({result:'PASS',groups,copied_files:published.length,mutation_refusals:refusals,scope:'SOURCE declaration/module publication only',
    compiler_build:false,genuine_receipt:false,network:false,real_credentials:false,runtime_preview:false}))
} finally {await rm(root,{recursive:true,force:true})}
