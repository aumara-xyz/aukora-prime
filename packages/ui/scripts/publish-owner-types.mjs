import {mkdir,readdir,lstat,readFile,writeFile} from 'node:fs/promises'
import {join} from 'node:path'
import assert from 'node:assert/strict'

const adapters=Object.freeze(['capture-metadata','capture-presentation','capture-review','forget-result','forget-review','passkey','provider-settings','transport'])
const rebase=bytes=>Buffer.from(bytes.toString('utf8').replaceAll('../../../adapters/','../adapters/'))
async function directoryAt(path) {
  const metadata=await lstat(path)
  if(!metadata.isDirectory()||metadata.isSymbolicLink())throw new Error('ui-build:unsupported-owned-type-seat')
}
async function bytesAt(root,name) {
  const path=join(root,name),metadata=await lstat(path)
  if(!metadata.isFile()||metadata.isSymbolicLink())throw new Error(`ui-build:unsupported-owned-type-input:${name}`)
  return readFile(path)
}

/** Independently re-derived expected copied closure for publication/verifier. */
export async function ownerTypeSourceRecords({sourceClient,adapterRoot}) {
  await directoryAt(sourceClient);await directoryAt(adapterRoot)
  const records=[]
  for(const name of (await readdir(sourceClient)).sort()) {
    if(name.endsWith('.mjs')||name.endsWith('.d.mts'))records.push({path:`client/${name}`,bytes:rebase(await bytesAt(sourceClient,name))})
  }
  const names=await readdir(adapterRoot)
  for(const name of adapters) {
    records.push({path:`adapters/${name}.mjs`,bytes:await bytesAt(adapterRoot,`${name}.mjs`)})
    if(names.includes(`${name}.d.mts`))records.push({path:`adapters/${name}.d.mts`,bytes:await bytesAt(adapterRoot,`${name}.d.mts`)})
  }
  return records.sort((a,b)=>a.path.localeCompare(b.path,'en'))
}

/** Publish the owned JavaScript/declaration dependencies that TypeScript does
 * not emit. Source bytes stay unchanged; only the generated client module's
 * known adapter import seat is rebased into the self-contained lib/types tree. */
export async function publishOwnerTypeSources({sourceClient,adapterRoot,typeRoot}) {
  await directoryAt(sourceClient);await directoryAt(adapterRoot);await directoryAt(typeRoot)
  for(const folder of ['client','adapters']) {
    await mkdir(join(typeRoot,folder),{recursive:true})
    await directoryAt(join(typeRoot,folder))
  }
  // The compiler's React .js files remain auxiliary; only lib/client.js is the
  // browser runtime export. Rebase their adapter imports and declarations too.
  for(const name of await readdir(join(typeRoot,'client'))) {
    if(name.endsWith('.js')||name.endsWith('.d.ts')) {
      const path=join(typeRoot,'client',name)
      await writeFile(path,rebase(await bytesAt(join(typeRoot,'client'),name)))
    }
  }
  const records=await ownerTypeSourceRecords({sourceClient,adapterRoot})
  for(const item of records)await writeFile(join(typeRoot,item.path),item.bytes)
  return records.map(item=>item.path)
}

/** This verifies copied module/declaration publication only. Compiler output
 * hashes and the genuine build-input receipt remain verifyOwnerBuild's job. */
export async function verifyOwnerTypeSources({sourceClient,adapterRoot,typeRoot}) {
  await directoryAt(typeRoot)
  const expected=await ownerTypeSourceRecords({sourceClient,adapterRoot}),actual=[]
  for(const folder of ['client','adapters']) {
    await directoryAt(join(typeRoot,folder))
    for(const name of await readdir(join(typeRoot,folder))) {
      if(name.endsWith('.mjs')||name.endsWith('.d.mts'))actual.push(`${folder}/${name}`)
    }
  }
  assert.deepEqual(actual.sort((a,b)=>a.localeCompare(b,'en')),expected.map(item=>item.path),'ui-build:copied-type-closure-mismatch')
  for(const item of expected)assert.deepEqual(await bytesAt(typeRoot,item.path),item.bytes,`ui-build:copied-type-mismatch:${item.path}`)
  return {copied_files:expected.length}
}
