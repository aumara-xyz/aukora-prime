import assert from 'node:assert/strict'
import { readFile, writeFile, mkdir, mkdtemp, cp, rm, lstat, realpath, symlink, rename } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { join, dirname, resolve, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as verifier from './verify-owner-build.mjs'
const { snapshotOwnerSources, publishedOwnerOutputs, verifyOwnerBuild } = verifier

// Mutate disposable copies of the genuine compiler receipt and its bound files.
// Never synthesize/repair release evidence, compile, mount, or contact services.
const ui = fileURLToPath(new URL('../', import.meta.url))
const work = fileURLToPath(new URL('../../../.runtime/', import.meta.url))
const flags = {}
for (let index = 2; index < process.argv.length; index++) {
  const flag = process.argv[index]
  if (flag === '--dependencies-only') flags.dependenciesOnly = true
  else if (flag === '--dsh' && process.argv[index + 1]) flags.dsh = resolve(process.argv[++index])
  else throw new Error('usage: check-owner-build.mjs [--dependencies-only] [--dsh <existing pinned harness>]')
}
const dshSource = flags.dsh ?? resolve(ui, '../../vendor/dsh')
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const clone = value => JSON.parse(JSON.stringify(value))
const receipt = JSON.parse(await readFile(join(ui, 'prime-authority/lib/build.json'), 'utf8'))
await mkdir(work, { recursive: true })
const fixture = await mkdtemp(join(work, 'owner-receipt-check-'))
const root = join(fixture, 'ui')
const receiptPath = join(root, 'prime-authority/lib/build.json')
const dependencyCases = []
const directoryCases = []

async function dependencyChecks() {
  for (const name of ['validateDependencyRecords', 'verifyDependencyMetadata', 'discoverPinnedWorkspace','compilerCommand','validateBuildDirectories']) {
    if (typeof verifier[name] !== 'function') throw new Error('owner-dependency-check:missing-verifier-seam:' + name)
  }
  const dsh = join(fixture, 'dsh')
  const inputs = clone(receipt.owner_build.build_inputs)
  const all = value => [...value.declared_dependencies, ...value.build_dependencies]
  const find = (value, name) => all(value).find(item => item.name === name)
  const actual = item => join(item.origin === 'prime-ui' ? root : dsh, item.path)
  // Refuse authored paths/origins before they can select reads or writes.
  await verifier.validateDependencyRecords(inputs)
  await mkdir(dsh, {recursive:true})
  // Copy exactly the metadata named by the genuine compiler receipt. These
  // fixture seats are not a build, a full DSH closure or newly minted evidence.
  for (const item of all(inputs)) {
    const source = join(item.origin === 'prime-ui' ? ui : dshSource, item.path)
    const bytes = await readFile(source)
    assert.equal(bytes.length,item.bytes,'actual genuine dependency byte count: '+item.name)
    assert.equal(sha(bytes),item.sha256,'actual genuine dependency hash: '+item.name)
    await mkdir(dirname(actual(item)),{recursive:true})
    await writeFile(actual(item),bytes)
  }
  for (const path of ['prime-authority/package.json','compatibility.json']) {
    await mkdir(dirname(join(root,path)),{recursive:true})
    await cp(join(ui,path),join(root,path))
  }
  const compilerBins=[]
  for(const [name,bin] of [['typescript','bin/tsc'],['tsdown','dist/run.mjs']]) {
    const item=find(inputs,name),source=join(dirname(join(dshSource,item.path)),bin),destination=join(dirname(actual(item)),bin)
    assert((await lstat(source)).isFile(),'genuine regular compiler script: '+name)
    const bytes=await readFile(source)
    await mkdir(dirname(destination),{recursive:true});await writeFile(destination,bytes)
    compilerBins.push({name,bin,path:destination,bytes})
  }
  // Detach existing PNPM module seats from the original harness. Their target
  // relationship is independently compared with the genuine receipt first.
  const seats = new Map()
  for (const name of ['react','@types/react','typescript','tsdown','lightningcss']) {
    const item = find(inputs,name), target = dirname(actual(item))
    let count = 0
    for (const prefix of ['node_modules','node_modules/.pnpm/node_modules']) {
      const source = join(dshSource,prefix,name), destination = join(dsh,prefix,name)
      try { await lstat(source) } catch (error) {if(error.code==='ENOENT')continue;throw error}
      assert.equal(await realpath(source),await realpath(dirname(join(dshSource,item.path))),
        'actual genuine module seat: '+name)
      if (resolve(destination)!==resolve(target)) {
        await mkdir(dirname(destination),{recursive:true})
        await symlink(relative(dirname(destination),target),destination,'dir')
      }
      if (!seats.has(name)) seats.set(name,destination)
      count++
    }
    assert(count>0,'existing genuine module seat required: '+name)
  }
  const verify = value => verifier.verifyDependencyMetadata({uiRoot:root,dsh,inputs:value})
  await verifier.validateDependencyRecords(inputs)
  await verify(inputs)
  await verifier.discoverPinnedWorkspace(dsh)
  // The pinned archive contains a harmless file link here. It must remain
  // discoverable without treating this documentation as a package directory.
  await cp(join(dshSource,'vendor/AGENTS.md'),join(dsh,'vendor/AGENTS.md'))
  await symlink('AGENTS.md',join(dsh,'vendor/CLAUDE.md'))
  await verifier.discoverPinnedWorkspace(dsh)
  for(const item of compilerBins) assert.equal(await verifier.compilerCommand(dsh,item.name),await realpath(item.path))
  const react=find(inputs,'react'),reactPath=actual(react),reactBytes=await readFile(reactPath)
  const alternate = join(dsh,'alternate-react'),outside = join(fixture,'outside-react')
  for(const directory of [alternate,outside]) {
    await mkdir(directory,{recursive:true});await writeFile(join(directory,'package.json'),reactBytes)
  }
  // Wrong-origin/path mutations still have real, identical metadata to read;
  // they must fail identity checks rather than merely encounter a missing file.
  const layout=find(inputs,'@aukora/face-layout'),falseLayoutOrigin=join(dsh,layout.path)
  await mkdir(dirname(falseLayoutOrigin),{recursive:true})
  await writeFile(falseLayoutOrigin,await readFile(actual(layout)))
  async function refused(label,work,cases=dependencyCases) {
    let error
    try {await work()} catch (caught) {error=caught}
    assert(error instanceof Error,label+' must be refused')
    assert.match(error.message,/^ui-owner-build:/,label+' must fail its identity guard, not an unrelated fixture/read error')
    cases.push({case:label,refusal:String(error.message)})
  }
  const recordMutation = async(label,mutate) => {
    const changed=clone(inputs);mutate(changed)
    await refused(label,()=>verify(changed))
  }
  await recordMutation('unknown dependency origin',value=>{find(value,'react').origin='untrusted'})
  await recordMutation('Layout falsely attributed to harness',value=>{find(value,'@aukora/face-layout').origin='pinned-harness'})
  await recordMutation('noncanonical dot path alias',value=>{find(value,'react').path='./'+find(value,'react').path})
  await recordMutation('noncanonical parent path alias',value=>{
    const item=find(value,'react');item.path=dirname(item.path)+'/../react/package.json'
  })
  await recordMutation('same-byte metadata at alternate receipt seat',value=>{find(value,'react').path='alternate-react/package.json'})
  await recordMutation('receipt-authored dependency version',value=>{find(value,'react').version='18.3.999'})
  await recordMutation('duplicated dependency identity',value=>{
    const index=value.declared_dependencies.findIndex(item=>item.name==='react')
    value.declared_dependencies[index]=clone(find(value,'@types/react'))
  })
  const laundered=clone(inputs)
  for (const item of all(laundered)) Object.assign(item,{origin:'prime-ui',path:layout.path,
    version:layout.version,bytes:layout.bytes,sha256:layout.sha256})
  await refused('all ten records laundered through genuine Layout metadata',()=>verify(laundered))

  for (const [label,patch] of [['actual package name differs',{name:'unrelated-synthetic-package'}],
    ['actual package version differs',{version:'18.3.999'}]]) {
    const changed=clone(inputs),metadata={...JSON.parse(reactBytes),...patch}
    const bytes=Buffer.from(JSON.stringify(metadata)+'\n')
    await writeFile(reactPath,bytes)
    Object.assign(find(changed,'react'),{version:metadata.version,bytes:bytes.length,sha256:sha(bytes)})
    try {await refused(label+' with self-consistent receipt hash',()=>verify(changed))}
    finally {await writeFile(reactPath,reactBytes)}
  }
  await writeFile(reactPath,Buffer.concat([reactBytes,Buffer.from('\n')]))
  try {await refused('actual dependency bytes changed',()=>verify(inputs))}
  finally {await writeFile(reactPath,reactBytes)}

  const seat=seats.get('react'),canonicalReact=dirname(reactPath)
  assert.notEqual(resolve(seat),resolve(canonicalReact),'genuine PNPM alias seat required for module mutation')
  for(const [label,target] of [['module alias points to same-name alternate seat',alternate],
    ['module alias escapes harness',outside]]) {
    await rm(seat);await symlink(relative(dirname(seat),target),seat,'dir')
    try {await refused(label,()=>verify(inputs))}
    finally {await rm(seat);await symlink(relative(dirname(seat),canonicalReact),seat,'dir')}
  }
  const hiddenReact=join(fixture,'hidden-original-react')
  await rename(canonicalReact,hiddenReact);await symlink(outside,canonicalReact,'dir')
  try {await refused('dependency directory ancestor escapes with identical metadata',()=>verify(inputs))}
  finally {await rm(canonicalReact);await rename(hiddenReact,canonicalReact)}

  const locale=find(inputs,'@deepseek-ai/dsh-client-locale'),localeDir=dirname(actual(locale)),localeBytes=await readFile(actual(locale))
  const duplicate=join(dsh,'packages/client/owner-check-duplicate')
  await mkdir(duplicate,{recursive:true});await writeFile(join(duplicate,'package.json'),localeBytes)
  try {await refused('duplicate pinned workspace package name',()=>verifier.discoverPinnedWorkspace(dsh))}
  finally {await rm(duplicate,{recursive:true,force:true})}
  const outsideLocale=join(fixture,'outside-locale'),hiddenLocale=join(fixture,'hidden-original-locale')
  await mkdir(outsideLocale,{recursive:true});await writeFile(join(outsideLocale,'package.json'),localeBytes)
  await rename(localeDir,hiddenLocale);await symlink(outsideLocale,localeDir,'dir')
  try {await refused('workspace package ancestor escapes with identical metadata',()=>verifier.discoverPinnedWorkspace(dsh))}
  finally {await rm(localeDir);await rename(hiddenLocale,localeDir)}
  for(const path of ['.pnpmfile.cjs','.npmrc']) {
    await writeFile(join(dsh,path),path.endsWith('.cjs')?'module.exports = { hooks: {} }\n':'# unarchived disposable fixture configuration\n')
    try {await refused('unarchived package-manager configuration: '+path,()=>verifier.discoverPinnedWorkspace(dsh))}
    finally {await rm(join(dsh,path))}
  }
  for(const item of compilerBins) {
    const metadataPath=actual(find(inputs,item.name)),metadataBytes=await readFile(metadataPath),packageDir=dirname(metadataPath)
    const alternateBin=join(packageDir,'owner-check-alternate-bin.mjs')
    await writeFile(alternateBin,item.bytes)
    const parentAlias='./'+dirname(item.bin)+'/../'+item.bin
    for(const [label,bin] of [['alternate in-root compiler entry','./owner-check-alternate-bin.mjs'],
      ['parent alias of exact compiler entry',parentAlias]]) {
      const metadata=JSON.parse(metadataBytes),command=item.name==='typescript'?'tsc':item.name
      if(typeof metadata.bin==='string') metadata.bin=bin
      else metadata.bin={...metadata.bin,[command]:bin}
      await writeFile(metadataPath,JSON.stringify(metadata)+'\n')
      try {await refused(item.name+' '+label,()=>verifier.compilerCommand(dsh,item.name))}
      finally {await writeFile(metadataPath,metadataBytes)}
    }
    const alternatePackage=join(dsh,'alternate-'+item.name),module=seats.get(item.name)
    await mkdir(dirname(join(alternatePackage,item.bin)),{recursive:true})
    await writeFile(join(alternatePackage,'package.json'),metadataBytes)
    await writeFile(join(alternatePackage,item.bin),item.bytes)
    assert.notEqual(resolve(module),resolve(packageDir),'genuine compiler module alias required: '+item.name)
    await rm(module);await symlink(relative(dirname(module),alternatePackage),module,'dir')
    try {await refused(item.name+' wrong module compiler seat with identical script bytes',()=>verifier.compilerCommand(dsh,item.name))}
    finally {await rm(module);await symlink(relative(dirname(module),packageDir),module,'dir')}
    assert.equal(await verifier.compilerCommand(dsh,item.name),await realpath(item.path))
  }
  const safeWork=join(fixture,'safe-build-work'),safeOutput=join(fixture,'safe-build-output')
  await mkdir(safeWork)
  await writeFile(join(safeWork,'existing-owned-file.txt'),'owned nonempty work fixture\n')
  const directories = (work,output) => verifier.validateBuildDirectories({uiRoot:root,dsh,work,output})
  assert.deepEqual(await directories(safeWork,safeOutput),{work:await realpath(safeWork),output:safeOutput})
  const childOutput=join(safeWork,'client-dist')
  assert.deepEqual(await directories(safeWork,childOutput),{work:await realpath(safeWork),output:childOutput})
  await assert.rejects(lstat(safeOutput),error=>error.code==='ENOENT','validation must not create output')
  await assert.rejects(lstat(childOutput),error=>error.code==='ENOENT','validation must not create child output')
  const uiAlias=join(fixture,'ui-directory-alias'),dshAlias=join(fixture,'dsh-directory-alias')
  await symlink(relative(dirname(uiAlias),root),uiAlias,'dir')
  await symlink(relative(dirname(dshAlias),dsh),dshAlias,'dir')
  for(const [label,work,output] of [
    ['direct owned UI descendant work',join(root,'prime-authority/owned-work'),safeOutput],
    ['direct owned UI descendant output',safeWork,join(root,'prime-authority/owned-output')],
    ['UI ancestor alias redirects work',join(uiAlias,'prime-authority/owned-work'),safeOutput],
    ['DSH ancestor alias redirects output',safeWork,join(dshAlias,'owned-output')],
    ['same work and output destination',safeWork,safeWork],
    ['work nested inside output destination',join(safeOutput,'nested-work'),safeOutput],
  ]) await refused(label,()=>directories(work,output),directoryCases)
  await verifier.validateDependencyRecords(inputs)
  await verify(inputs)
  await verifier.discoverPinnedWorkspace(dsh)
}
try {
  if(flags.dependenciesOnly) {
    await dependencyChecks()
    console.log(JSON.stringify({result:'PASS',mode:'dependencies-only',fixture:'genuine compiler dependency records and metadata in disposable copies; no new production receipt',
      genuine_receipt_version:receipt.version,killed_dependency_mutations:dependencyCases.length,cases:dependencyCases,
      killed_directory_mutations:directoryCases.length,directory_cases:directoryCases,directory_positive_profiles:2,
      compiler_scripts:'two genuine scripts copied and resolved only; never executed',contained_document_symlink:'PASS',
      source_output_checks:'UNPERFORMED: full genuine rebuilt receipt required',build:false,install:false,runtime:false}))
  } else {
  const source = await snapshotOwnerSources({ uiRoot: ui })
  for (const item of source) {
    await mkdir(dirname(join(root, item.path)), { recursive: true })
    await cp(join(ui, item.path), join(root, item.path))
  }
  await cp(join(ui, 'prime-authority/lib'), join(root, 'prime-authority/lib'), { recursive: true })
  const outputs = await publishedOwnerOutputs(root)
  const save = value => writeFile(receiptPath, JSON.stringify(value))
  await save(receipt)
  assert.equal((await verifyOwnerBuild({ uiRoot: root })).result, 'PASS')
  let killed = 0
  for (const path of ['prime-authority/src/client/OwnerSurface.tsx', 'scripts/build-client.mjs', 'prime-authority/lib/client.js', 'prime-authority/lib/types/client/index.d.ts']) {
    const original = await readFile(join(root, path))
    await writeFile(join(root, path), Buffer.concat([original, Buffer.from('\n// altered verifier fixture\n')]))
    await assert.rejects(verifyOwnerBuild({ uiRoot: root }), /source-input-mismatch|output-artifact-mismatch/)
    await writeFile(join(root, path), original)
    killed++
  }
  const bundlePath = join(root, 'prime-authority/lib/client.js')
  const bundle = await readFile(bundlePath)
  await rm(bundlePath)
  await assert.rejects(verifyOwnerBuild({ uiRoot: root }), /ENOENT/)
  await writeFile(bundlePath, bundle)
  killed++
  await rm(receiptPath)
  await assert.rejects(verifyOwnerBuild({ uiRoot: root }), /ENOENT/)
  await save(receipt)
  killed++
  const missingSource = structuredClone(receipt)
  missingSource.owner_build.source_inputs = missingSource.owner_build.source_inputs.filter(item => item.path !== 'prime-authority/src/client/OwnerSurface.tsx')
  await save(missingSource)
  await assert.rejects(verifyOwnerBuild({ uiRoot: root }), /source-input-mismatch/)
  killed++
  await save({ ...receipt, source_commit_attribution: 'Prime source' })
  await assert.rejects(verifyOwnerBuild({ uiRoot: root }), /upstream-attribution-mismatch/)
  killed++
  await save(receipt)
  assert.equal((await verifyOwnerBuild({ uiRoot: root })).result, 'PASS')
  if(flags.dsh) await dependencyChecks()
  console.log(JSON.stringify({ result: 'PASS', fixture: 'genuine compiler receipt/files in disposable copies; no runtime claim', killed_mutations: killed,
    cases: ['owner source', 'recipe', 'client bundle', 'published type', 'missing bundle', 'missing receipt', 'omitted source', 'false source attribution'],
    source_inputs: source.length, output_artifacts: outputs.length, killed_dependency_mutations:dependencyCases.length,
    killed_directory_mutations:directoryCases.length,directory_cases:directoryCases,
    dependency_cases:dependencyCases,dependency_checks:flags.dsh?'PASS':'UNPERFORMED: --dsh required',live_effects: false }))
  }
} finally {
  await rm(fixture, { recursive: true, force: true })
}
