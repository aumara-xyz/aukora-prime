// SPDX-License-Identifier: AGPL-3.0-or-later
// Missing prerequisites cannot report PASS or hide a failed child.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync,mkdtempSync,writeFileSync,rmSync} from 'node:fs'
import {spawnSync} from 'node:child_process'
import {fileURLToPath} from 'node:url'
import {join} from 'node:path'
import {main,childStatus} from './check-unregistered.mjs'

const root=fileURLToPath(new URL('../../',import.meta.url))
const run=(file,args=[],env=process.env)=>spawnSync(process.execPath,[file,...args],
  {cwd:root,env,encoding:'utf8',timeout:10000})
const missing=[
  ['packages/desktop/check.cjs',[],"if (!process.versions.electron ||"],
  ['packages/execution/checks/profile-sdk.mjs',[],"if(process.argv.length===2) {"],
  ['packages/execution/checks/effective-policy.mjs',[],"if(!sdk) {"],
  ['packages/runtime-bridge/test/verify-owner-memory-source-join.mjs',[],"if(args.length===0) {"],
  ['packages/runtime-bridge/test/verify-owner-recovery-source-join.mjs',[],"if(args.length===0) {"],
]

test('fixed missing prerequisites print one named gap and exit 2',()=>{
  const env={...process.env};delete env.PRIME_OPEN_SHELL_SDK_DIR
  for(const [file,args] of missing) {
    const result=run(file,args,env)
    assert.equal(result.status,2,file)
    assert.match(result.stdout,/^UNPERFORMED: [^\n]+\n$/,file)
    assert.equal(result.stderr,'',file)
  }
})

test('refused selection and failed child cannot become a missing-prerequisite pass',async()=>{
  await assert.rejects(main(['../outside.mjs']),/CHECK_PATH_REFUSED/)
  await assert.rejects(main([]),/CHECK_PATH_REFUSED/)
  for(const status of [0,1,2,137])assert.equal(childStatus({status}),status)
  for(const result of [{status:null},{status:0,error:Error('synthetic')},{status:0,signal:'SIGTERM'}])
    assert.throws(()=>childStatus(result),/CHECK_CHILD_FAILED/)
})

test('removing each missing-prerequisite guard fails its exit-2 regression',()=>{
  const env={...process.env};delete env.PRIME_OPEN_SHELL_SDK_DIR
  const temporary=mkdtempSync(join(root,'.check-prerequisite-mutants-'))
  try {
    for(const [file,args,guard] of missing) {
      const source=readFileSync(join(root,file),'utf8'),start=source.indexOf(guard)
      assert.notEqual(start,-1,file)
      const end=source.indexOf('\n}',start)+2
      assert(end>start,file)
      const mutant=source.slice(0,start)+'if(false) {'+source.slice(source.indexOf('\n',start),end)+source.slice(end)
      // Preserve relative source imports while using only the disposable copy.
      const path=join(temporary,file.endsWith('.cjs')?'mutant.cjs':'mutant.mjs')
      const relative=source.matchAll(/from ['"](\.[^'"]+)['"]/g)
      let text=mutant
      for(const match of relative)text=text.replace(match[0],match[0].replace(match[1],new URL(match[1],new URL(file,new URL('../../',import.meta.url))).href))
      writeFileSync(path,text)
      const result=run(path,args,env)
      assert.notEqual(result.status,2,file+' missing guard survived')
      assert.notEqual(result.status,0,file+' missing guard became PASS')
    }
  } finally {rmSync(temporary,{recursive:true,force:true})}
  console.log('PASS 5 missing-prerequisite guard mutations killed')
})


test('type fixture compiler absence is a named gap; removing it fails the control',()=>{
  const temporary=mkdtempSync(join(root,'.check-types-mutants-'))
  try {
    const path=join(temporary,'types.mjs')
    const source=readFileSync(join(root,'packages/inference/check-types.mjs'),'utf8')
      .replace("require.resolve('typescript/bin/tsc')","require.resolve('./absent-compiler.cjs')")
    writeFileSync(path,source)
    const baseline=run(path);assert.equal(baseline.status,2)
    assert.match(baseline.stdout,/^UNPERFORMED: [^\n]+\n$/)
    const guard="  console.log('UNPERFORMED: installed TypeScript compiler, Node types and local workspace packages are required')\n  process.exit(2)"
    assert.equal(source.split(guard).length,2)
    writeFileSync(path,source.replace(guard,'  throw error'))
    const mutant=run(path);assert.equal(mutant.status,1)
    assert.match(mutant.stderr,/MODULE_NOT_FOUND/)
  } finally {rmSync(temporary,{recursive:true,force:true})}
  console.log('PASS missing-compiler guard mutation killed')
})

test('type compiler interruption and failure cannot report success',()=>{
  const temporary=mkdtempSync(join(root,'.check-type-child-'))
  try {
    const source=readFileSync(join(root,'packages/inference/check-types.mjs'),'utf8')
    const path=join(temporary,'types.mjs')
    const invoke=result=>spawnSync(process.execPath,['--input-type=module','-e',
      "const modules=await import('node:module');const child=await import('node:child_process');"+
      "modules.default.createRequire=()=>({resolve:()=>'/unused/synthetic-compiler'});"+
      "child.default.spawnSync=()=> ("+JSON.stringify(result)+");modules.syncBuiltinESMExports();await import("+
      JSON.stringify(new URL('file://'+path).href)+");"],{cwd:root,encoding:'utf8',timeout:10000})
    for(const [result,guard,replacement] of [
      [{status:0,signal:'SIGTERM'},"if(result.error||result.signal)throw Error('TYPE_CHECK_CHILD_FAILED')",''],
      [{status:1},'process.exitCode=result.status','process.exitCode=0'],
    ]) {
      assert.equal(source.split(guard).length,2)
      writeFileSync(path,source)
      const baseline=invoke(result)
      assert.equal(baseline.status,1,'baseline must refuse interrupted or failed compilation')
      if(result.signal)assert.match(baseline.stderr,/TYPE_CHECK_CHILD_FAILED/)
      else assert.equal(baseline.stderr,'')
      writeFileSync(path,source.replace(guard,replacement))
      assert.throws(()=>assert.equal(invoke(result).status,1),{code:'ERR_ASSERTION'})
    }
  } finally {rmSync(temporary,{recursive:true,force:true})}
  console.log('PASS 2 type compiler child guard mutations killed')
})

test('path refusal and child failure propagation mutations fail their controls',()=>{
  const temporary=mkdtempSync(join(root,'.check-wrapper-mutants-'))
  try {
    const source=readFileSync(join(root,'packages/ops/check-unregistered.mjs'),'utf8')
    for(const [guard,replacement,control] of [
      ["if(args.length!==1||!checks.has(args[0]))throw Error('CHECK_PATH_REFUSED')",'',
        "await assert.rejects(m.main([]),/CHECK_PATH_REFUSED/)"],
      ['return result.status','return 0',"assert.equal(m.childStatus({status:1}),1)"],
      ["if(result.error||result.signal||!Number.isInteger(result.status))throw Error('CHECK_CHILD_FAILED')",'',
        "assert.throws(()=>m.childStatus({status:0,signal:'SIGTERM'}),/CHECK_CHILD_FAILED/)"],
      ["if(!['EPERM','EACCES'].includes(error.code))throw error",'',
        "const net=await import('node:net');const {EventEmitter}=await import('node:events');const modules=await import('node:module');net.default.createServer=()=>{const server=new EventEmitter();server.listen=()=>setImmediate(()=>server.emit('error',Object.assign(Error('synthetic listener defect'),{code:'EADDRINUSE'})));return server};modules.syncBuiltinESMExports();await assert.rejects(m.main(['packages/ops/check-external-state.mjs']),e=>e.code==='EADDRINUSE')"],
    ]) {
      assert.equal(source.split(guard).length,2)
      const path=join(temporary,'wrapper.mjs');writeFileSync(path,source.replace(guard,replacement))
      const answer=spawnSync(process.execPath,['--input-type=module','-e',
        "import assert from 'node:assert/strict';const m=await import("+JSON.stringify(new URL('file://'+path).href)+");"+control],
        {cwd:root,encoding:'utf8',timeout:10000})
      assert.equal(answer.status,1);assert.match(answer.stderr,/AssertionError/)
    }
  } finally {rmSync(temporary,{recursive:true,force:true})}
  console.log('PASS 4 wrapper guard mutations killed')
})

test('unexpected compiler or workspace lookup errors cannot become named gaps',()=>{
  const temporary=mkdtempSync(join(root,'.check-lookup-mutants-'))
  try {
    for(const file of ['packages/inference/check-types.mjs','packages/ops/check-unregistered.mjs']) {
      const source=readFileSync(join(root,file),'utf8')
      const guard="if(error.code!=='MODULE_NOT_FOUND')throw error"
      assert.equal(source.split(guard).length,2)
      const path=join(temporary,'lookup.mjs')
      const invoke="const builtin=await import('node:module');builtin.default.createRequire=()=>({resolve(){throw Object.assign(Error('synthetic lookup failure'),{code:'EACCES'})}});builtin.syncBuiltinESMExports();const m=await import("+
        JSON.stringify(new URL('file://'+path).href)+");"+
        (file.includes('/ops/')?"process.exitCode=await m.main(['packages/runtime-bridge/checks/inference-real-authority.test.mjs'])":"")
      const runLookup=()=>spawnSync(process.execPath,['--input-type=module','-e',invoke],
        {cwd:root,encoding:'utf8',timeout:10000})
      writeFileSync(path,source)
      const baseline=runLookup();assert.equal(baseline.status,1);assert.match(baseline.stderr,/EACCES/)
      writeFileSync(path,source.replace(guard,''))
      const mutant=runLookup();assert.equal(mutant.status,2)
      assert.match(mutant.stdout,/^UNPERFORMED:/)
    }
  } finally {rmSync(temporary,{recursive:true,force:true})}
  console.log('PASS 2 module lookup classification guard mutations killed')
})

test('an explicitly absent SDK reports its named gap; removing the file guard fails the control',()=>{
  const temporary=mkdtempSync(join(root,'.check-sdk-mutants-'))
  try {
    const file='packages/execution/checks/effective-policy.mjs',path=join(temporary,'sdk.mjs')
    const source=readFileSync(join(root,file),'utf8').replace(/(from ['"])(\.[^'"]+)(['"])/g,
      (_,before,specifier,after)=>before+new URL(specifier,new URL(file,new URL('../../',import.meta.url))).href+after)
    const guard="    if(!existsSync(join(sdk,'node_modules/@bufbuild/protobuf/dist/esm/index.js'))||!existsSync(join(sdk,'dist/raw.js'))) {\n      console.log('UNPERFORMED: built pinned OpenShell SDK with protobuf dependency is absent')\n      process.exit(2)\n    }"
    assert.equal(source.split(guard).length,2)
    const env={...process.env,PRIME_OPEN_SHELL_SDK_DIR:join(temporary,'absent-sdk')}
    const control=result=>{
      assert.equal(result.status,2)
      assert.equal(result.stdout,'UNPERFORMED: built pinned OpenShell SDK with protobuf dependency is absent\n')
      assert.equal(result.stderr,'')
    }
    writeFileSync(path,source);control(run(path,['sdk_vectors'],env))
    writeFileSync(path,source.replace(guard,''))
    const mutant=run(path,['sdk_vectors'],env)
    assert.throws(()=>control(mutant),{code:'ERR_ASSERTION'})
    assert.match(mutant.stderr,/ERR_MODULE_NOT_FOUND/)
    assert(mutant.stderr.includes(join(env.PRIME_OPEN_SHELL_SDK_DIR,'node_modules/@bufbuild/protobuf/dist/esm/index.js')))
  } finally {rmSync(temporary,{recursive:true,force:true})}
  console.log('PASS explicit absent-SDK file guard mutation killed')
})

test('expected listener refusals and an absent helper report gaps; removing reporting fails the controls',()=>{
  const temporary=mkdtempSync(join(root,'.check-expected-gap-mutants-'))
  try {
    const source=readFileSync(join(root,'packages/ops/check-unregistered.mjs'),'utf8')
    const listener="    console.log(`UNPERFORMED: local listen() is refused (${error.code})`)\n    return 2"
    const helper="      console.log('UNPERFORMED: installed local inference workspace helper is absent')\n      return 2"
    const setup="const net=await import('node:net');const child=await import('node:child_process');const modules=await import('node:module');const {EventEmitter}=await import('node:events');let dispatched=0;child.default.spawnSync=()=>{dispatched++;return {status:0}};"
    for(const code of ['EPERM','EACCES','MODULE_NOT_FOUND']) {
      const absent=code==='MODULE_NOT_FOUND',guard=absent?helper:listener
      assert.equal(source.split(guard).length,2)
      const path=join(temporary,'wrapper.mjs')
      const mock=absent
        ? "modules.default.createRequire=()=>({resolve(specifier){assert.equal(specifier,'@aukora-prime/inference/budget-binding');throw Object.assign(Error('synthetic absent helper'),{code:'MODULE_NOT_FOUND'})}});net.default.createServer=()=>{const server=new EventEmitter();server.listen=(_port,_host,ready)=>setImmediate(ready);server.close=done=>done();return server};"
        : "net.default.createServer=()=>{const server=new EventEmitter();server.listen=()=>setImmediate(()=>server.emit('error',Object.assign(Error('synthetic listener refusal'),{code:"+JSON.stringify(code)+"})));return server};"
      const expected=absent?'UNPERFORMED: installed local inference workspace helper is absent':`UNPERFORMED: local listen() is refused (${code})`
      const selected=absent?'packages/runtime-bridge/checks/inference-real-authority.test.mjs':'packages/ops/check-external-state.mjs'
      const invoke="import assert from 'node:assert/strict';"+setup+mock+"modules.syncBuiltinESMExports();const m=await import("+JSON.stringify(new URL('file://'+path).href)+");const lines=[];console.log=line=>lines.push(line);assert.equal(await m.main(["+JSON.stringify(selected)+"]),2);assert.deepEqual(lines,["+JSON.stringify(expected)+"]);assert.equal(dispatched,0);"
      const execute=()=>spawnSync(process.execPath,['--input-type=module','-e',invoke],{cwd:root,encoding:'utf8',timeout:10000})
      writeFileSync(path,source)
      const baseline=execute();assert.equal(baseline.status,0,baseline.stderr)
      writeFileSync(path,source.replace(guard,''))
      const mutant=execute();assert.equal(mutant.status,1)
      assert.match(mutant.stderr,/AssertionError/)
      assert.doesNotMatch(mutant.stderr,/ERR_MODULE_NOT_FOUND/)
    }
  } finally {rmSync(temporary,{recursive:true,force:true})}
  console.log('PASS 3 expected listener/helper gap reporting mutations killed')
})
