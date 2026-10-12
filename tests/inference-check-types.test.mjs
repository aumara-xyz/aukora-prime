// SPDX-License-Identifier: AGPL-3.0-or-later
// Check ESM dependency resolution and absent prerequisites before compiler dispatch.
import assert from 'node:assert/strict'
import test from 'node:test'
import {chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync} from 'node:fs'
import {basename, dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {spawnSync} from 'node:child_process'

const repository=fileURLToPath(new URL('..',import.meta.url))
const source=readFileSync(new URL('../packages/inference/check-types.mjs',import.meta.url),'utf8')
const args=['--noEmit','--strict','--target','ES2023','--module','NodeNext',
  '--moduleResolution','NodeNext','--skipLibCheck','check-worker-types.mts','check-private-transport-types.mts']
const contracts=JSON.parse(readFileSync(new URL('../packages/contracts/package.json',import.meta.url),'utf8'))
const inference=JSON.parse(readFileSync(new URL('../packages/inference/package.json',import.meta.url),'utf8'))

function run(text=source,{missing=false,missingPackage=false,broken=false}={}) {
  const mask=process.umask(0o002)
  let root
  try {
    root=mkdtempSync(join(repository,'.inference-types-'))
    chmodSync(root,0o700)
    assert.equal(statSync(root).mode&0o777,0o700)
    const directory=join(root,'packages/inference')
    mkdirSync(directory,{recursive:true,mode:0o700})
    const write=(name,body)=>{
      const path=join(root,name)
      mkdirSync(dirname(path),{recursive:true,mode:0o700})
      writeFileSync(path,body,{mode:0o600})
    }
    // A unique absent name prevents an ancestor's installed dependencies filling the gap.
    if(missingPackage)text=text.replace('typescript/bin/tsc',`test-only-${basename(root)}/bin/tsc`)
    write('packages/inference/check-types.mjs',text)
    write('packages/inference/check-worker-types.mts','// TEST_ONLY worker consumer\n')
    write('packages/inference/check-private-transport-types.mts','// TEST_ONLY private consumer\n')
    write('node_modules/typescript/package.json',JSON.stringify({name:'typescript',type:'module',
      exports:{'./bin/tsc':'./bin/tsc.mjs'}}))
    if(!missing)write('node_modules/typescript/bin/tsc.mjs',
      "console.log('TEST_ONLY_COMPILER '+JSON.stringify(process.argv.slice(2)));\n")
    write('node_modules/@types/node/package.json',JSON.stringify({name:'@types/node'}))
    write('node_modules/@aukora-prime/contracts/package.json',JSON.stringify(broken?
      {...contracts,exports:{'.':{types:'./src/index.ts'}}}:contracts))
    write('node_modules/@aukora-prime/contracts/src/runtime.mjs',"throw Error('TYPES_MUST_NOT_EXECUTE_CONTRACTS');\n")
    write('node_modules/@aukora-prime/inference/package.json',JSON.stringify(inference))
    write('node_modules/@aukora-prime/inference/src/index.mjs',"throw Error('TYPES_MUST_NOT_EXECUTE_INFERENCE');\n")
    const env={...process.env}
    delete env.NODE_OPTIONS
    const child=spawnSync(process.execPath,[join(directory,'check-types.mjs')],
      {cwd:directory,env,encoding:'utf8',timeout:5000})
    assert.equal(child.error,undefined)
    assert.equal(child.signal,null)
    return child
  } finally {
    if(root)rmSync(root,{recursive:true,force:true})
    process.umask(mask)
  }
}

function installed(text=source) {
  const result=run(text)
  assert.equal(result.status,0,'installed import-only contracts must reach the compiler')
  assert.equal(result.stderr,'')
  assert.equal(result.stdout.trim(),'TEST_ONLY_COMPILER '+JSON.stringify(args))
}
function absent(text=source,missingPackage=false) {
  const result=run(text,{missing:true,missingPackage})
  assert.equal(result.status,2,'an absent compiler executable is unperformed')
  assert.match(result.stdout,/^UNPERFORMED: .+required\n$/u)
  assert.equal(result.stderr,'')
  assert.doesNotMatch(result.stdout,/TEST_ONLY_COMPILER/u)
}
test('installed ESM-only contracts resolve before both type consumers compile',()=>installed())
test('a genuinely absent dependency entry reports UNPERFORMED and exits 2',()=>absent())
test('a genuinely absent package reports UNPERFORMED and exits 2',()=>absent(source,true))
test('an installed package with no runtime export remains a failure',()=>{
  const result=run(source,{broken:true})
  assert.equal(result.status,1)
  assert.match(result.stderr,/ERR_PACKAGE_PATH_NOT_EXPORTED/u)
  assert.doesNotMatch(result.stdout,/UNPERFORMED|TEST_ONLY_COMPILER/u)
})
test('mutants are rejected by the same installed and absent regressions',t=>{
  const requireMutation="import {createRequire} from 'node:module'\nconst require=createRequire(import.meta.url)\n"+
    source.replace('fileURLToPath(import.meta.resolve(name))','require.resolve(name)')
  assert.match(run(requireMutation).stderr,/ERR_PACKAGE_PATH_NOT_EXPORTED/u)
  assert.throws(()=>installed(requireMutation),/installed import-only contracts/u)
  assert.throws(()=>absent(source.replace("error.code!=='ERR_MODULE_NOT_FOUND'&&",''),true),/absent compiler/u)
  assert.throws(()=>absent(source.replace("&&error.code!=='ENOENT'",'')),/absent compiler/u)
  assert.throws(()=>absent(source.replace('  accessSync(compiler)\n','')),/absent compiler/u)
  t.diagnostic('4/4 mutants rejected: CommonJS resolution, missing-package reporting, missing-entry reporting, compiler existence')
})
