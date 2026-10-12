// SPDX-License-Identifier: AGPL-3.0-or-later
// Missing selected build inputs report exit 2 instead of a successful check.
import test from 'node:test'
import assert from 'node:assert/strict'
import {mkdtempSync,readFileSync,writeFileSync,rmSync,readdirSync} from 'node:fs'
import {dirname,join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {spawnSync} from 'node:child_process'

const files = [
  'check-owner-build.mjs','verify-owner-build.mjs','check-provider-settings.mjs',
  '../prime-authority/checks/css-provenance.mjs','../prime-authority/checks/css-reproduction.mjs',
  '../prime-authority/checks/inference-native-join.mjs','../prime-authority/checks/native-join.mjs',
  '../prime-authority/checks/ordinary-lifecycle.mjs','../prime-authority/checks/ordinary-render.mjs',
  '../prime-authority/checks/pilot-render.mjs','../prime-authority/checks/render.mjs',
  '../prime-authority/checks/render-fixture.mjs','../prime-authority/checks/serve-fixture.mjs',
]
for(const file of files)test(`${file}: missing selected input and mutation`,()=>{
  const url=new URL(file,import.meta.url),source=readFileSync(url,'utf8')
  const directory=mkdtempSync(join(dirname(fileURLToPath(url)),'.prerequisite-'))
  const program=join(dirname(fileURLToPath(url)),`.prerequisite-${directory.split('/').at(-1)}.mjs`)
  try {
    const run=bytes=>{
      writeFileSync(program,bytes)
      return spawnSync(process.execPath,[program],{encoding:'utf8',timeout:10000,env:{...process.env,NODE_NO_WARNINGS:'1'}})
    }
    const expected=result=>{
      assert.equal(result.status,2,result.stderr)
      assert.match(result.stdout,/^UNPERFORMED: [^\n]+\n$/)
    }
    assert.ok(source.includes('process.exit(2)'))
    expected(run(source))
    assert.throws(()=>expected(run(source.replaceAll('process.exit(2)','process.exit(0)'))),{name:'AssertionError'})
    const guard=source.match(/^[^\n]*(?:if|for)[^\n]*\{\n[ \t]*console\.log\('UNPERFORMED: [^'\n]*'\)\n[ \t]*process\.exit\(2\)\n[ \t]*\}/m)
    assert.ok(guard,'missing-input guard must be removable')
    assert.throws(()=>expected(run(source.replace(guard[0],''))),{name:'AssertionError'})
  } finally {rmSync(program,{force:true});rmSync(directory,{recursive:true,force:true})}
})

test('dependency-only owner check requires an explicitly selected harness and kills its removal',()=>{
  const url=new URL('check-owner-build.mjs',import.meta.url),source=readFileSync(url,'utf8')
  const directory=mkdtempSync(join(dirname(fileURLToPath(url)),'.dependency-prerequisite-'))
  const program=join(dirname(fileURLToPath(url)),`.dependency-prerequisite-${directory.split('/').at(-1)}.mjs`)
  try {
    const run=bytes=>{
      writeFileSync(program,bytes)
      return spawnSync(process.execPath,[program,'--ui',fileURLToPath(new URL('../',import.meta.url)),'--dependencies-only'],{encoding:'utf8',timeout:10000})
    }
    const expected=result=>{
      assert.equal(result.status,2,result.stderr)
      assert.match(result.stdout,/^UNPERFORMED: pinned harness dependency inputs required \(--dsh\)\n$/)
    }
    expected(run(source))
    const mutant=source.replace('flags.dependenciesOnly && !flags.dsh','false')
    assert.notEqual(mutant,source)
    assert.throws(()=>expected(run(mutant)),{name:'AssertionError'})
  } finally {rmSync(program,{force:true});rmSync(directory,{recursive:true,force:true})}
})

test('carried TypeScript tests report absent Vitest and forward every selected path to its CLI',()=>{
  const url=new URL('../../../plugins/aukora-face/apps/scripts/check-vendor-tests.mjs',import.meta.url)
  const source=readFileSync(url,'utf8'),root=fileURLToPath(new URL('../',url))
  const fixture=mkdtempSync(join(dirname(fileURLToPath(import.meta.url)),'.vendor-test-tool-'))
  const manifest=join(fixture,'package.json')
  const run=(bytes,selected)=>{
    const anchor="const require = createRequire(join(root, 'package.json'))"
    assert.ok(bytes.includes(anchor))
    bytes=bytes.replace(anchor,selected
      ? `const require = { resolve: () => ${JSON.stringify(selected)} }`
      : "const require = { resolve: () => { throw Object.assign(Error('absent fixture tooling'), { code: 'MODULE_NOT_FOUND' }) } }")
      .replaceAll('import.meta.url',JSON.stringify(url.href))
    return spawnSync(process.execPath,['--input-type=module','-e',bytes],{encoding:'utf8',timeout:10000})
  }
  const expected=result=>{
    assert.equal(result.status,2,result.stdout+result.stderr)
    assert.match(result.stdout,/^UNPERFORMED: installed Vitest absent for 20 carried TypeScript tests\n$/)
  }
  try {
    expected(run(source))
    assert.throws(()=>expected(run(source.replace('process.exit(2)','process.exit(0)'))),{name:'AssertionError'})
    const paths=['vendor/auma-lingwa/tooling/core/tests','vendor/auma-live/original-closure/core/tests']
      .flatMap(directory=>readdirSync(join(root,directory)).filter(name=>name.endsWith('.test.ts')).sort().map(name=>join(root,directory,name)))
    assert.equal(paths.length,20)
    writeFileSync(manifest,JSON.stringify({bin:'cli.mjs'}))
    writeFileSync(join(fixture,'cli.mjs'),`import assert from 'node:assert/strict'; assert.deepEqual(process.argv.slice(2),${JSON.stringify(['run',...paths])}); console.log('PASS Vitest CLI received 20 carried tests')\n`)
    const result=run(source,manifest)
    assert.equal(result.status,0,result.stdout+result.stderr)
    assert.match(result.stdout,/PASS Vitest CLI received 20 carried tests/)
    const mutant=run(source.replace("[cli, 'run', ...files]","[cli, 'run']"),manifest)
    assert.equal(mutant.status,1,mutant.stdout+mutant.stderr)
  } finally {rmSync(fixture,{recursive:true,force:true})}
})

test('copied declaration check resolves the new TSX type import and its stale-check mutant fails',()=>{
  const url=new URL('check-owner-types.mjs',import.meta.url),source=readFileSync(url,'utf8')
  const directory=mkdtempSync(join(dirname(fileURLToPath(url)),'.type-regression-'))
  const program=join(dirname(fileURLToPath(url)),`.type-regression-${directory.split('/').at(-1)}.mjs`)
  try {
    const run=bytes=>{
      writeFileSync(program,bytes)
      return spawnSync(process.execPath,[program],{encoding:'utf8',timeout:10000})
    }
    assert.equal(run(source).status,0)
    const anchor="name.endsWith('.d.mts')&&!/\\.[a-z]+$/i.test(relative)"
    assert.ok(source.includes(anchor))
    const mutant=run(source.replace(anchor,'false'))
    assert.equal(mutant.status,1)
    assert.match(mutant.stderr,/ENOENT[\s\S]*AumaReplyView/)
  } finally {rmSync(program,{force:true});rmSync(directory,{recursive:true,force:true})}
})
