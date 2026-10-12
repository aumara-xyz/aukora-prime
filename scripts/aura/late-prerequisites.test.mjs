// SPDX-License-Identifier: AGPL-3.0-or-later
// Missing selected organism inputs report exit 2 before installed-state access.
import test from 'node:test'
import assert from 'node:assert/strict'
import {mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs'
import {dirname,join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {spawnSync} from 'node:child_process'

const cases=[
  ['../organism-live.sh',[],"  printf '%s\\n' 'UNPERFORMED: readable launch record required for organism-live'\n  exit 2"],
  ['../organism-accept.sh',['--release','/dev/null/unselected-release'],
    '    say "UNPERFORMED: explicitly selected existing release required for organism acceptance"\n    exit 2'],
  ['organism-breath.sh',['--state','/dev/null/unselected-store','--subject','aukora:1:'+'1'.repeat(64)],
    "  trap - EXIT\n  printf '%s\\n' 'UNPERFORMED: explicitly selected readable Kira store required for organism breath'\n  exit 2"],
  ['echo-head.mjs',['/dev/null/unselected-aura.jsonl'],"    process.stdout.write('UNPERFORMED: readable Aura chain required for disposable Echo verification\\n')\n    process.exit(2)"],
]
for(const[file,args,guard]of cases)test(`${file}: missing input and guard removal`,()=>{
  const url=new URL(file,import.meta.url),source=readFileSync(url,'utf8')
  const folder=mkdtempSync(join(dirname(fileURLToPath(url)),'.late-prerequisite-'))
  const program=join(dirname(fileURLToPath(url)),`${folder.split('/').at(-1)}${file.endsWith('.mjs')?'.mjs':'.sh'}`)
  const env={...process.env,TMPDIR:folder,AUKORA_LIVE_STATE:'/dev/null/unselected-launch',
    AUKORA_HOME:folder,AUKORA_OVERLAY:'/dev/null/unselected-overlay',AUKORA_CONFIG:'/dev/null/unselected-config',
    AUKORA_ACCEPT_NODE:'/dev/null/unselected-node'}
  delete env.NODE_OPTIONS
  try{
    assert.equal(source.split(guard).length,2,'unique prerequisite guard')
    const run=body=>{
      writeFileSync(program,body)
      return spawnSync(file.endsWith('.mjs')?process.execPath:'bash',[program,...args],{
        encoding:'utf8',env,timeout:10000,maxBuffer:1024*1024})
    }
    const expected=result=>{
      assert.equal(result.error,undefined)
      assert.equal(result.signal,null)
      assert.equal(result.status,2,result.stderr)
      assert.match(result.stdout,/^UNPERFORMED: [^\n]+\n$/)
      assert.equal(result.stderr,'')
    }
    expected(run(source))
    const mutant=run(source.replace(guard,file.endsWith('.mjs')?'':'  :'))
    assert.doesNotMatch(mutant.stderr,/syntax error|SyntaxError/)
    assert.throws(()=>expected(mutant),{name:'AssertionError'})
  }finally{rmSync(program,{force:true});rmSync(folder,{recursive:true,force:true})}
})
