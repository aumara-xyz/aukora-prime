// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic command arguments and failures cannot print enrollment secrets outside the owner link.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const source = fs.readFileSync(new URL('../bin/browser-passkey-claim.mjs',import.meta.url),'utf8')
const url = text => 'data:text/javascript;base64,' + Buffer.from(text).toString('base64')
const helper = url('export async function mintBrowserPasskeyClaim(args) { return globalThis.__browserClaimBin(args) }')
const link = 'https://owner.example.test/owner/enroll#claim=' + 'x'.repeat(43)
let sequence = 0
async function run(args, text = source, error) {
  const argv = process.argv, write = process.stdout.write, log = console.error, status = process.exitCode
  const stdout = [], stderr = [], calls = []
  process.argv = ['node','synthetic-command',...args]
  process.stdout.write = value => { stdout.push(value); return true }
  console.error = value => stderr.push(value)
  globalThis.__browserClaimBin = input => { calls.push(input); if(error) throw error; return link }
  try { await import(url(text.replace("'../src/browser-passkey-claim.mjs'",JSON.stringify(helper))+'\n// '+ ++sequence)); return {stdout,stderr,calls,status:process.exitCode} }
  finally { process.argv=argv;process.stdout.write=write;console.error=log;process.exitCode=status;delete globalThis.__browserClaimBin }
}
const args = ['--owner-origin','https://owner.example.test','--app-origin','https://app.example.test','--release','/synthetic/release']

test('browser-passkey-claim.mjs accepts three unique options and prints only one owner link', async()=>{
  const result = await run(args)
  assert.deepEqual(result.stdout,[link+'\n']); assert.deepEqual(result.stderr,[])
  assert.deepEqual(result.calls,[{ownerOrigin:'https://owner.example.test',appOrigin:'https://app.example.test',release:'/synthetic/release'}])
})
test('missing, extra, duplicate and positional command arguments refuse without minting', async()=>{
  for (const bad of [args.slice(0,4),[...args,'--release','/other'],['--owner-origin','https://owner.example.test','--owner-origin','https://owner.example.test','--release','/synthetic/release'],[...args,'extra'],[...args,'--unknown','input']]) {
    const result=await run(bad);assert.deepEqual(result.calls,[]);assert.deepEqual(result.stdout,[]);assert.deepEqual(result.stderr,['browser-passkey:refused']);assert.equal(result.status,1)
  }
})
test('command failures print fixed refusal codes without secret-bearing error messages',async()=>{
  for(const error of [new Error('synthetic-secret'),Object.assign(new Error('synthetic-secret'),{code:'browser-passkey:enrollment-closed'}),Object.assign(new Error('synthetic-secret'),{code:'secret-error-code'})]){
    const result=await run(args,source,error);assert.deepEqual(result.stdout,[]);assert.deepEqual(result.stderr,[error.code==='browser-passkey:enrollment-closed'?error.code:'browser-passkey:refused']);assert.equal(result.status,1)
  }
})
if(process.argv.includes('--mutations')) test('browser-passkey-claim.mjs command mutations fail their focused assertions',async t=>{
  const mutations=[
    ['unique options',"tokens.filter(t => t.kind === 'option' && t.name === name).length !== 1",'false',async text=>{const r=await run(['--owner-origin','https://owner.example.test','--owner-origin','https://owner.example.test','--release','/synthetic/release'],text);assert.deepEqual(r.calls,[])}],
    ['single link output',"process.stdout.write(link + '\\n')","process.stdout.write(JSON.stringify({link}) + '\\n')",async text=>{const r=await run(args,text);assert.deepEqual(r.stdout,[link+'\n'])}],
    ['fixed refusal',"'browser-passkey:refused')",'error.message)',async text=>{const r=await run(args,text,new Error('synthetic-secret'));assert.deepEqual(r.stderr,['browser-passkey:refused'])}],
    ['refusal namespace',"error.code.startsWith('browser-passkey:')",'true',async text=>{const r=await run(args,text,Object.assign(new Error('synthetic-secret'),{code:'secret-error-code'}));assert.deepEqual(r.stderr,['browser-passkey:refused'])}],
  ]
  for(const [name,before,after,exercise] of mutations){assert.ok(source.includes(before),name);await assert.rejects(()=>exercise(source.replace(before,after)),assert.AssertionError)}
  t.diagnostic(`SOURCE-ONLY browser-passkey-claim command mutations: ${mutations.length}/${mutations.length} KILLED; 0 SURVIVED`)
})
