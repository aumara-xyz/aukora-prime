// SPDX-License-Identifier: AGPL-3.0-or-later
// Run fixed local-listener checks; missing permissions are explicit gaps.
import {createServer} from 'node:net'
import {createRequire} from 'node:module'
import {spawnSync} from 'node:child_process'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {resolve} from 'node:path'

const root=fileURLToPath(new URL('../../',import.meta.url))
const checks=new Map([
  ['packages/ops/check-external-state.mjs',[]],
  ['packages/execution/checks/guardian-process.mjs',[]],
  ['packages/runtime-bridge/checks/inference-boundary.test.mjs',['--test','--test-reporter=tap']],
  ['packages/runtime-bridge/checks/inference-real-authority.test.mjs',['--test','--test-reporter=tap']],
  ['packages/runtime-bridge/test/inference-ipc.test.mjs',['--test','--test-reporter=tap']],
])

export function childStatus(result) {
  if(result.error||result.signal||!Number.isInteger(result.status))throw Error('CHECK_CHILD_FAILED')
  return result.status
}

async function localListen() {
  const server=createServer()
  return await new Promise((resolve,reject)=>{
    server.once('error',reject)
    server.listen(0,'127.0.0.1',()=>server.close(error=>error?reject(error):resolve()))
  })
}

export async function main(args) {
  if(args.length!==1||!checks.has(args[0]))throw Error('CHECK_PATH_REFUSED')
  const file=args[0]
  if(file==='packages/runtime-bridge/checks/inference-real-authority.test.mjs') {
    try {createRequire(pathToFileURL(resolve(root,file))).resolve('@aukora-prime/inference/budget-binding')}
    catch(error) {
      if(error.code!=='MODULE_NOT_FOUND')throw error
      console.log('UNPERFORMED: installed local inference workspace helper is absent')
      return 2
    }
  }
  try {await localListen()}
  catch(error) {
    if(!['EPERM','EACCES'].includes(error.code))throw error
    console.log(`UNPERFORMED: local listen() is refused (${error.code})`)
    return 2
  }
  return childStatus(spawnSync(process.execPath,[...checks.get(file),file],{cwd:root,stdio:'inherit'}))
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {process.exitCode=await main(process.argv.slice(2))}
  catch(error) {console.error(error.message);process.exitCode=1}
}
