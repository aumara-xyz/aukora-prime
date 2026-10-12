// SPDX-License-Identifier: AGPL-3.0-or-later
// Compile both static type fixtures only with installed local compiler and types.
import {accessSync} from 'node:fs'
import {spawnSync} from 'node:child_process'
import {fileURLToPath} from 'node:url'

let compiler
try {
  compiler=fileURLToPath(import.meta.resolve('typescript/bin/tsc'))
  for(const name of ['@types/node/package.json','@aukora-prime/contracts','@aukora-prime/inference'])
    accessSync(fileURLToPath(import.meta.resolve(name)))
  accessSync(compiler)
} catch(error) {
  if(error.code!=='ERR_MODULE_NOT_FOUND'&&error.code!=='ENOENT')throw error
  console.log('UNPERFORMED: installed TypeScript compiler, Node types and local workspace packages are required')
  process.exit(2)
}
const result=spawnSync(process.execPath,[compiler,'--noEmit','--strict','--target','ES2023',
  '--module','NodeNext','--moduleResolution','NodeNext','--skipLibCheck',
  'check-worker-types.mts','check-private-transport-types.mts'],
  {cwd:fileURLToPath(new URL('.',import.meta.url)),stdio:'inherit'})
if(result.error||result.signal)throw Error('TYPE_CHECK_CHILD_FAILED')
process.exitCode=result.status
