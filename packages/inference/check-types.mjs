// SPDX-License-Identifier: AGPL-3.0-or-later
// Compile both static type fixtures only with installed local compiler and types.
import {createRequire} from 'node:module'
import {spawnSync} from 'node:child_process'
import {fileURLToPath} from 'node:url'

const require=createRequire(import.meta.url)
let compiler
try {
  compiler=require.resolve('typescript/bin/tsc')
  require.resolve('@types/node/package.json')
  require.resolve('@aukora-prime/contracts')
  require.resolve('@aukora-prime/inference')
} catch(error) {
  if(error.code!=='MODULE_NOT_FOUND')throw error
  console.log('UNPERFORMED: installed TypeScript compiler, Node types and local workspace packages are required')
  process.exit(2)
}
const result=spawnSync(process.execPath,[compiler,'--noEmit','--strict','--target','ES2023',
  '--module','NodeNext','--moduleResolution','NodeNext','--skipLibCheck',
  'check-worker-types.mts','check-private-transport-types.mts'],
  {cwd:fileURLToPath(new URL('.',import.meta.url)),stdio:'inherit'})
if(result.error||result.signal)throw Error('TYPE_CHECK_CHILD_FAILED')
process.exitCode=result.status
