// SPDX-License-Identifier: AGPL-3.0-or-later
// TEST ONLY: permits a disposable mutable same-UID config to exercise actual
// worker factories. Never import from production or use as an installed entry.
import {lstat,realpath} from 'node:fs/promises'
import {resolve} from 'node:path'
import {pathToFileURL} from 'node:url'
import {startWorker} from '../src/worker.mjs'
const args=process.argv.slice(2)
if(args.length!==2||args[0]!=='--config'||resolve(args[1])!==args[1])throw new TypeError('TEST_ONLY_CONFIG_REQUIRED')
const stat=await lstat(args[1])
if(!stat.isFile()||stat.isSymbolicLink()||await realpath(args[1])!==args[1]||(stat.mode&0o7777)!==0o600||stat.uid!==process.getuid())throw new TypeError('TEST_ONLY_PRIVATE_CONFIG_REQUIRED')
const worker=await startWorker((await import(pathToFileURL(args[1]).href)).default)
process.stdout.write(JSON.stringify({status:'STARTED',loader:'test-only',...worker.status()})+'\n')
let closing=false
const stop=async()=>{if(closing)return;closing=true;await worker.close();process.exit(0)}
process.once('SIGTERM',stop);process.once('SIGINT',stop)
