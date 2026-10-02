// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit host-launched executable. Not imported/mounted by the application.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { closed } from './registration.mjs'
import { decodeMessage } from './ipc.mjs'
import { GuardianStore,privatePath } from './store.mjs'
import { startGuardian } from './worker.mjs'
import { PinnedGuardianBackend } from './pinned-backend.mjs'
import { loadPinnedSdk } from '../load-sdk.mjs'

if(process.argv.length!==3)throw new Error('usage: node process.mjs <protected-config.json>')
const configPath=process.argv[2];privatePath(configPath)
const configBytes=readFileSync(configPath)
if(configBytes.length>65536)throw new Error('guardian config bound exceeded')
const config=decodeMessage(configBytes)
closed(config,['version','store_root','scope','poll_ms','control_timeout_ms','sdk_root','connect_options'])
if(config.version!==1||config.connect_options.gateway!==config.scope.gateway_identity)throw new Error('guardian config binding differs')
// Existing provisioned state only; missing state cannot silently reset custody.
const store=new GuardianStore(config.store_root,{scope:config.scope})
const {transport}=await loadPinnedSdk(config.sdk_root,config.connect_options)
await store.withOwner(async()=>{
  const service=await startGuardian({store,backend:new PinnedGuardianBackend(transport,store.scope),socketPath:join(store.root,'guardian.sock'),pollMs:config.poll_ms,controlTimeoutMs:config.control_timeout_ms})
  process.stdout.write('guardian ready; runtime unavailable\n')
  const stop=await new Promise(resolve=>{const handler=()=>resolve(handler);process.once('SIGTERM',handler);process.once('SIGINT',handler)})
  process.removeListener('SIGTERM',stop);process.removeListener('SIGINT',stop)
  await service.close()
})
store.close()
