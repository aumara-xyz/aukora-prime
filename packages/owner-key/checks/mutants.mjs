// SPDX-License-Identifier: AGPL-3.0-or-later
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
const loader=fileURLToPath(new URL('./mutant-loader.mjs',import.meta.url))
const test=fileURLToPath(new URL('./owner-key.test.mjs',import.meta.url))
let failures=0
for(const name of ['signature','expiry','challenge','expectations','wire','consume']) {
  const result=spawnSync(process.execPath,['--import',loader,'--test','--test-reporter=spec',test],
    {env:{PATH:'/usr/bin:/bin',AUKORA_OWNER_KEY_MUTANT:name},encoding:'utf8',timeout:5000,maxBuffer:1048576})
  const completed=/tests 6/u.test(result.stdout??'')
  const killed=!result.error&&result.signal===null&&result.status===1&&completed&&/fail [1-6]/u.test(result.stdout??'')
  console.log(`${killed?'KILLED':'UNQUALIFIED'} ${name}`)
  if(!killed) failures++
}
if(failures)process.exitCode=1
