// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify planned wire fields against the actual source-built protobuf SDK.
// Explicit local SDK directory only. No client, credentials or RPC is created.
import assert from 'node:assert/strict'
import { resolve,join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { readFileSync } from 'node:fs'
import { proposedCreateTemplate } from '../runtime/pilot-profile.mjs'

if(process.argv.length!==3)throw new Error('usage: node checks/profile-sdk.mjs /path/to/pinned/sdk/typescript')
const sdk=resolve(process.argv[2]),pkg=JSON.parse(readFileSync(join(sdk,'package.json'),'utf8'))
assert.equal(pkg.name,'@nvidia/openshell-sdk');assert.equal(pkg.version,'0.0.0')
const protobuf=await import(pathToFileURL(join(sdk,'node_modules/@bufbuild/protobuf/dist/esm/index.js')).href)
const schemas=await import(pathToFileURL(join(sdk,'dist/gen/openshell_pb.js')).href)
const input={workspaceScope:{workspace:'disposable-qualification'},name:'source-only-proposal',
  requestId:'00000000-0000-4000-8000-000000000001',
  spec:{template:proposedCreateTemplate('sha256:'+'a'.repeat(64)),providers:[],environment:{},command:['/bin/sleep','infinity'],tty:false}}
const message=protobuf.fromJson(schemas.CreateSandboxRequestSchema,input)
const roundTrip=protobuf.toJson(schemas.CreateSandboxRequestSchema,
  protobuf.fromBinary(schemas.CreateSandboxRequestSchema,protobuf.toBinary(schemas.CreateSandboxRequestSchema,message)))
assert.deepEqual(roundTrip.spec.template,input.spec.template)
console.log('PASS actual built SDK protobuf resources/driverConfig round trip; no RPC')
