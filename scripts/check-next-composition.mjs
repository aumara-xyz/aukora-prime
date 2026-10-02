// SPDX-License-Identifier: AGPL-3.0-or-later
// Read/import only: inspect an explicitly selected composed NEXT release.
// No worker, listener, credential service, owner action or provider is started.
import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {resolve,relative,isAbsolute} from 'node:path';
import {pathToFileURL} from 'node:url';

const root=await realpath(resolve(process.argv[2]??''));
assert(process.argv.length===3,'explicit composed release directory required');
const metadata=JSON.parse(await readFile(resolve(root,'prime-release.json'),'utf8'));
const composition=JSON.parse(await readFile(resolve(root,'prime-composition.json'),'utf8'));
const load=path=>import(pathToFileURL(resolve(root,path)));
const authorityRequire=createRequire(resolve(root,'prime-packages/authority/src/inference-profile.mjs'));
const helper=await realpath(authorityRequire.resolve('@aukora-prime/inference/budget-binding'));
assert.equal(helper,await realpath(resolve(root,'prime-packages/inference/src/budget-binding.mjs')));
const rel=relative(root,helper);assert(!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('../'));
assert.equal(typeof authorityRequire('@aukora-prime/inference/budget-binding').inferenceBudgetState,'function');
const authority=await load('prime-packages/authority/src/inference-profile.mjs');
assert.equal(authority.configureInferenceProfile(undefined),null);
const bridge=await load('prime-packages/runtime-bridge/src/inference.mjs');
assert.equal(typeof bridge.createInferenceAuthorityConnection,'function');
const native=await load('harness/owner-memory-native.mjs');
assert.equal(typeof native.createOwnerMemoryNativeBinding,'function');
const provider=await load('prime-packages/cordis-tool-provider/src/index.mjs');
assert.equal(typeof provider.createCordisToolProvider,'function');
const {assertEntrySet}=await load('harness/composition-policy.mjs');
assertEntrySet(composition.entries);
assert(!composition.entries.some(entry=>/cordis-tool-provider|owner-memory|inference-worker/.test(entry.name)));
assert(metadata.unavailable_capabilities.includes('model-inference'));
assert(metadata.unavailable_capabilities.includes('approved-shell'));
console.log(JSON.stringify({status:'PASS',source_commit:metadata.source_commit,
  checks:['release-local C/E package peer','C default profile absent','Bridge inference import',
    'rewritten native memory closure import','Cordis provider import','unchanged disabled plugin set'],
  workers_started:0,provider_calls:0,runtime_qualified:false}));
