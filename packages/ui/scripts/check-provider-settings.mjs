import assert from 'node:assert/strict'
import {createRequire} from 'node:module'
import {pathToFileURL} from 'node:url'
import {resolve,join} from 'node:path'
import {providerNamespaceView,refuseGenericProviderCredentials,PRIME_PROVIDER_DIRECTORY} from '../adapters/provider-settings.mjs'
const [harness,contractFile,providerFile]=process.argv.slice(2)
if(!harness||!contractFile||!providerFile)throw Error('check-provider-settings.mjs <Prime pinned DSH> <Prime contracts> <Prime provider-settings>')
const require=createRequire(join(resolve(harness),'node_modules/.pnpm/node_modules/prime-provider-fixture.cjs'))
const Schema=require('@deepseek-ai/schemastery'),contracts=await import(pathToFileURL(resolve(contractFile)).href)
const {providerNamespace}=await import(pathToFileURL(resolve(providerFile)).href)
const empty=providerNamespace(),view=providerNamespaceView(empty,{Schema,contracts})
const rehydrated=new Schema(view.schema)
assert.deepEqual(rehydrated(view.value),view.value)
assert.equal(view.value.providers.externalDeepSeek.enabled,false);assert.equal(view.value.providers.externalDeepSeek.taskSpendCeiling,null)
assert.equal(view.secrets.length,0);assert.equal(Object.hasOwn(view.value.providers.externalDeepSeek,'apiKeyEnv'),false)
assert.equal(PRIME_PROVIDER_DIRECTORY.settingsNs,view.ns)
const scoped=providerNamespace({profile:{route:{model:'fixture-model',region:'fixture-region',allowed_data_classes:['public-fixture'],max_input_tokens:10,max_output_tokens:20,max_requests:1,task_spend_ceiling:{currency:'USD',amount:'0.01'}}}})
assert.deepEqual(new Schema(providerNamespaceView(scoped,{Schema,contracts}).schema)(scoped.section),scoped.section)
for(const method of ['describe','set','unset'])assert.throws(()=>refuseGenericProviderCredentials(method,'synthetic-value'),e=>e.code==='UNAVAILABLE')
const injected=structuredClone(empty);injected.section.providers.externalDeepSeek.apiKeyEnv='fixture-secret-ref'
assert.throws(()=>providerNamespaceView(injected,{Schema,contracts}),e=>e.code==='INVALID')
console.log(JSON.stringify({result:'PASS',groups:4,pinned_schemastery:require('@deepseek-ai/schemastery/package.json').version,namespace:'prime-inference',generic_credentials:'REFUSED',external_calls:0,live_entry:false}))
