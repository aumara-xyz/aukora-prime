import {PrimeTransportError} from './transport.mjs'
const invalid=()=>{throw new PrimeTransportError('INVALID','ui:invalid-provider-namespace')}
const closed=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',')
const fields=['endpoint','model','region','allowedDataClasses','maxInputTokens','maxOutputTokens','maxRequests','enabled','credentialConfigured','taskSpendCeiling']
export const PRIME_PROVIDER_DIRECTORY=Object.freeze({provider:'externalDeepSeek',displayName:'DeepSeek',settingsNs:'prime-inference',settingsPath:Object.freeze(['providers','externalDeepSeek']),declared:false})

/** Convert E's nonsecret read view into the pinned Schemastery protocol. No writes or credential access. */
export function providerNamespaceView(input,{Schema,contracts,revision=0}={}) {
  if(typeof Schema?.object!=='function'||typeof contracts?.canonicalJson!=='function')throw new PrimeTransportError('UNAVAILABLE','ui:provider-schema-helper-unavailable')
  let value
  try {value=JSON.parse(contracts.canonicalJson(input))}catch{invalid()}
  if(!closed(value,['namespace','section'])||value.namespace!=='prime-inference'||!closed(value.section,['providers'])||
    !closed(value.section.providers,['externalDeepSeek'])||!Number.isSafeInteger(revision)||revision<0)invalid()
  const row=value.section.providers.externalDeepSeek
  if(!closed(row,fields)||row.endpoint!=='https://api.deepseek.com'||typeof row.model!=='string'||typeof row.region!=='string'||
    !Array.isArray(row.allowedDataClasses)||row.allowedDataClasses.some(s=>typeof s!=='string'||!s)||
    ['maxInputTokens','maxOutputTokens','maxRequests'].some(k=>!Number.isSafeInteger(row[k])||row[k]<0)||
    typeof row.enabled!=='boolean'||typeof row.credentialConfigured!=='boolean')invalid()
  const cost=row.taskSpendCeiling
  if(cost!==null&&(!closed(cost,['currency','amount'])||cost.currency!=='USD'||typeof cost.amount!=='string'||! /^(?:0|[1-9]\d*)(?:\.\d{1,8})?$/.test(cost.amount)))invalid()
  const readonly=node=>node.role('readonly')
  const money=Schema.object({currency:readonly(Schema.const('USD')),amount:readonly(Schema.string())})
  const provider=Schema.object({endpoint:readonly(Schema.string()),model:readonly(Schema.string()),region:readonly(Schema.string()),
    allowedDataClasses:readonly(Schema.array(Schema.string())),maxInputTokens:readonly(Schema.number().min(0).step(1)),
    maxOutputTokens:readonly(Schema.number().min(0).step(1)),maxRequests:readonly(Schema.number().min(0).step(1)),
    enabled:readonly(Schema.boolean()),credentialConfigured:readonly(Schema.boolean()),taskSpendCeiling:readonly(Schema.union([Schema.const(null),money]))})
  const schema=Schema.object({providers:Schema.object({externalDeepSeek:provider})})
  return {ns:'prime-inference',schema:schema.toJSON(),value:value.section,base:value.section,applies:'live',secrets:[],revision}
}

/** Host maps this named refusal through its existing typed Remote error boundary. */
export function refuseGenericProviderCredentials() {
  throw new PrimeTransportError('UNAVAILABLE','ui:generic-provider-credentials-refused-use-separated-owner-entry')
}
