// SPDX-License-Identifier: AGPL-3.0-or-later
// Static, maps-empty port of NVIDIA OpenShell 6648bd0 policy_identity.rs and
// grpc/policy.rs configuration fingerprints (upstream Apache-2.0).
// This verifies a fixed desired/admitted snapshot. ExecSandbox has no atomic
// configuration-revision precondition; this is not runtime qualification.
import { createHash } from 'node:crypto'
import { refused } from './policy.mjs'

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const U64_MAX=(1n<<64n)-1n
const SETTING_KEYS=['agent_policy_proposals_enabled','ocsf_json_enabled','ocsf_schema_version','proposal_approval_mode']
const POLICY_KEYS=['version','filesystem','landlock','process','networkPolicies','networkMiddlewares']
const CONFIG_KEYS=['policy','version','policyHash','settings','configRevision','policySource','globalPolicyVersion',
  'providerEnvRevision','supervisorMiddlewareServices','workspace','policyValidationFailureMode',
  'extensionAuthenticationEnabled','providerAttachmentEpoch','configurationAdmitted','configurationError','configurationInstanceId']
const EMPTY_PROVIDER_REVISION=createHash('sha256').update('openshell-provider-env-revision-v4').digest().readBigUInt64LE(0).toString()
const fail=()=>{throw refused('exact effective OpenShell configuration was not admitted','UNAVAILABLE')}
const has=(value,key)=>Object.hasOwn(value,key)

function object(value,keys,typeName,required=keys) {
  if(!value||typeof value!=='object'||Array.isArray(value)
    ||![Object.prototype,null].includes(Object.getPrototypeOf(value)))fail()
  for(const key of Reflect.ownKeys(value)) {
    const descriptor=Object.getOwnPropertyDescriptor(value,key)
    if(typeof key!=='string'||!descriptor||!has(descriptor,'value'))fail()
    if(key==='$typeName') {if(typeof typeName!=='string'||descriptor.value!==typeName)fail()}
    else if(key==='$unknown') {if(typeof typeName!=='string'||(descriptor.value!==undefined&&(!Array.isArray(descriptor.value)||descriptor.value.length)))fail()}
    else if(!keys.includes(key))fail()
  }
  if(required.some(key=>!has(value,key)))fail()
  return value
}
function text(value) {
  if(typeof value!=='string'||Buffer.byteLength(value)>4096||value.includes('\0'))fail()
  return value
}
function uint32(value,min=0) {
  if(!Number.isSafeInteger(value)||value<min||value>0xffffffff)fail()
  return value
}
function uint64(value) {
  if(typeof value==='bigint') {if(value<0n||value>U64_MAX)fail();return value.toString()}
  if(typeof value!=='string'||!/^(?:0|[1-9][0-9]{0,19})$/.test(value)||BigInt(value)>U64_MAX)fail()
  return value
}
function strings(value) {
  if(!Array.isArray(value)||Object.getPrototypeOf(value)!==Array.prototype||value.length>256)fail()
  if(Reflect.ownKeys(value).length!==value.length+1)fail()
  for(let i=0;i<value.length;i++)if(!has(value,i)||!has(Object.getOwnPropertyDescriptor(value,String(i)),'value'))fail()
  return value.map(text)
}
function emptyMap(value) {
  object(value,[],undefined)
  if(Reflect.ownKeys(value).length)fail()
  return {}
}
function emptyList(value) {
  if(!Array.isArray(value)||Object.getPrototypeOf(value)!==Array.prototype||value.length||Reflect.ownKeys(value).length!==1)fail()
}
function policyShape(value) {
  object(value,POLICY_KEYS,'openshell.sandbox.v1.SandboxPolicy',['version','networkPolicies','networkMiddlewares'])
  const policy={version:uint32(value.version),networkPolicies:emptyMap(value.networkPolicies),networkMiddlewares:emptyMap(value.networkMiddlewares)}
  if(value.filesystem!==undefined) {
    const fs=object(value.filesystem,['includeWorkdir','readOnly','readWrite'],'openshell.sandbox.v1.FilesystemPolicy')
    if(typeof fs.includeWorkdir!=='boolean')fail()
    policy.filesystem={includeWorkdir:fs.includeWorkdir,readOnly:strings(fs.readOnly),readWrite:strings(fs.readWrite)}
    if(policy.filesystem.readOnly.length+policy.filesystem.readWrite.length>256)fail()
  }
  if(value.landlock!==undefined) {
    const landlock=object(value.landlock,['compatibility'],'openshell.sandbox.v1.LandlockPolicy')
    policy.landlock={compatibility:text(landlock.compatibility)}
  }
  if(value.process!==undefined) {
    const process=object(value.process,['runAsUser','runAsGroup'],'openshell.sandbox.v1.ProcessPolicy')
    policy.process={runAsUser:text(process.runAsUser),runAsGroup:text(process.runAsGroup)}
  }
  return policy
}
function fixedPolicy(value) {
  const p=policyShape(value)
  if(p.version!==1||!p.filesystem||p.landlock?.compatibility!=='hard_requirement'
    ||p.process?.runAsUser!=='1000'||p.process?.runAsGroup!=='1000')fail()
  return p
}

const concat=parts=>Buffer.concat(parts)
function varint(number) {
  let value=BigInt(number);const bytes=[]
  do {let byte=Number(value&127n);value>>=7n;if(value)byte|=128;bytes.push(byte)}while(value)
  return Buffer.from(bytes)
}
function fieldString(tag,value) {
  const bytes=Buffer.from(value,'utf8')
  return bytes.length?concat([varint(tag),varint(bytes.length),bytes]):Buffer.alloc(0)
}
function message(tag,bytes) {return concat([varint(tag),varint(bytes.length),bytes])}
function policyProtobuf(p) {
  const parts=[]
  if(p.version)parts.push(concat([Buffer.from([8]),varint(p.version)]))
  if(p.filesystem)parts.push(message(18,concat([
    ...(p.filesystem.includeWorkdir?[Buffer.from([8,1])]:[]),
    ...p.filesystem.readOnly.map(value=>message(18,Buffer.from(value,'utf8'))),
    ...p.filesystem.readWrite.map(value=>message(26,Buffer.from(value,'utf8'))),
  ])))
  if(p.landlock)parts.push(message(26,fieldString(10,p.landlock.compatibility)))
  if(p.process)parts.push(message(34,concat([fieldString(10,p.process.runAsUser),fieldString(18,p.process.runAsGroup)])))
  return concat(parts)
}
const le64=value=>{const bytes=Buffer.alloc(8);bytes.writeBigUInt64LE(BigInt(value));return bytes}
const frame=bytes=>concat([le64(bytes.length),bytes])
const le32=value=>{const bytes=Buffer.alloc(4);bytes.writeInt32LE(value);return bytes}

/** Upstream identity for the supported static, maps-empty protobuf shape. */
export function policyIdentity(policy) {
  const p=policyShape(policy)
  return createHash('sha256').update(concat([
    frame(policyProtobuf(p)),frame(Buffer.from('network_policies')),le64(0),
    frame(Buffer.from('network_middlewares')),le64(0),
  ])).digest('hex')
}

/** The exact pinned no-provider/no-global/no-middleware default configuration. */
export function expectedConfigIdentity(policy) {
  const policy_hash=policyIdentity(fixedPolicy(policy))
  const config_revision=createHash('sha256').update(concat([
    le32(1),Buffer.from('fail_closed'),Buffer.from([0]),Buffer.from(policy_hash),
    ...SETTING_KEYS.flatMap(key=>[Buffer.from(key),le32(0)]),
  ])).digest().readBigUInt64LE(0).toString()
  return Object.freeze({policy_hash,config_revision,provider_env_revision:EMPTY_PROVIDER_REVISION})
}

/** Desired and accepted evidence must corroborate the exact fixed profile. */
export function assertEffectiveConfiguration({sandbox,config,policy,workspace}) {
  const expectedPolicy=fixedPolicy(policy),expected=expectedConfigIdentity(expectedPolicy)
  object(config,CONFIG_KEYS,'openshell.sandbox.v1.GetSandboxConfigResponse')
  if(typeof workspace!=='string'||!workspace||config.workspace!==workspace||sandbox?.metadata?.workspace!==workspace
    ||config.policySource!==1||config.globalPolicyVersion!==0||config.configurationAdmitted!==true
    ||config.configurationError!==''||config.policyValidationFailureMode!=='fail_closed'||config.extensionAuthenticationEnabled!==false)fail()
  emptyList(config.supervisorMiddlewareServices);emptyList(sandbox?.spec?.providers)
  const policy_version=uint32(config.version,1)
  // This lifecycle creates a fresh sandbox with exactly one policy revision.
  // Even an equal-payload administrative revision is outside this fixed profile.
  if(policy_version!==1)fail()
  if(JSON.stringify(policyShape(config.policy))!==JSON.stringify(expectedPolicy)
    ||JSON.stringify(policyShape(sandbox?.spec?.policy))!==JSON.stringify(expectedPolicy)
    ||config.policyHash!==expected.policy_hash||uint64(config.configRevision)!==expected.config_revision
    ||uint64(config.providerEnvRevision)!==expected.provider_env_revision)fail()
  object(config.settings,SETTING_KEYS,undefined)
  for(const key of SETTING_KEYS) {
    const setting=object(config.settings[key],['scope','value'],'openshell.sandbox.v1.EffectiveSetting',['scope'])
    if(setting.scope!==0||setting.value!==undefined)fail()
  }
  const admission=object(sandbox?.status?.configurationAdmission,
    ['instanceId','state','policyVersion','policyHash','configRevision','providerEnvRevision','error'],
    'openshell.v1.SandboxConfigurationAdmission')
  if(admission.state!==2||admission.error!==''||admission.policyVersion!==policy_version
    ||admission.policyHash!==expected.policy_hash||uint64(admission.configRevision)!==expected.config_revision
    ||uint64(admission.providerEnvRevision)!==expected.provider_env_revision
    ||typeof config.configurationInstanceId!=='string'||!UUID.test(config.configurationInstanceId)||admission.instanceId!==config.configurationInstanceId
    ||typeof config.providerAttachmentEpoch!=='string'||!UUID.test(config.providerAttachmentEpoch)||sandbox.spec.providerAttachmentEpoch!==config.providerAttachmentEpoch)fail()
  return Object.freeze({version:1,workspace,policy_version,...expected,
    provider_attachment_epoch:config.providerAttachmentEpoch,configuration_instance_id:config.configurationInstanceId,
    policy_source:1,global_policy_version:0})
}
