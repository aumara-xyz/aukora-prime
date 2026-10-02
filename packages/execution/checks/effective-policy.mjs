// SPDX-License-Identifier: AGPL-3.0-or-later
// Pure disposable DTO/encoding fixtures. No client, RPC, guest, key or C store.
import assert from 'node:assert/strict'
import { createHash,randomUUID } from 'node:crypto'
import { pathToFileURL,fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { guestPolicy } from '../src/policy.mjs'
import { policyIdentity,expectedConfigIdentity,assertEffectiveConfiguration } from '../src/effective-policy.mjs'

const SETTINGS=['agent_policy_proposals_enabled','ocsf_json_enabled','ocsf_schema_version','proposal_approval_mode']
const FIXED_POLICY={version:1,filesystem:{includeWorkdir:false,readOnly:['/usr','/sandbox'],readWrite:['/sandbox/work','/tmp','/dev/null']},
  landlock:{compatibility:'hard_requirement'},process:{runAsUser:'1000',runAsGroup:'1000'},networkPolicies:{},networkMiddlewares:{}}
function wirePolicy(mode) {
  const p=guestPolicy(mode)
  return {version:p.version,filesystem:{includeWorkdir:p.filesystem_policy.include_workdir,
    readOnly:p.filesystem_policy.read_only,readWrite:p.filesystem_policy.read_write},landlock:p.landlock,
    process:{runAsUser:p.process.run_as_user,runAsGroup:p.process.run_as_group},networkPolicies:{},networkMiddlewares:{}}
}
function fixture(policy=wirePolicy('read-only')) {
  const expected=expectedConfigIdentity(policy),instanceId=randomUUID(),providerAttachmentEpoch=randomUUID()
  const config={policy:structuredClone(policy),version:1,policyHash:expected.policy_hash,
    settings:Object.fromEntries(SETTINGS.map(key=>[key,{scope:0,value:undefined}])),configRevision:BigInt(expected.config_revision),
    policySource:1,globalPolicyVersion:0,providerEnvRevision:BigInt(expected.provider_env_revision),supervisorMiddlewareServices:[],
    workspace:'synthetic-config-fixture',policyValidationFailureMode:'fail_closed',extensionAuthenticationEnabled:false,
    providerAttachmentEpoch,configurationAdmitted:true,configurationError:'',configurationInstanceId:instanceId}
  const sandbox={metadata:{id:randomUUID(),name:'synthetic-owned-job',workspace:config.workspace},
    spec:{policy:structuredClone(policy),providers:[],providerAttachmentEpoch},status:{configurationAdmission:{
      instanceId,state:2,policyVersion:1,policyHash:expected.policy_hash,configRevision:config.configRevision,
      providerEnvRevision:config.providerEnvRevision,error:''}}}
  return {sandbox,config,policy,workspace:config.workspace}
}
const rejects=fn=>assert.throws(fn,error=>error.code==='UNAVAILABLE')
const cases={
  async sdk_vectors() {
    const sdk=process.env.PRIME_OPEN_SHELL_SDK_DIR??fileURLToPath(new URL('../../../../reference/sdk-selected-build/sdk/typescript/',import.meta.url))
    const {create,toBinary}=await import(pathToFileURL(join(sdk,'node_modules/@bufbuild/protobuf/dist/esm/index.js')))
    const raw=await import(pathToFileURL(join(sdk,'dist/raw.js')))
    const le64=v=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(v));return b}
    const frame=b=>Buffer.concat([le64(b.length),b])
    function sdkHash(policy) {
      const message=create(raw.SandboxPolicySchema,policy)
      const protobuf=Buffer.from(toBinary(raw.SandboxPolicySchema,message,{writeUnknownFields:false}))
      return createHash('sha256').update(Buffer.concat([frame(protobuf),frame(Buffer.from('network_policies')),le64(0),
        frame(Buffer.from('network_middlewares')),le64(0)])).digest('hex')
    }
    const empty={version:0,networkPolicies:{},networkMiddlewares:{}}
    assert.equal(policyIdentity(empty),'79fbe53f9ea97345bd1de5c9321294f25f7d7aea914fd02db9b59dc4c4c6774a')
    assert.equal(policyIdentity(FIXED_POLICY),'00929220b0f9f0d510fc54f589cd2d9498adc222f188363a6de8774906ba4217')
    for(const p of [empty,FIXED_POLICY,wirePolicy('read-only'),wirePolicy('workspace-write'),
      {...FIXED_POLICY,version:0xffffffff,filesystem:{includeWorkdir:true,readOnly:['/'+'a'.repeat(180),''],readWrite:['/λ']}},
      {...empty,filesystem:{includeWorkdir:false,readOnly:[],readWrite:[]}}])assert.equal(policyIdentity(p),sdkHash(p))
    assert.deepEqual(expectedConfigIdentity(FIXED_POLICY),{
      policy_hash:'00929220b0f9f0d510fc54f589cd2d9498adc222f188363a6de8774906ba4217',
      config_revision:'416236243379448755',provider_env_revision:'3176606324465211593'})
    const f=fixture();f.config=create(raw.GetSandboxConfigResponseSchema,f.config)
    f.sandbox.spec.policy=create(raw.SandboxPolicySchema,f.sandbox.spec.policy)
    f.sandbox.status.configurationAdmission=create(raw.SandboxConfigurationAdmissionSchema,f.sandbox.status.configurationAdmission)
    assert.equal(typeof f.config.configRevision,'bigint');assert.equal(typeof f.config.providerEnvRevision,'bigint')
    assertEffectiveConfiguration(f)
  },
  json_fingerprint() {
    const f=fixture(),fingerprint=assertEffectiveConfiguration(f)
    assert.equal(typeof fingerprint.config_revision,'string')
    assert.equal(typeof fingerprint.provider_env_revision,'string')
    assert.deepEqual(JSON.parse(JSON.stringify(fingerprint)),fingerprint)
    assert.equal(Object.isFrozen(fingerprint),true)
    for(const value of [f.config,f.sandbox.status.configurationAdmission]) {
      value.configRevision=value.configRevision.toString();value.providerEnvRevision=value.providerEnvRevision.toString()
    }
    assert.deepEqual(assertEffectiveConfiguration(f),fingerprint)
    f.config.version=2;f.sandbox.status.configurationAdmission.policyVersion=2
    rejects(()=>assertEffectiveConfiguration(f))
  },
  uint64_precision() {
    for(const target of ['config','admission'])for(const key of ['configRevision','providerEnvRevision']) {
      const f=fixture(),object=target==='config'?f.config:f.sandbox.status.configurationAdmission
      object[key]=Number(object[key]);rejects(()=>assertEffectiveConfiguration(f))
      for(const value of ['00','+1','-1','1e2',' 1','18446744073709551616',-1n,1n<<64n]) {
        object[key]=value;rejects(()=>assertEffectiveConfiguration(f))
      }
    }
  },
  no_overlays() {
    for(const mutate of [f=>{f.config.policySource=2},f=>{f.config.globalPolicyVersion=1},
      f=>{f.config.supervisorMiddlewareServices=[{name:'synthetic-unexpected'}]},f=>{f.sandbox.spec.providers=['synthetic-unexpected']},
      f=>{f.config.policyValidationFailureMode='retain_last_valid'},f=>{f.config.extensionAuthenticationEnabled=true}]) {
      const f=fixture();mutate(f);rejects(()=>assertEffectiveConfiguration(f))
    }
  },
  exact_settings() {
    for(const mutate of [f=>{f.config.settings={}},f=>{delete f.config.settings.ocsf_json_enabled},
      f=>{f.config.settings.unregistered={scope:0}},f=>{f.config.settings.ocsf_json_enabled={scope:2,value:{value:{case:'boolValue',value:false}}}},
      f=>{f.config.settings.proposal_approval_mode={scope:1,value:{value:{case:'stringValue',value:'manual'}}}},
      f=>{f.config.settings.agent_policy_proposals_enabled.value=null}]) {
      const f=fixture();mutate(f);rejects(()=>assertEffectiveConfiguration(f))
    }
  },
  effective_policy_additions() {
    for(const target of ['config','spec'])for(const mutate of [p=>p.filesystem.readOnly.push('/synthetic-extra'),
      p=>p.filesystem.readWrite.push('/synthetic-extra'),p=>{p.filesystem.includeWorkdir=!p.filesystem.includeWorkdir},
      p=>{p.landlock.compatibility='best_effort'},p=>{p.process.runAsUser='0'},p=>{p.networkPolicies.extra={}},
      p=>{p.networkMiddlewares.extra={}}]) {
      const f=fixture(),p=target==='config'?f.config.policy:f.sandbox.spec.policy;mutate(p)
      rejects(()=>assertEffectiveConfiguration(f))
    }
  },
  admission_tuple() {
    for(const key of ['policyHash','configRevision','providerEnvRevision','policyVersion','instanceId','state','error']) {
      const f=fixture(),admission=f.sandbox.status.configurationAdmission
      admission[key]=typeof admission[key]==='bigint'?admission[key]+1n:typeof admission[key]==='number'?admission[key]+1:'synthetic-mismatch'
      rejects(()=>assertEffectiveConfiguration(f))
    }
    for(const key of ['policyHash','configRevision','providerEnvRevision','configurationInstanceId','providerAttachmentEpoch','version']) {
      const f=fixture();f.config[key]=typeof f.config[key]==='bigint'?f.config[key]+1n:typeof f.config[key]==='number'?f.config[key]+1:randomUUID()
      rejects(()=>assertEffectiveConfiguration(f))
    }
    for(const mutate of [f=>{f.config.configurationAdmitted=false},f=>{f.config.configurationError='synthetic-rejection'},
      f=>{f.config.workspace='different'},f=>{f.sandbox.metadata.workspace='different'},f=>{f.sandbox.spec.providerAttachmentEpoch=randomUUID()}]) {
      const f=fixture();mutate(f);rejects(()=>assertEffectiveConfiguration(f))
    }
  },
  closed_shapes() {
    for(const target of ['config','settings','setting','admission','policy','filesystem','landlock','process']) {
      const f=fixture(),object={config:f.config,settings:f.config.settings,setting:f.config.settings.ocsf_json_enabled,
        admission:f.sandbox.status.configurationAdmission,policy:f.config.policy,filesystem:f.config.policy.filesystem,
        landlock:f.config.policy.landlock,process:f.config.policy.process}[target]
      object.unexpected=true;rejects(()=>assertEffectiveConfiguration(f))
      delete object.unexpected;object.$unknown=[{}];rejects(()=>assertEffectiveConfiguration(f))
    }
    const f=fixture();f.config.$typeName='wrong.message';rejects(()=>assertEffectiveConfiguration(f))
    delete f.config.$typeName;f.config.configurationInstanceId=new String(f.config.configurationInstanceId)
    rejects(()=>assertEffectiveConfiguration(f))
    const sparse=fixture();delete sparse.config.policy.filesystem.readOnly[0];rejects(()=>assertEffectiveConfiguration(sparse))
    const getter=fixture();Object.defineProperty(getter.config,'policyHash',{get(){throw new Error('must not invoke getter')}})
    rejects(()=>assertEffectiveConfiguration(getter))
    for(const target of ['middleware','providers']) {
      const f=fixture(),array=target==='middleware'?f.config.supervisorMiddlewareServices:f.sandbox.spec.providers
      array.hidden={};rejects(()=>assertEffectiveConfiguration(f))
    }
  },
  policy_presence_and_order() {
    const p=structuredClone(FIXED_POLICY),first=policyIdentity(p)
    p.filesystem.readOnly.reverse();assert.notEqual(policyIdentity(p),first)
    const empty={version:0,networkPolicies:{},networkMiddlewares:{}}
    assert.notEqual(policyIdentity({...empty,filesystem:{includeWorkdir:false,readOnly:[],readWrite:[]}}),policyIdentity(empty))
    rejects(()=>policyIdentity({...FIXED_POLICY,networkPolicies:{unexpected:{}}}))
    rejects(()=>expectedConfigIdentity({...FIXED_POLICY,version:0}))
  },
}
const selected=process.argv[2]
if(selected&&!Object.hasOwn(cases,selected))throw new Error('unknown scoped effective-policy check')
for(const [name,check] of Object.entries(cases))if(!selected||selected===name) {await check();console.log(`PASS ${name}`)}
console.log(`PASS effective-policy ${selected?1:Object.keys(cases).length} scoped cases (no RPC or runtime)`)
