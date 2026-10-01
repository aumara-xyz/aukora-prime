// SPDX-License-Identifier: AGPL-3.0-or-later
// Host acceptance is a trusted boundary, never a model/wire callback. A source
// build, mocked check or boolean cannot constitute observed runtime evidence.
import { createHash } from 'node:crypto'
import { canonicalJson } from '../../contracts/src/runtime.mjs'
import { SDK_SOURCE_COMMIT,SDK_PACKAGE_VERSION } from './sdk-transport.ts'

const DIGEST=/^sha256:[a-f0-9]{64}$/
const hash=(domain,value)=>'sha256:'+createHash('sha256').update(domain+'\0'+canonicalJson(value)).digest('hex')
const closed=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(',')
const required=['image_pin','sdk_pin','policy_admission','host_profile','identity_isolation','private_control_credentials','no_host_mounts','network_denial','cpu_bound','memory_bound','scratch_bound','pid_bound','timeout_cleanup','restart_reconciliation','scoped_cleanup']
export const qualificationRecordDigest=v=>hash('aukora-prime.runtime-qualification.v1',v)
export const qualificationEvidenceDigest=v=>hash('aukora-prime.runtime-evidence.v1',v)
export const hostProfileDigest=v=>hash('aukora-prime.host-profile.v1',v)

export function inspectQualification(input,settings,policyDigest=null,bounds=null,expected=null) {
  try {
    if(!closed(input,['record','evidence','proof','verifyAcceptedProof'])||typeof input.verifyAcceptedProof!=='function'
      ||!closed(expected?.binding,['host_profile_digest','gateway_identity','ledger_id'])||!DIGEST.test(expected.binding.host_profile_digest)
      ||expected.binding.gateway_identity!==expected.gateway_identity||expected.binding.ledger_id!==expected.ledger_id)return null
    // Detach host records before verification; neither mutations nor accessors
    // introduced during verification can alter the checked dispatch scope.
    const record=JSON.parse(canonicalJson(input.record)),evidence=JSON.parse(canonicalJson(input.evidence)),proof=JSON.parse(canonicalJson(input.proof))
    if(!closed(record,['version','qualification_id','workspace','logical_workspace_root','image_digest','policy_digest','sdk_source_commit','sdk_package_version','host_profile','gateway_identity','ledger_id','bounds','evidence_digest','accepted_at','expires_at'])
      ||record.version!==1||typeof record.qualification_id!=='string'||!record.qualification_id
      ||record.workspace!==settings.workspace||record.logical_workspace_root!==settings.logical_workspace_root||record.image_digest!==settings.image_digest
      ||!DIGEST.test(record.policy_digest)||record.sdk_source_commit!==SDK_SOURCE_COMMIT||record.sdk_package_version!==SDK_PACKAGE_VERSION
      ||!Number.isFinite(Date.parse(record.accepted_at))||Date.parse(record.accepted_at)>Date.now()||!Number.isFinite(Date.parse(record.expires_at))||Date.parse(record.expires_at)<=Date.now()
      ||(policyDigest&&record.policy_digest!==policyDigest)||record.gateway_identity!==expected.binding.gateway_identity||record.ledger_id!==expected.binding.ledger_id)return null
    const host=record.host_profile
    if(!closed(host,['host_id','os','architecture','kernel_release','landlock_abi','seccomp_notify','cgroup_version','docker_version'])
      ||typeof host.host_id!=='string'||!host.host_id||host.os!=='linux'||host.architecture!=='amd64'||typeof host.kernel_release!=='string'||!host.kernel_release
      ||!Number.isSafeInteger(host.landlock_abi)||host.landlock_abi<3||host.seccomp_notify!==true||host.cgroup_version!==2||typeof host.docker_version!=='string'||!host.docker_version||hostProfileDigest(host)!==expected.binding.host_profile_digest)return null
    if(!closed(record.bounds,['cpu_millicores','memory_bytes','scratch_bytes','pids','wall_time_ms','max_output_bytes'])
      ||Object.values(record.bounds).some(n=>!Number.isSafeInteger(n)||n<=0)
      ||(bounds&&(bounds.wall_time_ms>record.bounds.wall_time_ms||bounds.max_output_bytes>record.bounds.max_output_bytes)))return null
    const scope=hash('aukora-prime.runtime-scope.v1',{workspace:record.workspace,logical_workspace_root:record.logical_workspace_root,image_digest:record.image_digest,policy_digest:record.policy_digest,sdk_source_commit:record.sdk_source_commit,sdk_package_version:record.sdk_package_version,host_profile:host,gateway_identity:record.gateway_identity,ledger_id:record.ledger_id,bounds:record.bounds})
    if(!Array.isArray(evidence)||evidence.length!==required.length||evidence.some(v=>!closed(v,['check','artifact_digest','observed_at','scope_digest','status'])||!required.includes(v.check)||v.status!=='passed'||!DIGEST.test(v.artifact_digest)||v.scope_digest!==scope||!Number.isFinite(Date.parse(v.observed_at))||Date.parse(v.observed_at)>Date.parse(record.accepted_at))
      ||new Set(evidence.map(v=>v.check)).size!==required.length||record.evidence_digest!==qualificationEvidenceDigest(evidence))return null
    const rd=qualificationRecordDigest(record),hd=hostProfileDigest(host)
    if(!closed(proof,['kind','record_digest','evidence_digest','host_profile_digest','accepted_by','material'])||proof.kind!=='host_runtime_acceptance'||proof.record_digest!==rd||proof.evidence_digest!==record.evidence_digest||proof.host_profile_digest!==hd||typeof proof.accepted_by!=='string'||!proof.accepted_by||proof.material===null)return null
    const acceptance=input.verifyAcceptedProof({record:JSON.parse(canonicalJson(record)),evidence:JSON.parse(canonicalJson(evidence)),proof:JSON.parse(canonicalJson(proof))})
    if(!closed(acceptance,['status','record_digest','evidence_digest','host_profile_digest','accepted_by'])||acceptance.status!=='ACCEPTED'||acceptance.record_digest!==rd||acceptance.evidence_digest!==record.evidence_digest||acceptance.host_profile_digest!==hd||acceptance.accepted_by!==proof.accepted_by)return null
    return record
  } catch {return null}
}
