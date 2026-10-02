#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Remove one binding guard in disposable copies, then require its control to fail.
import pathlib, shutil, subprocess, tempfile
root=pathlib.Path(__file__).resolve().parents[3]
mutants=[
 ('digest','src/owned-executor.mjs','grant.operation_digest!==digest || ','', 'digest'),
 ('grant','src/owned-executor.mjs',"for (const key of ['operation_id','owner_id','audience','authorization_epoch']) if(op[key]!==grant[key]) throw refused('consumed grant binding differs','UNAUTHORIZED')",'', 'grant'),
 ('expiry','src/owned-executor.mjs',"if(!this.admission(snap.r)||Date.parse(snap.r.operation.expiry)<=Date.now())throw refused('runtime evidence revoked or operation expired before create','UNAVAILABLE')","if(!this.admission(snap.r))throw refused('runtime evidence revoked or operation expired before create','UNAVAILABLE')",'expiry_after_claim'),
 ('target','src/owned-executor.mjs','target.image_digest!==settings.image_digest','false','target'),
 ('bounds','src/owned-executor.mjs','r.wall_time_ms!==spec.timeoutMs','false','bounds'),
 ('lease','src/ledger.mjs',"lease.exec('PRAGMA busy_timeout=0; BEGIN IMMEDIATE;')","lease.exec('PRAGMA busy_timeout=0; BEGIN DEFERRED;')", 'lease'),
 ('admission','src/effective-policy.mjs','||JSON.stringify(policyShape(sandbox?.spec?.policy))!==JSON.stringify(expectedPolicy)','','admission'),
 ('gateway','src/owned-executor.mjs','job.gateway_identity!==this.transport.gatewayIdentity','false','gateway_recovery'),
 ('check_lease','src/ledger.mjs',"checkLease() { if (!this.leased) throw refused('lifecycle mutation requires exclusive lease', 'RECONCILIATION_REQUIRED') }","checkLease() {}",['lease_reserve','lease_save'],'mechanisms.mjs'),
 ('bash_parameters','src/bash.mjs',"if(canonicalJson(request?.operation?.canonical_parameters)!==canonicalJson(expected))throw refused('broker operation differs from resolved Bash spec','TARGET_MISMATCH')",'', 'bash_parameters','mechanisms.mjs'),
 ('pre_exec_qualification','src/owned-executor.mjs',"if(!this.admission(snap.r)||Date.parse(snap.r.operation.expiry)<=Date.now())throw refused('operation expired or runtime evidence revoked before exec','UNAVAILABLE')","if(Date.parse(snap.r.operation.expiry)<=Date.now())throw refused('operation expired or runtime evidence revoked before exec','UNAVAILABLE')",'pre_exec_qualification','mechanisms.mjs'),
 ('pre_exec_expiry','src/owned-executor.mjs',"if(!this.admission(snap.r)||Date.parse(snap.r.operation.expiry)<=Date.now())throw refused('operation expired or runtime evidence revoked before exec','UNAVAILABLE')","if(!this.admission(snap.r))throw refused('operation expired or runtime evidence revoked before exec','UNAVAILABLE')",'pre_exec_expiry','mechanisms.mjs'),
 ('admitted_image','src/owned-executor.mjs','s.spec.template?.image!==settings.image_digest','false','admitted_image','mechanisms.mjs'),
 ('claim_grant_reply','src/owned-executor.mjs','||canonicalJson(reply.consumed_grant)!==canonicalJson(job.request.consumed_grant)','', 'claim_grant_reply','mechanisms.mjs'),
 ('claim_digest_reply','src/owned-executor.mjs',"if(reply.ok!==true||reply.status!=='DISPATCHED'||reply.request_id!==job.request_id||reply.request_digest!==job.request_digest","if(reply.ok!==true||reply.status!=='DISPATCHED'||reply.request_id!==job.request_id",'claim_digest_reply','mechanisms.mjs'),
 ('settlement_status_reply','src/owned-executor.mjs','reply.status!==expected||','','settlement_status_reply','mechanisms.mjs'),
 ('owner_label','src/owned-executor.mjs','||m.labels?.[LABEL]!==job.token','','owner_label','mechanisms.mjs'),
 ('ambiguous124','src/sdk-transport.ts','payload.value.exitCode === 124','false','source_readiness','readiness.mjs'),
 ('effective_policy','src/effective-policy.mjs','JSON.stringify(policyShape(config.policy))!==JSON.stringify(expectedPolicy)','false','configuration_altered_filesystem_policy','configuration.mjs'),
 ('config_revision','src/effective-policy.mjs','||uint64(config.configRevision)!==expected.config_revision','','configuration_config_revision_mismatch','configuration.mjs'),
 ('pre_exec_configuration','src/owned-executor.mjs','await this.verifyConfiguration(job,snap,controller.signal)','void 0','configuration_pre_exec_identity_drift','configuration.mjs'),
 ('post_drain_configuration','src/owned-executor.mjs','try {await this.verifyConfiguration(job,snap);', 'try {','configuration_post_drain_identity_drift','configuration.mjs'),
 ('effect_ownership','src/bash.mjs',"ctx.effect(()=>()=>cleanup??=Promise.resolve().then(()=>dispose?.call(executor)),'owned OpenShell lifecycle')",'void 0',None,'lifecycle.mjs'),
 ('initial_history','src/effective-policy.mjs','if(policy_version!==1)fail()','void 0','configuration_initial_history_revision','configuration.mjs'),
 ('durable_configuration_pending','src/owned-executor.mjs',"||job.configuration_verification==='pending'",'','configuration_post_drain_process_death_preserves_unknown','configuration.mjs'),
]
with tempfile.TemporaryDirectory(prefix='prime-executor-guard-') as directory:
 dest=pathlib.Path(directory)
 for mutant in mutants:
  name,path,before,after,control=mutant[:5]
  script=mutant[5] if len(mutant)>5 else 'controls.mjs'
  tree=dest/name
  shutil.copytree(root/'packages'/'execution',tree/'packages'/'execution')
  shutil.copytree(root/'packages'/'contracts',tree/'packages'/'contracts')
  target=tree/'packages'/'execution'/path
  text=target.read_text()
  assert text.count(before)==1,(name,text.count(before))
  target.write_text(text.replace(before,after,1))
  for selected in control if isinstance(control,list) else [control]:
   command=['node','packages/execution/checks/'+script]
   if selected is not None: command.append(selected)
   result=subprocess.run(command,cwd=tree,capture_output=True,text=True,timeout=15)
   assert result.returncode!=0,('SURVIVED',name,selected,result.stdout)
   assert 'AssertionError' in result.stderr,(name,selected,result.stderr)
   print('KILLED '+name+' via '+(selected if selected is not None else '<all>'),flush=True)
print('PASS 25 single-guard mutation variants / 26 controls; disposable trees removed')
