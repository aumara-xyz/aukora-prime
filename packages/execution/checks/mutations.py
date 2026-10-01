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
 ('admission','src/owned-executor.mjs','hash(normalized)!==hash(policy)','false','admission'),
 ('gateway','src/owned-executor.mjs','job.gateway_identity!==this.transport.gatewayIdentity','false','gateway_recovery'),
]
with tempfile.TemporaryDirectory(prefix='prime-executor-guard-') as directory:
 dest=pathlib.Path(directory)
 for name,path,before,after,control in mutants:
  tree=dest/name
  shutil.copytree(root/'packages'/'execution',tree/'packages'/'execution')
  shutil.copytree(root/'packages'/'contracts',tree/'packages'/'contracts')
  target=tree/'packages'/'execution'/path
  text=target.read_text()
  assert text.count(before)==1,(name,text.count(before))
  target.write_text(text.replace(before,after,1))
  result=subprocess.run(['node','packages/execution/checks/controls.mjs',control],cwd=tree,capture_output=True,text=True,timeout=15)
  assert result.returncode!=0,('SURVIVED',name,result.stdout)
  assert 'AssertionError' in result.stderr,(name,result.stderr)
  print('KILLED '+name,flush=True)
print('PASS 8 single-guard mutants; disposable trees removed')
