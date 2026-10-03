#!/usr/bin/env python3
"""Prime-only composition of verified pinned harness + immutable donor client artifacts."""
import json,shutil,subprocess,sys,hashlib,os,stat
from pathlib import Path
# Composition output must be safe to capture into a protected release.
os.umask(0o022)
root=Path(__file__).resolve().parents[1]
source=root/'vendor/dsh'
arguments=[arg for arg in sys.argv[1:] if arg!='--reuse-runtime']
reuse_runtime='--reuse-runtime' in sys.argv[1:]
release=Path(arguments[0]).resolve() if arguments else root/'.runtime/release'
if not release.is_relative_to(root/'.runtime'):raise SystemExit('release-path-refused')
def require_clean_source():
 if subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=root,text=True).strip():raise SystemExit('source-not-committed: compose requires a coherent clean source checkpoint')
require_clean_source()
ui_donor='645d3213b8aede3b544269b4224ae09df06b0a42'
manifest=json.loads((root/'packages/ui/baseline-manifest.json').read_text())
if manifest.get('commit')!=ui_donor:raise SystemExit('ui-donor-pin-mismatch: composition and frozen baseline must agree')
if not reuse_runtime:
 subprocess.run([sys.executable,str(root/'scripts/build-dsh.py'),'--verify-built'],cwd=root,check=True)
 subprocess.run(['node',str(root/'packages/ui/scripts/verify-baseline.mjs')],cwd=root,check=True)
 subprocess.run(['node',str(root/'harness/release-integrity.mjs'),'source',str(root)],check=True)
if release.exists() and not reuse_runtime: raise SystemExit('release-exists: keep previous bytes; remove only this task-owned release before explicit rebuild')
if reuse_runtime:
 if not release.is_dir() or not (release/'prime-release.json').is_file():raise SystemExit('existing-composed-runtime-required')
 prior=json.loads((release/'prime-release.json').read_text())
 if prior.get('dsh_commit')!='0d1f50007f9bca3f52b06e1c3074fa14d5fb0720' or prior.get('ui_donor')!=ui_donor:raise SystemExit('existing-runtime-pin-mismatch')
 retained_snapshot=(release/'prime-ui-integrity.json').read_bytes()
 snapshot=json.loads(retained_snapshot)
 if snapshot.get('version')!=2 or snapshot.get('donor')!=ui_donor:raise SystemExit('existing-ui-snapshot-required')
 for item in snapshot['source_records']:
  current=(root/'packages/ui'/item['path']).read_bytes()
  if len(current)!=item['bytes'] or hashlib.sha256(current).hexdigest()!=item['sha256']:raise SystemExit('retained-ui-source-changed: '+item['path'])
release.parent.mkdir(exist_ok=True)
def overlay(src,dst,ignore=None):
 if not reuse_runtime:return shutil.copytree(src,dst,symlinks=True,ignore=ignore)
 if dst.is_symlink():raise SystemExit('overlay-directory-link-refused: '+str(dst.relative_to(release)))
 dst.mkdir(parents=True,exist_ok=True)
 excluded=set(ignore(str(src),[entry.name for entry in src.iterdir()]) if ignore else [])
 for entry in src.iterdir():
  if entry.name in excluded:continue
  target=dst/entry.name
  if entry.is_symlink():
   link=os.readlink(entry)
   if target.is_symlink():
    if os.readlink(target)!=link:raise SystemExit('overlay-link-changed: '+str(target.relative_to(release)))
   elif target.exists():raise SystemExit('overlay-link-collision: '+str(target.relative_to(release)))
   else:target.symlink_to(link,target_is_directory=entry.is_dir())
  elif entry.is_dir():overlay(entry,target,ignore)
  else:
   if target.is_symlink() or target.exists() and not target.is_file():raise SystemExit('overlay-file-collision: '+str(target.relative_to(release)))
   shutil.copy2(entry,target)
def ignored(directory,names):
 if 'node_modules' in Path(directory).parts:return []
 return [n for n in names if n in ['tests','__tests__','.agents','.github','.claude','docs','website','snapshots','benchmarks'] or n.endswith(('.spec.ts','.test.ts','.tsbuildinfo'))]
if not reuse_runtime:shutil.copytree(source,release,symlinks=True,ignore=ignored)
for name in ([] if reuse_runtime else ['layout','sidebar','threads','apps','messages','memory','aumlok','documents','settings']):
 src=root/'packages/ui/faces'/name;dst=release/'plugins'/('aukora-face-'+name)
 dst.mkdir(parents=True)
 for n in ['package.json','lib','assets','vendor']:
  if (src/n).is_dir():shutil.copytree(src/n,dst/n,symlinks=True,dirs_exist_ok=reuse_runtime)
  elif (src/n).is_file():shutil.copy2(src/n,dst/n)
 shutil.copy2(root/'harness/ui-host.mjs',dst/'lib/prime-host.mjs')
overlay(root/'harness',release/'harness')
# Browser composition stays inside this release. No source checkout discovery.
client_binding=release/'harness/owner-memory-client.mjs'
client_text=client_binding.read_text()
for module in ['ui-adapter.mjs','owner-memory-workflow.mjs','owner-forget-workflow.mjs']:
 old="'../packages/runtime-bridge/src/"+module+"'"
 if client_text.count(old)!=1:raise SystemExit('owner-memory-import-mismatch: '+module)
 client_text=client_text.replace(old,"'../prime-packages/runtime-bridge/src/"+module+"'")
client_binding.write_text(client_text)
for package in ['contracts','execution','authority','memory','inference','ops','runtime-bridge','cordis-tool-provider']:
 overlay(root/'packages'/package,release/'prime-packages'/package,ignore=lambda directory,names:[n for n in names if n in ['test','tests','checks'] or n in ['check.mjs','build-sdk.py']])
# C deliberately resolves E's optional public helper as a package peer. Bind it
# only to this release's exact copied package, without install/home fallbacks.
# Presence supplies no protected profile, worker configuration or runtime mount.
inference_peer=release/'prime-packages/node_modules/@aukora-prime/inference'
inference_peer.parent.mkdir(parents=True,exist_ok=reuse_runtime)
if not inference_peer.is_symlink():inference_peer.symlink_to('../../inference',target_is_directory=True)
if inference_peer.resolve()!=(release/'prime-packages/inference').resolve():raise SystemExit('inference-peer-escape')
ui=release/'prime-packages/ui';ui.mkdir(parents=True,exist_ok=reuse_runtime)
if not reuse_runtime:
 shutil.copytree(root/'packages/ui/adapters',ui/'adapters')
 shutil.copy2(root/'packages/ui/baseline-manifest.json',ui/'baseline-manifest.json')
# The nine face bundles are immutable donor baseline bytes, never rebuilt substitutions.
served=[]
for item in manifest['files']:
 parts=Path(item['path']).parts
 if len(parts)<3 or parts[0]!='faces' or parts[2] not in ['package.json','lib','assets','vendor']:continue
 path=release/'plugins'/('aukora-face-'+parts[1])/Path(*parts[2:])
 if not path.is_file() or path.stat().st_size!=item['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:raise SystemExit('served-baseline-mismatch: '+item['path'])
 served.append(item)
if not reuse_runtime:(release/'prime-served-baseline.json').write_text(json.dumps({'version':1,'donor':manifest['commit'],'files':served,'rebuilt_substitutions':False},indent=2)+'\n')
for package,target in ([] if reuse_runtime else [('foundation','aukora-foundation'),('prime-authority','prime-authority')]):
 src=root/'packages/ui'/package;dst=release/'plugins'/target
 shutil.copytree(src,dst,symlinks=True,dirs_exist_ok=reuse_runtime,ignore=lambda directory,names:[n for n in names if n in ['src','checks','licenses']])
shutil.copy2(root/'harness/preview-connection.mjs',release/'packages/client/connection/lib/prime-host.mjs')
shutil.copy2(root/'harness/gateway-host.mjs',release/'packages/api/gateway/lib/prime-host.mjs')
for target in ['packages/api/workspace-controller','packages/client/file-upload']:
 shutil.copy2(root/'harness/ui-host.mjs',release/target/'lib/prime-host.mjs')
removed_links=[]
for link in release.rglob('*'):
 if link.is_symlink() and not link.exists():
  removed_links.append(str(link.relative_to(release)));link.unlink()
(release/'prime-stripped-links.json').write_text(json.dumps(removed_links,indent=2)+'\n')
if reuse_runtime:
 for item in snapshot['files']:
  path=release/item['path']
  if not path.is_file() or path.is_symlink() or path.stat().st_size!=item['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:raise SystemExit('retained-ui-bytes-changed: '+item['path'])
 if (release/'prime-ui-integrity.json').read_bytes()!=retained_snapshot:raise SystemExit('retained-ui-snapshot-changed')
else:subprocess.run(['node',str(root/'harness/release-integrity.mjs'),'snapshot',str(root),str(release)],check=True)
subprocess.run(['node',str(root/'scripts/compose-entries.mjs'),str(release)],check=True)
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
require_clean_source()
composition=json.loads((release/'prime-composition.json').read_text())
native_provider={'llm-deepseek','prime-deepseek-pilot'}.issubset({entry['id'] for entry in composition['entries']})
release_metadata={'version':'0.1.0','source_commit':commit,'dsh_commit':'0d1f50007f9bca3f52b06e1c3074fa14d5fb0720','cordis':'4.0.2','ui_donor':ui_donor,'unavailable_capabilities':['owner-passkey','approved-shell','sdk-child-launchers','model-inference','durable-memory','messaging','media-generation']}
if native_provider:release_metadata['native_model_inference']={'provider':'deepseek-official','model':'deepseek-flash','runtime_mount_required':True,'aggregate_ceiling_microusd':10000000}
(release/'prime-release.json').write_text(json.dumps(release_metadata,indent=2)+'\n')
# Upstream copies can retain their source checkout's group-writable modes.
# Tighten only the fresh output; exact bytes and executable bits stay unchanged.
for path in [release,*release.rglob('*')]:
 mode=path.lstat().st_mode
 if stat.S_ISDIR(mode) or stat.S_ISREG(mode):path.chmod(stat.S_IMODE(mode)&~0o7022)
print('COMPOSED',release)
