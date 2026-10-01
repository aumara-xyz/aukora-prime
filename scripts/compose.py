#!/usr/bin/env python3
"""Prime-only composition of verified pinned harness + immutable donor client artifacts."""
import json,shutil,subprocess,sys,hashlib,os,stat
from pathlib import Path
# Composition output must be safe to capture into a protected release.
os.umask(0o022)
root=Path(__file__).resolve().parents[1]
source=root/'vendor/dsh'
release=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else root/'.runtime/release'
if not release.is_relative_to(root/'.runtime'):raise SystemExit('release-path-refused')
def require_clean_source():
 if subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=root,text=True).strip():raise SystemExit('source-not-committed: compose requires a coherent clean source checkpoint')
require_clean_source()
ui_donor='645d3213b8aede3b544269b4224ae09df06b0a42'
manifest=json.loads((root/'packages/ui/baseline-manifest.json').read_text())
if manifest.get('commit')!=ui_donor:raise SystemExit('ui-donor-pin-mismatch: composition and frozen baseline must agree')
subprocess.run([sys.executable,str(root/'scripts/build-dsh.py'),'--verify-built'],cwd=root,check=True)
subprocess.run(['node',str(root/'packages/ui/scripts/verify-baseline.mjs')],cwd=root,check=True)
subprocess.run(['node',str(root/'harness/release-integrity.mjs'),'source',str(root)],check=True)
if release.exists(): raise SystemExit('release-exists: keep previous bytes; remove only this task-owned release before explicit rebuild')
release.parent.mkdir(exist_ok=True)
def ignored(directory,names):
 if 'node_modules' in Path(directory).parts:return []
 return [n for n in names if n in ['tests','__tests__','.agents','.github','.claude','docs','website','snapshots','benchmarks'] or n.endswith(('.spec.ts','.test.ts','.tsbuildinfo'))]
shutil.copytree(source,release,symlinks=True,ignore=ignored)
for name in ['layout','sidebar','threads','apps','messages','memory','aumlok','documents','settings']:
 src=root/'packages/ui/faces'/name;dst=release/'plugins'/('aukora-face-'+name)
 dst.mkdir(parents=True)
 for n in ['package.json','lib','assets','vendor']:
  if (src/n).is_dir():shutil.copytree(src/n,dst/n,symlinks=True)
  elif (src/n).is_file():shutil.copy2(src/n,dst/n)
 shutil.copy2(root/'harness/ui-host.mjs',dst/'lib/prime-host.mjs')
shutil.copytree(root/'harness',release/'harness')
# Browser composition stays inside this release. No source checkout discovery.
client_binding=release/'harness/owner-memory-client.mjs'
client_text=client_binding.read_text()
for module in ['ui-adapter.mjs','owner-memory-workflow.mjs']:
 old="'../packages/runtime-bridge/src/"+module+"'"
 if client_text.count(old)!=1:raise SystemExit('owner-memory-import-mismatch: '+module)
 client_text=client_text.replace(old,"'../prime-packages/runtime-bridge/src/"+module+"'")
client_binding.write_text(client_text)
for package in ['contracts','execution','authority','memory','inference','ops','runtime-bridge']:
 shutil.copytree(root/'packages'/package,release/'prime-packages'/package,symlinks=True,ignore=lambda directory,names:[n for n in names if n in ['test','tests','checks'] or n in ['check.mjs','build-sdk.py']])
ui=release/'prime-packages/ui';ui.mkdir(parents=True)
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
(release/'prime-served-baseline.json').write_text(json.dumps({'version':1,'donor':manifest['commit'],'files':served,'rebuilt_substitutions':False},indent=2)+'\n')
for package,target in [('foundation','aukora-foundation'),('prime-authority','prime-authority')]:
 src=root/'packages/ui'/package;dst=release/'plugins'/target
 shutil.copytree(src,dst,symlinks=True,ignore=lambda directory,names:[n for n in names if n in ['src','checks','licenses']])
shutil.copy2(root/'harness/preview-connection.mjs',release/'packages/client/connection/lib/prime-host.mjs')
shutil.copy2(root/'harness/gateway-host.mjs',release/'packages/api/gateway/lib/prime-host.mjs')
for target in ['packages/api/workspace-controller','packages/client/file-upload']:
 shutil.copy2(root/'harness/ui-host.mjs',release/target/'lib/prime-host.mjs')
removed_links=[]
for link in release.rglob('*'):
 if link.is_symlink() and not link.exists():
  removed_links.append(str(link.relative_to(release)));link.unlink()
(release/'prime-stripped-links.json').write_text(json.dumps(removed_links,indent=2)+'\n')
subprocess.run(['node',str(root/'harness/release-integrity.mjs'),'snapshot',str(root),str(release)],check=True)
subprocess.run(['node',str(root/'scripts/compose-entries.mjs'),str(release)],check=True)
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
require_clean_source()
(release/'prime-release.json').write_text(json.dumps({'version':'0.1.0','source_commit':commit,'dsh_commit':'0d1f50007f9bca3f52b06e1c3074fa14d5fb0720','cordis':'4.0.2','ui_donor':ui_donor,'unavailable_capabilities':['owner-passkey','approved-shell','sdk-child-launchers','model-inference','durable-memory','messaging','media-generation']},indent=2)+'\n')
# Upstream copies can retain their source checkout's group-writable modes.
# Tighten only the fresh output; exact bytes and executable bits stay unchanged.
for path in [release,*release.rglob('*')]:
 mode=path.lstat().st_mode
 if stat.S_ISDIR(mode) or stat.S_ISREG(mode):path.chmod(stat.S_IMODE(mode)&~0o7022)
print('COMPOSED',release)
