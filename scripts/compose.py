#!/usr/bin/env python3
"""Prime-only composition of verified pinned harness + immutable donor client artifacts."""
import json,shutil,subprocess,sys,hashlib
from pathlib import Path
root=Path(__file__).resolve().parents[1]
source=root/'vendor/dsh'
release=root/'.runtime/release'
subprocess.run([sys.executable,str(root/'scripts/build-dsh.py'),'--verify-built'],cwd=root,check=True)
subprocess.run(['node',str(root/'packages/ui/scripts/verify-baseline.mjs')],cwd=root,check=True)
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
removed_links=[]
for link in release.rglob('*'):
 if link.is_symlink() and not link.exists():
  removed_links.append(str(link.relative_to(release)));link.unlink()
(release/'prime-stripped-links.json').write_text(json.dumps(removed_links,indent=2)+'\n')
disabled=['ui-layout','ui-settings-general','ui-sidebar','ui-workspace','llm-deepseek','llm-pi-ai','bash-sandbox','pwsh-sandbox','tool-pwsh','tool-jobs','terminal-controller','ui-sidebar-terminal','tool-subagent','tool-subagent-fork','subagent-spawn-in-process','subagent-fork-in-process','subagent-codex','subagent-claude-code','subagent-dsh-sdk','ptc-runtime','workflow-ptc','tool-workflow','tool-web','web-fetch-http','web-search-deepseek','mcp-resources','tool-fs','tool-fs-search','tool-skill','skill-filesystem','tool-ralph']
text=''.join('- id: '+x+'\n  disabled: true\n' for x in disabled)
text+='- insert:\n    - id: prime-shell\n      name: ./harness/shell-unavailable.mjs\n    - id: prime-host\n      name: ./harness/host.mjs\n'
for name in ['layout','sidebar','threads','apps','messages','memory','aumlok','documents','settings']:
 text+='    - id: aukora-face-'+name+'\n      name: ./plugins/aukora-face-'+name+'/lib/prime-host.mjs\n'
(release/'prime.patch.yml').write_text(text)
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
(release/'prime-release.json').write_text(json.dumps({'version':'0.1.0','source_commit':commit,'dsh_commit':'0d1f50007f9bca3f52b06e1c3074fa14d5fb0720','cordis':'4.0.2','ui_donor':'645d3213b8aede3b544269b4224ae09df06b0a42','unavailable_capabilities':['owner-passkey','approved-shell','sdk-child-launchers','model-inference','durable-memory','messaging','media-generation']},indent=2)+'\n')
print('COMPOSED',release)

