#!/usr/bin/env node
// Generate the source release and host surface; refuse a stale page.
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'
import { generated, root, rows, source, sourcePath } from '../../tests/helpers/release-composition.mjs'

const upstream = {"commit":"0d1f50007f9bca3f52b06e1c3074fa14d5fb0720","archiveSha256":"ae0968314dcd5e3c9d7e8f1f5748bbd289afc4ef5668187e0ef6524a7c64c87e","files":{"packages/bundle/base/cordis.patch.yml":{"sha256":"984c2b4fab4b145d8db2b6d94f7584860b81dc6a1ff5fdecad806845a0410fa2","rows":[{"id":"timer","name":"@deepseek-ai/cordis-plugin-timer"},{"id":"hmr","name":"@deepseek-ai/cordis-plugin-hmr","disabled":true},{"id":"llm","name":"@deepseek-ai/dsh-llm"},{"id":"deepseek-llm-api-extensions","name":"@deepseek-ai/dsh-deepseek-llm-api-extensions"},{"id":"session","name":"@deepseek-ai/dsh-session"},{"id":"session-log-deepseek","name":"@deepseek-ai/dsh-session-log-deepseek"},{"id":"typert","name":"@deepseek-ai/dsh-typert-registry"},{"id":"typert-loader","name":"@deepseek-ai/dsh-typert-loader"},{"id":"typert-gateway","name":"@deepseek-ai/dsh-api-gateway"},{"id":"session-title","name":"@deepseek-ai/dsh-session-title"},{"id":"session-title-llm","name":"@deepseek-ai/dsh-session-title-first-prompt-llm"},{"id":"user-questions","name":"@deepseek-ai/dsh-user-questions"},{"id":"agent","name":"@deepseek-ai/dsh-agent"},{"id":"plugin-package-inventory-deepseek","name":"@deepseek-ai/dsh-plugin-package-inventory-deepseek"},{"id":"agent-default-model","name":"@deepseek-ai/dsh-agent-default-model"},{"id":"jobs","name":"@deepseek-ai/dsh-jobs-local"},{"id":"llm-retry","name":"@deepseek-ai/dsh-llm-retry"},{"id":"settings","name":"@deepseek-ai/dsh-settings-file"},{"id":"credentials","name":"@deepseek-ai/dsh-credentials-local"},{"id":"llm-pi-ai","name":"@deepseek-ai/dsh-llm-pi-ai"},{"id":"session-persistence-jsonl","name":"@deepseek-ai/dsh-session-persistence-jsonl"},{"id":"attachment-local","name":"@deepseek-ai/dsh-attachment-local"},{"id":"session-query-sqlite","name":"@deepseek-ai/dsh-session-query-sqlite"},{"id":"session-projection","name":"@deepseek-ai/dsh-session-projection"},{"id":"storage","name":"@deepseek-ai/dsh-storage"},{"id":"storage-json","name":"@deepseek-ai/dsh-storage-json"},{"id":"storage-domain","name":"@deepseek-ai/dsh-storage-domain"},{"id":"session-projection-cache","name":"@deepseek-ai/dsh-session-projection-cache"},{"id":"session-telemetry-otel","name":"@deepseek-ai/dsh-session-telemetry-otel"},{"id":"subprocess","name":"@deepseek-ai/dsh-subprocess-local"},{"id":"sandbox","name":"@deepseek-ai/dsh-sandbox-local"},{"id":"sandbox-policy","name":"@deepseek-ai/dsh-sandbox-policy"},{"id":"bash-sandbox","name":"@deepseek-ai/dsh-bash-sandbox","disabled":false},{"id":"pwsh-sandbox","name":"@deepseek-ai/dsh-pwsh-sandbox","disabled":true},{"id":"approval","name":"@deepseek-ai/dsh-user-approval"},{"id":"permission","name":"@deepseek-ai/dsh-permission-presets"},{"id":"shell-env","name":"@deepseek-ai/dsh-shell-env"},{"id":"tool-bash","name":"@deepseek-ai/dsh-tool-bash","disabled":false},{"id":"tool-pwsh","name":"@deepseek-ai/dsh-tool-pwsh","disabled":true},{"id":"tool-jobs","name":"@deepseek-ai/dsh-tool-jobs"},{"id":"fs-observation-policy","name":"@deepseek-ai/dsh-fs-observation-policy"},{"id":"tool-fs","name":"@deepseek-ai/dsh-tool-fs"},{"id":"tool-fs-search","name":"@deepseek-ai/dsh-tool-fs-search"},{"id":"agent-instructions","name":"@deepseek-ai/dsh-agent-instructions"},{"id":"skill","name":"@deepseek-ai/dsh-skill"},{"id":"skill-filesystem","name":"@deepseek-ai/dsh-skill-filesystem"},{"id":"skill-badge","name":"@deepseek-ai/dsh-skill-badge","disabled":true},{"id":"tool-skill","name":"@deepseek-ai/dsh-tool-skill"},{"id":"commands","name":"@deepseek-ai/dsh-commands"},{"id":"command-feedback","name":"@deepseek-ai/dsh-command-feedback"},{"id":"goal","name":"@deepseek-ai/dsh-goal"},{"id":"goal-round-driver","name":"@deepseek-ai/dsh-goal-round-driver"},{"id":"command-goal","name":"@deepseek-ai/dsh-command-goal"},{"id":"plan-mode","name":"@deepseek-ai/dsh-plan-mode"},{"id":"token-meter","name":"@deepseek-ai/dsh-token-meter"},{"id":"compaction-basic","name":"@deepseek-ai/dsh-compaction-basic"},{"id":"command-compact","name":"@deepseek-ai/dsh-command-compact"},{"id":"subagent","name":"@deepseek-ai/dsh-subagent"},{"id":"subagent-spawn-in-process","name":"@deepseek-ai/dsh-subagent-spawn-in-process"},{"id":"subagent-fork-in-process","name":"@deepseek-ai/dsh-subagent-fork-in-process"},{"id":"tool-subagent-control","name":"@deepseek-ai/dsh-tool-subagent-control"},{"id":"tool-subagent-list-agents","name":"@deepseek-ai/dsh-tool-subagent-control/list-agents"},{"id":"tool-subagent","name":"@deepseek-ai/dsh-tool-subagent"},{"id":"tool-subagent-fork","name":"@deepseek-ai/dsh-tool-subagent"},{"id":"ptc-runtime","name":"@deepseek-ai/dsh-ptc-runtime-node"},{"id":"workflow-ptc","name":"@deepseek-ai/dsh-workflow-ptc"},{"id":"tool-workflow","name":"@deepseek-ai/dsh-tool-workflow"},{"id":"timeout-policy","name":"@deepseek-ai/dsh-tool-call-timeout-policy"},{"id":"spill-local","name":"@deepseek-ai/dsh-spill-local"},{"id":"spill-policy","name":"@deepseek-ai/dsh-spill-policy"},{"id":"session-checkpoint-policy","name":"@deepseek-ai/dsh-session-checkpoint-policy"},{"id":"tool-result-pruner","name":"@deepseek-ai/dsh-compaction-tool-result-pruner"},{"id":"image-offload","name":"@deepseek-ai/dsh-compaction-image-offload"},{"id":"tool-todo","name":"@deepseek-ai/dsh-tool-todo"},{"id":"tool-goal","name":"@deepseek-ai/dsh-tool-goal"},{"id":"tool-ralph","name":"@deepseek-ai/dsh-tool-ralph","disabled":true},{"id":"repeat-tool-reminder","name":"@deepseek-ai/dsh-repeat-tool-reminder"},{"id":"web","name":"@deepseek-ai/dsh-web"},{"id":"web-search-deepseek","name":"@deepseek-ai/dsh-web-search-deepseek"},{"id":"web-fetch-http","name":"@deepseek-ai/dsh-web-fetch-http"},{"id":"tool-web","name":"@deepseek-ai/dsh-tool-web"},{"id":"mcp-resources","name":"@deepseek-ai/dsh-mcp-resources"},{"id":"tools","name":"@deepseek-ai/dsh-tools"},{"id":"system-prompt","name":"@deepseek-ai/dsh-system-prompt"},{"id":"agent-loop","name":"@deepseek-ai/dsh-agent-loop"},{"id":"fs-sandbox","name":"@deepseek-ai/dsh-fs-sandbox"},{"id":"llm-deepseek","name":"@deepseek-ai/dsh-llm-deepseek"}]},"packages/bundle/web-app/cordis.patch.yml":{"sha256":"66d91275b050a4f2b29f4584b58b128a49009d9c95ca62240c098fa57c5ee2e8","rows":[{"id":"system-prompt"},{"id":"session-query-sqlite"},{"id":"tools"},{"id":"subagent-model-selection-settings","name":"@deepseek-ai/dsh-tool-subagent/model-selection-settings"},{"id":"message-feedback","name":"@deepseek-ai/dsh-message-feedback"},{"id":"session-log-download","name":"@deepseek-ai/dsh-session-log-export"},{"id":"open-in-app","name":"@deepseek-ai/dsh-host-open-in-app"},{"id":"ui-open-in-app","name":"@deepseek-ai/dsh-client-ui-open-in-app"},{"id":"workspace","name":"@deepseek-ai/dsh-workspace"},{"id":"session-reference","name":"@deepseek-ai/dsh-session-reference"},{"id":"file-reference-local","name":"@deepseek-ai/dsh-file-reference-local"},{"id":"session-stats","name":"@deepseek-ai/dsh-session-stats"},{"id":"session-turn-outline","name":"@deepseek-ai/dsh-session-turn-outline"},{"id":"directory-picker","name":"@deepseek-ai/dsh-host-directory-picker-auto"},{"id":"plugin-inventory","name":"@deepseek-ai/dsh-host-plugin-inventory"},{"id":"session-controller","name":"@deepseek-ai/dsh-api-session-controller"},{"id":"terminal-controller","name":"@deepseek-ai/dsh-api-terminal-controller"},{"id":"workspace-files","name":"@deepseek-ai/dsh-api-workspace-files"},{"id":"settings-controller","name":"@deepseek-ai/dsh-api-settings-controller"},{"id":"workspace-controller","name":"@deepseek-ai/dsh-api-workspace-controller"},{"id":"cordis-host-runner","name":"@deepseek-ai/dsh-cordis-host-runner"},{"id":"web-startup","name":"@deepseek-ai/dsh-web-app/startup"},{"id":"webserver","name":"@deepseek-ai/dsh-host-webserver"},{"id":"web-runtime","name":"@deepseek-ai/dsh-web-app"},{"id":"client-hmr","name":"@deepseek-ai/dsh-client-hmr"},{"id":"modules","name":"@deepseek-ai/dsh-client-modules"},{"id":"connection","name":"@deepseek-ai/dsh-client-connection"},{"id":"file-upload","name":"@deepseek-ai/dsh-client-file-upload"},{"id":"api-remotes","name":"@deepseek-ai/dsh-api-remotes"},{"id":"cordis-client-runner","name":"@deepseek-ai/dsh-cordis-client-runner"},{"id":"ui-theme","name":"@deepseek-ai/dsh-client-ui-theme"},{"id":"locale","name":"@deepseek-ai/dsh-client-locale"},{"id":"ui-layout","name":"@deepseek-ai/dsh-client-ui-layout"},{"id":"ui-renderer","name":"@deepseek-ai/dsh-client-ui-renderer"},{"id":"ui-session","name":"@deepseek-ai/dsh-client-ui-session"},{"id":"resources","name":"@deepseek-ai/dsh-client-resources"},{"id":"ui-sidebar","name":"@deepseek-ai/dsh-client-ui-sidebar"},{"id":"ui-sidebar-right","name":"@deepseek-ai/dsh-client-ui-sidebar-right"},{"id":"ui-sidebar-documentpreview","name":"@deepseek-ai/dsh-client-ui-sidebar-documentpreview"},{"id":"ui-sidebar-terminal","name":"@deepseek-ai/dsh-client-ui-sidebar-terminal"},{"id":"ui-sidebar-files","name":"@deepseek-ai/dsh-client-ui-sidebar-files"},{"id":"ui-settings","name":"@deepseek-ai/dsh-client-ui-settings"},{"id":"ui-settings-general","name":"@deepseek-ai/dsh-client-ui-settings-general"},{"id":"ui-settings-models","name":"@deepseek-ai/dsh-client-ui-settings-models"},{"id":"ui-settings-plugin-inventory","name":"@deepseek-ai/dsh-client-ui-settings-plugin-inventory"},{"id":"ui-settings-unarchive-sessions","name":"@deepseek-ai/dsh-client-ui-settings-unarchive-sessions"},{"id":"ui-conversation","name":"@deepseek-ai/dsh-client-ui-conversation"},{"id":"ui-approval","name":"@deepseek-ai/dsh-client-ui-approval"},{"id":"ui-chat","name":"@deepseek-ai/dsh-client-ui-chat"},{"id":"ui-brand-official","name":"@deepseek-ai/dsh-client-ui-brand-official"},{"id":"ui-attachment","name":"@deepseek-ai/dsh-client-ui-attachment"},{"id":"ui-tool","name":"@deepseek-ai/dsh-client-ui-tool"},{"id":"ui-cordis","name":"@deepseek-ai/dsh-client-ui-cordis"},{"id":"ui-workflow-run","name":"@deepseek-ai/dsh-client-ui-workflow-run"},{"id":"ui-deliverables","name":"@deepseek-ai/dsh-client-ui-deliverables"},{"id":"ui-workspace","name":"@deepseek-ai/dsh-client-ui-workspace"},{"id":"ui-input-trigger","name":"@deepseek-ai/dsh-client-ui-input-trigger"},{"id":"ui-commands","name":"@deepseek-ai/dsh-client-ui-commands"},{"id":"ui-skill","name":"@deepseek-ai/dsh-client-ui-skill"},{"id":"ui-subagent","name":"@deepseek-ai/dsh-client-ui-subagent"},{"id":"ui-reference","name":"@deepseek-ai/dsh-client-ui-reference"},{"id":"ui-schedule","name":"@deepseek-ai/dsh-client-ui-schedule","disabled":true},{"id":"ui-jobs","name":"@deepseek-ai/dsh-client-ui-jobs"},{"id":"ui-goal","name":"@deepseek-ai/dsh-client-ui-goal"},{"id":"ui-message-feedback","name":"@deepseek-ai/dsh-client-ui-message-feedback"},{"id":"ui-model-selection","name":"@deepseek-ai/dsh-client-ui-model-selection"},{"id":"ui-permission","name":"@deepseek-ai/dsh-client-ui-permission-presets"},{"id":"ui-agent-preset","name":"@deepseek-ai/dsh-client-ui-agent-preset"},{"id":"ui-settings-plugins","name":"@deepseek-ai/dsh-client-ui-settings-plugins"},{"id":"ui-plan","name":"@deepseek-ai/dsh-client-ui-plan"},{"id":"ui-user-questions","name":"@deepseek-ai/dsh-client-ui-user-questions"},{"id":"ui-trajectory","name":"@deepseek-ai/dsh-client-ui-trajectory"},{"id":"tool-bash","disabled":true},{"id":"tool-pwsh","disabled":true},{"id":"tool-jobs","disabled":true},{"id":"tool-fs","disabled":true},{"id":"tool-fs-search","disabled":true},{"id":"skill-filesystem","disabled":true},{"id":"tool-skill","disabled":true},{"id":"command-goal","disabled":true},{"id":"tool-goal","disabled":true},{"id":"plan-mode","disabled":true},{"id":"compaction-basic","disabled":true},{"id":"command-compact","disabled":true},{"id":"tool-result-pruner","disabled":true},{"id":"tool-subagent-control","disabled":true},{"id":"tool-subagent-list-agents","disabled":true},{"id":"tool-subagent","disabled":true},{"id":"tool-subagent-fork","disabled":true},{"id":"workflow-ptc","disabled":true},{"id":"tool-workflow","disabled":true},{"id":"tool-ralph","disabled":true},{"id":"agent-instructions","disabled":true},{"id":"tool-todo","disabled":true},{"id":"tool-web","disabled":true},{"id":"agent-presets","name":"@deepseek-ai/dsh-agent-presets"}]},"packages/preset/agent-presets/presets/standard/agent.cordis.yml":{"sha256":"942480b0e441277063f358a511f2727dc2ef8ee6a5e5e127cee1faea3dab0149","rows":[{"id":"persona","name":"@deepseek-ai/dsh-persona"},{"id":"agent-instructions","name":"@deepseek-ai/dsh-agent-instructions"},{"id":"tool-bash","name":"@deepseek-ai/dsh-tool-bash","disabled":false},{"id":"tool-pwsh","name":"@deepseek-ai/dsh-tool-pwsh","disabled":true},{"id":"tool-fs","name":"@deepseek-ai/dsh-tool-fs"},{"id":"tool-fs-search","name":"@deepseek-ai/dsh-tool-fs-search"},{"id":"tool-jobs","name":"@deepseek-ai/dsh-tool-jobs"},{"id":"skill-filesystem","name":"@deepseek-ai/dsh-skill-filesystem"},{"id":"tool-skill","name":"@deepseek-ai/dsh-tool-skill"},{"id":"command-goal","name":"@deepseek-ai/dsh-command-goal"},{"id":"tool-goal","name":"@deepseek-ai/dsh-tool-goal"},{"id":"planning","name":"cordis:group"},{"id":"plan-mode","name":"@deepseek-ai/dsh-plan-mode"},{"id":"compaction","name":"cordis:group"},{"id":"compaction-basic","name":"@deepseek-ai/dsh-compaction-basic"},{"id":"command-compact","name":"@deepseek-ai/dsh-command-compact"},{"id":"tool-result-pruner","name":"@deepseek-ai/dsh-compaction-tool-result-pruner"},{"id":"delegation","name":"cordis:group"},{"id":"tool-subagent-control","name":"@deepseek-ai/dsh-tool-subagent-control"},{"id":"tool-subagent-list-agents","name":"@deepseek-ai/dsh-tool-subagent-control/list-agents"},{"id":"tool-subagent","name":"@deepseek-ai/dsh-tool-subagent"},{"id":"tool-subagent-fork","name":"@deepseek-ai/dsh-tool-subagent"},{"id":"tool-subagent-codex","name":"@deepseek-ai/dsh-tool-subagent","disabled":true},{"id":"tool-subagent-claude-code","name":"@deepseek-ai/dsh-tool-subagent","disabled":true},{"id":"workflow-ptc","name":"@deepseek-ai/dsh-workflow-ptc"},{"id":"tool-workflow","name":"@deepseek-ai/dsh-tool-workflow"},{"id":"tool-ralph","name":"@deepseek-ai/dsh-tool-ralph","disabled":true},{"id":"tool-ask-user","name":"@deepseek-ai/dsh-tool-ask-user"},{"id":"tool-todo","name":"@deepseek-ai/dsh-tool-todo"},{"id":"tool-web","name":"@deepseek-ai/dsh-tool-web"},{"id":"present","name":"@deepseek-ai/dsh-tool-present"}]}}}
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const fail = code => { throw Object.assign(new Error(code), { code }) }
const link = file => `[${file}](../${file})`
const code = value => `\`${value}\``
const loadTests = 'tests/release-plugins-load.test.mjs, tests/aukora-overlay-mounts.test.mjs'
const hostTests = 'packages/boundary-gate/host/install/check-bootstrap.py'
const unitTests = 'packages/boundary-gate/host/systemd/hardening.test.mjs'
const unitDirectories = ['packages/boundary-gate/host/systemd', 'host/units', 'host/relay',
  'host/auma-local-deny', 'host/aura-interim', 'host/prime-mirror', 'ops/buzz-relay', 'ops/buzz-relay/units', 'ops/systemd']
const purposes = {
  'aukora-foundation': 'Brand and palette', 'aukora-composition-gate': 'Inspect launch/import admission',
  'aukora-goal-resume': 'Resume interrupted goals', 'aukora-subscription-hands': 'Confined subscription commands',
  'aukora-action-gate': 'Judge and receipt tool calls', 'aukora-seatbelt': 'Confine child commands on macOS',
  'aukora-caged-worker': 'Dispatch bounded work', 'aukora-auma-theme': 'Propose an owner-reviewed theme',
  'aukora-buzz-door': 'Bounded Buzz channel reads, posts and wakeup', 'aukora-kira': 'Tracked memory capture and recall',
  'aukora-aumlok': 'Identity and owner review', 'aukora-aura-association': 'Associate evidence',
  'aukora-board': 'Cross-session board', 'aukora-eye': 'Owner-configured screen capture (tool denied by default)',
}
const toolPurposes = [
  [/^(read|read_image|grep|glob|present)$/u, 'Read/search files or present artifacts; paths judged'],
  [/^str_replace_editor$/u, 'Read/edit files; command and paths judged'],
  [/^(write|edit)$/u, 'Write workspace files; paths judged'],
  [/^(bash|terminal_open|terminal_send|run_code)$/u, 'Execute commands; shell/path policy applies'],
  [/^web_/u, 'Fetch or search the web; network policy applies'],
  [/^(skill|todo_write|ask_user_question|workflow|exit_plan_mode)$/u, 'Agent planning and workflow'],
  [/^aura_association$/u, 'Associate evidence; absolute paths required'],
  [/^(send_message|interrupt_agent|list_agents|subagent)/u, 'Manage or communicate with subagents'],
  [/^(get_goal|create_goal|update_goal)$/u, 'Manage goals'],
  [/^read_mcp_resource$/u, 'Read a connected resource'],
  [/^session_/u, 'Query or inspect session history'], [/^job_/u, 'Inspect or stop background jobs'],
  [/^(kira_|memory\.put|mcp__viking__|mcp__kira-memory__)/u, 'Tracked memory and configured memory bridge'],
  [/^cordis_inspect_/u, 'Inspect composition'], [/^list_/u, 'Deployment-approved list family'],
  [/^aukora_gate_propose$/u, 'Propose exact bytes; owner decides'],
  [/^buzz_/u, 'Bounded Buzz chat or signed receipt delivery'],
  [/^aukora_self_change$/u, 'Propose self-change through owner approval'],
  [/^aukora_workspace_patch$/u, 'Confined workspace patch proposal'],
]

export function upstreamRows(text) {
  const result = []
  let row, indent
  for (const line of text.split('\n')) {
    const id = /^(\s*)- id: (\S+)\s*$/u.exec(line)
    if (id) { row = { id: id[2] }; indent = id[1].length; result.push(row); continue }
    const field = /^(\s*)(name|disabled): (.+?)\s*$/u.exec(line)
    if (!field || !row || field[1].length !== indent + 2) continue
    const value = field[3]
    if (field[2] === 'name') row.name = value.replace(/^(['"])(.*)\1$/u, '$2')
    else if (value === 'true' || value === "!!js process.platform !== 'win32'") row.disabled = true
    else if (value === 'false' || value === "!!js process.platform === 'win32'") row.disabled = false
    else fail('surface:upstream-disabled-unreadable')
  }
  return result
}

export function verifyUpstream(pin, archive = join(root, 'vendor/dsh-source.tar.gz')) {
  if (pin.commit !== upstream.commit || pin.archiveSha256 !== upstream.archiveSha256) fail('surface:upstream-review-required')
  if (!archive || !existsSync(archive)) return
  const actual = JSON.parse(execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', `
import hashlib,json,sys,tarfile
from pathlib import Path
archive=Path(sys.argv[1]); expected=json.loads(sys.argv[2])
if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected['archiveSha256']: raise SystemExit('surface:archive-pin')
with tarfile.open(archive,'r:gz') as tar:
    names={entry.name.partition('/')[2]:entry for entry in tar.getmembers() if entry.isfile()}
    print(json.dumps({name:tar.extractfile(names[name]).read().decode() for name in expected['files']}))
`, archive, JSON.stringify(upstream)], { encoding: 'utf8', timeout: 5000 }))
  for (const [file, item] of Object.entries(upstream.files)) {
    if (hash(actual[file]) !== item.sha256) fail('surface:upstream-snapshot-drift')
    if (JSON.stringify(upstreamRows(actual[file])) !== JSON.stringify(item.rows)) fail('surface:upstream-rows-drift')
  }
}

export function inventory({ materializer = source, archive, pin = JSON.parse(readFileSync(join(root, 'upstream-dsh.json'))) } = {}) {
  verifyUpstream(pin, archive)
  const patch = generated(materializer, { includeUpstream: false }).patches['aukora-composition.patch.yml']
  const mounts = new Map()
  for (const item of Object.values(upstream.files).slice(0, 2)) for (const row of item.rows) mounts.set(row.id, { ...mounts.get(row.id), ...row })
  for (const row of rows(patch, 'default')) mounts.set(row.id, { ...mounts.get(row.id), ...row })
  const plugins = [...mounts.values()].filter(row => row.name && row.disabled !== true)
  const session = Object.values(upstream.files)[2].rows.filter(row => row.name !== 'cordis:group' && row.disabled !== true)
  const declared = mounts.get('aukora-action-gate')?.config.allowTools
  if (!Array.isArray(declared) || !declared.length) fail('surface:action-gate-absent')
  const policy = readFileSync(join(root, 'plugins/aukora-action-gate/lib/policy.mjs'), 'utf8')
  const known = [...policy.matchAll(/case '([^']+)':/gu)].map(match => match[1]).filter(name => !name.startsWith('cordis_'))
  const tools = [...new Set([...declared, ...known, 'memory.put'])].sort()
  const units = unitDirectories.flatMap(directory => readdirSync(join(root, directory)).filter(name => /\.(?:service|timer)(?:\.in)?$/u.test(name))
    .map(name => ({ file: `${directory}/${name}`, text: readFileSync(join(root, directory, name), 'utf8') })))
  const bootstrap = 'packages/boundary-gate/host/install/gate-bootstrap.py'
  const custody = JSON.parse(execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', `
import ast,json,sys
tree=ast.parse(sys.stdin.read()); names={'BOOTSTRAP','PYTHON','NODE','PACKAGE','MANIFEST','SIGNER_EPOCHS','LAUNCHER_ROOT','OWNER_KEY_ROOT','AURA_ROOT','AURA_CONFIG'}
print(json.dumps({n.targets[0].id:ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in names}))
`], { input: readFileSync(join(root, bootstrap), 'utf8'), encoding: 'utf8', timeout: 5000 }))
  return { plugins, session, tools, units, custody, bootstrap, patch }
}

export function renderSurface(options) {
  const { plugins, session, tools, units, custody, bootstrap } = inventory(options)
  const table = []
  const row = (kind, names, purpose, sources, tests) => table.push(`| ${kind} | ${names} | ${purpose.replaceAll('|', '/')} | ${sources} | ${tests.startsWith('UNPERFORMED:') ? tests : tests.split(', ').map(link).join(', ')} |`)
  for (const item of plugins.filter(item => item.id.startsWith('aukora-'))) {
    const purpose = item.id.startsWith('aukora-face-') ? `${item.id.slice(12)} face` : purposes[item.id]
    if (!purpose) fail(`surface:plugin-purpose-missing:${item.id}`)
    row('Release plugin', code(item.id), purpose, link(relative(root, sourcePath(item.name))),
      item.id.startsWith('aukora-face-') ? 'tests/face-plugins-load.test.mjs' : loadTests)
  }
  // Group inherited rows by subsystem so every name remains visible in one short table.
  const inherited = new Set(plugins.filter(item => !item.id.startsWith('aukora-')))
  for (const [pattern, purpose] of [
    [/^ui-|^locale$|^resources$|^modules$|^connection$|^client-/u, 'Browser presentation and client transport'],
    [/^llm|^deepseek-|^credentials$|^agent-default-model$|^token-meter$/u, 'Model routing, credentials and metering'],
    [/^session|^attachment-|^storage|^file-reference|^image-offload$/u, 'Session history, persistence and projection'],
    [/^sandbox|^bash-sandbox$|^permission$|^approval$|^subprocess$|^shell-env$|^fs-|^workspace|^ptc-/u, 'Execution, workspace files and confinement services'],
    [/^web|^mcp-|^api-|^typert|controller$|^file-upload$|^cordis-/u, 'Web transport, remote APIs and host controllers'],
    [/^subagent|^goal|^commands$|^command-|^skill$|^tools$|^system-prompt$|^agent/u, 'Agent, delegation, goals and tool registries'],
    [/./u, 'Scheduling, settings, feedback and session policies'],
  ]) {
    const selected = [...inherited].filter(item => pattern.test(item.id))
    for (const item of selected) inherited.delete(item)
    row('Release plugins', selected.map(item => code(item.id)).join(', '), purpose,
      `${code('upstream-dsh.json → base + web-app/cordis.patch.yml')}, ${link('scripts/materialize-aukora-release.py')}`, 'scripts/fresh-clone-runtime.mjs')
  }
  row('Standard session plugins', session.map(item => code(item.id)).join(', '), 'Default agent tools and prompt (Linux/macOS)',
    code('upstream-dsh.json → presets/standard/agent.cordis.yml'), 'scripts/fresh-clone-runtime.mjs')
  for (const tool of tools) {
    const purpose = toolPurposes.find(([pattern]) => pattern.test(tool))?.[1]
    if (!purpose) fail(`surface:tool-purpose-missing:${tool}`)
    row('Allowed tool/family', code(tool), purpose, `${link('overlays/action-gate.patch.yml')}, ${link('plugins/aukora-action-gate/lib/policy.mjs')}`, 'plugins/aukora-action-gate/check.mjs')
  }
  const rootPurpose = { BOOTSTRAP: 'Pre-Node custody verifier', PYTHON: 'System interpreter trust anchor', NODE: 'Pinned Node trust anchor',
    PACKAGE: 'Gate and receipt authority package', MANIFEST: 'Complete package hash inventory', SIGNER_EPOCHS: 'Public signer epoch registry',
    LAUNCHER_ROOT: 'Reviewed launcher checkout', OWNER_KEY_ROOT: 'Owner signature validation',
    AURA_ROOT: 'Optional protected Aura source profile', AURA_CONFIG: 'Optional protected Aura context profile' }
  for (const [name, path] of Object.entries(custody)) row('Root component', code(path), rootPurpose[name], link(bootstrap), hostTests)
  for (const unit of units) row('Root unit (operator install)', code(unit.file.split('/').at(-1)),
    /^Description=(.+)$/mu.exec(unit.text)?.[1] ?? 'Scheduled host service', link(unit.file),
    unit.file.startsWith('ops/buzz-relay/') ? 'ops/buzz-relay/test.mjs' : unitTests)
  const commands = new Map()
  for (const unit of units) for (const command of unit.text.matchAll(/^Exec\w+=(.+)$/gmu)) {
    for (const match of command[1].matchAll(/(?:^|\s)(\/usr\/local\/(?:lib|sbin)\/[^\s;]+|\/opt\/[^\s;]+)/gu)) {
      if (!Object.values(custody).includes(match[1])) commands.set(match[1], unit.file)
    }
  }
  for (const [command, file] of [...commands].sort()) row('Root unit path/helper', code(command),
    'Unit-referenced path; operator-provisioned', link(file), unitTests)
  for (const [path, purpose, file, tests] of [
    ['/usr/local/lib/aukora-boundary/{sbx-exec,openshell}', 'Confined Linux executor and gateway scripts', 'packages/boundary-gate/host/SETUP.md', 'tests/aukora-openshell-confinement.test.mjs'],
    ['/etc/aukora-boundary/auma-local-deny.nft', 'Host-local network deny rules', 'host/auma-local-deny/install.sh', unitTests],
    ['/usr/local/lib/aukora-buzz/{member,node-v24.11.1,*.sh}', 'Optional Buzz operator tools and admission closure', 'ops/buzz-relay/install.sh', 'ops/buzz-relay/close.test.mjs'],
    ['/usr/local/lib/aukora-aura; /etc/aukora-aura/context.mjs', 'Interim collector scripts and context', 'host/aura-interim/install.sh', 'UNPERFORMED: no independent installer check'],
    ['/usr/local/sbin/aukora-prime-mirror', 'Read-only repository mirror', 'host/prime-mirror/aukora-prime-mirror', unitTests],
  ]) row('Root component', code(path), purpose, link(file), tests)
  const port = (file, pattern) => {
    const match = pattern.exec(readFileSync(join(root, file), 'utf8'))
    if (!match) fail(`surface:listener-unreadable:${file}`)
    return match[1]
  }
  const listeners = [
    [`127.0.0.1:${port('scripts/launch-dsh.py', /default=(\d+), type=int/u)} / Linux unit :${port('packages/boundary-gate/host/systemd/aukora-genesis.service', /--port (\d+)/u)}`, 'Harness HTTP/WebSocket; launcher port is configurable', 'scripts/launch-dsh.py', 'tests/fresh-clone-check.test.mjs'],
    [`127.0.0.1:${port('packages/boundary-gate/src/server.mjs', /ownerHttpPort = (\d+)/u)} (owner-page opt-in)`, 'Gate owner review page; Linux unit leaves it off', 'packages/boundary-gate/src/server.mjs', 'packages/boundary-gate/checks/boundary.mjs'],
    ['/run/aukora-gate/{gate.sock,owner.sock}', 'Proposal and owner Unix sockets', 'packages/boundary-gate/src/server.mjs', 'packages/boundary-gate/checks/boundary.mjs'],
    [`127.0.0.1:${port('packages/boundary-gate/host/openshell/gateway.sh', /OPENSHELL_SERVER_PORT=(\d+)/u)}; /run/user/<uid>/podman/podman.sock`, 'OpenShell gateway and rootless Podman Unix API', 'packages/boundary-gate/host/openshell/gateway.sh', 'tests/aukora-openshell-confinement.test.mjs'],
    [`127.0.0.1:${port('ops/buzz-relay/install.sh', /AUKORA_BUZZ_PORT:-(\d+)/u)} (optional/configurable)`, 'Buzz relay; only published pod port', 'ops/buzz-relay/up.sh', 'ops/buzz-relay/test.mjs'],
    [`pod only: 5432, 6379, ${port('ops/buzz-relay/write-settings.sh', /BUZZ_HEALTH_PORT=(\d+)/u)}, ${port('ops/buzz-relay/write-settings.sh', /BUZZ_METRICS_PORT=(\d+)/u)}`, 'Buzz Postgres, Redis, health and metrics; not host-published', 'ops/buzz-relay/write-settings.sh', 'ops/buzz-relay/test.mjs'],
    [`127.0.0.1:${port('ops/buzz-relay/units/aukora-admission.service', /--port (\d+)/u)} (admission opt-in)`, 'Invite admission HTTP endpoint', 'ops/buzz-relay/units/aukora-admission.service', 'tests/admission-unit.test.mjs'],
    [`127.0.0.1:${port('scripts/openviking-setup.sh', /AUKORA_OPENVIKING_PORT:-(\d+)/u)}, :${port('scripts/openviking-setup.sh', /AUKORA_OPENVIKING_EMBED_PORT:-(\d+)/u)} (configured install)`, 'OpenViking and local CPU embedder; configurable', 'scripts/openviking-setup.sh', 'tests/openviking-load-mode.test.py'],
    [`127.0.0.1:${port('plugins/aukora-kira/lib/viking-door.mjs', /port = (\d+)/u)} (separate operator command)`, 'Tracked Viking HTTP door; configurable', 'plugins/aukora-kira/lib/viking-door.mjs', 'tests/kira-openviking-governed.test.mjs'],
    ['127.0.0.1:ephemeral (desktop)', 'Authenticated screen-capture door', 'apps/aukora-desktop/eye.mjs', 'tests/desktop-eye-privacy.test.mjs'],
    ['127.0.0.1:ephemeral (desktop)', 'Authenticated lane dispatch door', 'apps/aukora-desktop/lane-door.mjs', 'tests/lane-door-message-id.test.mjs'],
    [`127.0.0.1:${port('plugins/aukora-face/apps/vendor/auma-live/voice/sidecar.py', /AUKORA_VOICE_PORT", "(\d+)"/u)} (configured voice install)`, 'Auma Live voice sidecar; installed runtime/model required', 'plugins/aukora-face/apps/vendor/auma-live/voice/sidecar.py', 'tests/voice-sidecar-optional.test.mjs'],
    [`127.0.0.1:${port('scripts/aura/witness.py', /"--port", type=int, default=(\d+)/u)} (operator serve command)`, 'Retained Aura witness HTTP; bind host configurable', 'scripts/aura/witness.py', 'UNPERFORMED: no independent listener check'],
    ['Unix socket: explicitly configured (desktop)', 'Owner signer; no default socket or key', 'scripts/aumlok/signer.mjs', 'tests/fresh-clone-runtime.test.mjs'],
    ['Unix sockets: submit/approve (owner daemon)', 'Proposal submission and owner-only review', 'plugins/aukora-owner-daemon/lib/listener.mjs', 'tests/aukora-owner-protocol.test.mjs'],
    ['Unix sockets: issuer/broker (bounded worker)', 'One-use work dispatch authority', 'plugins/aukora-caged-worker/lib/run.mjs', 'tests/aukora-openshell-confinement.test.mjs'],
    [`127.0.0.1:${port('host/relay/aukora-relay.service', /RELAY_PORT=(\d+)/u)} (legacy service); CLI :${port('host/relay/server.mjs', /RELAY_PORT \?\? '(\d+)'/u)}`, 'Retained HTTP relay; no default plugin/tools', 'host/relay/aukora-relay.service', 'host/relay/check.mjs'],
  ]
  for (const [address, purpose, file, tests] of listeners) row('Listener (source)', code(address), purpose, link(file), tests)
  const inputs = [...new Set([bootstrap, 'scripts/launch-dsh.py', 'scripts/materialize-aukora-release.py',
    'overlays/action-gate.patch.yml', 'plugins/aukora-action-gate/lib/policy.mjs', 'upstream-dsh.json',
    ...units.map(item => item.file), ...listeners.map(item => item[2]), 'host/auma-local-deny/install.sh',
    'ops/buzz-relay/install.sh', 'host/relay/server.mjs', 'packages/boundary-gate/host/openshell/podman-service.sh',
    'host/aura-interim/install.sh', 'host/prime-mirror/aukora-prime-mirror'])].sort()
  const fingerprint = hash(inputs.map(file => `${file}\0${hash(readFileSync(join(root, file)))}`).join('\n'))
  return `# Trusted surface\n\nGenerated by \`node scripts/audit/surface.mjs\`; verify with \`--check\`. Source-only default release, Linux/macOS, without deployment overlays. Wildcards grant name families; allowance still applies argument, path, definition and approval checks. Units and listeners are operator-configured possibilities, not an installed-state claim.\n\n${plugins.length} host/client plugins and ${session.length} standard-session plugins; ${tools.length} allowed names/families. Inherited rows come from reviewed snapshots of the pinned harness bundle sources; upstream repinning requires snapshot review. Checks work without a harness archive; when present, its hash and those three source files are verified. Uploaders remain mounted with uploads disabled; telemetry mode is disabled. The table groups inherited names only.\n\n| Surface | Component/name | Purpose and condition | Source | Tested by (source/fixture unless stated) |\n|---|---|---|---|---|\n${table.join('\n')}\n\nLegacy HTTP relay: deprecated in favor of Buzz; \`--with-legacy-relay\` restores its mount and tools. Its service/source remain for existing installations. The old relay court currently reports 23 passes then \`Twin did not falsify its check: Peter-only decision\`; retention does not qualify it.\n\nRemaining migrations: frozen face generation; stock-app provenance extraction; shared authority/memory donor closure; reproducible generated output; shared Noble crypto; shipped operator-script allowlist; disabled core-read-deny packaging; archival pins/history links; PostgreSQL staging; native presence readers; shared inference store; file-bus launchd retirement; flattened Messages/Nostr resolver. Preserve each consumer and reviewed inventory before removing its copies. Nine sweep deletion candidates are already absent at this revision. Copy parity proves equality, not runtime non-use or safety. This inventory does not prove containment, owner enrollment, listener activation, or that all inherited plugins execute successfully.\n\n<!-- source-inputs-sha256: ${fingerprint} -->\n`
}

export function checkPage(actual, expected) {
  if (actual !== expected) fail('surface:stale')
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.slice(2).some(arg => arg !== '--check')) fail('surface:option')
    const page = join(root, 'docs/SURFACE.md'), expected = renderSurface()
    if (process.argv.includes('--check')) checkPage(readFileSync(page, 'utf8'), expected)
    else writeFileSync(page, expected)
    console.log(`surface: PASS (${process.argv.includes('--check') ? 'current' : 'generated'})`)
  } catch (error) { console.error(error.code ?? 'surface:failed'); process.exitCode = 1 }
}
