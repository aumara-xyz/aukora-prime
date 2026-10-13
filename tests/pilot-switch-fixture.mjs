// Runs the switch against a private synthetic root and records external commands.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, readdirSync, chmodSync, openSync, closeSync, existsSync } from 'node:fs'
import { spawnSync, spawn, execFileSync } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'

export const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const script = join(repo, 'ops/pilot/live-switch-main.sh')
export const commit = 'bbbbbbb' + 'b'.repeat(33)
export const oldCommit = 'aaaaaaa' + 'a'.repeat(33)
export const units = ['aukora-genesis', 'aukora-boundary-gate', 'aukora-selfcheck.timer', 'aukora-relay', 'aukora-buzz-relay', 'openviking']
const approval = '{"fixture":"owner-approved-new-plugin-set"}\n'
const sha = createHash('sha256').update(approval).digest('hex')
const shellQuote = value => "'" + value.replaceAll("'", "'\\''") + "'"
const missingTools = ['/bin/bash', '/usr/bin/python3', '/usr/bin/tar', '/usr/bin/install', '/bin/mv', '/bin/sleep'].filter(path => !existsSync(path))
if (missingTools.length) { console.log('UNPERFORMED: switch fixture requires ' + missingTools.join(', ')); process.exit(2) }
const json = path => JSON.parse(readFileSync(path, 'utf8'))
function put(path, body, mode) { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, body, mode ? { mode } : undefined) }

export function fixture(config = {}) {
  const root = mkdtempSync(join(repo, 'tests/.pilot-switch-'))
  chmodSync(root, 0o700)
  const at = path => join(root, path.replace(/^\//, ''))
  const oldFiles = {
    '/etc/aukora-genesis/release.env': `AUKORA_RELEASE_DIR=${at('/opt/aukora-genesis/release-aaaaaaa')}\nAUKORA_APPROVAL_ROOT=${at('/etc/aukora-approvals/old/state')}\nAUKORA_RECORD_SHA=old-record\n`,
    '/etc/aukora-boundary-gate/gate-package-manifest.json': 'old-manifest\n',
    '/etc/aukora-boundary-gate/signer-epochs.json': '{}\n',
    '/usr/local/lib/aukora-boundary/gate-bootstrap': 'old-bootstrap\n',
    '/etc/aukora-approvals/release-floor.json': '{"old":true}\n',
    '/opt/aukora-boundary-gate/package-marker': 'old-gate\n',
    '/opt/aukora-genesis/src/fresh-module/index.mjs': 'old source\n',
  }
  if (config.approvalCache) oldFiles['/etc/aukora-approvals/' + commit + '/state/gate-state/old.fixture'] = 'old-approval-cache\n'
  if (!config.ownerAbsent) oldFiles['/opt/owner-key/package-marker'] = 'old-owner\n'
  for (const [path, body] of Object.entries(oldFiles)) put(at(path), body)
  chmodSync(at('/opt/aukora-genesis/src/fresh-module'), 0o755)
  chmodSync(at('/opt/aukora-genesis/src/fresh-module/index.mjs'), 0o644)
  for (const path of ['/root', '/opt/aukora-genesis/src', '/opt/aukora-genesis/release-aaaaaaa', '/opt/aukora-genesis/release-bbbbbbb', '/run/aukora-gate', '/bin']) mkdirSync(at(path), { recursive: true })
  // The script waits for the gate's two sockets before installing an approval; the stand-in machine has them.
  // Bound from inside the directory so the path length limit for sockets cannot matter.
  execFileSync('/usr/bin/python3', ['-I', '-S', '-c', 'import socket\nfor n in ("gate.sock","owner.sock"):\n s=socket.socket(socket.AF_UNIX); s.bind(n); s.close()'], { cwd: at('/run/aukora-gate') })
  put(at('/home/aukora-host/genesis/state/launch-url.json'), '{"url":"http://127.0.0.1:18735/fixture"}\n', 0o600)
  put(at('/test-head'), oldCommit)
  put(at('/test-events'), '')
  put(at('/test-ss-large'), 'ESTAB 0 0 127.0.0.1:18735 127.0.0.1:50000\n' + 'ESTAB 0 0 127.0.0.1:44444 127.0.0.1:50001\n'.repeat(6000))
  for (const unit of units) put(at('/test-unit-' + unit), config.timerInactive && unit.endsWith('.timer') ? '0' : '1')
  put(at('/var/lib/aukora-boundary/targets/plugins/aukora-plugin-set/approval.json'), config.approved ? approval : '{}\n')
  for (const [path, body] of Object.entries({
    'packages/boundary-gate/package-marker': 'new-gate\n',
    'packages/boundary-gate/bin/owner-cli.mjs': '// synthetic owner CLI\n',
    'packages/boundary-gate/host/install/gate-bootstrap.py': 'new-bootstrap\n',
    'packages/boundary-gate/host/install/generate-manifest.py': '# synthetic generator\n',
    'packages/owner-key/package-marker': 'new-owner\n',
  })) put(at('/test-source/' + path), body)
  execFileSync('/usr/bin/tar', ['-C', at('/test-source'), '-cf', at('/test-source.tar'), '.'])
  const writeConfig = next => { put(at('/test-config.json'), JSON.stringify(next)); put(at('/test-config.sh'), Object.entries(next).filter(([, value]) => ['string', 'number', 'boolean'].includes(typeof value)).map(([key, value]) => `${key}=${shellQuote(typeof value === 'boolean' ? (value ? '1' : '0') : String(value))}`).join('\n') + '\n') }
  writeConfig({ approved: false, approveAfter: 2, ...config })
  put(at('/test-approval'), approval)
  put(at('/test-approved'), config.approved ? '1' : '0')
  put(at('/test-polls'), '0')
  put(at('/test-stub.sh'), stubSource(root, process.execPath, sha, commit), 0o755)
  for (const name of ['systemctl', 'ss', 'curl', 'git', 'journalctl', 'sudo', 'python3', 'node', 'sleep', 'chown', 'install', 'id', 'mv', 'owner-cli']) {
    put(at('/usr/bin/' + name), `#!/bin/bash\nset -- ${shellQuote(name)} "$@"\nsource ${shellQuote(at('/test-stub.sh'))}\n`, 0o755)
  }
  put(at('/opt/aukora-node/bin/node'), readFileSync(at('/usr/bin/node')), 0o755)
  put(at('/test-bash-env'), `export PILOT_FIXTURE_SHELL_PID=\${PILOT_FIXTURE_SHELL_PID:-$$}\n` + ['id', 'sleep', 'chown', 'systemctl', 'ss', 'curl', 'git', 'journalctl', 'sudo', 'mv', 'install'].map(name => `${name}() ( set -- ${shellQuote(name)} "$@"; source ${shellQuote(at('/test-stub.sh'))}; )`).join('\n') + '\n')

  const spawnArgs = (args, env, options) => {
    const bash = options.bash ?? '/bin/bash'
    const body = 'umask 002; exec "$0" "$@"'
    const argv = ['-c', body, bash, options.script ?? script, ...args]
    let executable = options.nohup ? '/usr/bin/nohup' : bash
    let commandArgs = options.nohup ? [bash, ...argv] : argv
    if (options.journal) {
      executable = '/usr/bin/python3'
      commandArgs = ['-I', '-S', '-c', 'import os,sys; s=os.fstat(1); os.environ["INVOCATION_ID"]="0123456789abcdef0123456789abcdef"; os.environ["JOURNAL_STREAM"]=str(s.st_dev)+":"+str(s.st_ino); os.execv(sys.argv[1],sys.argv[1:])', bash, ...argv]
    }
    const outputPath = options.journal ? at('/test-journal-output') : null
    const outputFd = outputPath ? openSync(outputPath, 'w', 0o600) : null
    return [executable, commandArgs, { cwd: repo, env: { ...process.env, SSH_CONNECTION: '', SSH_CLIENT: '', SSH_TTY: '', INVOCATION_ID: '', JOURNAL_STREAM: '', PILOT_FIXTURE_SHELL_PID: '', ROOT: root, PILOT_SWITCH_TEST: '1', WAIT_TICKS: '3', BASH_ENV: options.external ? '' : at('/test-bash-env'), PATH: `${at('/usr/bin')}:${process.env.PATH}`, ...env }, detached: !!options.session, timeout: 25000, ...(outputFd === null ? {} : { stdio: ['pipe', outputFd, 'pipe'] }) }, outputPath, outputFd]
  }
  const pendingDetached = new Set()
  const run = (args = [commit], env = {}, options = {}) => {
    const [command, argv, opts, outputPath, outputFd] = spawnArgs(args, env, options)
    try { const result = spawnSync(command, argv, { ...opts, encoding: 'utf8' }); return { ...result, stdout: outputPath ? readFileSync(outputPath, 'utf8') : result.stdout } }
    finally { if (outputFd !== null) closeSync(outputFd) }
  }
  const runAsync = (args = [commit], env = {}, options = {}) => new Promise((resolve, reject) => {
    const [command, argv, opts, outputPath, outputFd] = spawnArgs(args, env, options)
    const child = spawn(command, argv, opts); if (outputFd !== null) closeSync(outputFd)
    let stdout = '', stderr = ''
    child.stdout?.on('data', chunk => { stdout += chunk }); child.stderr.on('data', chunk => { stderr += chunk })
    child.on('error', reject); child.on('close', async (status, signal) => {
      if (outputPath) stdout = readFileSync(outputPath, 'utf8')
      const result = { status, signal, stdout, stderr }
      const detachedPid = result.stdout.match(/DETACHED: pid ([0-9]+);/)?.[1]
      if (detachedPid) pendingDetached.add(Number(detachedPid))
      try { await finishDetached(result, root); if (detachedPid) pendingDetached.delete(Number(detachedPid)); resolve(result) } catch (error) { reject(error) }
    })
  })
  return {
    root, at, oldFiles, run, runAsync,
    config: patch => writeConfig({ ...json(at('/test-config.json')), ...patch }),
    events: () => readFileSync(at('/test-events'), 'utf8').trim().split('\n').filter(Boolean).map(line => { const [name, args, active, head, release] = line.split('\t'); return { name, args: args.split('\x1f'), active: active.split(' ').filter(Boolean).sort(), head, release } }),
    active: () => units.filter(unit => readFileSync(at('/test-unit-' + unit), 'utf8') === '1').sort(),
    head: () => readFileSync(at('/test-head'), 'utf8').trim(),
    backups: () => readdirSync(at('/root')).filter(name => name.startsWith('aukora-backup-pre-')).map(name => at('/root/' + name)),
    cleanup: () => { if (pendingDetached.size) throw new Error('FIXTURE_CHILD_RUNNING: root kept at ' + root); rmSync(root, { recursive: true, force: true }) },
  }
}


async function finishDetached(result, root) {
  const match = result.stdout.match(/DETACHED: pid ([0-9]+);/)
  if (!match) return
  const pid = Number(match[1]); let terminating = false
  let end = Date.now() + 15000
  while (true) {
    let alive = true; try { process.kill(pid, 0) } catch { alive = false }
    const lock = join(root, 'root/aukora-switch.lock')
    const log = readdirSync(join(root, 'root')).find(name => name.startsWith('aukora-switch-log-'))
    const output = log ? readFileSync(join(root, 'root', log), 'utf8') : ''
    if (!alive || (!existsSync(lock) && /SWITCH_DONE|RECOVERY_FAILED|REFUSED:/.test(output))) return
    if (Date.now() > end) {
      if (terminating) throw new Error('fixture detached child did not stop; root retained at ' + root)
      try { process.kill(pid, 'SIGTERM') } catch { return }
      terminating = true; end = Date.now() + 5000
    }
    await new Promise(resolve => setTimeout(resolve, 20))
  }
}

function stubSource(root, node, sha, targetCommit) {
  return `#!/bin/bash
set -u
R=${shellQuote(root)}
REAL_NODE=${shellQuote(node)}
TARGET_COMMIT=${shellQuote(targetCommit)}
SHA=${shellQuote(sha)}
name=$1; shift
source "$R/test-config.sh"
read -r head < "$R/test-head" || true
release=$(< "$R/etc/aukora-genesis/release.env"); release=\${release//$'\\n'/ }
on=''
for unit in aukora-genesis aukora-boundary-gate aukora-selfcheck.timer aukora-relay aukora-buzz-relay openviking; do
  if [ "$(< "$R/test-unit-$unit")" = 1 ]; then on="$on$unit "; fi
done
args=''; for arg in "$@"; do arg=\${arg//$'\\n'/ }; args="$args$arg"$'\\037'; done; args=\${args%$'\\037'}
printf '%s\\t%s\\t%s\\t%s\\t%s\\n' "$name" "$args" "$on" "$head" "$release" >> "$R/test-events"
fail() { echo "fixture $*" >&2; exit 1; }
approve() {
  if [ "$(< "$R/test-approved")" = 0 ] && [ "\${neverApprove:-0}" = 0 ]; then
    n=$(< "$R/test-polls"); n=$((n+1)); printf '%s' "$n" > "$R/test-polls"
    if [ "$n" -ge "\${approveAfter:-2}" ]; then printf 1 > "$R/test-approved"; /bin/cp "$R/test-approval" "$R/var/lib/aukora-boundary/targets/plugins/aukora-plugin-set/approval.json"; fi
  fi
}
case "$name" in
id) echo 0 ;;
sleep|chown) exit 0 ;;
sudo) if [ "\${1:-}" = -u ]; then shift 2; fi; exec "$@" ;;
mv)
  /bin/mv "$@" || exit $?
  dest=\${!#}
  if [[ "$dest" = */state ]]; then
    phase=$(< "$dest"); phase=\${phase#phase=}
    if [ "\${failPhase:-}" = "$phase" ] && [ ! -f "$R/test-phase-failed" ]; then touch "$R/test-phase-failed"; fail "PHASE_FAILED $phase"; fi
    if [ "\${killPhase:-}" = "$phase" ] && [ ! -f "$R/test-killed" ]; then touch "$R/test-killed"; kill -KILL "\${PILOT_FIXTURE_SHELL_PID:-$PPID}"; fi
  fi ;;
install)
  kept=(); while [ "$#" -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) kept+=("$1"); shift ;; esac; done
  exec /usr/bin/install "\${kept[@]}" ;;
systemctl)
  command=$1; shift
  if [ "$command" = show ]; then echo 0123456789abcdef0123456789abcdef; exit 0; fi
  for unit in "$@"; do
    [[ "$unit" = -* ]] && continue
    case "$command" in
    is-active) if [ -f "$R/test-unit-$unit" ] && [ "$(< "$R/test-unit-$unit")" = 1 ]; then echo active; else echo inactive; exit 3; fi ;;
    is-failed) if [ "\${harnessNotReady:-0}" = 1 ] && [ "$unit" = aukora-genesis ] && [[ "$release" = *release-bbbbbbb* ]]; then echo failed; elif [ "$(< "$R/test-unit-$unit")" = 1 ]; then echo active; exit 1; else echo failed; fi ;;
    stop) printf 0 > "$R/test-unit-$unit" ;;
    start)
      if [ "$unit" = aukora-genesis ] && { [ "\${startAllFails:-0}" = 1 ] || { [ "\${startNewFails:-0}" = 1 ] && [[ "$release" = *release-bbbbbbb* ]]; }; }; then printf 0 > "$R/test-unit-$unit"; fail START_FAILED; fi
      if [ "$unit" = aukora-boundary-gate ] && [ "\${gateStartFails:-0}" = 1 ] && [[ "$(< "$R/opt/aukora-boundary-gate/package-marker")" = new* ]]; then fail GATE_START_FAILED; fi
      printf 1 > "$R/test-unit-$unit" ;;
    esac
  done ;;
ss) if [ "\${portNeverDrains:-0}" = 1 ] || { [ "\${portBusyOnNew:-0}" = 1 ] && [ "$head" = "$TARGET_COMMIT" ]; }; then if [ "\${ssLarge:-0}" = 1 ]; then large=$(< "$R/test-ss-large"); printf '%s\\n' "$large"; else echo 'ESTAB 0 0 127.0.0.1:18735 127.0.0.1:50000'; fi; fi ;;
curl) if [ "\${harnessNotReady:-0}" = 1 ] && [[ "$release" = *release-bbbbbbb* ]]; then echo 000; elif [ "$(< "$R/test-unit-aukora-genesis")" = 1 ]; then echo 200; else echo 000; fi ;;
journalctl)
  if [ "\${pluginError:-0}" = 1 ] && [[ "$release" = *release-bbbbbbb* ]]; then echo 'aukora-kira (file:///fixture/release/plugins/kira.js): Error: fixture load failure'; else echo 'fixture selfcheck passed; plugin set ENFORCED'; fi ;;
git)
  command=''; for arg in "$@"; do case "$arg" in status|rev-parse|cat-file|fetch|archive|checkout) command=$arg; break ;; esac; done
  case "$command" in
  rev-parse) if [[ " $* " = *' --short '* ]]; then echo "\${head:0:7}"; else echo "$head"; fi ;;
  archive) /bin/cat "$R/test-source.tar" ;;
  checkout) next=\${!#}; if [ "\${checkoutFails:-0}" = 1 ] && [ "$next" = "$TARGET_COMMIT" ]; then fail CHECKOUT_FAILED; fi; printf '%s\\n' "$next" > "$R/test-head"; rm -rf "$R/opt/aukora-genesis/src/fresh-module"; mkdir "$R/opt/aukora-genesis/src/fresh-module"; if [ "$next" = "$TARGET_COMMIT" ]; then printf 'new source\\n' > "$R/opt/aukora-genesis/src/fresh-module/index.mjs"; else printf 'old source\\n' > "$R/opt/aukora-genesis/src/fresh-module/index.mjs"; fi ;;
  esac ;;
owner-cli) [ "$(< "$R/test-approved")" = 1 ] || [ "\${noPending:-0}" = 1 ] || printf 'cccccccccccccccccccccccccccccccc pending plugins/aukora-plugin-set/approval.json plugins.new sha %s\\n  | release ${targetCommit} (release-bbbbbbb) | plugin set ${'f'.repeat(64)} | operation ${'d'.repeat(64)} (rechecked at launch) | release record ${'e'.repeat(64)}\\n' "\${SHA:0:12}" ;;
node)
  owner=0; probe=0; inline=0
  for arg in "$@"; do case "$arg" in */owner-cli.mjs) owner=1 ;; */ui-probe.mjs) probe=1 ;; --input-type*) inline=1 ;; esac; done
  if [ "$owner" = 1 ]; then [ "$(< "$R/test-approved")" = 1 ] || [ "\${noPending:-0}" = 1 ] || printf 'cccccccccccccccccccccccccccccccc pending plugins/aukora-plugin-set/approval.json plugins.new sha %s\\n  | release ${targetCommit} (release-bbbbbbb) | plugin set ${'f'.repeat(64)} | operation ${'d'.repeat(64)} (rechecked at launch) | release record ${'e'.repeat(64)}\\n' "\${SHA:0:12}"; exit 0; fi
  if [ "$probe" = 1 ]; then [ "\${probeFails:-0}" = 0 ] || fail UI_PROBE_FAILED; echo 'UI PROBE: all served'; exit 0; fi
  if [ "$inline" = 1 ]; then approve; exec "$REAL_NODE" "$@"; fi
  fail UNKNOWN_NODE ;;
python3)
  if [[ " $* " = *' -c '* ]]; then
    if [[ " $* " = *'signal.getsignal'* ]]; then exec /usr/bin/python3 "$@"; fi
    if [[ " $* " = *'os.symlink'* ]]; then
      if [ "\${lockPause:-0}" = 1 ]; then
        touch "$R/test-lock-ready-$PPID"
        for ((tick=0; tick<400; tick++)); do [ ! -f "$R/test-lock-release" ] || break; /bin/sleep 0.01; done
        [ -f "$R/test-lock-release" ] || fail LOCK_TEST_TIMEOUT
      fi
      exec /usr/bin/python3 "$@"
    fi
    state=\${!#}; phase=$(< "$state"); phase=\${phase#phase=}
    [ "\${syncFailPhase:-}" != "$phase" ] || [ -f "$R/test-sync-failed" ] || { touch "$R/test-sync-failed"; fail STATE_SYNC_FAILED; }
    exit 0
  fi
  generate=0; command=''; output=''; prev=''
  for arg in "$@"; do
    [[ "$arg" = *generate-manifest.py ]] && generate=1
    [ "$prev" != --output ] || output=$arg
    [ "$prev" != --out ] || output=$arg
    case "$arg" in show|raise|install|recover-cache|check-package|floor) command=$arg ;; esac
    prev=$arg
  done
  if [ "$generate" = 1 ]; then [ "\${generateFails:-0}" = 0 ] || fail GENERATE_FAILED; echo new-manifest > "$output"; exit 0; fi
  case "$command" in
  show) [ "\${showFails:-0}" = 0 ] || fail OLD_GATE_SHOW_FAILED; printf 'OPERATION %s\\nRECORD %s\\nPLUGIN SET %s\\nCONTENT SHA %s\\n' '${'d'.repeat(64)}' '${'e'.repeat(64)}' '${'f'.repeat(64)}' "$SHA" ;;
  raise) [ "\${raiseFails:-0}" = 0 ] || fail OLD_GATE_RAISE_FAILED; echo 'PENDING cccccccccccccccccccccccccccccccc' ;;
  check-package) [ "\${packageFails:-0}" = 0 ] || fail PACKAGE_FAILED; echo PACKAGE_VERIFIED ;;
  floor) [ "\${floorFails:-0}" = 0 ] || fail FLOOR_FAILED; echo FLOOR_VERIFIED ;;
  install|recover-cache)
    [ "$(< "$R/test-approved")" = 1 ] && [ "\${approvalInstallFails:-0}" = 0 ] || fail APPROVAL_NOT_AVAILABLE
    mkdir -p "$output"; echo 'synthetic approval' > "$output/approval.fixture"; echo '{"new":true}' > "$R/etc/aukora-approvals/release-floor.json"; printf 'INSTALLED fixture\\nFLOOR new\\n' ;;
  *) fail UNKNOWN_PYTHON ;;
  esac ;;
*) fail "UNKNOWN_COMMAND $name" ;;
esac
exit 0
`
}
