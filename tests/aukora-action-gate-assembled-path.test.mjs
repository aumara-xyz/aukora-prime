// SPDX-License-Identifier: AGPL-3.0-or-later
// One bounded source-policy regression. Shell strings are judged, never run;
// only harmless synthetic directories and an in-memory guard mutation are used.
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const policyUrl = new URL('../plugins/aukora-action-gate/lib/policy.mjs', import.meta.url)
async function loadPolicy() {
  if (!process.env.ASSEMBLED_PATH_MUTANT) return import(policyUrl.href)
  assert.equal(process.env.ASSEMBLED_PATH_MUTANT, 'unknown-write')
  let source = readFileSync(policyUrl, 'utf8')
  const original = source
  source = source.replace(/^        if \(writes\.undetermined\) return deny\('write:undetermined-target'.*\n/mu, '')
  assert.notEqual(source, original, 'the requested admission guard must actually be removed')
  source = source.replace(/from (['"])(\.[^'"]+)\1/gu,
    (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, policyUrl).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
}
const { createPolicy } = await loadPolicy()

test('assembled shell writes refuse undetermined targets without losing literal quote provenance', t => {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'aukora-assembled-path-'))
  const workspace = join(root, 'workspace')
  const outside = join(root, 'outside')
  const state = join(root, 'state')
  for (const dir of [workspace, outside, join(workspace, 'folder with spaces'), join(state, 'home')]) mkdirSync(dir, { recursive: true })
  symlinkSync(outside, join(workspace, 'outside-alias'))
  symlinkSync(outside, join(workspace, '{alias}'))
  const policy = createPolicy({
    home: root, supportRoot: join(root, 'support'), dshHome: join(state, 'home'),
    auraDir: join(state, 'home', 'aura-actions'), repoRoots: [], releaseRoots: [],
    extraWritableRoots: [], readRoots: [], defaultWorkspace: workspace,
    networkAllow: [], allowLoopback: false, mainBranch: 'main', confineReads: true,
  })
  const judge = command => policy.judge({ tool: 'bash', args: { command }, workspace })
  const unknown = [
    'D=$(printf /tmp); echo x > "$D/pre.cjs"',
    'D=/tmp; echo x >> "$D/file.txt"',
    'printf -v D /tmp; echo x > "$D/file.txt"',
    'echo x > "$(printf /tmp)/file.txt"',
    'echo x > `printf /tmp`/file.txt',
    'echo x > $D/file.txt',
    'echo x > ${D:-/tmp}/file.txt',
    'echo x > ~/file.txt',
    'echo x > *.txt',
    'echo x > file?.txt',
    'echo x > [ab].txt',
    'echo x > {first,second}.txt',
    'echo x > @(first|second)',
    'echo x > +(first|second)',
    'echo x > >(cat)',
    'echo x >',
    'tee "$D/file.txt"',
    'tee {first,second}',
    'rm "$D/file.txt"',
    'touch "$D/file.txt"',
    'mkdir -m 700 "$D/directory"',
    'rmdir "$D/directory"',
    'chmod 600 "$D/file.txt"',
    'truncate -s 0 "$D/file.txt"',
    'sed -i -e s/x/y/ "$D/file.txt"',
    'dd of="$D/file.txt"',
    'dd of=~/file.txt',
    'dd "$OPTIONS"',
    'cp source "$D/file.txt"',
    'mv source "$D/file.txt"',
    'install -d "$D/directory"',
    'cp source {first,second}/file.txt',
    'cp --target-directory="$D" source',
    'cp -t"$D" source',
    'cp -t "$D" source',
    'cp "$S" "folder with spaces/"',
    'cp "$S" literal-target',
    'sed "$OPTIONS" -e s/x/y/ literal-target',
    'env MODE=public sudo -n exec tee "$D/file.txt"',
    'xargs rm',
    'printf public | xargs tee',
    'xargs cp source literal-target',
    "xargs eval 'echo public'",
    "xargs sh -c 'echo public'",
    'sudo -u synthetic-user bash -c "$COMMAND"',
    "sudo -D /tmp tee local.txt",
    "env -C /tmp tee local.txt",
    "env -S 'tee local.txt'",
    'env MODE=$VALUE tee local.txt',
    'eval "$COMMAND"',
    'eval "$(printf command)"',
    'bash -c "$COMMAND"',
    'env MODE=public sh -c "$COMMAND"',
    'sh -c \'echo x > "$D/file.txt"\'',
    '"$PROGRAM" source target',
    'cd "$D"; echo x > local.txt',
    'cd *; echo x > local.txt',
    'cd {first,second}; echo x > local.txt',
    'cd -; echo x > local.txt',
    'pushd; echo x > local.txt',
    `${'command '.repeat(17)}tee "$D/file.txt"`,
  ]
  for (const command of unknown) assert.equal(judge(command).rule, 'write:undetermined-target', command)

  const literals = [
    'echo x > local.txt',
    'echo x >> "folder with spaces/file.txt"',
    "echo x > '$D.txt'",
    'echo x > "\\$D.txt"',
    'echo x > \\$D.txt',
    "echo x > '*.txt'",
    'echo x > \\*.txt',
    "echo $D > '$D'",
    'echo "backslash data" > "folder with spaces/\\q.txt"',
    "tee '$D.txt' '*.txt'",
    'touch -t 202001010000 local.txt',
    'mkdir -m 700 local-directory',
    'rmdir local-directory',
    "dd 'of=$D.txt'",
    "cp source '$D.txt'",
    "cp source '*.txt'",
    "cp --target-directory='folder with spaces' '$D.txt'",
    "cp '-tfolder with spaces' '*.txt'",
    "install -d '$D' 'folder with spaces'",
    'env MODE=public sudo -n exec tee local.txt',
    'sudo -u synthetic-user tee local.txt',
    'nice -n 5 tee local.txt',
    'timeout 30 tee local.txt',
    'stdbuf -oL tee local.txt',
    'tee \\{name}/file.txt',
    "eval 'echo x > local.txt'",
    "bash -c 'echo x > local.txt'",
    "cd 'folder with spaces'; echo x > local.txt",
    '{ echo x > local.txt; }',
    'printf "%s" "$VALUE"',
    'xargs echo',
    'echo "$(printf public)"',
    "printf '%s' public > local.txt",
  ]
  for (const command of literals) assert.equal(judge(command).decision, 'allow', command)
  const outsideWrites = [
    `echo x > '${join(outside, 'file.txt')}'`,
    'echo x > ../outside/file.txt',
    'echo x > outside-alias/file.txt',
    'tee \\{alias}/file.txt',
    'sudo -n tee ../outside/file.txt',
    "cd 'outside-alias'; echo x > local.txt",
  ]
  for (const command of outsideWrites) assert.equal(judge(command).rule, 'write:outside-workspace', command)
  t.diagnostic(`${unknown.length} undetermined refusals, ${literals.length} literal/read-only allows, ${outsideWrites.length} outside-workspace refusals`)
})
