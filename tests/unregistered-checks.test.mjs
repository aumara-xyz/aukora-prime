// SPDX-License-Identifier: AGPL-3.0-or-later
// Missing check prerequisites remain explicit and removed reporting guards fail their controls.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const root = resolve(import.meta.dirname, '..');
mkdirSync(join(root, '.scratch'), {recursive: true});
const scratch = mkdtempSync(join(root, '.scratch/check-contract-'));
const environment = {...process.env, PYTHONDONTWRITEBYTECODE: '1', GIT_NO_LAZY_FETCH: '1'};
delete environment.NODE_OPTIONS;
let gaps = 0, killed = 0;
const run = (argv, options = {}) => spawnSync(argv[0], argv.slice(1), {
  cwd: root, env: environment, encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024, ...options,
});
function requireGap(result, reason) {
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.stdout, `UNPERFORMED: ${reason}\n`);
  assert.equal(result.stderr, '');
}
const nodeGaps = [
  ['scripts/check-next-composition.mjs', 'an explicitly selected composed NEXT release is required',
    "if (process.argv.length === 2) {\n  console.log('UNPERFORMED: an explicitly selected composed NEXT release is required');\n  process.exit(2);\n}"],
  ['scripts/verify-aukora-render.mjs', 'an explicitly selected running UI and browser installation are required',
    "if (url === undefined) {\n  console.log('UNPERFORMED: an explicitly selected running UI and browser installation are required')\n  process.exit(2)\n}"],
  ['scripts/face-parse-check.mjs', 'an explicitly selected emitted face directory is required',
    "if (roots.length === 0) {\n  process.stdout.write('UNPERFORMED: an explicitly selected emitted face directory is required\\n')\n  process.exit(2)\n}"],
  ['scripts/kira/she-remembers-check.mjs', 'an explicitly selected installed Kira state is required',
    "if (value('--state') === undefined) {\n  console.log('UNPERFORMED: an explicitly selected installed Kira state is required')\n  process.exit(2)\n}"],
  ['scripts/kira/verify-memory.mjs', 'an explicitly selected installed Kira state is required',
    "if (value('--state') === undefined) {\n  console.log('UNPERFORMED: an explicitly selected installed Kira state is required')\n  process.exit(2)\n}"],
  ['scripts/kira/verify-memory.mjs', 'the selected Kira state has no remembered store',
    "  console.log('UNPERFORMED: the selected Kira state has no remembered store')", ['--state', 'absent-kira-fixture']],
  ['scripts/face-parse-check.mjs', 'the selected face directories contain no emitted JavaScript',
    "if (files.length === 0) {\n  process.stdout.write('UNPERFORMED: the selected face directories contain no emitted JavaScript\\n')\n  process.exit(2)\n}", ['absent-emitted-fixture']],
  ['scripts/verify-aukora-render.mjs', 'Playwright from the pinned harness is absent',
    "  console.log('UNPERFORMED: Playwright from the pinned harness is absent')\n  process.exit(2)", ['--url', 'https://example.invalid']],
  ['scripts/aukora/box-confinement-check.mjs', 'macOS Seatbelt is required',
    "    console.log('UNPERFORMED: macOS Seatbelt is required')\n    process.exitCode = 2"],
  ['scripts/aukora/box-confinement-check.mjs', 'Seatbelt admission refused by nested sandbox',
    "      console.log('UNPERFORMED: Seatbelt admission refused by nested sandbox')\n      process.exitCode = 2"],
  ['scripts/aura/release-boot-smoke.mjs', 'a selected built release and disposable boot state are required',
    "if (isMainModule(import.meta.url) && process.argv.length === 2) {\n  console.log('UNPERFORMED: a selected built release and disposable boot state are required')\n  process.exit(2)\n}"],
  ['scripts/aukora/airlock-probe.mjs', 'separated owner custody after the admin ceremony must be selected with --installed',
    "if (!process.argv.includes('--installed')) {\n  console.log('UNPERFORMED: separated owner custody after the admin ceremony must be selected with --installed')\n  process.exit(2)\n}"],
];
try {
  for (const [file, reason, guard, args = []] of nodeGaps) {
    const original = readFileSync(join(root, file), 'utf8');
    assert.equal(original.split(guard).length, 2, `${file}: unique guard`);
    let safe = original.replace(/^#![^\n]*\n/u, '').replaceAll('import.meta.url', JSON.stringify(pathToFileURL(join(root, file)).href))
      .replace(/(from\s+['"])(\.\.?\/[^'"]+)(['"])/gu,
        (_, before, specifier, after) => before + pathToFileURL(resolve(dirname(join(root, file)), specifier)).href + after)
      .replace("join(homedir(), 'Library', 'Application Support', 'AUKORA', 'state', 'home')", JSON.stringify(join(scratch, 'absent-state')))
      .replace("join(root, 'vendor/dsh/apps/web/package.json')", JSON.stringify(join(scratch, 'absent-harness/package.json')))
      .replace("join(root, '.runtime/aukora-render')", JSON.stringify(join(scratch, 'render-output')));
    if (file === 'scripts/aukora/box-confinement-check.mjs') {
      safe = safe.replaceAll('process.platform', JSON.stringify(reason.startsWith('macOS') ? 'linux' : 'darwin'))
        .replace("import { spawnSync } from 'node:child_process'",
          "const spawnSync = () => ({error: undefined, signal: null, status: 1, stdout: '', stderr: 'sandbox-exec: sandbox_apply: Operation not permitted'})");
    }
    if (file === 'scripts/aukora/airlock-probe.mjs') {
      safe = safe.replace(/import \{ readOwnerDaemonConfig \} from '[^']+'/u,
        'const readOwnerDaemonConfig = () => null');
    }
    if (file === 'scripts/aura/release-boot-smoke.mjs') {
      safe = safe.replace(/import \{ repointOverlayText \} from '[^']+'/u,
        "const repointOverlayText = () => { throw Error('BOOT_FIXTURE_NOT_SELECTED') }");
    }
    const invoke = text => run([process.execPath, '--input-type=module', '--eval',
      `process.argv = [process.execPath, ${JSON.stringify(file)}, ...${JSON.stringify(args)}];\n${text}`]);
    requireGap(invoke(safe), reason); gaps++;
    const safeGuard = guard.replaceAll('import.meta.url', JSON.stringify(pathToFileURL(join(root, file)).href));
    assert.equal(safe.split(safeGuard).length, 2, `${file}: transformed guard is unique`);
    assert.throws(() => requireGap(invoke(safe.replace(safeGuard, '')), reason), {code: 'ERR_ASSERTION'}, file);
    killed++;
  }
  for (const file of ['scripts/composition/self-contained-release-test.py', 'scripts/composition/receipt-closure-test.py']) {
    const original = readFileSync(join(root, file), 'utf8');
    const condition = file.endsWith('/receipt-closure-test.py') ? 'named is None and not' : 'not';
    const guard = `    if ${condition} (ROOT / 'vendor/dsh/.dsh-build/pinned-harness-build.json').is_file():\n        print('UNPERFORMED: a built pinned harness with its successful build receipt is required')\n        return 2\n`;
    assert.equal(original.split(guard).length, 2);
    // A deliberately absent fixture root never selects the operator's build.
    const safe = original.replace(/ROOT = .+/u, `ROOT = Path(${JSON.stringify(join(scratch, 'absent-harness'))})`);
    const invoke = text => run(['/usr/bin/python3', '-c',
      `exec(compile(${JSON.stringify(text)}, ${JSON.stringify(file)}, 'exec'), {'__name__': '__main__', '__file__': ${JSON.stringify(join(root, file))}})`]);
    const reason = 'a built pinned harness with its successful build receipt is required';
    requireGap(invoke(safe), reason); gaps++;
    assert.throws(() => requireGap(invoke(safe.replace(guard, '')), reason), {code: 'ERR_ASSERTION'});
    killed++;
  }
  const shell = readFileSync(join(root, 'scripts/aura/post-relaunch-check.sh'), 'utf8');
  const shellGuard = 'if [ "${AUKORA_POST_RELAUNCH_LIVE:-}" != 1 ]; then\n  printf \'%s\\n\' \'UNPERFORMED: an explicitly selected installed app and AUKORA_POST_RELAUNCH_LIVE=1 are required\'\n  exit 2\nfi';
  assert.equal(shell.split(shellGuard).length, 2);
  const shellReason = 'an explicitly selected installed app and AUKORA_POST_RELAUNCH_LIVE=1 are required';
  const shellEnvironment = {...environment, AUKORA_POST_RELAUNCH_LIVE: '0', AUKORA_ROOT: scratch,
    AUKORA_STATE: scratch, AUKORA_KIRA_STORE: scratch, AUKORA_ALPHA_REPORT: join(scratch, 'absent-report'),
    AUKORA_SERVER_LOG: join(scratch, 'absent-log'), AUKORA_LAUNCH_RECORD: join(scratch, 'absent-launch'),
    AUKORA_LANE_PORT_FILE: join(scratch, 'absent-port'), AUKORA_ADD_CONTACT_SHEET: join(scratch, 'absent-sheet'),
    AUKORA_SIGNER_SOCK: join(scratch, 'absent-signer'), AUKORA_VOICE_PORT: '0',
    AUKORA_LANE_DOOR: 'http://127.0.0.1:0', AUKORA_EYE_DOOR: 'http://127.0.0.1:0'};
  requireGap(run(['bash', '-c', shell], {env: shellEnvironment}), shellReason); gaps++;
  assert.throws(() => requireGap(run(['bash', '-c', shell.replace(shellGuard, '')], {env: shellEnvironment}), shellReason), {code: 'ERR_ASSERTION'});
  killed++;
  // The build court is not registered per commit: it measures how fresh a local harness build is against
  // the checkout (see plan/CHECKS-INVENTORY.md), so its registration guard is not checked here.
  console.log(`unregistered-checks: ${gaps} prerequisite cases PASS; ${killed} prerequisite guard removals killed`);

} finally { rmSync(scratch, {recursive: true, force: true}); }
