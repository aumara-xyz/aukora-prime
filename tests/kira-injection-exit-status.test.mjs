#!/usr/bin/env node
/** Exercise the actual injection court's process outcome, with disposable inputs. */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const court = new URL('./kira-injection.test.mjs', import.meta.url)
const mutantAt = process.argv.indexOf('--mutant')
const mutant = mutantAt < 0 ? undefined : process.argv[mutantAt + 1]
assert.ok(mutantAt < 0 || ['unperformed-status', 'fail-precedence'].includes(mutant), 'unknown outcome mutant')
const anchor = 'process.exitCode = process.exitCode === 1 ? 1 : unperformed.length ? 2 : 0'
if (mutant) assert.equal(readFileSync(court, 'utf8').split(anchor).length, 2, 'actual court outcome anchor must be unique')
const environment = { ...process.env, GIT_NO_LAZY_FETCH: '1' }
delete environment.AUKORA_DSH_SOURCE
const root = mkdtempSync(join(tmpdir(), 'kira-injection-outcome-'))

function run(args) {
  const replacement = mutant === 'unperformed-status'
    ? 'process.exitCode = process.exitCode === 1 ? 1 : 0'
    : 'process.exitCode = unperformed.length ? 2 : process.exitCode === 1 ? 1 : 0'
  const bootstrap = `
    import { registerHooks } from 'node:module';
    const target = ${JSON.stringify(court.href)};
    registerHooks({ load(url, context, next) {
      const loaded = next(url, context);
      if (url !== target) return loaded;
      const source = typeof loaded.source === 'string' ? loaded.source : Buffer.from(loaded.source).toString('utf8');
      if (source.split(${JSON.stringify(anchor)}).length !== 2) throw new Error('outcome mutation anchor missing');
      return { ...loaded, source: source.replace(${JSON.stringify(anchor)}, ${JSON.stringify(replacement)}) };
    } });
    await import(target);
  `
  const invocation = mutant ? ['--input-type=module', '-e', bootstrap, '--', ...args] : [fileURLToPath(court), ...args]
  const result = spawnSync(process.execPath, invocation, {
    cwd: fileURLToPath(new URL('../', import.meta.url)), env: environment,
    encoding: 'utf8', timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
  })
  assert.equal(result.error, undefined, 'court must execute without a driver failure')
  assert.equal(result.signal, null, 'court must finish normally')
  return result
}

let passed = 0
function check(name, args, status, inspect) {
  const result = run(args)
  assert.equal(result.status, status, `${name}: unexpected actual court status\n${result.stderr}`)
  inspect(result)
  console.log(`PASS ${name}: exit ${result.status}; ${result.stdout.trim().split('\n').at(-1)}`)
  passed++
}
const incomplete = result => {
  assert.match(result.stdout, /0 failed; [12] unperformed checks; DSH source dispatch UNPERFORMED; installed profile UNPERFORMED/u)
  assert.doesNotMatch(result.stderr, /^\s*FAIL /mu)
}
try {
  check('missing DSH stays incomplete', [], 2, incomplete)
  check('source-only does not suppress incompleteness', ['--source-only'], 2, incomplete)
  check('passing mutation court stays incomplete', ['--source-only', '--mutate'], 2, incomplete)
  for (const survivor of ['quoting', 'metadata', 'directories', 'origins']) {
    check(`${survivor} survivor remains a genuine failure`, ['--source-only', '--mutate', '--surviving-control', survivor], 1, result => {
      assert.match(result.stderr, /FAIL .*mutation survived/u)
      assert.match(result.stdout, /[1-9]\d* failed; 2 unperformed checks/u)
    })
  }
  check('absent pinned dependency is unperformed', ['--dsh', root], 2, result => {
    incomplete(result)
    assert.match(result.stderr, /UNPERFORMED: DSH dependency binding missing pnpm-lock\.yaml/u)
  })
  writeFileSync(join(root, 'pnpm-lock.yaml'), 'synthetic corrupted dependency, never a substitute pin\n')
  check('present corrupted dependency retains the original failing hash assertion', ['--dsh', root], 1, result => {
    assert.match(result.stderr, /AssertionError/u)
    assert.match(result.stderr, /DSH dependency binding: pnpm-lock\.yaml/u)
    assert.doesNotMatch(result.stderr, /UNPERFORMED: DSH dependency binding missing/u)
  })
  console.log(`kira-injection-exit-status: ${passed}/9 PASS (actual source processes; installed profile not exercised)`)
} finally { rmSync(root, { recursive: true, force: true }) }
