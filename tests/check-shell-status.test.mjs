// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise the actual shell child runner, collector and aggregate with bounded
// synthetic reports. No whole court, DSH, store, network or installed acceptance.
// Fixtures are retained: this check never deletes files under the no-delete hold.
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

const source = readFileSync(new URL('../scripts/check.sh', import.meta.url), 'utf8')
const root = mkdtempSync(join(tmpdir(), 'aukora-shell-status-'))
const command = 'node tests/kira-injection.test.mjs --mutate'
const quote = value => "'" + value.replaceAll("'", "'\\''") + "'"
const environment = { ...process.env, GIT_NO_LAZY_FETCH: '1' }
for (const key of ['NODE_OPTIONS', 'NODE_TEST_CONTEXT', 'AUKORA_TEST_KIRA_SOURCE', 'AUKORA_TEST_AURA_SOURCE']) delete environment[key]
const footer = (pass = 46, arms = 46, failed = 0, pending = 2, dsh = 'UNPERFORMED') =>
  `  ${pass}/${arms} arms passed, ${failed} failed; ${pending} unperformed checks; DSH source dispatch ${dsh}; installed profile UNPERFORMED.`
const registrations = text => text.split('\n').filter(line => /^check(?:_tap|_unittest|_darwin|_injection)? '/u.test(line))
assert.equal(registrations(source).length, 100, 'preserve every existing fixed registration')
assert.equal(registrations(source).filter(line => line.includes(command)).length, 1)

function fragments(text) {
  const collector = text.match(/(^collect_checks\(\) \{[\s\S]*?^\})\n\n# Formats/mu)?.[1]
  const launcher = text.match(/(^run_check\(\) \{[\s\S]*?^\})\n# The precard/mu)?.[1]
  const end = text.lastIndexOf('\ncollect_checks\nperl -MTime::HiRes=time')
  assert(collector && launcher && end >= 0, 'use actual production runner/collector/aggregate')
  return { collector, launcher, aggregate: text.slice(end) }
}

let sequence = 0
function run(rows, text = source) {
  const directory = join(root, `case-${++sequence}`)
  mkdirSync(join(directory, 'tests'), { recursive: true, mode: 0o700 })
  const work = join(directory, 'reports')
  mkdirSync(work, { mode: 0o700 })
  const { collector, launcher, aggregate } = fragments(text)
  const calls = []
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index]
    const file = row.court ? 'tests/kira-injection.test.mjs' : `tests/producer-${index}.mjs`
    writeFileSync(join(directory, file), row.body ??
      `console.log(${JSON.stringify(row.output ?? '')});process.exit(${row.exit ?? 0});\n`, { mode: 0o600 })
    const runCommand = row.runCommand ?? (row.court ? command : `node ${file}`)
    const courtFormat = text.includes(`check_injection '${command}'`) ? 'injection' : 'plain'
    calls.push(`run_check ${quote(row.label ?? runCommand)} ${quote(runCommand)} ${quote(row.format ?? (row.court ? courtFormat : 'plain'))}`)
  }
  const driver = `set -eu\nwork=${quote(work)}\nstarted=$(perl -MTime::HiRes=time -e 'print time')\npids=\nactive=0\nindex=0\ncount=0\npassed=0\nfailed=0\nskipped=0\nplatform_skipped=0\nunperformed=0\n${collector}\n${launcher}\n${calls.join('\n')}\n${aggregate}`
  const script = join(directory, 'runner.sh')
  writeFileSync(script, driver, { mode: 0o600 })
  const child = spawnSync('/bin/sh', [script], { cwd: directory, env: environment, encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024 })
  assert.equal(child.error, undefined, 'actual extracted runner must finish')
  assert.equal(child.signal, null)
  writeFileSync(join(directory, 'stdout.txt'), child.stdout, { mode: 0o600 })
  writeFileSync(join(directory, 'stderr.txt'), child.stderr, { mode: 0o600 })
  const match = child.stdout.match(/^TOTAL [^|]+\| (\d+)\/(\d+) passed \| (\d+) failed \| (\d+) skipped \((\d+) platform\) \| (\d+) unperformed/mu)
  assert(match, 'actual aggregate must report all dispositions')
  return { ...child, counts: match.slice(1).map(Number), output: child.stdout }
}

const cases = [
  ['46-arm missing DSH remains unperformed', { court: true, output: footer(), exit: 2 }, 'UNPERFORMED', 2],
  ['54-arm source dispatch remains unperformed', { court: true, output: footer(54, 54, 0, 1, 'RAN'), exit: 2 }, 'UNPERFORMED', 2],
  ['incorrect exit zero cannot green an open profile', { court: true, output: footer(), exit: 0 }, 'UNPERFORMED', 2],
  ['failed arm exit one remains failure', { court: true, output: '  FAIL synthetic arm: assertion\n' + footer(45, 46, 1), exit: 1 }, 'FAIL', 1],
  ['failed footer wins incorrect exit two', { court: true, output: footer(45, 46, 1), exit: 2 }, 'FAIL', 1],
  ['failed footer wins incorrect exit zero', { court: true, output: footer(45, 46, 1), exit: 0 }, 'FAIL', 1],
  ['failure line wins passing footer', { court: true, output: '  FAIL synthetic arm: assertion\n' + footer(), exit: 2 }, 'FAIL', 1],
  ['TAP failure cannot hide behind court footer', { court: true, output: '# fail 1\n' + footer(), exit: 2 }, 'FAIL', 1],
  ['expected failure control is not an arm failure', { court: true, output: '  EXPECTED FAIL synthetic mutation: rejected\n' + footer(), exit: 2 }, 'UNPERFORMED', 2],
  ['missing footer fails closed', { court: true, output: 'incomplete output', exit: 2 }, 'FAIL', 1],
  ['duplicate footer fails closed', { court: true, output: footer() + '\n' + footer(), exit: 2 }, 'FAIL', 1],
  ['malformed footer fails closed', { court: true, output: footer().replace('46/46', 'x/46'), exit: 2 }, 'FAIL', 1],
  ['contradictory arm arithmetic fails closed', { court: true, output: footer(45, 46, 0), exit: 2 }, 'FAIL', 1],
  ['zero arms cannot establish a result', { court: true, output: footer(0, 0), exit: 2 }, 'FAIL', 1],
  ['installed unperformed requires a pending count', { court: true, output: footer(46, 46, 0, 0, 'RAN'), exit: 2 }, 'FAIL', 1],
  ['missing dispatch plus profile requires two gaps', { court: true, output: footer(46, 46, 0, 1), exit: 2 }, 'FAIL', 1],
  ['other child exits remain failure', { court: true, output: footer(), exit: 3 }, 'FAIL', 1],
  ['signal remains failure', { court: true, body: "process.kill(process.pid,'SIGTERM');\n" }, 'FAIL', 1],
  ['generic exit two gets no exemption', { output: footer(), exit: 2 }, 'FAIL', 1],
  ['literal command binding refuses a different label', { court: true, label: 'node tests/another-court.mjs', output: footer(), exit: 2 }, 'FAIL', 1],
  ['ordinary completed child stays pass', { output: 'completed synthetic assertions', exit: 0 }, 'PASS', 0],
  ['exact label cannot authorize different execution argv', { court: true, label: command, runCommand: 'node tests/kira-injection.test.mjs --source-only --mutate', output: footer(), exit: 2 }, 'FAIL', 1],
]

function checkCase(name, row, status, exit, text = source) {
  const result = run([row], text)
  assert.equal(result.status, exit, name)
  assert.match(result.output, new RegExp(`^${status}\\s`, 'mu'), name)
  const count = status === 'PASS' ? [1, 1, 0, 0, 0, 0] : status === 'FAIL' ? [0, 1, 1, 0, 0, 0] : [0, 1, 0, 0, 0, 1]
  assert.deepEqual(result.counts, count, name)
}
for (const args of cases) {
  checkCase(...args)
  console.log(`PASS ${args[0]}`)
}
assert.equal(source.split(`check_injection '${command}'`).length, 2, 'only the literal court uses the governed format')

const timeoutAnchor = 'alarm 55;'
assert.equal(source.split(timeoutAnchor).length, 2)
checkCase('watchdog failure stays failure', { court: true, body: 'setInterval(()=>{},1000);\n' }, 'FAIL', 1, source.replace(timeoutAnchor, 'alarm 1;'))
console.log('PASS watchdog failure stays failure (one-second fixture timer; production remains 55 seconds)')

function checkAggregate(text = source) {
  let result = run([{ court: true, output: footer(), exit: 2 }, { output: 'completed', exit: 0 }], text)
  assert.equal(result.status, 2, 'unperformed aggregate must not be green')
  assert.deepEqual(result.counts, [1, 2, 0, 0, 0, 1])
  result = run([{ court: true, output: footer(), exit: 2 }, { output: 'synthetic failed assertion', exit: 1 }, { output: 'completed', exit: 0 }], text)
  assert.equal(result.status, 1, 'real failure must outrank unperformed')
  assert.deepEqual(result.counts, [1, 3, 1, 0, 0, 1])
}
checkAggregate()
console.log('PASS aggregate: one gap remains exit 2; mixed failure remains exit 1')

const controls = [
  ['green unperformed row', '$disposition = "UNPERFORMED"; $reason = "reported unperformed injection checks";', '$disposition = "PASS"; $reason = "reported unperformed injection checks";', () => checkCase(...cases[0])],
  ['drop aggregate unperformed', 'if [ "$skipped" -ne 0 ] || [ "$unperformed" -ne 0 ]; then exit 2; fi', 'if [ "$skipped" -ne 0 ]; then exit 2; fi', checkAggregate],
  ['drop aggregate failure precedence', 'if [ "$failed" -ne 0 ]; then exit 1; fi', 'if false; then exit 1; fi', checkAggregate],
  ['drop reported failure guard', 'if ($court_failure || $reported_failure) {', 'if (0) {', () => checkCase(...cases[6])],
  ['drop unique footer guard', '$court_reports != 1 || $court_invalid', '0 || $court_invalid', () => checkCase(...cases[10])],
  ['drop explicit command binding', 'die "injection command" unless $command eq "node tests/kira-injection.test.mjs --mutate" && $run eq $command;', '# removed command binding', () => checkCase(...cases[19])],
  ['drop execution argv binding', '$run eq $command', '1', () => checkCase(...cases[21])],
]
if (process.argv.includes('--mutate')) {
  for (const [name, before, after, inspect] of controls) {
    assert.equal(source.split(before).length, 2, `${name}: exact unique production anchor`)
    const mutated = source.replace(before, after)
    let caught = false
    try {
      if (inspect === checkAggregate) inspect(mutated)
      else {
        const position = name === 'drop reported failure guard' ? 6 : name === 'drop unique footer guard' ? 10 : name === 'drop explicit command binding' ? 19 : name === 'drop execution argv binding' ? 21 : 0
        checkCase(...cases[position], mutated)
      }
    } catch (error) {
      assert.equal(error.code, 'ERR_ASSERTION', 'mutant must be killed by its disposition assertion, not an execution accident')
      caught = true
    }
    assert(caught, `${name}: removal survived`)
    console.log(`KILLED ${name}`)
  }
}
console.log(`check-shell-status: ${cases.length + 3} cases PASS; ${process.argv.includes('--mutate') ? controls.length : 0} controls killed; 100 registrations retained; synthetic child/actual runner only; no fixture deletes`)
