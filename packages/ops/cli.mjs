#!/usr/bin/env node
import { dirname, resolve, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import { mkdtempSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { fullTreeDigest, evaluatorDigest, runGate } from './gates.mjs'
import { PILOT, unitTemplate } from './deployment.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const argv = process.argv.slice(2)
const command = argv.shift()
function options(args) {
  const result = {}
  for (let i = 0; i < args.length; i += 2) {
    if (!args[i]?.startsWith('--') || args[i + 1] === undefined || args[i + 1].startsWith('--')) throw new Error('INVALID_ARGUMENTS')
    result[args[i].slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = args[i + 1]
  }
  return result
}
try {
  if (['package', 'verify', 'restore', 'stage-release'].includes(command)) {
    const child = spawnSync(process.env.PRIME_OPS_PYTHON ?? 'python3', [join(here, 'archive.py'), command, ...argv], {
      stdio: 'inherit', shell: false,
      env: { PATH: '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin', LANG: 'C.UTF-8' }
    })
    process.exitCode = child.status ?? 1
  } else if (command === 'check') {
    const gate = argv.shift()
    const opts = options(argv)
    if (/[\x00-\x1f\x7f]/.test(String(opts.root ?? '.'))) throw new Error('RELEASE_PATH_CONTROL_CHARACTER')
    opts.root = resolve(opts.root ?? '.')
    opts.evidenceDir ??= mkdtempSync(join(tmpdir(), 'prime-gate-'))
    opts.disposableHome ??= mkdtempSync(join(tmpdir(), 'prime-probe-'))
    opts.prerequisites = opts.prerequisites?.split(',') ?? []
    const result = await runGate(gate, opts)
    console.log(JSON.stringify(result))
    process.exitCode = result.status === 'PASS' ? 0 : result.status === 'FAIL' ? 1 : 2
  } else if (command === 'digest') {
    const opts = options(argv)
    console.log(JSON.stringify(fullTreeDigest(opts.root ?? '.')))
  } else if (command === 'evaluator-digest') {
    console.log(JSON.stringify({ evaluator_digest: evaluatorDigest() }))
  } else if (command === 'plan') {
    console.log(JSON.stringify({ status: 'PREPARED_NOT_DEPLOYED', ...PILOT }, null, 2))
  } else if (command === 'unit-template') {
    process.stdout.write(unitTemplate())
  } else {
    console.log('prime-ops: check G1..G6 | digest | evaluator-digest | package | verify | restore | stage-release | plan | unit-template')
    process.exitCode = command === 'help' ? 0 : 2
  }
} catch (error) {
  console.log(JSON.stringify({ status: 'REFUSED', reason: /^[A-Z0-9_:.,-]+$/.test(error.message) ? error.message : error.name }))
  process.exitCode = 1
}
