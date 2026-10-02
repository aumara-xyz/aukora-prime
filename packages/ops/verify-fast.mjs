#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// H owns ./prime verify dispatch. This standalone source entry leaves archive
// verification in cli.mjs unchanged and accepts no commands, selectors or env.
import {runFastVerify} from './fast-verify/runner.mjs'

function parse(args) {
  const values = {}
  const flags = new Map([['--root','root'],['--evidence-dir','evidenceDir'],['--json','json']])
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index], name = flags.get(flag), value = args[index + 1]
    if (!name || Object.hasOwn(values, name) || typeof value !== 'string'
      || value.startsWith('--') || /[\x00-\x1f\x7f]/.test(value)) throw Error('INVALID_ARGUMENTS')
    values[name] = value
  }
  if (!values.root || !values.evidenceDir || (values.json !== undefined && !['true','false'].includes(values.json)))
    throw Error('INVALID_ARGUMENTS')
  return {...values, json:values.json === 'true'}
}

if (process.argv.slice(2).join(' ') === '--help') {
  console.log('verify-fast.mjs --root CANONICAL_SOURCE --evidence-dir NEW_EXTERNAL_DIR [--json true]')
  console.log('Closed ordinary source profile. Exit 0 complete PASS, 1 FAIL, 2 UNPERFORMED. G1 stays PENDING.')
} else {
  try {
    const options = parse(process.argv.slice(2))
    const controller = new AbortController()
    const cancel = () => controller.abort()
    process.once('SIGINT', cancel); process.once('SIGTERM', cancel)
    let result
    try { result = await runFastVerify({...options, signal:controller.signal}) }
    finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel) }
    if (options.json) console.log(JSON.stringify(result))
    else {
      for (const row of result.cases) {
        const count = row.counter ? `; ${row.counter.key} ${row.counter.observed ?? 'UNPERFORMED'}/${row.counter.expected}`
          : Number.isSafeInteger(row.required_test_count) ? `; required ${row.test_count ?? 'UNPERFORMED'}/${row.required_test_count}; skipped ${row.skipped_count ?? 'UNPERFORMED'}` : ''
        console.log(`${row.status} ${row.id}: ${row.reason ?? row.property}${count}`)
        for (const title of row.failed_titles ?? []) console.log(`  FAIL required: ${title}`)
        for (const item of row.external_skips ?? []) console.log(`  UNPERFORMED external: ${item.title}; ${item.reason}`)
      }
      for (const record of result.historical) console.log(`HISTORICAL_ONLY ${record.id}: ${record.reported_result}; ${record.provenance}; current UNPERFORMED`)
      for (const row of result.unperformed) console.log(`UNPERFORMED ${row.id}: ${row.reason}`)
      console.log(`${result.status} ordinary source suite${result.reason ? ': '+result.reason : ''}; functional ${result.functional_status ?? 'UNPERFORMED'}; ${result.duration_ms ?? 'UNPERFORMED'} ms; qualification UNPERFORMED; G1 PENDING`)
      console.log(`Evidence: ${result.evidence_path ?? 'UNPERFORMED'}`)
    }
    process.exitCode = result.exit_code
  } catch (error) {
    const reason = /^[A-Z0-9_]+$/.test(error.message) ? error.message : 'RUNNER_INPUT_OR_IO_ERROR'
    console.log(JSON.stringify({schema:'prime-fast-verify/v1', status:'FAIL', reason, exit_code:1,
      scope:'ordinary source regressions', qualification:'UNPERFORMED', g1:'PENDING'}))
    process.exitCode = 1
  }
}
