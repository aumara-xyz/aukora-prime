#!/usr/bin/env node
'use strict'

const fs = require('node:fs')
const path = require('node:path')
const { spawn } = require('node:child_process')
const { trustedOrigin } = require('./policy.cjs')

try {
  const argv = process.argv.slice(2)
  const check = argv.length === 1 && argv[0] === '--check'
  const options = {}
  if (!check) for (let i = 0; i < argv.length; i += 2) {
    if (!['--access-file', '--expected-pid', '--origin'].includes(argv[i]) || !argv[i + 1]
      || options[argv[i]]) throw new Error('INVALID_ARGUMENTS')
    options[argv[i]] = argv[i + 1]
  }
  if (!check && (!path.isAbsolute(options['--access-file'] ?? '')
    || !/^[1-9][0-9]*$/.test(options['--expected-pid'] ?? ''))) throw new Error('ACCESS_FILE_AND_PID_REQUIRED')
  const origin = trustedOrigin(options['--origin'])
  const runtime = path.join(__dirname, '.runtime', 'electron')
  let executable
  if (fs.existsSync(runtime)) {
    if (fs.readFileSync(path.join(runtime, 'version'), 'utf8').trim() !== '44.4.3') throw new Error('ELECTRON_PIN_MISMATCH')
    executable = path.join(runtime, 'Electron.app', 'Contents', 'MacOS', 'Electron')
  } else {
    const pkg = require('./node_modules/electron/package.json')
    if (pkg.version !== '44.4.3') throw new Error('ELECTRON_PIN_MISMATCH')
    executable = require('./node_modules/electron')
  }
  const env = {}
  for (const key of ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL']) if (process.env[key]) env[key] = process.env[key]
  Object.assign(env, { PRIME_PREVIEW_ORIGIN: origin.origin,
    PRIME_PREVIEW_ACCESS_FILE: options['--access-file'] ?? '',
    PRIME_PREVIEW_EXPECTED_PID: options['--expected-pid'] ?? '' })
  const child = spawn(executable, [check ? path.join(__dirname, 'check.cjs') : __dirname],
    { env, stdio: 'inherit', cwd: __dirname })
  child.on('error', () => { console.error('PRIME_PREVIEW_RUNTIME_UNAVAILABLE'); process.exitCode = 1 })
  child.on('exit', code => { process.exitCode = code ?? 1 })
} catch {
  console.error('Usage: node packages/desktop/run.cjs --access-file /private/launch-url.json --expected-pid PID [--origin https://trusted.example]')
  console.error('Requires official pinned Electron 44.4.3 in packages/desktop/.runtime/electron or package-local npm install.')
  process.exitCode = 1
}
