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
    if (!['--access-file', '--expected-pid', '--origin', '--electron-runtime'].includes(argv[i]) || !argv[i + 1]
      || options[argv[i]]) throw new Error('INVALID_ARGUMENTS')
    options[argv[i]] = argv[i + 1]
  }
  if (!check && (!path.isAbsolute(options['--access-file'] ?? '')
    || !/^[1-9][0-9]*$/.test(options['--expected-pid'] ?? ''))) throw new Error('ACCESS_FILE_AND_PID_REQUIRED')
  const origin = trustedOrigin(options['--origin'])
  if(options['--electron-runtime']!==undefined&&!path.isAbsolute(options['--electron-runtime']))throw new Error('ABSOLUTE_ELECTRON_RUNTIME_REQUIRED')
  const runtime = options['--electron-runtime'] ?? path.join(__dirname, '.runtime', 'electron')
  let executable
  if (fs.existsSync(runtime)) {
    if (fs.readFileSync(path.join(runtime, 'version'), 'utf8').trim() !== '44.4.3') throw new Error('ELECTRON_PIN_MISMATCH')
    executable = path.join(runtime, 'Electron.app', 'Contents', 'MacOS', 'Electron')
  } else {
    if (options['--electron-runtime'] !== undefined) throw new Error('SELECTED_ELECTRON_RUNTIME_MISSING')
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
  let stopping, killTimer
  const stop = signal => {
    if (stopping) return
    stopping = signal
    child.kill(signal)
    killTimer = setTimeout(() => child.kill('SIGKILL'), 5000)
  }
  const interrupt = () => stop('SIGINT'), terminate = () => stop('SIGTERM')
  process.on('SIGINT', interrupt)
  process.on('SIGTERM', terminate)
  child.on('error', () => { console.error('PRIME_PREVIEW_RUNTIME_UNAVAILABLE'); process.exitCode = 1 })
  child.once('close', code => {
    clearTimeout(killTimer)
    process.removeListener('SIGINT', interrupt)
    process.removeListener('SIGTERM', terminate)
    process.exitCode = code ?? (stopping === 'SIGINT' ? 130 : stopping ? 143 : 1)
  })
} catch {
  console.error('Usage: node packages/desktop/run.cjs --access-file /private/launch-url.json --expected-pid PID [--origin https://trusted.example] [--electron-runtime /absolute/pinned/runtime]')
  console.error('Requires official pinned Electron 44.4.3 in packages/desktop/.runtime/electron or package-local npm install.')
  process.exitCode = 1
}
