#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// The enrollment claim is printed only in the fixed owner-origin fragment link.
import { parseArgs } from 'node:util'
import { mintBrowserPasskeyClaim } from '../src/browser-passkey-claim.mjs'

try {
  const { values, tokens } = parseArgs({ options: { 'owner-origin': { type: 'string' }, 'app-origin': { type: 'string' }, release: { type: 'string' } }, strict: true, tokens: true })
  if (['owner-origin', 'app-origin', 'release'].some(name =>
    tokens.filter(t => t.kind === 'option' && t.name === name).length !== 1)) throw new Error('arguments')
  const link = await mintBrowserPasskeyClaim({ ownerOrigin: values['owner-origin'], appOrigin: values['app-origin'], release: values.release })
  process.stdout.write(link + '\n')
} catch (error) {
  console.error(typeof error.code === 'string' && error.code.startsWith('browser-passkey:') ? error.code : 'browser-passkey:refused')
  process.exitCode = 1
}
