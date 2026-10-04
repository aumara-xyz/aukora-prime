// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixed H bootstrap target, finite actions. No caller-selected config/code path,
// secret argv/env, provider transport, credential provisioning or gate effects.
import { pathToFileURL } from 'node:url'
import { loadAuraContext } from './context.mjs'
import { collectGateOnce } from '../../../../scripts/aura/collect-gate.mjs'
import { verifyCollectorStore } from '../../../../scripts/aura/verify-collected.mjs'

export async function runAuraAction(action, loaded) {
  if (action !== 'collect' && action !== 'verify')
    throw Object.assign(new Error('aura-entry:action-invalid'), { code: 'aura-entry:action-invalid' })
  const context = loaded?.collectorContext
  if (!context) throw Object.assign(new Error('aura-entry:context-unavailable'), { code: 'aura-entry:context-unavailable' })
  return action === 'collect' ? collectGateOnce(context) : verifyCollectorStore(context)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const action = process.argv[2]
    if (process.argv.length !== 3 || (action !== 'collect' && action !== 'verify'))
      throw Object.assign(new Error('aura-entry:action-invalid'), { code: 'aura-entry:action-invalid' })
    const result = await runAuraAction(action, await loadAuraContext())
    process.stdout.write(`${JSON.stringify(result)}\n`)
    process.exitCode = result.ok ? 0 : 2
  } catch (error) {
    const reason = typeof error?.code === 'string' && /^(aura-context:|aura-entry:)[a-z-]+$/u.test(error.code)
      ? error.code : 'aura-entry:unavailable'
    process.stdout.write(`${JSON.stringify({ ok: false, status: 'incomplete', reason, grants_authority: false })}\n`)
    process.exitCode = 2
  }
}
