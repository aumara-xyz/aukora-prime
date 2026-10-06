// SPDX-License-Identifier: AGPL-3.0-or-later
// SOURCE_FIXTURE: real recovery/retry/selfcheck code; fake systemctl and synthetic
// custody, readiness, sandbox responses and unsigned selfcheck recording. No systemd.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

test('SOURCE_FIXTURE owned periodic failure-stop-recover protocol and guard-removal witnesses', () => {
  const result = spawnSync('/usr/bin/python3', ['-I', '-S', '-B',
    fileURLToPath(new URL('./aukora-genesis-recovery.test.py', import.meta.url))],
  { encoding: 'utf8', timeout: 120_000, env: { PATH: '/usr/bin:/bin:/usr/local/bin',
    HOME: process.env.HOME, LANG: 'C', LC_ALL: 'C' } })
  process.stdout.write(result.stdout ?? '')
  process.stderr.write(result.stderr ?? '')
  assert.equal(result.status, 0, result.error?.message ?? 'recovery source fixture failed')
})
