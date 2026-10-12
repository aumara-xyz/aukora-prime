#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/** Probe local OpenViking with one disposable note; suppress credentials and server bodies. */
import { randomUUID } from 'node:crypto'
import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { isMainModule } from '../lib/is-main.mjs'
import { readBridgeConfig } from '../../plugins/aukora-kira/lib/recall-openviking.mjs'
import { readJsonStrict } from '../../plugins/aukora-kira/lib/strict-read.mjs'

class ProbeRefusal extends Error {
  constructor(code) { super(code); this.code = `viking.probe:${code}` }
}
const refuse = code => { throw new ProbeRefusal(code) }
const localUrl = value => {
  let url
  try { url = new URL(value) } catch { refuse('local-url-required') }
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
      || url.username || url.password || url.search || url.hash) refuse('local-url-required')
  return url
}
const codeOf = error => error instanceof ProbeRefusal ? error.code : 'viking.probe:request-failed'
const TEXT = 'Scarlet bicycle parked beneath maple foliage.'
const QUESTION = 'Where was my red two-wheeler left?'

export async function probeViking({ home, fetch: request = globalThis.fetch, timeoutMs } = {}) {
  const steps = []
  const step = async (name, run) => {
    try { const reason = await run(); steps.push({ step: name, ok: true, reason }); return true }
    catch (error) { steps.push({ step: name, ok: false, reason: codeOf(error) }); return false }
  }
  let config, server, embedder, timeout
  const configured = await step('configuration', () => {
    if (typeof home !== 'string' || !isAbsolute(home)) refuse('home-required')
    config = readBridgeConfig(home)
    if (!config.configured) refuse('configuration-unavailable')
    server = localUrl(config.url)
    if (server.pathname !== '/') refuse('local-url-required')
    const dense = readJsonStrict(join(home, 'ov.conf'), { maxBytes: 1024 * 1024 })?.embedding?.dense
    embedder = localUrl(dense?.api_base)
    timeout = timeoutMs ?? config.timeoutMs
    if (!Number.isInteger(timeout) || timeout < 100 || timeout > 120_000) refuse('timeout-invalid')
    return 'bridge, root key and local endpoints loaded; no credentials displayed'
  })
  if (!configured) return { ok: false, steps }
  const call = async (url, { method = 'GET', body, authenticated = false, missing = false, raw = false } = {}) => {
    let response
    try {
      response = await request(url, { method, redirect: 'error', signal: AbortSignal.timeout(timeout),
        headers: { 'content-type': 'application/json', ...(authenticated ? {
          'x-api-key': config.key, 'x-openviking-account': config.account, 'x-openviking-user': config.user,
        } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) })
    } catch (error) { refuse(error?.name === 'TimeoutError' || error?.name === 'AbortError' ? 'timeout' : 'unreachable') }
    if (response.status === 401 || response.status === 403) refuse('key-refused')
    if (response.status === 409) refuse('already-exists')
    if (missing && response.status === 404) return null
    if (!response.ok) refuse(response.status >= 500 || response.status === 429 ? 'service-unavailable' : 'request-refused')
    let parsed
    try { parsed = await response.json() } catch { refuse('response-invalid') }
    if (raw) return parsed
    if (parsed?.status !== 'ok') refuse('request-refused')
    return parsed.result
  }
  const api = (path, options) => call(new URL(path, server), { ...options, authenticated: true })
  const up = await step('server', async () => {
    if ((await call(new URL('/health', server), { raw: true }))?.healthy !== true) refuse('server-unhealthy')
    return 'health answers'
  })
  const key = await step('key', async () => {
    if (!up) refuse('server-unavailable')
    const status = await api('/api/v1/system/status')
    if (status?.initialized !== true || status?.user !== config.user) refuse('account-unavailable')
    return 'authenticated account and user accepted'
  })
  const embedding = await step('embedder', async () => {
    const health = await call(new URL('/health', embedder), { raw: true })
    if (health?.status !== 'ok') refuse('embedder-unhealthy')
    return 'local embedder health answers; indexing below exercises embeddings'
  })
  const probeId = randomUUID(), directory = `viking://user/${config.user}/memories/kira/content`
  const uri = `${directory}/probe-${probeId}.md`
  let attempted = false, cleanupUri
  try {
    const indexed = await step('index', async () => {
      if (!key || !embedding) refuse('index-prerequisite-failed')
      attempted = true
      let result
      try {
        result = await api('/api/v1/content/write', { method: 'POST', body: { uri, content: TEXT, mode: 'create', wait: true,
          timeout: Math.max(1, Math.floor(timeout / 1000) - 1), tags: ['source=kira-viking-probe', `probe_id=${probeId}`] } })
      } catch (error) { if (error?.code === 'viking.probe:already-exists') attempted = false; throw error }
      if (result?.vector_status !== 'complete') refuse('index-incomplete')
      if (await api(`/api/v1/content/read?uri=${encodeURIComponent(uri)}`) !== TEXT) refuse('content-mismatch')
      return 'throwaway content written and read back'
    })
    await step('recall', async () => {
      if (!indexed) refuse('index-unavailable')
      const found = await api('/api/v1/search/find', { method: 'POST', body: {
        query: `${config.queryInstruction}${QUESTION}`, target_uri: directory, tags: [`probe_id=${probeId}`], limit: 5,
      } })
      const hit = [...(found?.memories ?? []), ...(found?.resources ?? [])]
        .find(row => row?.uri === uri && Number.isFinite(row.score) && row.score >= config.scoreThreshold)
      if (!hit) refuse('semantic-miss')
      return 'meaning query found the exact throwaway URI above the configured threshold'
    })
  } finally {
    const deleted = await step('delete', async () => {
      if (!attempted) return 'no throwaway write attempted'
      await api(`/api/v1/fs?uri=${encodeURIComponent(uri)}`, { method: 'DELETE', missing: true })
      if (await api(`/api/v1/content/read?uri=${encodeURIComponent(uri)}`, { missing: true }) !== null) refuse('delete-not-confirmed')
      return 'throwaway content is absent after deletion'
    })
    if (!deleted && attempted) cleanupUri = uri
  }
  return { ok: steps.every(row => row.ok), steps, ...(cleanupUri ? { cleanupUri } : {}) }
}

export function probeArgs(argv, env = process.env) {
  const args = { home: env.AUKORA_OPENVIKING_HOME || join(homedir(), 'openviking') }
  for (let i = 0; i < argv.length; i++) {
    if (!['--home', '--timeout-ms'].includes(argv[i]) || !argv[i + 1] || argv[i + 1].startsWith('--')) refuse('usage')
    if (argv[i] === '--home') args.home = argv[++i]
    else args.timeoutMs = Number(argv[++i])
  }
  return args
}

if (isMainModule(import.meta.url)) {
  try {
    const report = await probeViking(probeArgs(process.argv.slice(2)))
    for (const row of report.steps) process.stdout.write(`${row.ok ? 'PASS' : 'FAIL'} ${row.step}: ${row.reason}\n`)
    if (report.cleanupUri) process.stdout.write(`REMAINS throwaway URI: ${report.cleanupUri}\n`)
    process.stdout.write('LIMIT: probes this local service; does not prove the installed Kira mount or model recall quality.\n')
    process.exitCode = report.ok ? 0 : 1
  } catch (error) { process.stderr.write(`FAIL arguments: ${codeOf(error)}\n`); process.exitCode = 1 }
}
