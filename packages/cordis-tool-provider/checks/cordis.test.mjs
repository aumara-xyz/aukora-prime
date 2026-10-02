// SPDX-License-Identifier: AGPL-3.0-or-later
// Real pinned Cordis/DSH and actual C/F code; synthetic owner proof and MOCKED
// runtime qualification/SDK. No real gateway, credential, or container action.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import test from 'node:test'
import { createCordisToolProvider, SERVICE_NAME, TOOL_NAME } from '../src/index.mjs'

const buildRoot = process.env.PRIME_PINNED_DSH_DIR
const absentBuild = 'UNPERFORMED: set PRIME_PINNED_DSH_DIR to an existing built, pinned DSH tree; no install or build is performed'
const jsonFile = async path => JSON.parse(await readFile(path, 'utf8'))
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

test('real pinned Cordis/DSH and actual C/F; synthetic approvals and MOCKED qualification/SDK; no real gateway', {
  skip: buildRoot ? false : absentBuild,
}, async t => {
  const root = resolve(buildRoot)
  const pin = await jsonFile(new URL('../../../upstream-dsh.json', import.meta.url))
  const metadata = await jsonFile(resolve(root, '.dsh-build/pinned-harness-build.json'))
  const cordisPackage = await jsonFile(resolve(root, 'vendor/cordis/package.json'))

  // Refuse the selected tree before importing its code if pin checks fail.
  // This checks retained build provenance, not a fresh build or installation.
  assert.equal(metadata.formatVersion, 2)
  assert.equal(metadata.kind, 'pinned-harness-build')
  for (const field of ['commit', 'archiveSha256', 'lockfileSha256', 'packageManager']) {
    assert.equal(metadata.inputs?.upstream?.[field], pin[field], `build upstream ${field}`)
  }
  assert.equal(sha256(await readFile(resolve(root, 'pnpm-lock.yaml'))), pin.lockfileSha256)
  assert.equal(cordisPackage.name, '@deepseek-ai/cordis')
  assert.equal(cordisPackage.version, '4.0.2')
  assert.equal(cordisPackage.version, pin.cordisVersion)

  const [{ Context }, { default: SystemPrompt }, { default: ToolRuntime }] = await Promise.all([
    import(pathToFileURL(resolve(root, 'vendor/cordis/lib/index.js')).href),
    import(pathToFileURL(resolve(root, 'packages/core/system-prompt/lib/index.js')).href),
    import(pathToFileURL(resolve(root, 'packages/core/tools/lib/index.js')).href),
  ])

  for (const mode of ['default', 'unqualified fixture collaborators']) {
    await t.test(`${mode}: registration grants no effect; captured references refuse after disposal`, async () => {
      let collaboratorCalls = 0
      const neverCall = () => {
        collaboratorCalls++
        throw new Error('Unqualified fixture collaborator must not be called')
      }
      const options = mode === 'default' ? undefined : {
        authority: Object.fromEntries(['reserve', 'claimDispatch', 'requestCancel', 'settle', 'reconcileSettlement'].map(name => [name, neverCall])),
        executor: { capability: 'qualified', availability: neverCall, execute: neverCall, dispose: neverCall },
        readApproval: neverCall,
      }
      const ctx = new Context()
      const promptFiber = await ctx.plugin(SystemPrompt)
      const toolsFiber = await ctx.plugin(ToolRuntime)
      let providerFiber
      try {
        providerFiber = await ctx.plugin(createCordisToolProvider(options))
        const capturedService = ctx.get(SERVICE_NAME)
        const capturedTool = ctx.tools.get(TOOL_NAME)
        assert.ok(capturedService)
        assert.ok(capturedTool)
        assert.equal(capturedService.proposal, null)
        assert.deepEqual(capturedService.availability(), { state: 'unavailable', disposed: false, executor: null })
        assert.deepEqual(ctx.tools.schemas(), [{
          name: TOOL_NAME,
          description: capturedTool.description,
          parameters: { type: 'object', properties: {}, additionalProperties: false },
        }])

        // DSH calls render(args, value), and output must represent value rather
        // than the empty model arguments. This is a synthetic projection only.
        const fixtureValue = { receipt: { status: 'FIXTURE_ONLY_NO_EFFECT' } }
        assert.deepEqual(capturedTool.output.render({}, fixtureValue), [{
          type: 'text', text: JSON.stringify(fixtureValue),
        }])

        await assert.rejects(capturedService.invoke({}), { code: 'UNAVAILABLE' })
        const result = await ctx.tools.execute({
          callId: `cordis-unavailable-${mode === 'default' ? 'default' : 'fixture'}`,
          name: TOOL_NAME, arguments: {}, signal: new AbortController().signal,
        })
        assert.equal(result.isError, true)
        assert.match(JSON.stringify(result), /Qualified private authority\/executor configuration required/)
        assert.equal(collaboratorCalls, 0)

        await providerFiber.dispose()
        assert.equal(ctx.get(SERVICE_NAME), undefined)
        assert.equal(ctx.tools.get(TOOL_NAME), undefined)
        assert.deepEqual(ctx.tools.schemas(), [])
        assert.equal(capturedService.availability().disposed, true)
        await assert.rejects(capturedService.invoke({}), { code: 'REVOKED' })
        await assert.rejects(capturedTool.execute({}, { signal: new AbortController().signal }), { code: 'REVOKED' })
        assert.equal(collaboratorCalls, 0)
      } finally {
        await providerFiber?.dispose()
        await toolsFiber.dispose()
        await promptFiber.dispose()
      }
    })
  }

  const { providerFixture } = await import('./provider-fixture.mjs')
  for (const outcome of ['completed', 'outcome_unknown']) {
    await t.test(`real DSH pipeline and actual C/F preserve ${outcome}; MOCKED SDK and runtime qualification`, async () => {
      const fixture = providerFixture(outcome === 'outcome_unknown' ? { protocol: { trailerFailure: true } } : {})
      const ctx = new Context()
      let promptFiber, toolsFiber, providerFiber
      const protocolCount = name => fixture.protocol.calls.filter(([method]) => method === name).length
      try {
        assert.equal(fixture.propose().status, 'PROPOSED')
        assert.equal(protocolCount('create'), 0)
        fixture.approve()
        promptFiber = await ctx.plugin(SystemPrompt)
        toolsFiber = await ctx.plugin(ToolRuntime)
        providerFiber = await ctx.plugin(fixture.makePlugin())
        const service = ctx.get(SERVICE_NAME)
        assert.equal(service.availability().state, 'awaiting_authority')
        assert.equal(service.availability().executor.protocol, 'mocked')
        assert.equal(service.availability().executor.runtimeEnforcementVerified, false)
        assert.equal(fixture.calls.length, 0)
        assert.equal(protocolCount('create'), 0)

        const result = await ctx.tools.execute({
          callId: `cordis-fixture-${outcome}`,
          name: TOOL_NAME, arguments: {}, signal: new AbortController().signal,
        })
        assert.deepEqual(fixture.calls.map(row => row.method), ['reserve', 'claimDispatch', 'settle'])
        assert.equal(protocolCount('create'), 1)
        assert.equal(protocolCount('exec'), 1)
        const settlement = fixture.calls.find(row => row.method === 'settle')
        const receipt = settlement.input.receipt
        assert.equal(receipt.status, outcome)
        assert.equal(receipt.operation_id, fixture.operation.operation_id)
        assert.equal(fixture.status().status, outcome.toUpperCase())
        assert.deepEqual(fixture.ledger.lookup(receipt.request_id).receipt, receipt)

        if (outcome === 'completed') {
          assert.equal(result.isError, false)
          assert.equal(receipt.rpc_completion, 'complete')
          assert.equal(receipt.reconciliation_required, false)
          assert.deepEqual(JSON.parse(result.content.find(block => block.type === 'text').text), { receipt })
        } else {
          assert.equal(result.isError, true)
          assert.match(JSON.stringify(result), /Probe did not settle; exact receipt retained by executor\/authority/)
          assert.equal(receipt.rpc_completion, 'transport_failed')
          assert.equal(receipt.reconciliation_required, true)
          assert.equal(fixture.status().reconciliation_required, true)
          assert.equal(fixture.ledger.recovery().length, 1)
        }

        const replay = await ctx.tools.execute({
          callId: `cordis-fixture-${outcome}-replay`,
          name: TOOL_NAME, arguments: {}, signal: new AbortController().signal,
        })
        assert.equal(replay.isError, true)
        assert.equal(fixture.calls.filter(row => row.method === 'reserve').length, 1)
        assert.equal(protocolCount('exec'), 1)
        await providerFiber.dispose()
        assert.equal(ctx.get(SERVICE_NAME), undefined)
        assert.equal(ctx.tools.get(TOOL_NAME), undefined)
        assert.equal(fixture.status().status, outcome.toUpperCase())
        if (outcome === 'outcome_unknown') {
          // Cordis logs effect teardown errors while its Fiber disposal settles;
          // neither settling nor unregistering makes F's uncertainty disappear.
          assert.ok(ctx.logger.buffer.some(message => message.type === 'error'
            && message.args.some(error => error?.code === 'RECONCILIATION_REQUIRED')))
          await assert.rejects(fixture.executor.dispose(), { code: 'RECONCILIATION_REQUIRED' })
          assert.equal(fixture.ledger.recovery().length, 1)
        }
      } finally {
        await providerFiber?.dispose()
        await toolsFiber?.dispose()
        await promptFiber?.dispose()
        await fixture.cleanup({ allowPending: outcome === 'outcome_unknown' })
      }
    })
  }
})
