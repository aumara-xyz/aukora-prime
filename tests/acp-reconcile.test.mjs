// SPDX-License-Identifier: AGPL-3.0-only
// Adapted from aukora-phi a099901ad5a2d623c5343263de6ae5f9994d3159 test/reconcile.test.ts.
// Exercises supplied records and synthetic windows; no live engine or filesystem sweep.
import assert from 'node:assert/strict'
import { after, test } from 'node:test'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { argsDigest, createReceiptLog } from '../plugins/aukora-action-gate/lib/receipts.mjs'
import * as original from '../scripts/audit/acp-reconcile.mjs'

const sourceURL = new URL('../scripts/audit/acp-reconcile.mjs', import.meta.url)
const dir = mkdtempSync(fileURLToPath(new URL('./.acp-reconcile-check-', import.meta.url)))
after(() => rmSync(dir, { recursive: true, force: true }))
const updatesPath = join(dir, 'updates.jsonl'), receiptsPath = join(dir, 'receipts.jsonl')
const line = value => JSON.stringify(value)
function call(name = 'write', path, id = name, session = 's1', extra = {}) {
  return { method: 'session/update', params: { sessionId: session,
    update: { sessionUpdate: 'tool_call', toolCallId: id, title: name,
      rawInput: { ...(path === undefined ? {} : { file_path: path }), ...extra } } } }
}
const noise = () => ({ method: 'session/update', params: { sessionId: 's1',
  update: { sessionUpdate: 'agent_thought_chunk', content: { type: 'text', text: 'synthetic thought' } } } })
function receipt(update = call(), decision = 'allow', overrides = {}) {
  return { op: 'tool.decision', by: 'aukora-action-gate/v1', at: '2026-10-12T00:00:00.000Z',
    session: update.params.sessionId, callId: update.params.update.toolCallId, tool: update.params.update.title,
    argsDigest: argsDigest(update.params.update.rawInput), decision, nested: false,
    rule: decision === 'allow' ? 'allow:ok' : 'path:protected', kernelCode: decision === 'allow' ? 'allowed' : 'sacred_target',
    sequence: 1, prev: 'synthetic-head', hash: 'a'.repeat(64), ...overrides }
}
function write(api, updates, receipts, effect) {
  writeFileSync(updatesPath, updates.map(line).join('\n'))
  writeFileSync(receiptsPath, receipts.map(line).join('\n'))
  return api.reconcile(updatesPath, receiptsPath, 's1', effect)
}
const window = (changed = [], unknown = []) => ({ repoRoot: '/repo',
  diff: { changed, unknown, ruleFor: Object.fromEntries(changed.map(path => [path, 'protected'])) } })
function refused(result, code, input) {
  assert.equal(result.ok, false)
  assert.equal(result.kind, 'uninspected')
  assert.equal(result.agrees, false)
  assert.equal(result.code, code)
  if (input) assert.equal(result.input, input)
}
const cases = [
  ['tool calls are read under params.update, with all donor path spellings', api => {
    const paths = { file_path: '/repo/LAW.md', path: 'a', notebook_path: 'b', filePath: 'c', target: 'd' }
    write(api, [call('write', undefined, 'c1', 's1', paths), noise(), call('read_file')], [])
    const result = api.acpToolCalls(updatesPath, 's1')
    assert.equal(result.ok, true)
    assert.equal(result.calls.length, 2)
    assert.equal(result.calls[0].name, 'write')
    assert.deepEqual(result.calls[0].paths, Object.values(paths))
  }],
  ['non-tool updates are ignored', api => {
    write(api, [noise(), noise()], [])
    assert.deepEqual(api.acpToolCalls(updatesPath, 's1'), { ok: true, calls: [] })
  }],
  ['known status-only tool updates do not duplicate a declaration; unsupported updates refuse', api => {
    const update = { method: 'session/update', params: { sessionId: 's1',
      update: { sessionUpdate: 'tool_call_update', toolCallId: 'write', status: 'completed' } } }
    assert.equal(write(api, [call(), update], [receipt()]).acpCalls, 1)
    refused(write(api, [update], []), api.REFUSE.ACP)
    for (const change of [{ sessionUpdate: 'unknown' }, { toolCallId: null }, { rawInput: { path: 'late' } }]) {
      const malformed = { ...update, params: { ...update.params, update: { ...update.params.update, ...change } } }
      refused(write(api, [malformed], []), api.REFUSE.ACP)
    }
  }],
  ['agree when every declaration has a matching Prime decision', api => {
    const calls = [call(), call('read_file')]
    const result = write(api, calls, calls.map(c => receipt(c)))
    assert.equal(result.kind, 'agree'); assert.equal(result.agrees, true)
  }],
  ['gap when some declarations have no receipt', api => {
    const calls = [call(), call('run_terminal_command'), call('read_file')]
    const result = write(api, calls, [receipt(calls[0]), receipt(calls[2])])
    assert.equal(result.kind, 'gap')
    assert.deepEqual(result.missingFromChain.map(c => c.name), ['run_terminal_command'])
  }],
  ['no-record when no receipts belong to the session', api => {
    assert.equal(write(api, [call(), call('read_file')], []).kind, 'no-record')
    assert.equal(write(api, [call()], [receipt(call(), 'allow', { session: 'other' })]).kind, 'no-record')
  }],
  ['refusals are counted', api => {
    assert.equal(write(api, [call()], [receipt(call(), 'deny')]).refusals, 1)
  }],
  ['other sessions in the ACP stream are excluded', api => {
    const result = write(api, [call(), call('other', undefined, 'c2', 'other')], [receipt()])
    assert.equal(result.acpCalls, 1); assert.equal(result.kind, 'agree')
  }],
  ['undeclared when a protected path changed without a named declaration', api => {
    const shell = call('run_terminal_command')
    const result = write(api, [shell], [receipt(shell)], window(['LAW.md']))
    assert.equal(result.recordsConcur, true); assert.equal(result.kind, 'undeclared')
    assert.equal(result.agrees, false)
    assert.deepEqual(result.undeclaredPaths, [{ path: 'LAW.md', rule: 'protected' }])
  }],
  ['a refused call then a shell declaration cannot account for changed bytes', api => {
    const calls = [call('write', 'LAW.md'), call('run_terminal_command')]
    const result = write(api, calls, [receipt(calls[0], 'deny'), receipt(calls[1])], window(['LAW.md']))
    assert.equal(result.kind, 'undeclared'); assert.equal(result.refusals, 1)
  }],
  ['empty shell paths account for no path', api => {
    const shell = call('run_terminal_command', '')
    assert.equal(write(api, [shell], [receipt(shell)], window(['.env'])).kind, 'undeclared')
  }],
  ['refused declaration without a change is not an undeclared effect', api => {
    const c = call('write', 'LAW.md')
    const result = write(api, [c], [receipt(c, 'deny')], window())
    assert.equal(result.kind, 'agree'); assert.equal(result.agrees, true)
  }],
  ['allowed declaration naming a changed path accounts for it', api => {
    const c = call('write', 'LAW.md')
    assert.deepEqual(write(api, [c], [receipt(c)], window(['LAW.md'])).accountedPaths, ['LAW.md'])
  }],
  ['absolute declarations match the same relative sweep key', api => {
    const c = call('Write', '/repo/LAW.md')
    assert.equal(write(api, [c], [receipt(c)], window(['LAW.md'])).kind, 'agree')
  }],
  ['no alias resolution is invented from Prime receipts which omit paths', api => {
    const c = call('Write', 'innocent.txt')
    const result = write(api, [c], [receipt(c, 'allow', { path: 'LAW.md', resolved: 'LAW.md' })], window(['LAW.md']))
    assert.equal(result.kind, 'undeclared')
  }],
  ['declaration without a receipt remains no-record, not a second undeclared finding', api => {
    const result = write(api, [call('write', 'LAW.md')], [], window(['LAW.md']))
    assert.equal(result.kind, 'no-record'); assert.deepEqual(result.undeclaredPaths, [])
    assert.equal(result.agrees, false)
  }],
  ['many calls with no changed paths agree', api => {
    const calls = ['read_file', 'list_dir', 'grep', 'run_terminal_command'].map(name => call(name))
    assert.equal(write(api, calls, calls.map(c => receipt(c)), window()).agrees, true)
  }],
  ['unknown sweep paths are neither clean nor undeclared', api => {
    const result = write(api, [], [], window([], ['locked/a.key']))
    assert.deepEqual(result.unknownPaths, ['locked/a.key']); assert.deepEqual(result.undeclaredPaths, [])
    assert.equal(result.agrees, false); assert.equal(result.recordsConcur, true)
  }],
  ['omitting a sweep checks only records', api => {
    const result = write(api, [call()], [receipt()])
    assert.equal(result.effectsChecked, false); assert.equal(result.kind, 'agree')
    assert.deepEqual(result.undeclaredPaths, []); assert.deepEqual(result.unknownPaths, [])
  }],
  ['undeclared outranks a record gap while retaining both findings', api => {
    const result = write(api, [call('read_file'), call('run_terminal_command')], [receipt(call('read_file'))], window(['LAW.md']))
    assert.equal(result.kind, 'undeclared'); assert.equal(result.recordKind, 'gap')
    assert.equal(result.missingFromChain[0].name, 'run_terminal_command')
  }],
  ['output states attribution, execution and authentication limits', api => {
    const result = write(api, [], [], window(['LAW.md']))
    assert.match(result.limit, /do not say which process/)
    assert.match(result.limit, /does not prove execution or owner approval/)
    assert.match(result.limit, /authentication and log completeness are unchecked/)
  }],
  ['each receipt is consumed once and extra receipts remain a gap', api => {
    const result = write(api, [call()], [receipt(), receipt(call('read_file'))])
    assert.equal(result.kind, 'gap'); assert.equal(result.unmatchedInChain.length, 1)
    const twice = write(api, [call(), call('write', undefined, 'second')], [receipt()])
    assert.equal(twice.kind, 'gap'); assert.equal(twice.missingFromChain.length, 1)
  }],
  ['call IDs, exact tool names and argument digests cannot substitute for each other', api => {
    for (const overrides of [{ callId: 'different' }, { tool: 'Write' }, { argsDigest: 'b'.repeat(64) }]) {
      const result = write(api, [call()], [receipt(call(), 'allow', overrides)])
      assert.equal(result.kind, 'gap'); assert.equal(result.agrees, false)
      assert.equal(result.missingFromChain.length, 1); assert.equal(result.unmatchedInChain.length, 1)
    }
  }],
  ['allow and deny on the same path still preserve an allowed declaration', api => {
    const first = call('write', 'LAW.md'), second = call('write', 'LAW.md', 'second')
    assert.equal(write(api, [first, second], [receipt(first, 'deny'), receipt(second)], window(['LAW.md'])).kind, 'agree')
  }],
  ['read, view and unknown tools do not declare mutations', api => {
    for (const name of ['read', 'read_file', 'custom_tool', 'run_terminal_command', 'str_replace_editor']) {
      const c = call(name, 'LAW.md', name, 's1', { command: 'view' })
      assert.equal(write(api, [c], [receipt(c)], window(['LAW.md'])).kind, 'undeclared')
    }
    for (const command of ['create', 'str_replace', 'insert', 'undo_edit']) {
      const c = call('str_replace_editor', 'LAW.md', 'edit', 's1', { command })
      assert.equal(write(api, [c], [receipt(c)], window(['LAW.md'])).kind, 'agree')
    }
  }],
  ['rule lookup uses own properties even for filenames resembling object members', api => {
    const effect = { repoRoot: '/repo', diff: { changed: ['toString', '__proto__'], unknown: [], ruleFor: {} } }
    assert.deepEqual(write(api, [], [], effect).undeclaredPaths,
      [{ path: 'toString', rule: null }, { path: '__proto__', rule: null }])
  }],
  ['lexical path comparison excludes outside paths and preserves case and directories', api => {
    for (const path of ['/elsewhere/LAW.md', '../LAW.md', '/repo-other/LAW.md', 'sub/LAW.md', 'law.md', '.']) {
      const c = call('write', path)
      assert.equal(write(api, [c], [receipt(c)], window(['LAW.md'])).kind, 'undeclared')
    }
    const c = call('write', './sub/../LAW.md')
    assert.equal(write(api, [c], [receipt(c)], window(['LAW.md'])).kind, 'agree')
  }],
  ['a missing file is uninspected rather than empty', api => {
    write(api, [], [])
    refused(api.reconcile(join(dir, 'missing'), receiptsPath, 's1'), api.REFUSE.READ, 'updates')
    refused(api.reconcile(updatesPath, join(dir, 'missing'), 's1'), api.REFUSE.READ, 'receipts')
  }],
  ['malformed JSON, null, arrays and scalars never become quiet logs', api => {
    for (const raw of ['{broken', 'null', '[]', '1', '"text"']) {
      for (const path of [updatesPath, receiptsPath]) {
        write(api, [call()], [receipt()]); writeFileSync(path, `${readFileSync(path, 'utf8')}\n${raw}`)
        const result = api.reconcile(updatesPath, receiptsPath, 's1')
        refused(result, api.REFUSE.JSON); assert.equal(result.line, 2)
      }
    }
  }],
  ['malformed ACP envelopes and tool records are explicit errors', api => {
    const valid = call()
    const variants = [{}, { method: 'session/update', update: valid.params.update },
      { ...valid, method: 'wrong' }, { ...valid, params: { ...valid.params, sessionId: null } },
      ...[{ toolCallId: '' }, { title: null }, { rawInput: [] }, { rawInput: null }, { rawInput: undefined }, { rawInput: { path: 3 } },
        { rawInput: { file_path: 'bad\0path' } }].map(change => ({ ...valid, params: {
          ...valid.params, update: { ...valid.params.update, ...change } } }))]
    for (const malformed of variants) refused(write(api, [malformed], []), api.REFUSE.ACP)
  }],
  ['duplicate JSON keys are not collapsed into a single interpretation', api => {
    for (const [path, before, after] of [
      [updatesPath, '"sessionId":"s1"', '"sessionId":"other","sessionId":"s1"'],
      [updatesPath, '"rawInput":{}', '"rawInput":{"path":"x","path":"y"}'],
      [receiptsPath, '"decision":"allow"', '"decision":"deny","decision":"allow"'],
    ]) {
      write(api, [call()], [receipt()])
      writeFileSync(path, readFileSync(path, 'utf8').replace(before, after))
      refused(api.reconcile(updatesPath, receiptsPath, 's1'), api.REFUSE.JSON)
    }
  }],
  ['Prime receipt fields are validated and donor receipt shapes are refused', api => {
    for (const change of [{ op: 'unknown' }, { by: 'unknown' }, { session: null }, { callId: null }, { tool: '' },
      { argsDigest: 'invalid' }, { decision: 'unknown' }, { nested: null }, { rule: '' }, { kernelCode: null },
      { at: 'bad-date' }, { sequence: 0 }, { prev: null }, { hash: 'invalid' }]) {
      refused(write(api, [call()], [receipt(call(), 'allow', change)]), api.REFUSE.RECEIPT)
    }
    refused(write(api, [], [{ tool: 'write', verdict: 'allowed', session: 's1', path: '' }]), api.REFUSE.RECEIPT)
  }],
  ['duplicate identities and segment markers cannot yield agreement', api => {
    refused(write(api, [call(), call()], [receipt()]), api.REFUSE.DUPLICATE, 'updates')
    refused(write(api, [call()], [receipt(), receipt()]), api.REFUSE.DUPLICATE, 'receipts')
    refused(write(api, [], [{ op: 'segment', reason: 'rotated' }]), api.REFUSE.SEGMENT)
  }],
  ['an explicit nonempty session is required', api => {
    write(api, [], [])
    for (const session of [undefined, null, '', ' ']) refused(api.reconcile(updatesPath, receiptsPath, session), api.REFUSE.SESSION)
  }],
  ['invalid or contradictory effect windows are uninspected', api => {
    for (const effect of [null, {}, { ...window(), repoRoot: 'relative' },
      { ...window(), diff: { changed: [], unknown: [] } }, window(['../x']), window(['/repo/x']),
      window(['x', 'x']), window(['x'], ['x']), window(['./x']), window(['x\0']),
      { ...window(), diff: { changed: [], unknown: [], ruleFor: { x: 4 } } }]) {
      refused(write(api, [], [], effect), api.REFUSE.EFFECT)
    }
  }],
  ['raw arguments and malformed input contents are not echoed', api => {
    const marker = 'SYNTHETIC_PRIVATE_ARGUMENT'
    const c = call('shell', undefined, 'shell', 's1', { command: marker })
    assert.equal(JSON.stringify(write(api, [c], [])).includes(marker), false)
    writeFileSync(updatesPath, `{${marker}`)
    assert.equal(JSON.stringify(api.reconcile(updatesPath, receiptsPath, 's1')).includes(marker), false)
  }],
  ['only explicitly supplied CLI paths are read', api => {
    refused(api.main([]), api.REFUSE.USAGE)
    refused(api.main(['a', 'b']), api.REFUSE.USAGE)
    write(api, [], [])
    refused(api.main([updatesPath, receiptsPath, 's1', join(dir, 'missing')]), api.REFUSE.READ, 'effects')
    const path = join(dir, 'effects.json')
    writeFileSync(path, '{broken')
    refused(api.main([updatesPath, receiptsPath, 's1', path]), api.REFUSE.JSON, 'effects')
    writeFileSync(path, line(window(['LAW.md'])))
    assert.equal(api.main([updatesPath, receiptsPath, 's1', path]).kind, 'undeclared')
  }],
]
for (const [name, run] of cases) test(name, () => run(original))

test('accepts receipts made by Prime createReceiptLog without translating their schema', () => {
  const log = createReceiptLog({ auraDir: join(dir, 'producer') })
  const { sequence, prev, hash, ...body } = receipt()
  log.append(body)
  writeFileSync(updatesPath, line(call()))
  assert.equal(original.reconcile(updatesPath, log.path, 's1').kind, 'agree')
})

test('CLI reports distinct exit statuses for agreement, findings, unknowns and bad input', () => {
  function cli(...extra) {
    return spawnSync(process.execPath, [fileURLToPath(sourceURL), updatesPath, receiptsPath, 's1', ...extra], { encoding: 'utf8' })
  }
  write(original, [call()], [receipt()]); assert.equal(cli().status, 0)
  write(original, [call()], []); assert.equal(cli().status, 1)
  const path = join(dir, 'unknown.json')
  write(original, [], []); writeFileSync(path, line(window([], ['locked'])))
  assert.equal(cli(path).status, 1)
  writeFileSync(updatesPath, '{broken')
  const result = cli()
  assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).code, original.REFUSE.JSON)
})

test('removing each comparison protection fails its regression', async t => {
    const source = readFileSync(sourceURL, 'utf8').replace(/from '(\.\.[^']+)'/g,
      (_, path) => `from ${JSON.stringify(new URL(path, sourceURL).href)}`)
    const mutants = [
      ['nested updates', 'const update = params?.update', 'const update = row.update'],
      ['ACP session isolation', 'if (params.sessionId !== session) continue', 'if (false) continue'],
      ['receipt session isolation', 'if (row.session !== session) continue', 'if (false) continue'],
      ['call identity', 'pool.get(call.id)', '[...pool.values()][0]'],
      ['tool identity', 'receipt.name === call.name', 'true'],
      ['argument binding', 'receipt.argsDigest === call.argsDigest', 'true'],
      ['receipt consumption', 'if (matched) pool.delete(call.id)', 'if (false) pool.delete(call.id)'],
      ['unmatched receipts', 'const unmatchedInChain = [...pool.values()]', 'const unmatchedInChain = []'],
      ['no-record distinction', "receipts.entries.length === 0 ? 'no-record' : 'gap'", "'gap'"],
      ['refusal accounting', "receipt.decision === 'allow' ? allowed : refused", 'allowed'],
      ['mutation declarations', 'if (effect && call.mutating)', 'if (effect)'],
      ['editor view exclusion', "['create', 'str_replace', 'insert', 'undo_edit'].includes(input.command)", 'true'],
      ['undeclared effects', 'else undeclaredPaths.push({ path, rule: Object.hasOwn(effect.diff.ruleFor, path) ? effect.diff.ruleFor[path] : null })', 'else accountedPaths.push(path)'],
      ['own rule properties', 'Object.hasOwn(effect.diff.ruleFor, path) ? effect.diff.ruleFor[path] : null', 'effect.diff.ruleFor[path] ?? null'],
      ['unknown is not clean', '&& unknownPaths.length === 0', ''],
      ['outside path exclusion', 'key.startsWith(\'../\')', 'false'],
      ['case preservation', "split(sep).join('/')", "split(sep).join('/').toLowerCase()"],
      ['read failures', 'catch { return failure(REFUSE.READ, input) }', 'catch { raw = \'\' }'],
      ['JSON damage', 'catch { return failure(REFUSE.JSON, input, index + 1) }', 'catch { continue }'],
      ['duplicate JSON keys', 'parseStrictText(lines[index], input)', 'JSON.parse(lines[index])'],
      ['non-object JSON', 'if (!object(value)) return failure(REFUSE.JSON, input, index + 1)', 'if (!object(value)) continue'],
      ['ACP schema', "return failure(REFUSE.ACP, 'updates', line)", 'continue'],
      ['unknown update kinds', "if (update.sessionUpdate !== 'tool_call') return failure(REFUSE.ACP, 'updates', line)", "if (update.sessionUpdate !== 'tool_call') continue"],
      ['orphan call updates', 'params.sessionId === session && !ids.has(update.toolCallId)', 'false'],
      ['missing arguments', 'const input = update.rawInput', 'const input = update.rawInput ?? {}'],
      ['receipt schema', "return failure(REFUSE.RECEIPT, 'receipts', line)", 'continue'],
      ['duplicate ACP IDs', 'if (ids.has(update.toolCallId))', 'if (false)'],
      ['duplicate receipt IDs', 'if (ids.has(row.callId))', 'if (false)'],
      ['segment visibility', "if (row.op === 'segment') return failure(REFUSE.SEGMENT, 'receipts', line)", "if (row.op === 'segment') continue"],
      ['session requirement', 'if (!text(session))', 'if (false)'],
      ['effect validation', 'effect !== undefined && !validEffect(effect)', 'false'],
      ['no raw input echo', 'paths: PATH_FIELDS.map', 'rawInput: input, paths: PATH_FIELDS.map'],
      ['attribution limit', 'File changes do not say which process changed them.', ''],
      ['explicit CLI arguments', 'argv.length !== 3 && argv.length !== 4', 'false'],
    ]
    for (const [name, before, replacement] of mutants) {
      assert.ok(source.includes(before), `mutation target exists: ${name}`)
      const mutant = await import(`data:text/javascript;base64,${Buffer.from(source.replace(before, replacement)).toString('base64')}#${encodeURIComponent(name)}`)
      const detected = cases.some(([, run]) => {
        try { run(mutant); return false } catch (error) {
          if (error.code === 'ERR_ASSERTION') return true
          throw error
        }
      })
      assert.equal(detected, true, `surviving mutant: ${name}`)
    }
    t.diagnostic(`MUTATIONS ${mutants.length}/${mutants.length} detected by assertion failures`)
})
