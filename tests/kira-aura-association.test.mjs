// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { registerHooks } from 'node:module';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createAuraAssociation, parseAuraSourceProjection, referenceForAssociatedNote, sourceIdentity,
} from '../plugins/aukora-kira/lib/aura-association.mjs';

const hash = 'a'.repeat(64);
const recordId = 'b'.repeat(64);
const noteId = `rem:${'c'.repeat(64)}`;
const source = { journal_id: 'aukora-gate-pilot', position: 7, hash };
const makeNote = () => ({
  id: noteId, grantsAuthority: false,
  source: { provider: 'fixture', aura_source: { ...source } },
  auraAssociation: createAuraAssociation(noteId, source),
});
let groups = 0;
function group(name, check) {
  check();
  groups++;
  console.log(`PASS ${name}`);
}

group('closed capture projection and detached association preserve exact coordinates', () => {
  const projection = { source: { ...source } };
  const parsed = parseAuraSourceProjection(projection);
  assert.deepEqual(parsed, source);
  assert.notEqual(parsed, projection.source);
  const association = createAuraAssociation(noteId, parsed);
  assert.deepEqual(association, {
    v: 1, kind: 'aukora-kira-aura-association/v1', note_id: noteId, source,
  });
  parsed.position = 8;
  projection.source.hash = 'd'.repeat(64);
  assert.equal(association.source.position, 7);
  assert.equal(association.source.hash, hash);
  assert.deepEqual(Object.keys(association).sort(), ['kind', 'note_id', 'source', 'v']);
});

group('trusted journal, safe positive position and exact lowercase hash are required', () => {
  for (const invalid of [
    null, [], 'source', {},
    { ...source, journal_id: 'other-journal' },
    { ...source, journal_id: new String('aukora-gate-pilot') },
    ...[0, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '7', 7n]
      .map(position => ({ ...source, position })),
    ...['A'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), 'g'.repeat(64), `${hash}\n`, null, 123]
      .map(value => ({ ...source, hash: value })),
  ]) {
    assert.equal(parseAuraSourceProjection({ source: invalid }), null);
    assert.equal(createAuraAssociation(noteId, invalid), null);
    assert.equal(sourceIdentity(invalid), null);
  }
  assert.equal(parseAuraSourceProjection({ source: { ...source, position: Number.MAX_SAFE_INTEGER } }).position,
    Number.MAX_SAFE_INTEGER);
});

group('closed projections reject surplus fields, symbols and inherited data', () => {
  assert.equal(parseAuraSourceProjection({ source, owner: 'fixture' }), null);
  assert.equal(parseAuraSourceProjection({ source, grants_authority: false }), null);
  assert.equal(parseAuraSourceProjection({ source, [Symbol('hidden')]: true }), null);
  assert.equal(parseAuraSourceProjection({ source: { ...source, record_id: recordId } }), null);
  assert.equal(parseAuraSourceProjection({ source: { ...source, [Symbol('hidden')]: true } }), null);
  assert.equal(parseAuraSourceProjection(Object.create({ source })), null);
  assert.equal(parseAuraSourceProjection({ source: Object.assign(Object.create({ inherited: true }), source) }), null);
  const bareSource = Object.assign(Object.create(null), source);
  const bareProjection = Object.assign(Object.create(null), { source: bareSource });
  assert.deepEqual(parseAuraSourceProjection(bareProjection), source);
});

group('accessors are refused without invoking their getters', () => {
  let reads = 0;
  const getter = { enumerable: true, get() { reads++; throw new Error('getter executed'); } };
  const projection = Object.defineProperty({}, 'source', getter);
  const sourceGetter = Object.defineProperty({ journal_id: source.journal_id, position: 7 }, 'hash', getter);
  const noteGetter = Object.defineProperty(makeNote(), 'auraAssociation', getter);
  const noteSourceGetter = makeNote();
  noteSourceGetter.source = Object.defineProperty({}, 'aura_source', getter);
  const associationGetter = makeNote();
  Object.defineProperty(associationGetter.auraAssociation, 'record_id', getter);
  assert.equal(parseAuraSourceProjection(projection), null);
  assert.equal(parseAuraSourceProjection({ source: sourceGetter }), null);
  assert.equal(sourceIdentity(sourceGetter), null);
  assert.equal(referenceForAssociatedNote(noteGetter), null);
  assert.equal(referenceForAssociatedNote(noteSourceGetter), null);
  assert.equal(referenceForAssociatedNote(associationGetter), null);
  assert.equal(reads, 0);
});

group('matching ID-covered source returns detached advisory selector', () => {
  const note = makeNote();
  const reference = referenceForAssociatedNote(note);
  assert.deepEqual(reference, { source });
  assert.notEqual(reference.source, note.source.aura_source);
  assert.notEqual(reference.source, note.auraAssociation.source);
  reference.source.position = 88;
  assert.equal(note.source.aura_source.position, 7);
  assert.equal(note.auraAssociation.source.position, 7);
  assert.deepEqual(Object.keys(reference), ['source']);
  assert.equal(Object.hasOwn(reference, 'grants_authority'), false);
});

group('historical, substituted and authority-bearing notes never produce selectors', () => {
  const historical = makeNote();
  delete historical.auraAssociation;
  assert.equal(referenceForAssociatedNote(historical), null);
  const withoutCoveredSource = makeNote();
  delete withoutCoveredSource.source.aura_source;
  assert.equal(referenceForAssociatedNote(withoutCoveredSource), null);
  for (const change of [
    note => { note.id = `rem:${'d'.repeat(64)}`; },
    note => { note.auraAssociation.note_id = `rem:${'d'.repeat(64)}`; },
    note => { note.auraAssociation.source.position++; },
    note => { note.source.aura_source.position++; },
    note => { note.source.aura_source.hash = 'e'.repeat(64); },
    note => { note.auraAssociation.source.hash = 'e'.repeat(64); },
    note => { note.source.aura_source.journal_id = 'other-journal'; },
    note => { note.grantsAuthority = true; },
    note => { delete note.grantsAuthority; },
    note => { note.id = 'rem:invented'; },
  ]) {
    const note = makeNote();
    change(note);
    assert.equal(referenceForAssociatedNote(note), null);
  }
});

group('association schema is closed and optional record ID is structural data only', () => {
  for (const change of [
    association => { association.v = 2; },
    association => { association.v = '1'; },
    association => { association.kind = 'other-kind'; },
    association => { association.extra = true; },
    association => { association[Symbol('hidden')] = true; },
    association => { association.record_id = 'B'.repeat(64); },
    association => { association.record_id = undefined; },
    association => { association.source.owner = 'fixture'; },
    association => { delete association.note_id; },
  ]) {
    const note = makeNote();
    change(note.auraAssociation);
    assert.equal(referenceForAssociatedNote(note), null);
  }
  const optional = makeNote();
  optional.auraAssociation = createAuraAssociation(noteId, source, recordId);
  assert.deepEqual(referenceForAssociatedNote(optional), { source, record_id: recordId });
  for (const invalid of ['rem:bad', 'rem:' + 'C'.repeat(64), `${noteId}\n`, null, 123]) {
    assert.equal(createAuraAssociation(invalid, source), null);
  }
  for (const invalid of ['B'.repeat(64), 'b'.repeat(63), `${recordId}\n`, null, 123]) {
    assert.equal(createAuraAssociation(noteId, source, invalid), null);
  }
});

group('source identity is stable for exact coordinates and changes with source', () => {
  const expected = `{"journal_id":"aukora-gate-pilot","position":7,"hash":"${hash}"}`;
  assert.equal(sourceIdentity(source), expected);
  assert.equal(sourceIdentity({ hash, position: 7, journal_id: source.journal_id }), expected);
  assert.notEqual(sourceIdentity({ ...source, position: 8 }), expected);
  assert.notEqual(sourceIdentity({ ...source, hash: 'd'.repeat(64) }), expected);
  assert.equal(sourceIdentity({ ...source, toJSON() { throw new Error('untrusted hook'); } }), null);
});

console.log(`PASS ${groups} helper groups; invented data only, no capture or citation qualification`);

// Load missing first-party dependencies from immutable local Git objects into
// memory only, using the same pinned closure as the separate recall fixture.
// No dependency blobs are copied and Git is forbidden from lazy fetching.
const root = fileURLToPath(new URL('../', import.meta.url));
const primeBase = 'f6c398869f709000233a2fe7962837d5ee2e2a13';
const citationBase = 'c3f07af37d8e5dd291a655d0ba22f67115288d36';
const git = process.env.AUKORA_PRIME_CHECK_GIT ?? root;
registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('node:')) return next(specifier, context);
    try { return next(specifier, context); } catch (error) {
      if (!context.parentURL || !specifier.startsWith('.')) throw error;
      const url = new URL(specifier, context.parentURL);
      if (url.protocol !== 'file:') throw error;
      const path = relative(root, fileURLToPath(url)).replaceAll('\\', '/');
      if (path.startsWith('../') || !git) throw error;
      return { url: url.href, shortCircuit: true };
    }
  },
  load(url, context, next) {
    const missingPath = url.startsWith('file:') && !existsSync(fileURLToPath(url))
      ? relative(root, fileURLToPath(url)).replaceAll('\\', '/') : null;
    if (!missingPath || missingPath.startsWith('../')) return next(url, context);
    if (missingPath.includes('..') || !git) throw Error('pinned Git source required');
    return {
      format: missingPath.endsWith('.json') ? 'json' : 'module', shortCircuit: true,
      source: execFileSync('git', ['show',
        (missingPath === 'scripts/aura/collect-gate.mjs' ? citationBase : primeBase) + ':' + missingPath], {
        cwd: git, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
        env: { ...process.env, GIT_NO_LAZY_FETCH: '1' },
      }),
    };
  },
});

const scratch = mkdtempSync(join(tmpdir(), 'kira-aura-association-check-'));
const savedEnv = new Map(['AUKORA_STATE', 'AUKORA_ROOM_LOG', 'AUKORA_OPENVIKING_HOME']
  .map(name => [name, process.env[name]]));
let functionalGroups = 0;
let networkCalls = 0;
const instant = '2026-01-01T00:00:00Z';
const subject = 'aukora:1:' + '1'.repeat(64);
const fixtureSource = position => ({ journal_id: 'aukora-gate-pilot', position,
  hash: position.toString(16).padStart(64, '0') });
const hostProjection = coordinates => ({ auraSource: { source: coordinates } });

function bytesIn(directory, prefix = '') {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))
    .flatMap(entry => {
      const path = join(directory, entry.name), name = prefix + entry.name;
      assert(!entry.isSymbolicLink(), 'fixture must not follow external paths');
      return entry.isDirectory() ? bytesIn(path, name + '/') : [[name, readFileSync(path).toString('hex')]];
    });
}

async function functional(name, check) {
  await check();
  functionalGroups++;
  console.log(`PASS ${name}`);
}

try {
  process.env.AUKORA_STATE = scratch;
  process.env.AUKORA_ROOM_LOG = join(scratch, 'absent-room.jsonl');
  process.env.AUKORA_OPENVIKING_HOME = join(scratch, 'absent-openviking');
  const { createTrackedMemory, MAX_NOTE_CHARS } = await import('../plugins/aukora-kira/lib/tracked-memory.mjs');
  const { recomputeNoteId } = await import('../plugins/aukora-kira/lib/memory-tiers.mjs');
  const { nextEntry } = await import('../plugins/aukora-kira/lib/memory-journal.mjs');
  const { registerGateCaptureIngestion, apply } = await import('../plugins/aukora-kira/lib/index.js');
  const makeMemory = (name, options = {}) => createTrackedMemory({
    stateDir: join(scratch, name), subject, config: { configured: false },
    now: () => Date.parse(instant),
    fetch: () => { networkCalls++; throw Error('fixture forbids provider calls'); },
    ...options,
  });
  const objectBytes = (directory, id) => readFileSync(join(directory, 'remembered', id.slice(4) + '.json'), 'utf8');
  const assertPersisted = (directory, id, coordinates) => {
    const persisted = JSON.parse(objectBytes(directory, id));
    assert.equal(persisted.id, id);
    assert.equal(recomputeNoteId(persisted), id, 'gate source must be covered by the actual note ID');
    assert.deepEqual(persisted.source.aura_source, coordinates);
    assert.deepEqual(persisted.auraAssociation, {
      v: 1, kind: 'aukora-kira-aura-association/v1', note_id: id, source: coordinates,
    });
    assert.equal(persisted.grantsAuthority, false);
    return persisted;
  };
  const assertRecoveredEnvelope = (retained, repaired) => {
    const original = JSON.parse(retained), current = JSON.parse(repaired);
    // Other captures may commit before the retained orphan. Its durable chain
    // position is then reassigned, while every remembered envelope value stays.
    current.aura.index = original.aura.index;
    assert.deepEqual(current, original);
  };
  const deferred = () => {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
  };
  const bounded = async promise => {
    let deadline;
    try {
      return await Promise.race([promise, new Promise((_, reject) => {
        deadline = setTimeout(() => reject(Error('disposable fixture wait exceeded 1500ms')), 1500);
      })]);
    } finally { clearTimeout(deadline); }
  };
  const until = async check => {
    let stopped = false, timer;
    try {
      await bounded(new Promise((resolve, reject) => {
        const poll = () => {
          if (stopped) return;
          try { if (check()) return resolve(); }
          catch (error) { return reject(error); }
          timer = setTimeout(poll, 2);
        };
        poll();
      }));
    } finally { stopped = true; clearTimeout(timer); }
  };
  const observerFixture = () => {
    const listeners = new Map(), disposers = [], provided = new Map();
    const ctx = {
      on(name, listener) {
        if (!listeners.has(name)) listeners.set(name, new Set());
        listeners.get(name).add(listener);
        return () => listeners.get(name).delete(listener);
      },
      effect(callback) { const dispose = callback(); if (typeof dispose === 'function') disposers.push(dispose); },
      tools: { register: () => () => {} }, sessions: { get: () => undefined },
      inject: () => {}, emit: () => {}, reflect: { get: () => undefined },
      provide: (name, service) => provided.set(name, service), logger: { warn: () => {} },
    };
    return {
      ctx, provided,
      emit(name, ...args) { for (const listener of listeners.get(name) ?? []) listener(...args); },
      count(name) { return listeners.get(name)?.size ?? 0; },
      dispose() { for (const dispose of disposers.reverse()) dispose(); },
    };
  };
  const fixtureUuid = number => `00000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
  const nativeExecution = () => ({ name: 'aukora_gate_propose', callId: 'fixture-call',
    rootCallId: 'fixture-root-call', agent: {} });
  const nativeToolResult = id => ({ isError: false,
    value: JSON.stringify({ ok: true, state: 'PENDING_OWNER', id, expires: Date.now() + 10_000 }),
    content: [{ type: 'text', text: 'Display-only gate proposal summary.' }] });
  const completedFixture = id => ({ state: 'applied', applied: true,
    receipt: { proposal: id, target: 'synthetic-target.txt', applied_at: instant } });
  const mockHostOptions = (memory, sourceCoordinates, overrides = {}) => ({
    memoryFor: () => memory,
    // Explicit toy host composition: no H verifier, gate client, keys or grants.
    stateForProposal: async id => completedFixture(id),
    proposalFromToolResult: returned => ({ id: returned.id, expires: returned.expires }),
    inputForCompletion: execution => ({ text: 'Synthetic observer completion retained as ordinary memory.',
      from: 'gate-observer-fixture', scope: execution.scope, at: instant }),
    isLive: () => true,
    verifyCompletedGateCapture: () => ({ source: { ...sourceCoordinates } }),
    capturePins: Object.freeze({ fixture: 'toy' }),
    referenceForAppliedAction: () => ({ source: { ...sourceCoordinates } }),
    pollIntervalMs: 2, maxWaitMs: 1000, maxPending: 2,
    ...overrides,
  });

  await functional('actual remember persists host projection and leaves historical object bytes unchanged', async () => {
    const directory = join(scratch, 'persisted'), memory = makeMemory('persisted');
    const input = { text: 'Synthetic tracked association observation, with ordinary note body only.', from: 'fixture' };
    const historical = await memory.remember(input);
    assert.equal(historical.remembered, 1);
    const historicalBytes = objectBytes(directory, historical.ids[0]);
    assert.equal(Object.hasOwn(JSON.parse(historicalBytes), 'auraAssociation'), false);
    const coordinates = fixtureSource(41), projection = hostProjection(coordinates);
    const bound = await memory.remember(input, projection);
    assert.equal(bound.remembered, 1);
    assert.notEqual(bound.ids[0], historical.ids[0]);
    assertPersisted(directory, bound.ids[0], coordinates);
    assert.equal(objectBytes(directory, historical.ids[0]), historicalBytes);
    coordinates.position = 99;
    const reloaded = makeMemory('persisted');
    const persisted = reloaded.read().notes.find(note => note.id === bound.ids[0]);
    assert.deepEqual(persisted.source.aura_source, fixtureSource(41));
    assert.deepEqual(await reloaded.referenceForRecord(bound.ids[0]), { source: fixtureSource(41) });
    assert.equal(await reloaded.referenceForRecord(historical.ids[0]), null);
  });

  await functional('actual source-aware dedup reuses exact source and separates different gate sources', async () => {
    const directory = join(scratch, 'dedup'), memory = makeMemory('dedup');
    const input = { text: 'Same synthetic remembered body for deduplication.', from: 'fixture' };
    const first = await memory.remember(input, hostProjection(fixtureSource(51)));
    const before = bytesIn(directory);
    const repeated = await memory.remember(input, hostProjection(fixtureSource(51)));
    assert.equal(repeated.remembered, 0);
    assert.deepEqual(repeated.ids, first.ids);
    assert.deepEqual(bytesIn(directory), before, 'same-source dedup must not rewrite persisted data');
    const other = await memory.remember(input, hostProjection(fixtureSource(52)));
    assert.equal(other.remembered, 1);
    assert.notEqual(other.ids[0], first.ids[0]);
    const samePositionNewHash = { ...fixtureSource(51), hash: 'e'.repeat(64) };
    const changedHash = await memory.remember(input, hostProjection(samePositionNewHash));
    assert.equal(changedHash.remembered, 1);
    assert.notEqual(changedHash.ids[0], first.ids[0]);
    assert.notEqual(changedHash.ids[0], other.ids[0]);
    assert.equal(memory.read().notes.length, 3);
    assertPersisted(directory, first.ids[0], fixtureSource(51));
    assertPersisted(directory, other.ids[0], fixtureSource(52));
    assertPersisted(directory, changedHash.ids[0], samePositionNewHash);
  });

  await functional('actual batch keeps host source aligned to input index after a skipped row', async () => {
    const directory = join(scratch, 'batch'), memory = makeMemory('batch');
    const inputs = [
      { text: '\ud800', from: 'fixture' },
      { text: 'Synthetic batch second input after an omitted row.', from: 'fixture' },
      { text: 'Synthetic batch third input after an omitted row.', from: 'fixture' },
    ];
    const auraSources = [61, 62, 63].map(position => ({ source: fixtureSource(position) }));
    const batch = await memory.rememberBatch(inputs, { auraSources });
    assert.equal(batch.results.length, 3);
    assert.equal(batch.results[0].reason, 'memory-text-not-well-formed');
    assert.deepEqual(batch.results[0].ids, []);
    assert.equal(batch.results[1].remembered, 1);
    assert.equal(batch.results[2].remembered, 1);
    assertPersisted(directory, batch.results[1].ids[0], fixtureSource(62));
    assertPersisted(directory, batch.results[2].ids[0], fixtureSource(63));
    assert.equal(memory.read().notes.some(note => note.source.aura_source.position === 61), false);
    const beforeRejectedCount = bytesIn(directory);
    await assert.rejects(memory.rememberBatch(inputs, { auraSources: auraSources.slice(1) }), /memory-aura-source-count-invalid/);
    assert.deepEqual(bytesIn(directory), beforeRejectedCount);
  });

  await functional('actual chunked remember binds association to each final chunk ID', async () => {
    const directory = join(scratch, 'chunks'), memory = makeMemory('chunks');
    const text = 'Synthetic long note chunk content. '.repeat(Math.ceil((MAX_NOTE_CHARS * 2 + 53) / 35));
    assert(text.length > MAX_NOTE_CHARS * 2);
    const coordinates = fixtureSource(71);
    const result = await memory.remember({ text, from: 'fixture' }, hostProjection(coordinates));
    assert.equal(result.remembered, 3);
    assert.equal(new Set(result.ids).size, 3);
    const parts = result.ids.map(id => assertPersisted(directory, id, coordinates));
    assert.equal(parts.map(part => part.statement).join(''), text);
    let offset = 0;
    for (const part of parts) {
      assert.equal(part.source.span.start, offset);
      assert.equal(part.source.span.end - part.source.span.start, part.statement.length);
      assert(part.statement.length <= MAX_NOTE_CHARS);
      assert.deepEqual(await memory.referenceForRecord(part.id), { source: coordinates });
      offset = part.source.span.end;
    }
    assert.equal(offset, text.length);
  });

  await functional('actual migration-key input refuses retroactive association without changing saved bytes', async () => {
    const directory = join(scratch, 'legacy'), memory = makeMemory('legacy');
    const input = { text: 'Synthetic historical migration note with no gate association.', from: 'fixture',
      migrationKey: 'toy' };
    const historical = await memory.remember(input);
    assert.equal(historical.remembered, 1);
    const before = bytesIn(directory);
    await assert.rejects(memory.remember(input, hostProjection(fixtureSource(81))), /memory-aura-historical-association-refused/);
    assert.deepEqual(bytesIn(directory), before);
    assert.equal(await memory.referenceForRecord(historical.ids[0]), null);
  });

  await functional('actual caller association fields are refused and invalid host projection creates no note', async () => {
    const directory = join(scratch, 'caller'), memory = makeMemory('caller');
    const input = { text: 'Synthetic caller input cannot name a gate association.', from: 'fixture' };
    const beforeRefusals = bytesIn(directory);
    for (const forged of [
      { ...input, aura_source: fixtureSource(91) },
      { ...input, auraSource: { source: fixtureSource(91) } },
      { ...input, auraSources: [{ source: fixtureSource(91) }] },
      { ...input, auraAssociation: createAuraAssociation(noteId, fixtureSource(91)) },
      { ...input, source: { aura_source: fixtureSource(91) } },
      { ...input, source: { auraAssociation: createAuraAssociation(noteId, fixtureSource(91)) } },
    ]) {
      await assert.rejects(memory.remember(forged), /memory-aura-source-host-only/);
      assert.deepEqual(bytesIn(directory), beforeRefusals);
    }
    await assert.rejects(memory.remember(input, { auraSource: { source: fixtureSource(91), extra: true } }),
      /memory-aura-source-invalid/);
    assert.deepEqual(bytesIn(directory), beforeRefusals);
    assert.equal(memory.read().notes.length, 0);
    assert.equal(existsSync(join(directory, 'remembered', 'aura.jsonl')), false);
  });

  await functional('actual read-only references respect historical, hidden, forgotten and current policy', async () => {
    const directory = join(scratch, 'readonly');
    let currentPolicy = {};
    const memory = makeMemory('readonly', { policyOf: () => currentPolicy });
    const historical = await memory.remember({ text: 'Synthetic historical reference remains undetermined.', from: 'fixture' });
    const hidden = await memory.remember({ text: 'Synthetic note selected for local hide control.', from: 'fixture' },
      hostProjection(fixtureSource(101)));
    const forgotten = await memory.remember({ text: 'Synthetic note selected for local forget control.', from: 'fixture' },
      hostProjection(fixtureSource(102)));
    const id = hidden.ids[0];
    const before = bytesIn(directory);
    assert.deepEqual(await memory.referenceForRecord(id), { source: fixtureSource(101) });
    assert.equal(await memory.referenceForRecord(historical.ids[0]), null);
    for (const policy of [
      { privacy: 'remote' }, { subject: 'aukora:1:' + '2'.repeat(64) }, { offTheRecord: true },
      { controls: { pause: true } }, { controls: { 'someone-is-here': true } },
    ]) {
      currentPolicy = policy;
      assert.equal(await memory.referenceForRecord(id), null);
    }
    currentPolicy = {};
    assert.deepEqual(await memory.referenceForRecord(id), { source: fixtureSource(101) });
    assert.deepEqual(bytesIn(directory), before, 'reference lookup must not write the memory store');
    const journalFile = join(directory, 'remembered', 'journal.jsonl');
    for (const [op, target] of [['hide', id], ['forget', forgotten.ids[0]]]) {
      const prior = JSON.parse(readFileSync(journalFile, 'utf8').trim().split('\n').at(-1));
      const note = JSON.parse(objectBytes(directory, target));
      const entry = nextEntry({ previous: prior, op, id: target, objectDigest: note.contentHash,
        actor: 'fixture', at: instant, reason: 'disposable ordinary memory control' });
      appendFileSync(journalFile, JSON.stringify(entry) + '\n');
      const controlledBytes = bytesIn(directory);
      assert.equal(await memory.referenceForRecord(target), null);
      assert.deepEqual(bytesIn(directory), controlledBytes);
    }
    assert.equal(networkCalls, 0);
  });

  await functional('unmounted ingestion reports only current eligible associations after dedup', async () => {
    const { createGateCaptureIngestion } = await import('../plugins/aukora-kira/lib/index.js');
    const directory = join(scratch, 'ingestion'), memory = makeMemory('ingestion');
    let coordinates = fixtureSource(111);
    const completedResult = Object.freeze({ fixture: 'ordinary-invented-result' });
    const fixturePins = Object.freeze({ fixture: 'toy' });
    // These injected projection callbacks exercise only adapter composition.
    // They are not H verifiers, D readers, grants or production host mounts.
    const verifyProjection = (result, pins) => {
      assert.equal(result, completedResult);
      assert.equal(pins, fixturePins);
      return { source: { ...coordinates } };
    };
    const resolveProjection = result => {
      assert.equal(result, completedResult);
      return { source: { ...coordinates } };
    };
    const adapter = createGateCaptureIngestion({ memoryFor: () => memory,
      verifyCompletedGateCapture: verifyProjection, capturePins: fixturePins,
      referenceForAppliedAction: resolveProjection });
    const hiddenInput = { text: 'Synthetic ingestion duplicate selected for hide.', from: 'fixture' };
    const fresh = await adapter.remember(hiddenInput, completedResult);
    assert.equal(fresh.remembered, 1);
    assert.deepEqual(fresh.auraCapture, { status: 'associated', reason: null, grantsAuthority: false });
    assertPersisted(directory, fresh.ids[0], coordinates);
    const duplicate = await adapter.remember(hiddenInput, completedResult);
    assert.equal(duplicate.remembered, 0);
    assert.deepEqual(duplicate.ids, fresh.ids);
    assert.equal(duplicate.auraCapture.status, 'associated');
    const control = (op, id) => {
      const journal = join(directory, 'remembered', 'journal.jsonl');
      const previous = JSON.parse(readFileSync(journal, 'utf8').trim().split('\n').at(-1));
      const note = JSON.parse(objectBytes(directory, id));
      appendFileSync(journal, JSON.stringify(nextEntry({ previous, op, id,
        objectDigest: note.contentHash, actor: 'fixture', at: instant, reason: 'disposable local control' })) + '\n');
    };
    control('hide', fresh.ids[0]);
    const hidden = await adapter.remember(hiddenInput, completedResult);
    assert.equal(hidden.remembered, 0);
    assert.deepEqual(hidden.ids, fresh.ids);
    assert.deepEqual(hidden.auraCapture, { status: 'undetermined',
      reason: 'kira-aura-capture:association-unavailable', grantsAuthority: false });
    assert.equal(await memory.referenceForRecord(hidden.ids[0]), null);

    coordinates = fixtureSource(112);
    const forgottenInput = { text: 'Synthetic ingestion duplicate selected for forget.', from: 'fixture' };
    const toForget = await adapter.remember(forgottenInput, completedResult);
    assert.equal(toForget.auraCapture.status, 'associated');
    control('forget', toForget.ids[0]);
    const forgotten = await adapter.remember(forgottenInput, completedResult);
    assert.equal(forgotten.remembered, 0);
    assert.deepEqual(forgotten.ids, toForget.ids);
    assert.equal(forgotten.auraCapture.status, 'undetermined');
    assert.equal(forgotten.auraCapture.reason, 'kira-aura-capture:association-unavailable');
    assert.equal(await memory.referenceForRecord(forgotten.ids[0]), null);

    const mismatchedMemory = { ...memory, referenceForRecord: () => ({ source: fixtureSource(999) }) };
    const mismatched = createGateCaptureIngestion({
      memoryFor: () => mismatchedMemory,
      verifyCompletedGateCapture: verifyProjection, capturePins: fixturePins,
      referenceForAppliedAction: resolveProjection,
    });
    const wrongCurrent = await mismatched.remember({ text: 'Synthetic mismatched current selector.', from: 'fixture' },
      completedResult);
    assert.equal(wrongCurrent.auraCapture.status, 'undetermined');
    assert.equal(wrongCurrent.auraCapture.reason, 'kira-aura-capture:association-unavailable');
    const unavailable = createGateCaptureIngestion({ memoryFor: () => undefined,
      verifyCompletedGateCapture: verifyProjection, capturePins: fixturePins,
      referenceForAppliedAction: resolveProjection });
    const missing = await unavailable.remember({ text: 'Synthetic absent memory host.', from: 'fixture' }, completedResult);
    assert.equal(missing.remembered, 0);
    assert.deepEqual(missing.auraCapture, { status: 'undetermined',
      reason: 'kira-aura-capture:host-unavailable', grantsAuthority: false });

    for (const [label, verify, resolve, expectedReason] of [
      ['null-projection', () => null, resolveProjection, 'kira-aura-capture:source-mismatch'],
      ['thrown-projection', () => { throw Error('invented callback unavailable'); }, resolveProjection,
        'kira-aura-capture:unavailable'],
      ['source-disagreement', verifyProjection, () => ({ source: fixtureSource(113) }),
        'kira-aura-capture:source-mismatch'],
    ]) {
      const existingObjects = new Map(memory.read().notes.map(note => [note.id, objectBytes(directory, note.id)]));
      const rejectedAssociation = createGateCaptureIngestion({ memoryFor: () => memory,
        verifyCompletedGateCapture: verify, capturePins: fixturePins, referenceForAppliedAction: resolve });
      const retained = await rejectedAssociation.remember({ text: `Synthetic ${label} preserves body without an association.`,
        from: 'fixture' }, completedResult);
      assert.equal(retained.remembered, 1, 'ordinary remembered content remains available');
      assert.deepEqual(retained.auraCapture, { status: 'undetermined', reason: expectedReason, grantsAuthority: false });
      const persisted = JSON.parse(objectBytes(directory, retained.ids[0]));
      assert.equal(Object.hasOwn(persisted, 'auraAssociation'), false);
      assert.equal(Object.hasOwn(persisted.source, 'aura_source'), false);
      assert.equal(await memory.referenceForRecord(persisted.id), null);
      for (const [id, bytes] of existingObjects) assert.equal(objectBytes(directory, id), bytes);
    }
    assert.equal(networkCalls, 0);
  });

  await functional('native canonical tool string polls exact pending proposal and persists final source', async () => {
    const directory = join(scratch, 'observer-canonical'), memory = makeMemory('observer-canonical');
    const observer = observerFixture(), id = fixtureUuid(1), coordinates = fixtureSource(121);
    const stateIds = [], states = ['pending', 'applying', 'applied'];
    let snapshot;
    for (const missing of ['stateForProposal', 'inputForCompletion', 'isLive']) {
      assert.throws(() => registerGateCaptureIngestion(observer.ctx,
        { ...mockHostOptions(memory, coordinates), [missing]: undefined }), /host-unconfigured/);
    }
    assert.equal(observer.count('tools/result'), 0);
    const handle = registerGateCaptureIngestion(observer.ctx, mockHostOptions(memory, coordinates, {
      // H's actual current producer adds proposal_id; the short proposal remains
      // display data. Exercise E's default decoder against that exact DTO shape.
      proposalFromToolResult: undefined,
      stateForProposal: async selectedId => {
        stateIds.push(selectedId);
        const state = states.shift();
        return state === 'applied' ? completedFixture(selectedId) : { state };
      },
      inputForCompletion: (execution, selected, completed) => {
        snapshot = execution;
        assert.equal(selected.id, id);
        assert.equal(completed.receipt.proposal, id);
        return { text: 'Synthetic exact proposal observer note.', from: 'gate-observer-fixture',
          scope: execution.scope, at: instant };
      },
    }));
    try {
      assert.equal(observer.count('tools/result'), 1);
      const execution = nativeExecution(), result = {
        ...nativeToolResult(id),
        value: JSON.stringify({ ok: true, state: 'PENDING_OWNER',
          proposal: id.slice(0, 8), proposal_id: id,
          expires: new Date(Date.now() + 10_000).toISOString() }),
      };
      assert.equal(typeof result.value, 'string', 'actual native result.value is the canonical JSON string');
      observer.emit('tools/result', execution, result);
      execution.callId = 'changed-after-native-event';
      execution.rootCallId = 'changed-after-native-event';
      assert.equal(handle.pending(), 1);
      assert.deepEqual(bytesIn(directory), []);
      await bounded(handle.whenIdle());
      assert.deepEqual(stateIds, [id, id, id]);
      assert.deepEqual(snapshot, { callId: 'fixture-call', rootCallId: 'fixture-root-call', scope: 'owner' });
      assert(Object.isFrozen(snapshot));
      const notes = memory.read().notes;
      assert.equal(notes.length, 1);
      assertPersisted(directory, notes[0].id, coordinates);
      assert.equal(notes[0].scope, 'owner');
      assert.equal(handle.pending(), 0);
    } finally { handle.dispose(); observer.dispose(); }
  });

  await functional('native refused, terminal and legacy display-only results write no note', async () => {
    const directory = join(scratch, 'observer-terminal'), memory = makeMemory('observer-terminal');
    const observer = observerFixture(), stateIds = [];
    const handle = registerGateCaptureIngestion(observer.ctx, mockHostOptions(memory, fixtureSource(122), {
      stateForProposal: async id => { stateIds.push(id); return { state: 'refused' }; },
    }));
    try {
      const execution = nativeExecution(), before = bytesIn(directory), id = fixtureUuid(2);
      observer.emit('tools/result', execution, { isError: false,
        value: JSON.stringify({ ok: false, state: 'REFUSED' }) });
      observer.emit('tools/result', execution, { ...nativeToolResult(id), isError: true });
      observer.emit('tools/result', execution, { isError: false,
        value: { ok: true, state: 'PENDING_OWNER', id, expires: Date.now() + 10_000 } });
      observer.emit('tools/result', execution, nativeToolResult('legacy-short-display-id'));
      assert.equal(handle.pending(), 0);
      assert.deepEqual(stateIds, []);
      observer.emit('tools/result', execution, nativeToolResult(id));
      await bounded(handle.whenIdle());
      assert.deepEqual(stateIds, [id]);
      assert.deepEqual(bytesIn(directory), before);
      assert.equal(memory.read().notes.length, 0);
    } finally { handle.dispose(); observer.dispose(); }
  });

  await functional('native state outage retains pending flight and recovers the same proposal', async () => {
    const directory = join(scratch, 'observer-outage'), memory = makeMemory('observer-outage');
    const observer = observerFixture(), recovered = deferred(), secondRead = deferred();
    const id = fixtureUuid(3), coordinates = fixtureSource(123), stateIds = [];
    const handle = registerGateCaptureIngestion(observer.ctx, mockHostOptions(memory, coordinates, {
      stateForProposal: async selected => {
        stateIds.push(selected);
        if (stateIds.length === 1) throw Error('invented temporary state outage');
        secondRead.resolve();
        await recovered.promise;
        return completedFixture(selected);
      },
    }));
    try {
      observer.emit('tools/result', nativeExecution(), nativeToolResult(id));
      await bounded(secondRead.promise);
      assert.equal(handle.pending(), 1);
      assert.deepEqual(bytesIn(directory), []);
      recovered.resolve();
      await bounded(handle.whenIdle());
      assert.deepEqual(stateIds, [id, id]);
      assert.equal(handle.pending(), 0);
      const notes = memory.read().notes;
      assert.equal(notes.length, 1);
      assertPersisted(directory, notes[0].id, coordinates);
    } finally { recovered.resolve(); handle.dispose(); observer.dispose(); }
  });

  await functional('native completion for a different receipt proposal writes no note', async () => {
    const directory = join(scratch, 'observer-receipt'), memory = makeMemory('observer-receipt');
    const observer = observerFixture(), id = fixtureUuid(4);
    let projections = 0;
    const handle = registerGateCaptureIngestion(observer.ctx, mockHostOptions(memory, fixtureSource(124), {
      stateForProposal: async () => completedFixture(fixtureUuid(5)),
      verifyCompletedGateCapture: () => { projections++; return { source: fixtureSource(124) }; },
    }));
    try {
      const before = bytesIn(directory);
      observer.emit('tools/result', nativeExecution(), nativeToolResult(id));
      await bounded(handle.whenIdle());
      assert.equal(projections, 0);
      assert.deepEqual(bytesIn(directory), before);
      assert.equal(memory.read().notes.length, 0);
    } finally { handle.dispose(); observer.dispose(); }
  });

  await functional('native observer disposal during outstanding state prevents later memory writes', async () => {
    const directory = join(scratch, 'observer-disposal'), memory = makeMemory('observer-disposal');
    const observer = observerFixture(), started = deferred(), outstanding = deferred(), stateFinished = deferred();
    const id = fixtureUuid(6);
    let stateCalls = 0;
    const handle = registerGateCaptureIngestion(observer.ctx, mockHostOptions(memory, fixtureSource(125), {
      stateForProposal: async selected => {
        stateCalls++; started.resolve(); await outstanding.promise;
        stateFinished.resolve(); return completedFixture(selected);
      },
    }));
    try {
      const before = bytesIn(directory);
      observer.emit('tools/result', nativeExecution(), nativeToolResult(id));
      await bounded(started.promise);
      assert.equal(handle.pending(), 1);
      handle.dispose();
      assert.equal(observer.count('tools/result'), 0);
      outstanding.resolve();
      await bounded(stateFinished.promise);
      await new Promise(resolve => setImmediate(resolve));
      await bounded(handle.whenIdle());
      observer.emit('tools/result', nativeExecution(), nativeToolResult(fixtureUuid(7)));
      assert.equal(stateCalls, 1);
      assert.equal(handle.pending(), 0);
      assert.deepEqual(bytesIn(directory), before);
    } finally { outstanding.resolve(); handle.dispose(); observer.dispose(); }
  });

  await functional('native observer disposal during actual policy await prevents durable append', async () => {
    const directory = join(scratch, 'observer-policy'), policyEntered = deferred(), policyRelease = deferred();
    const producerDone = deferred(), observer = observerFixture();
    const memory = makeMemory('observer-policy', { policyOf: async () => {
      policyEntered.resolve(); await policyRelease.promise; return {};
    } });
    let produced;
    const observedMemory = { ...memory, remember: async (...args) => {
      try { produced = await memory.remember(...args); return produced; }
      finally { producerDone.resolve(); }
    } };
    const handle = registerGateCaptureIngestion(observer.ctx, mockHostOptions(observedMemory, fixtureSource(127)));
    try {
      const before = bytesIn(directory);
      observer.emit('tools/result', nativeExecution(), nativeToolResult(fixtureUuid(9)));
      await bounded(policyEntered.promise);
      assert.equal(handle.pending(), 1);
      handle.dispose();
      await bounded(handle.whenIdle());
      assert.equal(handle.pending(), 0, 'disposal releases the observer without waiting for the host policy');
      policyRelease.resolve();
      await bounded(producerDone.promise);
      assert.equal(produced.remembered, 0);
      assert.deepEqual(produced.ids, []);
      assert.equal(produced.reason, 'capture-paused');
      assert.deepEqual(bytesIn(directory), before);
      assert.equal(existsSync(directory), false, 'disposed producer must stop before store preparation');
    } finally { policyRelease.resolve(); handle.dispose(); observer.dispose(); }
  });

  await functional('native hung state callback expires and releases bounded pending capacity', async () => {
    const directory = join(scratch, 'observer-hung'), memory = makeMemory('observer-hung');
    const observer = observerFixture(), entered = deferred();
    let stateCalls = 0;
    const handle = registerGateCaptureIngestion(observer.ctx, mockHostOptions(memory, fixtureSource(128), {
      maxWaitMs: 30, maxPending: 1,
      stateForProposal: () => { stateCalls++; entered.resolve(); return new Promise(() => {}); },
    }));
    try {
      const before = bytesIn(directory);
      observer.emit('tools/result', nativeExecution(), nativeToolResult(fixtureUuid(10)));
      await bounded(entered.promise);
      assert.equal(handle.pending(), 1);
      await bounded(handle.whenIdle());
      assert.equal(handle.pending(), 0);
      assert.equal(stateCalls, 1);
      assert.deepEqual(bytesIn(directory), before);
      observer.emit('tools/result', nativeExecution(), nativeToolResult(fixtureUuid(11)));
      assert.equal(handle.pending(), 1, 'a later proposal can use the released capacity');
      handle.dispose();
      await bounded(handle.whenIdle());
      assert.equal(handle.pending(), 0);
    } finally { handle.dispose(); observer.dispose(); }
  });

  await functional('native callbacks retain frozen completion bytes while original result changes', async () => {
    const directory = join(scratch, 'observer-snapshot'), memory = makeMemory('observer-snapshot');
    const observer = observerFixture(), id = fixtureUuid(12), coordinates = fixtureSource(129);
    const original = { ...completedFixture(id), fixture_source: { ...coordinates } };
    const originalBytes = JSON.stringify(original), verifying = deferred(), release = deferred();
    const seenSnapshots = [];
    const handle = registerGateCaptureIngestion(observer.ctx, mockHostOptions(memory, coordinates, {
      stateForProposal: async () => original,
      verifyCompletedGateCapture: async completed => {
        seenSnapshots.push(completed);
        if (seenSnapshots.length === 1) { verifying.resolve(completed); await release.promise; }
        assert.equal(JSON.stringify(completed), originalBytes);
        return { source: completed.fixture_source };
      },
      referenceForAppliedAction: completed => {
        assert.equal(completed, seenSnapshots[0]);
        return { source: completed.fixture_source };
      },
      inputForCompletion: (execution, selected, completed) => {
        assert.equal(completed, seenSnapshots[0]);
        assert.equal(selected.id, id);
        return { text: `Synthetic snapshot completion for ${completed.receipt.target}.`,
          from: 'gate-observer-fixture', scope: execution.scope, at: instant };
      },
    }));
    try {
      observer.emit('tools/result', nativeExecution(), nativeToolResult(id));
      const snapshot = await bounded(verifying.promise);
      assert.notEqual(snapshot, original);
      assert(Object.isFrozen(snapshot));
      assert(Object.isFrozen(snapshot.receipt));
      assert(Object.isFrozen(snapshot.fixture_source));
      original.receipt.proposal = fixtureUuid(13);
      original.receipt.target = 'changed-original-target.txt';
      original.fixture_source.position = 999;
      original.fixture_source.hash = 'f'.repeat(64);
      assert.notEqual(JSON.stringify(original), originalBytes);
      assert.deepEqual(bytesIn(directory), []);
      release.resolve();
      await bounded(handle.whenIdle());
      assert.equal(seenSnapshots.length, 3);
      assert(seenSnapshots.every(value => value === snapshot));
      const note = memory.read().notes[0];
      assertPersisted(directory, note.id, coordinates);
      assert.equal(note.statement, 'Synthetic snapshot completion for synthetic-target.txt.');
      assert.equal(snapshot.receipt.proposal, id);
      assert.equal(JSON.stringify(snapshot), originalBytes);
    } finally { release.resolve(); handle.dispose(); observer.dispose(); }
  });

  await functional('actual apply third argument registers mock host observer and persists factual note', async () => {
    const directory = join(scratch, 'native-apply'), reader = makeMemory('native-apply');
    const observer = observerFixture(), id = fixtureUuid(8), coordinates = fixtureSource(126);
    const completed = completedFixture(id);
    const host = mockHostOptions(reader, coordinates, { stateForProposal: async selected => {
      assert.equal(selected, id); return completed;
    } });
    try {
      await apply(observer.ctx, { memoryOwner: { stateDir: directory, subject, permittedPrivacy: ['local'] } }, host);
      await Promise.resolve();
      assert.equal(observer.count('tools/result'), 1);
      assert(observer.provided.has('kira.recall'));
      observer.emit('tools/result', nativeExecution(), nativeToolResult(id));
      await until(() => reader.read().notes.length === 1);
      const note = reader.read().notes[0];
      assertPersisted(directory, note.id, coordinates);
      assert.equal(note.statement, `Boundary gate applied proposal ${id} for synthetic-target.txt.`);
      assert.equal(note.origin.by, 'gate-apply');
      assert.equal(note.observedAt, instant);
      assert.equal(note.scope, 'owner');
      assert.equal(networkCalls, 0);
    } finally { observer.dispose(); }
    assert.equal(observer.count('tools/result'), 0);
  });

  await functional('actual source-aware single orphan recovers original ID and clock without conflating another source', async () => {
    const directory = join(scratch, 'recovery-orphan'), memory = makeMemory('recovery-orphan');
    const coordinates = fixtureSource(141), otherSource = fixtureSource(142);
    const input = { text: 'Synthetic interrupted single note with a source-bound identity.',
      from: 'recovery-fixture', scope: 'owner', at: instant };
    const original = await memory.remember(input, hostProjection(coordinates));
    assert.equal(original.remembered, 1);
    const originalId = original.ids[0], retainedBytes = objectBytes(directory, originalId);
    // Only this disposable store is interrupted: leave its object intact while
    // removing its own commit records, as an interrupted append would do.
    writeFileSync(join(directory, 'remembered', 'aura.jsonl'), '');
    writeFileSync(join(directory, 'remembered', 'journal.jsonl'), '');
    const interrupted = memory.read();
    assert.equal(interrupted.notes.length, 0);
    assert.equal(interrupted.orphans.length, 1);
    assert.equal(interrupted.complete, false);
    assert.equal(objectBytes(directory, originalId), retainedBytes);
    assert.equal(await memory.referenceForRecord(originalId), null);

    const otherAt = '2026-01-02T00:00:00Z';
    const other = await memory.remember({ ...input, at: otherAt }, hostProjection(otherSource));
    assert.equal(other.remembered, 1);
    assert.notEqual(other.ids[0], originalId, 'a different source must not reuse the old orphan');
    assert.equal(assertPersisted(directory, other.ids[0], otherSource).observedAt, otherAt);
    assert.equal(objectBytes(directory, originalId), retainedBytes);
    assert.equal(memory.read().complete, false, 'the original orphan is still uncommitted');

    const recovered = await memory.remember({ ...input, at: '2026-01-03T00:00:00Z' }, hostProjection(coordinates));
    assert.equal(recovered.remembered, 1);
    assert.deepEqual(recovered.ids, [originalId]);
    assert.equal(assertPersisted(directory, originalId, coordinates).observedAt, instant);
    assertRecoveredEnvelope(retainedBytes, objectBytes(directory, originalId));
    const complete = memory.read();
    assert.equal(complete.complete, true);
    assert.deepEqual(complete.withheld, []);
    assert.deepEqual(complete.orphans, []);
    assert.equal(complete.notes.length, 2);
    assert.equal(new Set(complete.notes.map(note => note.id)).size, 2);
    assert.equal(complete.chain.filter(entry => entry.op === 'remember').length, 2);
    assert.deepEqual(await memory.referenceForRecord(originalId), { source: coordinates });
    const beforeRepeat = bytesIn(directory);
    const again = await memory.remember({ ...input, at: '2026-01-04T00:00:00Z' }, hostProjection(coordinates));
    assert.equal(again.remembered, 0);
    assert.deepEqual(again.ids, [originalId]);
    assert.equal(memory.read().notes.length, 2);
    assert.deepEqual(bytesIn(directory), beforeRepeat);
  });

  await functional('actual partial chunk recovery restores all final IDs and source clocks without duplicate chunks', async () => {
    const directory = join(scratch, 'recovery-chunks'), memory = makeMemory('recovery-chunks');
    const unit = 'Synthetic interrupted chunk content. ';
    const text = unit.repeat(Math.ceil((MAX_NOTE_CHARS * 2 + 100) / unit.length));
    const coordinates = fixtureSource(151), otherSource = fixtureSource(152);
    const input = { text, from: 'recovery-fixture', scope: 'owner', at: instant };
    const original = await memory.remember(input, hostProjection(coordinates));
    assert.equal(original.remembered, 3);
    const originalIds = [...original.ids];
    const retainedObjects = new Map(originalIds.map(id => [id, objectBytes(directory, id)]));
    for (const name of ['aura.jsonl', 'journal.jsonl']) {
      const file = join(directory, 'remembered', name);
      const firstCommittedLine = readFileSync(file, 'utf8').trim().split('\n')[0];
      writeFileSync(file, firstCommittedLine + '\n');
    }
    const interrupted = memory.read();
    assert.deepEqual(interrupted.notes.map(note => note.id), [originalIds[0]]);
    assert.equal(interrupted.orphans.length, 2);
    assert.equal(interrupted.complete, false);
    for (const [id, bytes] of retainedObjects) assert.equal(objectBytes(directory, id), bytes);
    for (const id of originalIds.slice(1)) assert.equal(await memory.referenceForRecord(id), null);

    const otherAt = '2026-01-02T00:00:00Z';
    const other = await memory.remember({ ...input, at: otherAt }, hostProjection(otherSource));
    assert.equal(other.remembered, 3);
    assert.equal(other.ids.some(id => originalIds.includes(id)), false);
    for (const id of other.ids) assert.equal(assertPersisted(directory, id, otherSource).observedAt, otherAt);
    for (const [id, bytes] of retainedObjects) assert.equal(objectBytes(directory, id), bytes);

    const recovered = await memory.remember({ ...input, at: '2026-01-03T00:00:00Z' }, hostProjection(coordinates));
    assert.equal(recovered.remembered, 2, 'only the uncommitted tail is appended');
    assert.deepEqual(recovered.ids, originalIds);
    const recoveredParts = originalIds.map(id => assertPersisted(directory, id, coordinates));
    assert(recoveredParts.every(note => note.observedAt === instant));
    assert.equal(recoveredParts.map(note => note.statement).join(''), text);
    for (const [id, bytes] of retainedObjects) assertRecoveredEnvelope(bytes, objectBytes(directory, id));
    assert.equal(objectBytes(directory, originalIds[0]), retainedObjects.get(originalIds[0]));
    const complete = memory.read();
    assert.equal(complete.complete, true);
    assert.deepEqual(complete.withheld, []);
    assert.deepEqual(complete.orphans, []);
    assert.equal(complete.notes.length, 6);
    assert.equal(new Set(complete.notes.map(note => note.id)).size, 6);
    const committedIds = complete.chain.filter(entry => entry.op === 'remember').map(entry => entry.id);
    assert.equal(committedIds.length, 6);
    assert.equal(new Set(committedIds).size, 6);
    for (const id of originalIds) assert.deepEqual(await memory.referenceForRecord(id), { source: coordinates });
    const beforeRepeat = bytesIn(directory);
    const again = await memory.remember({ ...input, at: '2026-01-04T00:00:00Z' }, hostProjection(coordinates));
    assert.equal(again.remembered, 0);
    assert.deepEqual(again.ids, originalIds);
    assert.equal(memory.read().notes.length, 6);
    assert.deepEqual(bytesIn(directory), beforeRepeat);
    assert.equal(networkCalls, 0);
  });
  console.log(`PASS ${groups} helper + ${functionalGroups} actual tracked-memory groups; invented disposable data, no network or citation qualification`);
} finally {
  for (const [name, value] of savedEnv) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
  rmSync(scratch, { recursive: true, force: true });
}
