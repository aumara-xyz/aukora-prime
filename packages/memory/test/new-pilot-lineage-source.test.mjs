// SPDX-License-Identifier: AGPL-3.0-or-later
// PURE constructor/source checks only. No setup.bootstrap, reader method, pool
// connection, query, filesystem fixture, keys, PG or runtime setup is invoked.
import test from 'node:test'
import assert from 'node:assert/strict'
import { MemoryRefusal } from '../src/codecs.mjs'
import { createNewPilotLineageSetup } from '../src/new-pilot-lineage.mjs'
import { createPrivateV2FileRetentionReader, isPrivateV2FileRetentionReader }
  from '../src/private-v2-retention.mjs'

const calls = {connect: 0, query: 0, bootstrap: 0, contract: 0}
const forbidden = name => () => { calls[name]++; throw new Error(`${name} forbidden by PURE constructor check`) }
const pool = Object.freeze({connect: forbidden('connect'), query: forbidden('query')})
const contracts = Object.freeze({validateContract: forbidden('contract'), operationDigest: forbidden('contract'),
  canonicalJson: forbidden('contract')})
const profile = Object.freeze({version: 2, kind: 'prime-private-unsent-closure/v2',
  expected_authority_store_id: 'a'.repeat(64), expected_memory_store_id: 'b'.repeat(64),
  retention_profile: 'required-retained/v2'})
const expected_schema = 'prime_pilot_123456781234423489ab123456789abc'

// The genuine factory performs native identity validation only at construction.
// This unused path is never opened; no filesystem fixture or identity mock exists.
const nativeUid = process.getuid(), nativeGid = process.getgid()
const readerFor = pair => createPrivateV2FileRetentionReader({
  directory: '/source-only-new-pilot-lineage-no-storage', publisher_uid: nativeUid + 1,
  reader_uid: nativeUid, retention_gid: nativeGid, contracts, profile: pair,
})
const reader = readerFor(profile)
const publisher = Object.freeze({bootstrap: forbidden('bootstrap'), status: Object.freeze({
  kind: 'private-v2-new-lineage-bootstrap-publisher',
  expected_authority_store_id: profile.expected_authority_store_id,
  expected_memory_store_id: profile.expected_memory_store_id,
})})
const configuration = () => ({pool, reader, publisher, profile, contracts, expected_schema})
const assertIdle = () => assert.deepEqual(calls, {connect: 0, query: 0, bootstrap: 0, contract: 0})
const refuses = (input, code) => {
  assert.throws(() => createNewPilotLineageSetup(input), error => error instanceof MemoryRefusal
    && (code === undefined || error.code === code))
  assertIdle()
}

test('new-pilot lineage source: construction configures a genuine reader and transport without initialization', () => {
  assert.equal(isPrivateV2FileRetentionReader(reader), true)
  const setup = createNewPilotLineageSetup(configuration())
  assert.deepEqual(Object.keys(setup).sort(), ['bootstrap', 'status'])
  assert.equal(typeof setup.bootstrap, 'function')
  assert.deepEqual(setup.status, {configured: true, kind: 'new-pilot-lineage-setup-source',
    guarantee: 'REDUCED-GUARANTEE', qualified_runtime: false, grants_authority: false})
  assert.equal(Object.isFrozen(setup), true)
  assert.equal(Object.isFrozen(setup.status), true)
  // A trusted private transport may omit optional descriptive status. Neither
  // transport form is called or treated as runtime/custody qualification here.
  const withoutStatus = createNewPilotLineageSetup({...configuration(), publisher: {bootstrap: forbidden('bootstrap')}})
  assert.equal(typeof withoutStatus.bootstrap, 'function')
  assertIdle()
})

test('new-pilot lineage source: configuration has exactly six own enumerable inert fields', () => {
  const missing = configuration(); delete missing.profile
  const hidden = configuration(); Object.defineProperty(hidden, 'unexpected', {value: true})
  const symbolic = configuration(); symbolic[Symbol('unexpected')] = true
  for (const input of [undefined, null, [], missing, {...configuration(), allow_existing: true}, hidden, symbolic])
    refuses(input, 'memory:private-v2-coordinator-new-pilot-configuration-required')
  let getters = 0
  const accessor = configuration()
  Object.defineProperty(accessor, 'pool', {enumerable: true, get() {getters++; throw Error('config getter forbidden')}})
  refuses(accessor, 'memory:private-v2-coordinator-new-pilot-configuration-required')
  assert.equal(getters, 0)
})

test('new-pilot lineage source: old and malformed schemas refuse before any initialization', () => {
  for (const schema of ['prime_memory', 'public', 'prime_pilot_' + 'a'.repeat(32),
    'prime_pilot_123456781234123489ab123456789abc', 'prime_pilot_123456781234423479ab123456789abc',
    expected_schema.toUpperCase(), expected_schema + ';DROP TABLE x', [expected_schema], null])
    refuses({...configuration(), expected_schema: schema}, 'memory:new-pilot-lineage-fresh-schema-required')
})

test('new-pilot lineage source: fabricated readers and mismatched genuine reader profiles refuse', () => {
  for (const fake of [undefined, null, {}, {status: reader.status},
    {status: reader.status, readCurrent: forbidden('bootstrap'), readPublishedLineage: forbidden('bootstrap')},
    {...reader}])
    refuses({...configuration(), reader: fake}, 'memory:new-pilot-lineage-owned-reader-required')
  for (const name of ['expected_authority_store_id', 'expected_memory_store_id']) {
    const other = readerFor({...profile, [name]: 'c'.repeat(64)})
    refuses({...configuration(), reader: other}, 'memory:new-pilot-lineage-reader-profile-mismatch')
  }
})

test('new-pilot lineage source: malformed profile and contracts remain inadmissible inert data', () => {
  for (const pair of [null, {...profile, version: 1}, {...profile, kind: 'prime-private-unsent-closure/v1'},
    {...profile, retention_profile: 'optional'}, {...profile, extra: true},
    {...profile, expected_authority_store_id: 'sha256:' + 'a'.repeat(64)},
    {...profile, expected_memory_store_id: 'B'.repeat(64)}]) refuses({...configuration(), profile: pair})
  for (const candidate of [null, {}, {...contracts, canonicalJson: null}])
    refuses({...configuration(), contracts: candidate}, 'memory:new-pilot-lineage-contracts-required')
  let getters = 0
  const getterProfile = {...profile}
  Object.defineProperty(getterProfile, 'expected_memory_store_id',
    {enumerable: true, get() {getters++; throw Error('profile getter forbidden')}})
  refuses({...configuration(), profile: getterProfile})
  const getterContracts = {...contracts}
  Object.defineProperty(getterContracts, 'canonicalJson',
    {enumerable: true, get() {getters++; throw Error('contract getter forbidden')}})
  refuses({...configuration(), contracts: getterContracts}, 'memory:new-pilot-lineage-contracts-required')
  assert.equal(getters, 0)
})

test('new-pilot lineage source: bootstrap transport is closed, captured and profile bound', () => {
  for (const transport of [null, {}, {bootstrap: null}, {...publisher, retry: true},
    {bootstrap: publisher.bootstrap, status: {kind: 'legacy-publisher'}},
    {bootstrap: publisher.bootstrap, status: {...publisher.status, expected_memory_store_id: 'c'.repeat(64)}}])
    refuses({...configuration(), publisher: transport})
  let getters = 0
  const methodGetter = Object.defineProperty({}, 'bootstrap',
    {enumerable: true, get() {getters++; throw Error('bootstrap getter forbidden')}})
  refuses({...configuration(), publisher: methodGetter}, 'memory:new-pilot-lineage-bootstrap-publisher-required')
  const statusGetter = {bootstrap: publisher.bootstrap}
  Object.defineProperty(statusGetter, 'status',
    {enumerable: true, get() {getters++; throw Error('status getter forbidden')}})
  refuses({...configuration(), publisher: statusGetter}, 'memory:new-pilot-lineage-bootstrap-publisher-required')
  assert.equal(getters, 0)
})

test('new-pilot lineage source: invalid pool shape refuses without calling connect or query', () => {
  for (const candidate of [null, {}, {connect: null}])
    refuses({...configuration(), pool: candidate}, 'memory:owner-session-pool-required')
  let getters = 0
  const getterPool = Object.defineProperty({}, 'connect',
    {enumerable: true, get() {getters++; throw Error('connect getter forbidden')}})
  refuses({...configuration(), pool: getterPool}, 'memory:owner-session-pool-required')
  assert.equal(getters, 0)
})

test('new-pilot lineage source: proxies and function proxies refuse without executing traps', () => {
  let traps = 0
  const proxy = value => new Proxy(value, {get() {traps++; throw Error('proxy get forbidden')},
    ownKeys() {traps++; throw Error('proxy ownKeys forbidden')},
    getOwnPropertyDescriptor() {traps++; throw Error('proxy descriptor forbidden')},
    getPrototypeOf() {traps++; throw Error('proxy prototype forbidden')},
    apply() {traps++; throw Error('proxy apply forbidden')}})
  refuses(proxy(configuration()), 'memory:private-v2-coordinator-new-pilot-configuration-required')
  refuses({...configuration(), profile: proxy({...profile})})
  refuses({...configuration(), reader: proxy(reader)}, 'memory:new-pilot-lineage-owned-reader-required')
  refuses({...configuration(), contracts: proxy({...contracts})}, 'memory:new-pilot-lineage-contracts-required')
  refuses({...configuration(), contracts: {...contracts, operationDigest: proxy(contracts.operationDigest)}},
    'memory:new-pilot-lineage-contracts-required')
  refuses({...configuration(), publisher: proxy({...publisher})}, 'memory:new-pilot-lineage-bootstrap-publisher-required')
  refuses({...configuration(), publisher: {bootstrap: proxy(publisher.bootstrap)}},
    'memory:new-pilot-lineage-bootstrap-publisher-required')
  refuses({...configuration(), pool: proxy({...pool})}, 'memory:owner-session-pool-required')
  refuses({...configuration(), pool: Object.create(proxy({}))}, 'memory:owner-session-pool-required')
  assert.equal(traps, 0)
  assertIdle()
})
