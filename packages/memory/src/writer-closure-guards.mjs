// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from 'node:fs'
import { types } from 'node:util'
import { requireMemory, MemoryRefusal } from './codecs.mjs'

const check = (value, code) => requireMemory(value, 'memory:writer-closure-guards-' + code)
const SQL = readFileSync(new URL('./writer-closure-guards.sql', import.meta.url), 'utf8')
const TABLES = Object.freeze({
  prime_memory_intents: [['owner_subject','25'],['operation_id','25'],['operation_digest','25'],['grant_bytes','17'],
    ['operation_bytes','17'],['request_id','25'],['request_digest','25'],['request_bytes','17']],
  prime_memory_effects: [['owner_subject','25'],['operation_id','25'],['operation_digest','25'],['grant_id','25'],
    ['action','25'],['result_bytes','17'],['request_id','25'],['request_digest','25'],['request_bytes','17'],
    ['receipt_bytes','17'],['operation_bytes','17'],['grant_bytes','17']],
  prime_memory_replay_fences: [['owner_subject','25'],['operation_id','25'],['operation_digest','25'],['grant_id','25'],
    ['action','25'],['request_id','25'],['request_digest','25'],['status','25']],
  prime_memory_unsent_closures: [['owner_subject','25'],['owner_id','25'],['task_id','25'],['operation_id','25'],
    ['operation_digest','25'],['action_type','25'],['authorization_epoch','23'],['reference_bytes','17'],
    ['closure_bytes','17'],['closure_digest','25']],
})
const WRITE_FUNCTION = 'prime_memory_guard_write_after_unsent_closure'
const CLOSURE_FUNCTION = 'prime_memory_guard_unsent_closure_immutable'
const TRIGGERS = Object.freeze({
  prime_memory_intents_unsent_guard: {table:'prime_memory_intents', function:WRITE_FUNCTION, type:23},
  prime_memory_effects_unsent_guard: {table:'prime_memory_effects', function:WRITE_FUNCTION, type:23},
  prime_memory_replay_fences_unsent_guard: {table:'prime_memory_replay_fences', function:WRITE_FUNCTION, type:23},
  prime_memory_unsent_closures_immutable_guard: {table:'prime_memory_unsent_closures', function:CLOSURE_FUNCTION, type:31},
  prime_memory_unsent_closures_truncate_guard: {table:'prime_memory_unsent_closures', function:CLOSURE_FUNCTION, type:34},
})
function body(name) {
  const start = SQL.indexOf(`CREATE OR REPLACE FUNCTION ${name}()`)
  const delimiter = 'AS $prime_memory_guard$'
  const open = SQL.indexOf(delimiter, start), end = SQL.indexOf('$prime_memory_guard$;', open + delimiter.length)
  check(start >= 0 && open > start && end > open, 'source-invalid')
  return SQL.slice(open + delimiter.length, end)
}
export const MEMORY_WRITER_CLOSURE_GUARD_BODIES = Object.freeze({
  [WRITE_FUNCTION]: body(WRITE_FUNCTION), [CLOSURE_FUNCTION]: body(CLOSURE_FUNCTION),
})
const oid = value => typeof value === 'string' && /^[1-9][0-9]*$/.test(value) && Number(value) <= 4294967295
const xid = value => typeof value === 'string' && /^[1-9][0-9]*$/.test(value)
const quote = value => '"' + value.replaceAll('"', '""') + '"'
function method(object, name) {
  check(object && typeof object === 'object' && !types.isProxy(object), 'client-required')
  let current = object
  while (current) {
    const descriptor = Object.getOwnPropertyDescriptor(current, name)
    if (descriptor) {
      check(Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function', 'client-required')
      return descriptor.value.bind(object)
    }
    current = Object.getPrototypeOf(current)
    check(!current || !types.isProxy(current), 'client-required')
  }
  check(false, 'client-required')
}
function rows(result) { check(result && Array.isArray(result.rows), 'catalog-invalid'); return result.rows }

const RESOLVE = `SELECT r.name, c.oid::text AS table_oid, c.relnamespace::text AS namespace_oid,
 n.nspname AS schema_name, c.relkind, c.relpersistence, c.relispartition,
 pg_catalog.current_setting('session_replication_role') AS replication_role,
 pg_catalog.current_setting('transaction_isolation') AS isolation,
 pg_catalog.current_setting('transaction_read_only') AS read_only,
 pg_catalog.pg_backend_pid() AS backend_pid,
 pg_catalog.pg_current_xact_id()::text AS transaction_id,
 (SELECT pg_catalog.json_agg(pg_catalog.json_build_object('name',a.attname,'type',a.atttypid::text,
   'not_null',a.attnotnull) ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
   WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) AS columns
 FROM pg_catalog.unnest($1::text[]) r(name)
 LEFT JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass(r.name)
 LEFT JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace`

async function resolve(query) {
  const observed = rows(await query(RESOLVE, [Object.keys(TABLES)]))
  check(observed.length === Object.keys(TABLES).length, 'tables-unavailable')
  const seen = new Set(), table_oids = {}, first = observed[0]
  check(first && typeof first.schema_name === 'string' && Buffer.byteLength(first.schema_name)>0
    && Buffer.byteLength(first.schema_name)<=63 && !first.schema_name.includes('\0')
    && !/^(?:pg_|information_schema$)/.test(first.schema_name) && oid(first.namespace_oid)
    && Number.isSafeInteger(first.backend_pid) && first.backend_pid>0 && xid(first.transaction_id), 'namespace-invalid')
  for (const row of observed) {
    check(row && Object.hasOwn(TABLES,row.name) && !seen.has(row.name) && oid(row.table_oid)
      && row.namespace_oid===first.namespace_oid && row.schema_name===first.schema_name
      && row.relkind==='r' && row.relpersistence==='p' && row.relispartition===false, 'table-identity-invalid')
    check(row.replication_role==='origin' && row.isolation==='read committed' && row.read_only==='off'
      && row.backend_pid===first.backend_pid && row.transaction_id===first.transaction_id, 'session-invalid')
    const expected = TABLES[row.name]
    check(Array.isArray(row.columns) && row.columns.length===expected.length && row.columns.every((column,index)=>
      column.name===expected[index][0] && column.type===expected[index][1] && column.not_null===true), 'table-columns-invalid')
    seen.add(row.name); table_oids[row.name]=row.table_oid
  }
  check(new Set(Object.values(table_oids)).size===observed.length, 'table-identity-invalid')
  return {schema:first.schema_name,namespace_oid:first.namespace_oid,backend_pid:first.backend_pid,
    transaction_id:first.transaction_id,table_oids}
}
function sameScope(left,right) {
  check(['schema','namespace_oid','backend_pid','transaction_id'].every(key=>left[key]===right[key])
    && Object.keys(TABLES).every(name=>left.table_oids[name]===right.table_oids[name]), 'transaction-or-tables-changed')
}
const qualifiedTables = scope => Object.keys(TABLES).map(name=>`${quote(scope.schema)}.${quote(name)}`).join(', ')
const CATALOG = `SELECT t.tgname, t.tgrelid::text AS table_oid, t.tgtype, t.tgenabled, t.tgisinternal,
 t.tgfoid::text AS function_oid, t.tgconstraint::text AS constraint_oid, t.tgparentid::text AS parent_oid,
 t.tgdeferrable,t.tginitdeferred,t.tgnargs,t.tgattr::text AS attributes,
 t.tgqual IS NULL AS unqualified,t.tgoldtable,t.tgnewtable,
 p.proname,p.pronamespace::text AS namespace_oid,p.prosrc,p.proconfig,p.prosecdef,p.provolatile,
 p.proleakproof,p.proisstrict,p.pronargs,p.prorettype::text AS return_type,p.prokind,p.proparallel,
 l.lanname,l.lanpltrusted
 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
 JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 WHERE t.tgrelid=ANY($1::oid[]) AND NOT t.tgisinternal`

// This must run on the held owner's actual transaction client. ACCESS SHARE pins
// relation identities without blocking ordinary writers; DDL remains operator-owned.
// Real catalog replies prove this PG path; they do not attest the host OS identity.
async function inspectGuards(client) {
  const query = method(client,'query'), before = await resolve(query)
  await query(`LOCK TABLE ${qualifiedTables(before)} IN ACCESS SHARE MODE`)
  const scope = await resolve(query); sameScope(before,scope)
  const observed = rows(await query(CATALOG,[Object.values(scope.table_oids)]))
  check(observed.length===Object.keys(TRIGGERS).length,'triggers-unavailable')
  const seen = new Set(), functions = new Map()
  for (const row of observed) {
    const expected = row && Object.hasOwn(TRIGGERS,row.tgname) ? TRIGGERS[row.tgname] : null
    check(expected && !seen.has(row.tgname) && row.table_oid===scope.table_oids[expected.table]
      && row.tgtype===expected.type && row.tgenabled==='O' && row.tgisinternal===false
      && row.constraint_oid==='0' && row.parent_oid==='0' && row.tgdeferrable===false && row.tginitdeferred===false
      && row.tgnargs===0 && row.attributes==='' && row.unqualified===true
      && row.tgoldtable===null && row.tgnewtable===null, 'trigger-invalid')
    check(row.proname===expected.function && row.namespace_oid===scope.namespace_oid && oid(row.function_oid)
      && row.prosrc===MEMORY_WRITER_CLOSURE_GUARD_BODIES[expected.function]
      && Array.isArray(row.proconfig) && row.proconfig.length===1 && row.proconfig[0]==='search_path=pg_catalog'
      && row.prosecdef===false && row.provolatile==='v' && row.proleakproof===false && row.proisstrict===false
      && row.pronargs===0 && row.return_type==='2279' && row.prokind==='f' && row.proparallel==='u'
      && row.lanname==='plpgsql' && row.lanpltrusted===true, 'function-invalid')
    check(!functions.has(expected.function) || functions.get(expected.function)===row.function_oid, 'function-identity-invalid')
    functions.set(expected.function,row.function_oid); seen.add(row.tgname)
  }
  const after = await resolve(query); sameScope(scope,after)
  return Object.freeze({kind:'postgres-writer-closure-guards/v1',schema:scope.schema,namespace_oid:scope.namespace_oid,
    backend_pid:scope.backend_pid,transaction_id:scope.transaction_id,table_oids:Object.freeze({...scope.table_oids})})
}
export async function requireWriterClosureGuards(client) {
  try {return await inspectGuards(client)}
  catch(cause) {
    if(cause instanceof MemoryRefusal) throw cause
    const error = new MemoryRefusal('memory:writer-closure-guards-unavailable'); error.cause=cause; throw error
  }
}

// Explicit migration only; ordinary migrate() and fixture schemas are untouched.
// No CREATE SCHEMA, credentials, role grants or database privileges are requested.
export async function installWriterClosureGuards(pool) {
  const client = await method(pool,'connect')()
  const query = method(client,'query'), release = method(client,'release')
  let committed=false
  try {
    await query('BEGIN ISOLATION LEVEL READ COMMITTED')
    const before = await resolve(query)
    await query(`LOCK TABLE ${qualifiedTables(before)} IN SHARE ROW EXCLUSIVE MODE`)
    const locked = await resolve(query); sameScope(before,locked)
    await query(`SET LOCAL search_path TO ${quote(locked.schema)}, pg_catalog`)
    await query(SQL)
    const proof = await requireWriterClosureGuards(client)
    await query('COMMIT'); committed=true
    return proof
  } catch (cause) {
    if(!committed) await query('ROLLBACK').catch(()=>{})
    if(cause instanceof MemoryRefusal) throw cause
    const error = new MemoryRefusal('memory:writer-closure-guards-install-unavailable'); error.cause=cause; throw error
  } finally {release()}
}
