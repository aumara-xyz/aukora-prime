// SPDX-License-Identifier: AGPL-3.0-or-later
import {readFileSync} from 'node:fs'
import {types} from 'node:util'
import {canonicalJSON} from '../genesis/plugins/aukora-kira/lib/record.mjs'
import {MemoryRefusal,parseOriginal,requireMemory,sha256} from './codecs.mjs'
import {requireWriterClosureGuards} from './writer-closure-guards.mjs'

const check=(value,code)=>requireMemory(value,'memory:private-v2-guards-'+code)
const SQL=readFileSync(new URL('./private-v2-guards.sql',import.meta.url),'utf8')
const column=(name,type,not_null=true)=>[name,type,not_null]
const TABLES=Object.freeze({
  prime_memory_logical_store:[column('singleton','16'),column('metadata_bytes','17'),column('metadata_digest','25')],
  prime_runtime_workflows:[column('owner_subject','25'),column('owner_id','25'),column('task_id','25'),
    column('operation_id','25'),column('operation_digest','25'),column('action_type','25'),
    column('idempotency_key_sha256','25',false),column('record_id','25',false),column('phase','25'),
    column('request_id','25',false),column('request_digest','25',false),column('receipt_digest','25',false),column('created_at','25')],
  prime_runtime_workflow_closure_progress_v2:[column('owner_subject','25'),column('owner_id','25'),column('task_id','25'),
    column('operation_id','25'),column('progress_bytes','17'),column('progress_digest','25')],
})
const META='prime_memory_private_v2_metadata_immutable'
const FLOW='prime_memory_private_v2_workflow_immutable'
const PROGRESS='prime_memory_private_v2_progress_immutable'
const JOIN='prime_memory_private_v2_journal_correlated'
const trigger=(table,func,type,deferred=false)=>({table,function:func,type,deferred})
const TRIGGERS=Object.freeze({
  prime_memory_private_v2_metadata_row_guard:trigger('prime_memory_logical_store',META,31),
  prime_memory_private_v2_metadata_truncate_guard:trigger('prime_memory_logical_store',META,34),
  prime_memory_private_v2_workflow_row_guard:trigger('prime_runtime_workflows',FLOW,31),
  prime_memory_private_v2_workflow_truncate_guard:trigger('prime_runtime_workflows',FLOW,34),
  prime_memory_private_v2_progress_row_guard:trigger('prime_runtime_workflow_closure_progress_v2',PROGRESS,31),
  prime_memory_private_v2_progress_truncate_guard:trigger('prime_runtime_workflow_closure_progress_v2',PROGRESS,34),
  prime_memory_private_v2_workflow_correlation_guard:trigger('prime_runtime_workflows',JOIN,21,true),
  prime_memory_private_v2_progress_correlation_guard:trigger('prime_runtime_workflow_closure_progress_v2',JOIN,21,true),
})
function body(name) {
  const start=SQL.indexOf(`CREATE OR REPLACE FUNCTION ${name}()`),delimiter='AS $prime_private_v2_guard$'
  const open=SQL.indexOf(delimiter,start),end=SQL.indexOf('$prime_private_v2_guard$;',open+delimiter.length)
  check(start>=0&&open>start&&end>open,'source-invalid')
  return SQL.slice(open+delimiter.length,end)
}
export const MEMORY_PRIVATE_V2_GUARD_BODIES=Object.freeze(Object.fromEntries([META,FLOW,PROGRESS,JOIN].map(name=>[name,body(name)])))
const oid=value=>typeof value==='string'&&/^[1-9][0-9]*$/.test(value)&&Number(value)<=4294967295
const xid=value=>typeof value==='string'&&/^[1-9][0-9]*$/.test(value)
const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value)
const text=value=>typeof value==='string'&&value.length>0&&Buffer.byteLength(value)<=4096&&!value.includes('\0')
const quote=value=>'"'+value.replaceAll('"','""')+'"'
function method(object,name) {
  check(object&&typeof object==='object'&&!types.isProxy(object),'client-required')
  let current=object
  while(current) {
    const d=Object.getOwnPropertyDescriptor(current,name)
    if(d){check(Object.hasOwn(d,'value')&&typeof d.value==='function','client-required');return d.value.bind(object)}
    current=Object.getPrototypeOf(current);check(!current||!types.isProxy(current),'client-required')
  }
  check(false,'client-required')
}
function exact(input,names,code) {
  check(input&&typeof input==='object'&&!Array.isArray(input)&&!types.isProxy(input)
    &&[Object.prototype,null].includes(Object.getPrototypeOf(input)),code)
  const ds=Object.getOwnPropertyDescriptors(input)
  check(Reflect.ownKeys(ds).length===names.length&&names.every(k=>ds[k]&&Object.hasOwn(ds[k],'value')&&ds[k].enumerable),code)
  return Object.fromEntries(names.map(k=>[k,ds[k].value]))
}
function configuration(input) {
  const config=exact(input,['owner_subject','owner_id','expected_store_id','profile'],'configuration-required')
  check(text(config.owner_subject)&&text(config.owner_id)&&hex(config.expected_store_id),'configuration-invalid')
  const profile=exact(config.profile,['version','kind','expected_authority_store_id','expected_memory_store_id','retention_profile'],'profile-invalid')
  check(profile.version===2&&profile.kind==='prime-private-unsent-closure/v2'&&profile.retention_profile==='required-retained/v2'
    &&hex(profile.expected_authority_store_id)&&profile.expected_memory_store_id===config.expected_store_id,'profile-invalid')
  return Object.freeze({...config,profile:Object.freeze(profile)})
}
const rows=result=>{check(result&&Array.isArray(result.rows),'catalog-invalid');return result.rows}
const RESOLVE=`SELECT r.name,c.oid::text AS table_oid,c.relnamespace::text AS namespace_oid,
 n.nspname AS schema_name,c.relkind,c.relpersistence,c.relispartition,
 pg_catalog.current_setting('session_replication_role') AS replication_role,
 pg_catalog.current_setting('transaction_isolation') AS isolation,
 pg_catalog.current_setting('transaction_read_only') AS read_only,
 pg_catalog.pg_backend_pid() AS backend_pid,pg_catalog.pg_current_xact_id()::text AS transaction_id,
 (SELECT pg_catalog.json_agg(pg_catalog.json_build_object('name',a.attname,'type',a.atttypid::text,
  'not_null',a.attnotnull) ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
  WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) AS columns
 FROM pg_catalog.unnest($1::text[]) r(name)
 LEFT JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass(r.name)
 LEFT JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace`
async function resolve(query) {
  const observed=rows(await query(RESOLVE,[Object.keys(TABLES)])),first=observed[0],seen=new Set(),table_oids={}
  check(observed.length===Object.keys(TABLES).length,'tables-unavailable')
  check(first&&typeof first.schema_name==='string'&&Buffer.byteLength(first.schema_name)>0
    &&Buffer.byteLength(first.schema_name)<=63&&!first.schema_name.includes('\0')
    &&!/^(?:pg_|information_schema$)/.test(first.schema_name)&&oid(first.namespace_oid)
    &&Number.isSafeInteger(first.backend_pid)&&first.backend_pid>0&&xid(first.transaction_id),'namespace-invalid')
  for(const row of observed) {
    check(row&&Object.hasOwn(TABLES,row.name)&&!seen.has(row.name)&&oid(row.table_oid)
      &&row.namespace_oid===first.namespace_oid&&row.schema_name===first.schema_name
      &&row.relkind==='r'&&row.relpersistence==='p'&&row.relispartition===false,'table-identity-invalid')
    check(row.replication_role==='origin'&&row.isolation==='read committed'&&row.read_only==='off'
      &&row.backend_pid===first.backend_pid&&row.transaction_id===first.transaction_id,'session-invalid')
    const expected=TABLES[row.name]
    check(Array.isArray(row.columns)&&row.columns.length===expected.length&&row.columns.every((c,i)=>
      c.name===expected[i][0]&&c.type===expected[i][1]&&c.not_null===expected[i][2]),'table-columns-invalid')
    seen.add(row.name);table_oids[row.name]=row.table_oid
  }
  check(new Set(Object.values(table_oids)).size===observed.length,'table-identity-invalid')
  return {schema:first.schema_name,namespace_oid:first.namespace_oid,backend_pid:first.backend_pid,
    transaction_id:first.transaction_id,table_oids}
}
function sameScope(a,b) {
  check(['schema','namespace_oid','backend_pid','transaction_id'].every(k=>a[k]===b[k])
    &&Object.keys(TABLES).every(k=>a.table_oids[k]===b.table_oids[k]),'transaction-or-tables-changed')
}
function sameLegacyScope(scope,legacy) {
  check(['schema','namespace_oid','backend_pid','transaction_id'].every(k=>scope[k]===legacy[k]),'original-guard-scope-mismatch')
}
const qualified=scope=>Object.keys(TABLES).map(name=>`${quote(scope.schema)}.${quote(name)}`).join(', ')
const CATALOG=`SELECT t.tgname,t.tgrelid::text AS table_oid,t.tgtype,t.tgenabled,t.tgisinternal,
 t.tgfoid::text AS function_oid,t.tgconstraint::text AS constraint_oid,t.tgparentid::text AS parent_oid,
 t.tgdeferrable,t.tginitdeferred,t.tgnargs,t.tgattr::text AS attributes,t.tgqual IS NULL AS unqualified,
 t.tgoldtable,t.tgnewtable,p.proname,p.pronamespace::text AS namespace_oid,p.prosrc,p.proconfig,
 p.prosecdef,p.provolatile,p.proleakproof,p.proisstrict,p.pronargs,p.prorettype::text AS return_type,p.prokind,p.proparallel,
 l.lanname,l.lanpltrusted,c.contype AS constraint_type,c.conname AS constraint_name,
 c.conrelid::text AS constraint_table_oid,c.connamespace::text AS constraint_namespace_oid,
 c.condeferrable AS constraint_deferrable,c.condeferred AS constraint_deferred,c.convalidated AS constraint_validated
 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
 JOIN pg_catalog.pg_language l ON l.oid=p.prolang LEFT JOIN pg_catalog.pg_constraint c ON c.oid=t.tgconstraint
 WHERE t.tgrelid=ANY($1::oid[]) AND NOT t.tgisinternal`
const KEYS=`SELECT c.conrelid::text AS table_oid,c.connamespace::text AS namespace_oid,c.conkey AS columns,
 c.condeferrable,c.condeferred,c.convalidated,c.conislocal,c.coninhcount,
 i.indexrelid::text AS index_oid,i.indisunique,i.indisprimary,i.indisvalid,i.indisready,i.indislive,
 i.indnkeyatts,i.indnatts,i.indkey::text AS index_columns,i.indpred IS NULL AS unqualified,
 i.indexprs IS NULL AS simple,k.relkind,k.relpersistence
 FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_index i ON i.indexrelid=c.conindid
 JOIN pg_catalog.pg_class k ON k.oid=i.indexrelid
 WHERE c.conrelid=ANY($1::oid[]) AND c.contype='p'`
async function requireKeys(query,scope) {
  const table_oids=['prime_runtime_workflows','prime_runtime_workflow_closure_progress_v2'].map(k=>scope.table_oids[k])
  const observed=rows(await query(KEYS,[table_oids])),seen=new Set()
  check(observed.length===table_oids.length,'journal-keys-unavailable')
  for(const row of observed) {
    check(table_oids.includes(row.table_oid)&&!seen.has(row.table_oid)&&row.namespace_oid===scope.namespace_oid
      &&Array.isArray(row.columns)&&row.columns.length===2&&row.columns[0]===1&&row.columns[1]===4
      &&row.condeferrable===false&&row.condeferred===false&&row.convalidated===true&&row.conislocal===true&&row.coninhcount===0
      &&oid(row.index_oid)&&row.indisunique===true&&row.indisprimary===true&&row.indisvalid===true&&row.indisready===true&&row.indislive===true
      &&row.indnkeyatts===2&&row.indnatts===2&&row.index_columns==='1 4'&&row.unqualified===true&&row.simple===true
      &&row.relkind==='i'&&row.relpersistence==='p','journal-key-invalid')
    seen.add(row.table_oid)
  }
}
const OWNER_LOCK=`SELECT pg_catalog.pg_backend_pid() AS backend_pid,EXISTS (
 SELECT 1 FROM pg_catalog.pg_locks WHERE locktype='advisory' AND mode='ExclusiveLock' AND granted=true
 AND pid=pg_catalog.pg_backend_pid()
 AND classid=((pg_catalog.hashtextextended($1,0)>>32)&4294967295)::oid
 AND objid=(pg_catalog.hashtextextended($1,0)&4294967295)::oid AND objsubid=1) AS held`
async function heldOwner(query,scope,owner) {
  const found=rows(await query(OWNER_LOCK,[owner]))
  check(found.length===1&&found[0].held===true&&found[0].backend_pid===scope.backend_pid,'owner-lock-required')
}
async function metadata(query,scope,config) {
  const found=rows(await query(`SELECT singleton,metadata_bytes,metadata_digest FROM ${quote(scope.schema)}.prime_memory_logical_store`))
  check(found.length===1&&found[0].singleton===true&&Buffer.isBuffer(found[0].metadata_bytes),'logical-store-unavailable')
  const bytes=Buffer.from(found[0].metadata_bytes),value=parseOriginal(bytes)
  const checked=exact(value,['version','kind','store_id'],'logical-store-invalid')
  check(checked.version===1&&checked.kind==='prime-memory-logical-store/v1'&&checked.store_id===config.expected_store_id
    &&bytes.equals(Buffer.from(canonicalJSON(checked)))
    &&found[0].metadata_digest==='sha256:'+sha256(Buffer.from('aukora-prime.memory-logical-store.v1\0'+canonicalJSON(checked))),
  'logical-store-mismatch')
  return Object.freeze({metadata:Object.freeze(checked),metadata_digest:found[0].metadata_digest})
}
async function validateNativeTriggers(query,scope) {
  const observed=rows(await query(CATALOG,[Object.values(scope.table_oids)])),seen=new Set(),functions=new Map()
  check(observed.length===Object.keys(TRIGGERS).length,'triggers-unavailable')
  for(const row of observed) {
    const expected=row&&Object.hasOwn(TRIGGERS,row.tgname)?TRIGGERS[row.tgname]:null
    check(expected&&!seen.has(row.tgname)&&row.table_oid===scope.table_oids[expected.table]
      &&row.tgtype===expected.type&&row.tgenabled==='O'&&row.tgisinternal===false&&row.parent_oid==='0'
      &&row.tgdeferrable===expected.deferred&&row.tginitdeferred===expected.deferred
      &&row.tgnargs===0&&row.attributes===''&&row.unqualified===true&&row.tgoldtable===null&&row.tgnewtable===null,'trigger-invalid')
    if(expected.deferred)check(oid(row.constraint_oid)&&row.constraint_type==='t'&&row.constraint_name===row.tgname
      &&row.constraint_table_oid===row.table_oid&&row.constraint_namespace_oid===scope.namespace_oid
      &&row.constraint_deferrable===true&&row.constraint_deferred===true&&row.constraint_validated===true,'constraint-invalid')
    else check(row.constraint_oid==='0','constraint-invalid')
    check(row.proname===expected.function&&row.namespace_oid===scope.namespace_oid&&oid(row.function_oid)
      &&row.prosrc===MEMORY_PRIVATE_V2_GUARD_BODIES[expected.function]
      &&Array.isArray(row.proconfig)&&row.proconfig.length===1&&row.proconfig[0]==='search_path=pg_catalog'
      &&row.prosecdef===false&&row.provolatile==='v'&&row.proleakproof===false&&row.proisstrict===false
      &&row.pronargs===0&&row.return_type==='2279'&&row.prokind==='f'&&row.proparallel==='u'
      &&row.lanname==='plpgsql'&&row.lanpltrusted===true,'function-invalid')
    check(!functions.has(expected.function)||functions.get(expected.function)===row.function_oid,'function-identity-invalid')
    functions.set(expected.function,row.function_oid);seen.add(row.tgname)
  }
  await requireKeys(query,scope)
}
async function inspect(client,input) {
  const config=configuration(input),query=method(client,'query')
  // The original native fence is mandatory and unmodified. Identity and journal
  // hashes never stand in for its actual relation/transaction/catalog checks.
  const original=await requireWriterClosureGuards(client),before=await resolve(query)
  sameLegacyScope(before,original);await heldOwner(query,before,config.owner_subject)
  await query(`LOCK TABLE ${qualified(before)} IN ACCESS SHARE MODE`)
  const scope=await resolve(query);sameScope(before,scope)
  await validateNativeTriggers(query,scope)
  const logical_store=await metadata(query,scope,config),after=await resolve(query)
  sameScope(scope,after);await heldOwner(query,after,config.owner_subject)
  // This describes observed native PG evidence, not host UID/custody qualification.
  return Object.freeze({kind:'postgres-memory-private-v2-guards/v1',schema:scope.schema,namespace_oid:scope.namespace_oid,
    backend_pid:scope.backend_pid,transaction_id:scope.transaction_id,table_oids:Object.freeze({...scope.table_oids}),
    owner_subject:config.owner_subject,owner_id:config.owner_id,logical_store,original_writer_guards:original})
}
export async function requirePrivateV2Guards(client,config) {
  try{return await inspect(client,config)}
  catch(cause){if(cause instanceof MemoryRefusal)throw cause
    const error=new MemoryRefusal('memory:private-v2-guards-unavailable');error.cause=cause;throw error}
}

// Source-only explicit migration primitive. A separately authorized operator
// supplies an already opened writable READ COMMITTED transaction on existing
// provisioned tables. No BEGIN/COMMIT, connection, DDL custody or activation is
// acquired here. Installation cannot establish owner/protected-custody evidence.
export async function migratePrivateV2Guards(client) {
  try {
    const query=method(client,'query'),original=await requireWriterClosureGuards(client),before=await resolve(query)
    sameLegacyScope(before,original)
    await query(`LOCK TABLE ${qualified(before)} IN SHARE ROW EXCLUSIVE MODE`)
    const locked=await resolve(query);sameScope(before,locked)
    await query(`SET LOCAL search_path TO ${quote(locked.schema)}, pg_catalog`)
    await query(SQL)
    const after=await resolve(query);sameScope(locked,after)
    await validateNativeTriggers(query,after)
    const verified=await resolve(query);sameScope(after,verified)
    return Object.freeze({kind:'postgres-memory-private-v2-guard-installation/v1',schema:locked.schema,
      namespace_oid:locked.namespace_oid,backend_pid:locked.backend_pid,transaction_id:locked.transaction_id,
      ddl_executed:true,transaction_pending:true})
  } catch(cause) {
    if(cause instanceof MemoryRefusal)throw cause
    const error=new MemoryRefusal('memory:private-v2-guards-install-unavailable');error.cause=cause;throw error
  }
}
