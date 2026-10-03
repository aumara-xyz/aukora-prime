// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit NEW-store operator preparation. Never called by ordinary construction.
import {types} from 'node:util'
import {canonicalJSON} from '../genesis/plugins/aukora-kira/lib/record.mjs'
import {requireMemory} from './codecs.mjs'
import {assertPrivateHost,assertPrivateProfile,assertLogicalMetadata,logicalMetadataDigest,
  PRIVATE_CONTROL_TABLES,detachPrivateData,readControlV3} from './private-v2-control.mjs'

const check=(ok,reason)=>requireMemory(ok,'memory:new-pilot-store-'+reason)
const LOGICAL='prime_memory_logical_store'
const EXISTING=Object.freeze([...new Set([
  'prime_memory_records','prime_memory_events','prime_memory_heads','prime_memory_chain',
  'prime_memory_outbox','prime_memory_fts','prime_memory_snapshots','prime_memory_originals','prime_memory_quarantine',
  ...Object.values(PRIVATE_CONTROL_TABLES).map(value=>value.table),
])].sort())
export const NEW_PILOT_MEMORY_TABLE_NAMES=Object.freeze([...EXISTING,LOGICAL].sort())
const quote=value=>'"'+value.replaceAll('"','""')+'"'
const qualified=(schema,name)=>quote(schema)+'.'+quote(name)
const oid=value=>typeof value==='string'&&/^[1-9][0-9]*$/.test(value)&&Number(value)<=4294967295
const xid=value=>typeof value==='string'&&/^[1-9][0-9]*$/.test(value)
function exact(value,names,reason) {
  check(value&&typeof value==='object'&&!Array.isArray(value)&&!types.isProxy(value)
    &&[Object.prototype,null].includes(Object.getPrototypeOf(value)),reason)
  const descriptors=Object.getOwnPropertyDescriptors(value)
  check(Reflect.ownKeys(descriptors).length===names.length&&names.every(key=>descriptors[key]
    &&Object.hasOwn(descriptors[key],'value')&&descriptors[key].enumerable),reason)
  return Object.fromEntries(names.map(key=>[key,descriptors[key].value]))
}
function configuration(input) {
  const value=exact(input,['host','profile','contracts','expected_schema'],'configuration-required')
  check(typeof value.expected_schema==='string'
    &&/^prime_pilot_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$/.test(value.expected_schema),'schema-required')
  const host=assertPrivateHost(value.host),profile=assertPrivateProfile(value.profile)
  check(value.contracts&&typeof value.contracts==='object'&&!types.isProxy(value.contracts),'contracts-required')
  const descriptors=Object.getOwnPropertyDescriptors(value.contracts),contracts={}
  for(const key of ['validateContract','operationDigest','canonicalJson']) {
    const descriptor=descriptors[key]
    check(descriptor&&Object.hasOwn(descriptor,'value')&&typeof descriptor.value==='function'
      &&!types.isProxy(descriptor.value),'contracts-required')
    const fn=descriptor.value;contracts[key]=(...args)=>Reflect.apply(fn,undefined,args)
  }
  return Object.freeze({host,profile,contracts:Object.freeze(contracts),expected_schema:value.expected_schema})
}
function method(client) {
  check(client&&typeof client==='object'&&!types.isProxy(client),'client-required')
  let cursor=client
  while(cursor) {
    const descriptor=Object.getOwnPropertyDescriptor(cursor,'query')
    if(descriptor) {
      check(Object.hasOwn(descriptor,'value')&&typeof descriptor.value==='function'
        &&!types.isProxy(descriptor.value),'client-required')
      const fn=descriptor.value;return (...args)=>Reflect.apply(fn,client,args)
    }
    cursor=Object.getPrototypeOf(cursor);check(!cursor||!types.isProxy(cursor),'client-required')
  }
  check(false,'client-required')
}
function rows(result) {
  // pg.Result has its own native prototype. Inspect only its own inert rows
  // property, without reading parser state or reflecting on a Proxy first.
  check(result&&typeof result==='object'&&!types.isProxy(result),'sql-result-invalid')
  const descriptor=Object.getOwnPropertyDescriptor(result,'rows')
  check(descriptor&&Object.hasOwn(descriptor,'value')&&descriptor.enumerable
    &&Array.isArray(descriptor.value),'sql-result-invalid')
  return detachPrivateData({rows:descriptor.value}).rows
}
const RESOLVE=`SELECT r.name,c.oid::text AS table_oid,c.relnamespace::text AS namespace_oid,
 n.nspname AS schema_name,c.relkind,c.relpersistence,c.relispartition,c.relrowsecurity,c.relforcerowsecurity,
 EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid) AS inherited,
 pg_catalog.current_setting('session_replication_role') AS replication_role,
 pg_catalog.current_setting('transaction_isolation') AS isolation,
 pg_catalog.current_setting('transaction_read_only') AS read_only,
 pg_catalog.pg_backend_pid() AS backend_pid,pg_catalog.pg_current_xact_id()::text AS transaction_id
 FROM pg_catalog.unnest($1::text[]) r(name)
 LEFT JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass(r.name)
 LEFT JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace`
async function resolve(query,config,names) {
  const observed=rows(await query(RESOLVE,[names])),first=observed[0],seen=new Set(),table_oids={}
  check(observed.length===names.length&&first&&first.schema_name===config.expected_schema
    &&oid(first.namespace_oid)&&Number.isSafeInteger(first.backend_pid)&&first.backend_pid>0
    &&xid(first.transaction_id),'scope-unavailable')
  for(const row of observed) {
    check(names.includes(row.name)&&!seen.has(row.name)&&oid(row.table_oid)
      &&row.schema_name===config.expected_schema&&row.namespace_oid===first.namespace_oid
      &&row.relkind==='r'&&row.relpersistence==='p'&&row.relispartition===false&&row.inherited===false
      &&row.relrowsecurity===false&&row.relforcerowsecurity===false,
    'relation-identity-invalid')
    check(row.replication_role==='origin'&&row.isolation==='read committed'&&row.read_only==='off'
      &&row.backend_pid===first.backend_pid&&row.transaction_id===first.transaction_id,'session-invalid')
    seen.add(row.name);table_oids[row.name]=row.table_oid
  }
  check(new Set(Object.values(table_oids)).size===names.length,'relation-identity-invalid')
  return {schema:first.schema_name,namespace_oid:first.namespace_oid,backend_pid:first.backend_pid,
    transaction_id:first.transaction_id,table_oids}
}
function sameScope(before,after,names) {
  check(['schema','namespace_oid','backend_pid','transaction_id'].every(key=>before[key]===after[key])
    &&names.every(name=>before.table_oids[name]===after.table_oids[name]),'scope-changed')
}
const OWNER_LOCK=`SELECT pg_catalog.pg_backend_pid() AS backend_pid,EXISTS(
 SELECT 1 FROM pg_catalog.pg_locks WHERE locktype='advisory' AND mode='ExclusiveLock' AND granted=true
 AND pid=pg_catalog.pg_backend_pid()
 AND classid=((pg_catalog.hashtextextended($1,0)>>32)&4294967295)::oid
 AND objid=(pg_catalog.hashtextextended($1,0)&4294967295)::oid AND objsubid=1) AS held`
async function heldOwner(query,scope,config) {
  const observed=rows(await query(OWNER_LOCK,[config.host.owner_subject]))
  check(observed.length===1&&observed[0].held===true&&observed[0].backend_pid===scope.backend_pid,'owner-lock-required')
}
async function empty(query,schema) {
  const text=EXISTING.map(name=>`SELECT '${name}'::text AS name,EXISTS(SELECT 1 FROM ${qualified(schema,name)}) AS nonempty`)
    .join(' UNION ALL ')
  const observed=rows(await query(text)),seen=new Set()
  check(observed.length===EXISTING.length,'empty-census-invalid')
  for(const row of observed) {
    check(EXISTING.includes(row.name)&&!seen.has(row.name)&&row.nonempty===false,'history-present')
    seen.add(row.name)
  }
}
async function lockExisting(query,config,scope,names) {
  await query('LOCK TABLE '+names.map(name=>qualified(config.expected_schema,name)).join(', ')+' IN SHARE ROW EXCLUSIVE MODE')
  const after=await resolve(query,config,names);sameScope(scope,after,names)
  await heldOwner(query,after,config)
  return after
}
function guardConfig(config) {
  return {owner_subject:config.host.owner_subject,owner_id:config.host.owner_id,
    expected_store_id:config.profile.expected_memory_store_id,profile:config.profile}
}
function guardScope(proof,scope) {
  sameScope(scope,proof,Object.keys(proof.table_oids))
}
function freeze(value) {
  if(value&&typeof value==='object') {for(const child of Object.values(value))freeze(child);Object.freeze(value)}
  return value
}
async function receipt(session,query,config,scope,phase,requirePrivateV2Guards) {
  await empty(query,config.expected_schema)
  const proof=await requirePrivateV2Guards(session,guardConfig(config));guardScope(proof,scope)
  const control=await readControlV3(session,{owner_subject:config.host.owner_subject,owner_id:config.host.owner_id,
    profile:config.profile},{contracts:config.contracts})
  check(Object.keys(control.heads).length===0&&Object.keys(control.tables).length===11
    &&Object.values(control.tables).every(value=>Array.isArray(value)&&value.length===0),'baseline-not-empty')
  await empty(query,config.expected_schema)
  const after=await resolve(query,config,NEW_PILOT_MEMORY_TABLE_NAMES)
  sameScope(scope,after,NEW_PILOT_MEMORY_TABLE_NAMES);await heldOwner(query,after,config)
  const final=await requirePrivateV2Guards(session,guardConfig(config));guardScope(final,after)
  return freeze(detachPrivateData({version:1,kind:'prime-new-pilot-memory-store/v1',phase,
    owner_id:config.host.owner_id,owner_subject:config.host.owner_subject,authorization_epoch:config.host.authorization_epoch,
    expected_authority_store_id:config.profile.expected_authority_store_id,
    expected_memory_store_id:config.profile.expected_memory_store_id,physical_scope:after,control,
    transaction_pending:true,grants_authority:false}))
}

/** Caller owns the already-open transaction, supplied IDs, schema/table lifecycle
 * and any COMMIT uncertainty. Never retry preparation after a lost COMMIT reply:
 * an existing metadata relation is refused; independent verification is separate.
 * The expected C ID is only a profile value, never C provisioning evidence. */
export async function prepareNewPilotMemoryStore(client,input) {
  const config=configuration(input),query=method(client),session=Object.freeze({query})
  const {requireWriterClosureGuards}=await import('./writer-closure-guards.mjs')
  const {migratePrivateV2Guards,requirePrivateV2Guards}=await import('./private-v2-guards.mjs')
  const original=await requireWriterClosureGuards(session),before=await resolve(query,config,EXISTING)
  guardScope(original,before);await heldOwner(query,before,config)
  const locked=await lockExisting(query,config,before,EXISTING)
  const absent=rows(await query('SELECT pg_catalog.to_regclass($1) IS NULL AS absent',[qualified(config.expected_schema,LOGICAL)]))
  check(absent.length===1&&absent[0].absent===true,'logical-store-already-present')
  await empty(query,config.expected_schema)
  await query('CREATE TABLE '+qualified(config.expected_schema,LOGICAL)+' (singleton boolean NOT NULL PRIMARY KEY CHECK(singleton), '
    +'metadata_bytes bytea NOT NULL, metadata_digest text NOT NULL CHECK(metadata_digest ~ \'^sha256:[0-9a-f]{64}$\'))')
  const metadata=assertLogicalMetadata({version:1,kind:'prime-memory-logical-store/v1',store_id:config.profile.expected_memory_store_id})
  await query('INSERT INTO '+qualified(config.expected_schema,LOGICAL)+'(singleton,metadata_bytes,metadata_digest) VALUES(true,$1,$2)',
    [Buffer.from(canonicalJSON(metadata)),logicalMetadataDigest(metadata)])
  const all=await resolve(query,config,NEW_PILOT_MEMORY_TABLE_NAMES);sameScope(locked,all,EXISTING)
  await lockExisting(query,config,all,NEW_PILOT_MEMORY_TABLE_NAMES)
  const migration=await migratePrivateV2Guards(session)
  check(migration.transaction_pending===true&&['schema','namespace_oid','backend_pid','transaction_id']
    .every(key=>migration[key]===all[key]),'migration-scope-changed')
  return receipt(session,query,config,all,'prepared',requirePrivateV2Guards)
}

/** Read actual committed NEW baseline through a fresh caller-held transaction.
 * This verifies native PG/store identity and global emptiness, not host custody. */
export async function verifyNewPilotMemoryStore(client,input) {
  const config=configuration(input),query=method(client),session=Object.freeze({query})
  const {requirePrivateV2Guards}=await import('./private-v2-guards.mjs')
  const before=await resolve(query,config,NEW_PILOT_MEMORY_TABLE_NAMES)
  await heldOwner(query,before,config)
  const locked=await lockExisting(query,config,before,NEW_PILOT_MEMORY_TABLE_NAMES)
  return receipt(session,query,config,locked,'verified',requirePrivateV2Guards)
}
