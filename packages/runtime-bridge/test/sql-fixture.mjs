// SPDX-License-Identifier: AGPL-3.0-or-later
// Test ONLY: copied D's narrow SQLite dialect shim. Real bytes and transactions;
// not PostgreSQL WAL, FTS/advisory locks, RLS or durability acceptance.
import {DatabaseSync} from 'node:sqlite'
export class FixturePool {
  constructor(path){this.db=new DatabaseSync(path);this.failIndex=false;this.failAfterDispatch=false;this.commitAfterEffect=false}
  async connect(){return {query:this.query.bind(this),release(){}}}
  close(){this.db.close()}
  async query(sql,values=[]) {
    if(sql.startsWith('SELECT current_setting'))return {rows:[{fsync:'on',full_page_writes:'on'}]}
    if(this.failIndex&&sql.startsWith('INSERT INTO prime_memory_fts'))throw new Error('synthetic index unavailable')
    if(this.failAfterDispatch&&sql.startsWith('INSERT INTO prime_memory_records'))throw new Error('synthetic write interruption after dispatch')
    if(/^SET LOCAL|^SELECT pg_advisory_xact_lock/.test(sql))return {rows:[]}
    if(sql.startsWith('INSERT INTO prime_memory_effects'))this.effectInTransaction=true
    if(sql==='BEGIN'||sql.startsWith('BEGIN ISOLATION'))this.effectInTransaction=false
    const lostCommit=sql==='COMMIT'&&this.effectInTransaction&&this.commitAfterEffect
    sql=sql.replace('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY','BEGIN')
      .replace("document tsvector GENERATED ALWAYS AS (to_tsvector('simple',statement)) STORED",'document text GENERATED ALWAYS AS (statement) STORED')
      .replace('USING gin(document)','(document)').replace(/::integer/g,'')
      .replace(/=ANY\((\$\d+)::text\[\]\)/g,' IN (SELECT value FROM json_each($1))')
      .replace("f.document @@ plainto_tsquery('simple',$6)","f.statement LIKE '%' || $6 || '%'")
      .replace("ts_rank(f.document,plainto_tsquery('simple',$6))",'length(f.statement)')
      .replace(' FOR UPDATE SKIP LOCKED','')
    if(!values.length){this.db.exec(sql);if(lostCommit){this.commitAfterEffect=false;throw new Error('synthetic lost COMMIT reply')}return {rows:[]}}
    const ordered=[]
    sql=sql.replace(/\$(\d+)/g,(_,n)=>{const value=values[Number(n)-1];ordered.push(Array.isArray(value)?JSON.stringify(value):value);return '?'})
    return {rows:this.db.prepare(sql).all(...ordered).map(row=>({...row,...(row.searchable!==undefined?{searchable:row.searchable===1}:{})}))}
  }
}
