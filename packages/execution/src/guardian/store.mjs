// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from 'node:sqlite'
import { lstatSync,realpathSync,existsSync,chmodSync } from 'node:fs'
import { join,resolve,dirname } from 'node:path'
import { randomUUID } from 'node:crypto'
import { canonicalJson,parseStrictJson } from '../../../contracts/src/runtime.mjs'
import { copy,digest,validateScope,validateRegistration } from './registration.mjs'
import { refused } from '../policy.mjs'

// Same-host OS lease and FULL-sync records; protected placement is still H's
// obligation. Same-UID writes and wall-clock rollback are not trust anchors.
export function privatePath(path,kind='file') {
  if(resolve(path)!==path||realpathSync(path)!==path)throw refused('canonical private guardian path required','UNAVAILABLE')
  for(let ancestor=path;;ancestor=dirname(ancestor)) {
    if(lstatSync(ancestor).isSymbolicLink())throw refused('symlink guardian ancestor refused','UNAVAILABLE')
    if(ancestor===dirname(ancestor))break
  }
  const st=lstatSync(path)
  if((kind==='directory'?!st.isDirectory():!st.isFile())||(st.mode&0o077)||(process.getuid&&st.uid!==process.getuid()))throw refused('private host-owned guardian path required','UNAVAILABLE')
}
export class GuardianStore {
  constructor(root,{initialize=false,scope}={}) {
    privatePath(root,'directory');this.root=root;this.scope=validateScope(scope);this.owned=false
    const files=['guardian.sqlite','owner.sqlite','guardian.sqlite-wal','guardian.sqlite-shm']
    if(initialize&&files.some(name=>existsSync(join(root,name))))throw refused('guardian state already exists; never replace','RECONCILIATION_REQUIRED')
    if(!initialize&&['guardian.sqlite','owner.sqlite'].some(name=>!existsSync(join(root,name))))throw refused('guardian state missing; never reinitialize recovery','RECONCILIATION_REQUIRED')
    for(const name of files)if(existsSync(join(root,name)))privatePath(join(root,name))
    this.db=new DatabaseSync(join(root,'guardian.sqlite'));chmodSync(join(root,'guardian.sqlite'),0o600)
    try {
      this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=1000;')
      if(initialize) {
        this.identity=randomUUID()
        this.db.exec(`PRAGMA application_id=1096108871; PRAGMA user_version=1;
          CREATE TABLE metadata (id TEXT PRIMARY KEY, scope TEXT NOT NULL, last_clock INTEGER NOT NULL) STRICT;
          CREATE TABLE registrations (request_id TEXT PRIMARY KEY, operation_id TEXT UNIQUE NOT NULL, grant_id TEXT UNIQUE NOT NULL,
            reservation_id TEXT UNIQUE NOT NULL, create_id TEXT UNIQUE NOT NULL, name TEXT UNIQUE NOT NULL, digest TEXT NOT NULL, body TEXT NOT NULL) STRICT;`)
        this.db.prepare('INSERT INTO metadata VALUES (?,?,?)').run(this.identity,canonicalJson(this.scope),Date.now())
        const owner=new DatabaseSync(join(root,'owner.sqlite'));owner.exec('CREATE TABLE owner (id TEXT PRIMARY KEY) STRICT');owner.prepare('INSERT INTO owner VALUES (?)').run(this.identity);owner.close();chmodSync(join(root,'owner.sqlite'),0o600)
      } else {
        if(this.db.prepare('PRAGMA application_id').get().application_id!==1096108871||this.db.prepare('PRAGMA user_version').get().user_version!==1
          ||this.db.prepare('PRAGMA quick_check').get().quick_check!=='ok')throw refused('guardian database identity/integrity differs','RECONCILIATION_REQUIRED')
        const meta=this.db.prepare('SELECT * FROM metadata').all()
        if(meta.length!==1||meta[0].scope!==canonicalJson(this.scope))throw refused('guardian immutable scope differs','TARGET_MISMATCH')
        this.identity=meta[0].id
      }
      for(const name of ['guardian.sqlite-wal','guardian.sqlite-shm'])if(existsSync(join(root,name)))chmodSync(join(root,name),0o600)
    } catch(error){this.db.close();throw error}
  }
  async withOwner(work) {
    if(this.owned)throw refused('guardian owner already running','RECONCILIATION_REQUIRED')
    const lease=new DatabaseSync(join(this.root,'owner.sqlite'))
    try {
      if(lease.prepare('SELECT id FROM owner').get()?.id!==this.identity)throw new Error('owner identity differs')
      lease.exec('PRAGMA busy_timeout=0; BEGIN IMMEDIATE;')
    } catch {lease.close();throw refused('guardian lifecycle owned or invalid','RECONCILIATION_REQUIRED')}
    this.owned=true
    try{return await work()}finally{this.owned=false;try{lease.exec('ROLLBACK')}finally{lease.close()}}
  }
  requireOwner(){if(!this.owned)throw refused('guardian mutation requires its process lease','RECONCILIATION_REQUIRED')}
  read(row) {
    if(!row)return null
    const value=parseStrictJson(row.body,{maxBytes:8*1024*1024})
    if(value.registration_digest!==row.digest||digest(validateRegistration(value.registration,this.scope))!==row.digest
      ||value.request_id!==row.request_id||value.guardian_id!==this.identity)throw refused('guardian durable binding differs','RECONCILIATION_REQUIRED')
    return value
  }
  lookup(id){return this.read(this.db.prepare('SELECT * FROM registrations WHERE request_id=?').get(id))}
  rows(){return this.db.prepare('SELECT * FROM registrations ORDER BY rowid').all().map(row=>this.read(row))}
  register(input) {
    this.requireOwner();const registration=validateRegistration(input,this.scope),request=registration.request,registration_digest=digest(registration)
    const old=this.lookup(request.request_id)
    if(old){if(old.registration_digest!==registration_digest)throw refused('guardian job permanently bound; no extension/replacement','REPLAYED');return old}
    if(this.db.prepare('SELECT count(*) AS n FROM registrations').get().n>=64)throw refused('guardian durable capacity reached; retain existing jobs','UNAVAILABLE')
    const row={version:1,guardian_id:this.identity,request_id:request.request_id,registration,registration_digest,
      mode:'watching',cleanup_reason:null,sandbox_uid:null,observation:null,reclaim:null,
      effect_outcome:'unknown',runtime_qualified:false,terminal_fence:'unavailable',artifact_cleanup:'unverified',last_error:null}
    try {this.db.prepare('INSERT INTO registrations VALUES (?,?,?,?,?,?,?,?)').run(request.request_id,request.operation.operation_id,request.consumed_grant.grant_id,
      request.consumed_grant.reservation_id,registration.create_request_id,registration.name,registration_digest,canonicalJson(row))}
    catch(error){if(String(error.code).includes('CONSTRAINT')||String(error.message).includes('UNIQUE'))throw refused('guardian operation/grant/launch already fenced','REPLAYED');throw error}
    return copy(row)
  }
  save(row) {
    this.requireOwner();const old=this.lookup(row.request_id)
    if(!old||row.registration_digest!==old.registration_digest||canonicalJson(row.registration)!==canonicalJson(old.registration)
      ||(old.mode==='cleanup_requested'&&row.mode!=='cleanup_requested')||row.runtime_qualified!==false
      ||row.terminal_fence!=='unavailable'||row.artifact_cleanup!=='unverified'||row.effect_outcome!=='unknown')throw refused('guardian state cannot renew or qualify a job','RECONCILIATION_REQUIRED')
    this.db.prepare('UPDATE registrations SET body=? WHERE request_id=?').run(canonicalJson(row),row.request_id)
  }
  observeClock(now=Date.now()) {
    this.requireOwner();if(!Number.isSafeInteger(now))throw refused('guardian clock uncertain','RECONCILIATION_REQUIRED')
    const previous=this.db.prepare('SELECT last_clock FROM metadata').get().last_clock
    if(now<previous)return false
    this.db.prepare('UPDATE metadata SET last_clock=?').run(now);return true
  }
  close(){if(this.owned)throw refused('cannot close running guardian store','RECONCILIATION_REQUIRED');this.db.close()}
}
