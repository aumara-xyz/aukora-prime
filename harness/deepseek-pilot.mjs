// SPDX-License-Identifier: AGPL-3.0-or-later
// Native harness provider pilot. This is app-process custody, not C/E admission.
import {constants,lstatSync,openSync,closeSync,fstatSync} from 'node:fs';
import {isAbsolute,dirname} from 'node:path';
import {existsSync} from 'node:fs';
const owned=existsSync(new URL('../prime-release.json',import.meta.url))?'../prime-packages/':'../packages/';
const {openPrivateDatabase,transaction}=await import(new URL(owned+'inference/src/private-db.mjs',import.meta.url));
const CAP=10_000_000,DAY=86400000,MAX_BODY=65536,MAX_OUTPUT=1024;
// Conservative whole-micro-USD rates above the published Flash peak prices:
// https://api-docs.deepseek.com/quick_start/pricing/ (2026-10-03).
const INPUT_RATE=1,OUTPUT_RATE=2;
const fail=reason=>{throw Object.assign(new Error(reason),{code:'PRIME_DEEPSEEK_PILOT_UNAVAILABLE'});};
function privateFile(path){
 if(typeof path!=='string'||!isAbsolute(path)||typeof process.getuid!=='function')fail('Private provider file is not configured.');
 const uid=process.getuid(),parent=lstatSync(dirname(path));
 if(!parent.isDirectory()||parent.isSymbolicLink()||parent.uid!==uid||(parent.mode&0o077))fail('Provider directory must be owner-private.');
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const stat=fstatSync(fd);
  if(!stat.isFile()||stat.nlink!==1||stat.uid!==uid||(stat.mode&0o777)!==0o600||stat.size<1||stat.size>4096)fail('Provider key must be an owner-owned 0600 file.');
  return true;
 }finally{closeSync(fd);}
}
export const name='prime-deepseek-pilot';
export const inject=['llm','credentials'];
export function apply(ctx){
 const previous=globalThis.fetch;let active=true,db;
 function database(){
  if(db)return db;
  const path=process.env.PRIME_DEEPSEEK_BUDGET_FILE;
  if(typeof path!=='string'||!isAbsolute(path))fail('The persistent $10 provider budget is not configured.');
  const parent=lstatSync(dirname(path));
  if(!parent.isDirectory()||parent.isSymbolicLink()||parent.uid!==process.getuid()||(parent.mode&0o077))fail('Budget directory must be owner-private.');
  if(existsSync(path)){const s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o777)!==0o600)fail('Budget file must be owner-owned 0600.');}
  const candidate=openPrivateDatabase(path);
  try{
   candidate.exec('CREATE TABLE IF NOT EXISTS native_deepseek_budget (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, ceiling INTEGER NOT NULL, input_rate INTEGER NOT NULL, output_rate INTEGER NOT NULL, charged INTEGER NOT NULL, starts INTEGER NOT NULL, expires INTEGER NOT NULL, observed INTEGER NOT NULL, closed INTEGER NOT NULL);');
   transaction(candidate,()=>{
    const row=candidate.prepare('SELECT * FROM native_deepseek_budget WHERE singleton=1').get();
    if(!row){const now=Date.now();candidate.prepare('INSERT INTO native_deepseek_budget VALUES(1,1,?,?,?,?,?,?,?,0)').run(CAP,INPUT_RATE,OUTPUT_RATE,0,now,now+DAY,now);}
    else validateBudget(row);
   });db=candidate;return db;
  }catch(error){candidate.close();throw error;}
 }
 function validateBudget(row){
  if(!row||row.version!==1||row.ceiling!==CAP||row.input_rate!==INPUT_RATE||row.output_rate!==OUTPUT_RATE
   ||![row.starts,row.expires,row.observed,row.charged].every(Number.isSafeInteger)||row.expires-row.starts!==DAY
   ||row.observed<row.starts||row.charged<0||row.charged>CAP||![0,1].includes(row.closed))fail('Existing provider budget cannot be replaced or reset.');
 }
 function reserve(amount=0,{available=false}={}){
  const store=database();let reason;
  transaction(store,()=>{
   const row=store.prepare('SELECT * FROM native_deepseek_budget WHERE singleton=1').get(),now=Date.now();
   validateBudget(row);
   if(row.closed||now<row.observed||now>=row.expires){store.prepare('UPDATE native_deepseek_budget SET closed=1 WHERE singleton=1').run();reason='The fixed provider window has ended.';return;}
   if(row.charged+amount>CAP||available&&CAP-row.charged<(MAX_BODY+4096)*INPUT_RATE+MAX_OUTPUT*OUTPUT_RATE){reason='The aggregate $10 provider budget is exhausted.';return;}
   store.prepare('UPDATE native_deepseek_budget SET charged=charged+?,observed=? WHERE singleton=1').run(amount,now);
  });if(reason)fail(reason);
 }
 async function configuredCredential(){
  const described=await ctx.credentials.describe('DEEPSEEK_API_KEY');
  if(!described.configured||described.source!=='file')fail('Configure the native DeepSeek key in Models.');
  privateFile(process.env.PRIME_DEEPSEEK_KEY_FILE);
 }
 const guarded=async(input,init)=>{
  const url=new URL(typeof input==='string'||input instanceof URL?input:input.url);
  if(url.hostname!=='api.deepseek.com')return previous(input,init);
  if(!active||url.origin!=='https://api.deepseek.com'||url.search||url.hash||url.username||url.password)fail('Provider pilot is withdrawn.');
  await configuredCredential();
  if(!active||globalThis.fetch!==guarded)fail('Provider pilot is withdrawn.');
  const method=(init?.method??input?.method??'GET').toUpperCase();
  if(method==='GET'&&url.pathname==='/models'){reserve();return previous(input,{...init,redirect:'error'});}
  if(method!=='POST'||url.pathname!=='/chat/completions'||typeof init?.body!=='string')fail('Only the selected native chat endpoint is enabled.');
  const bytes=Buffer.byteLength(init.body,'utf8');if(bytes>MAX_BODY)fail('The native chat request exceeds the pilot context bound.');
  let body;try{body=JSON.parse(init.body);}catch{fail('Invalid native chat request.');}
  if(Object.hasOwn(body,'dsh_session_log'))fail('Session-log provider uploads are unavailable in this pilot.');
  if(body.model!=='deepseek-flash'||body.stream!==true||body.thinking?.type!=='disabled'
   ||!Number.isSafeInteger(body.max_tokens)||body.max_tokens<1||body.max_tokens>MAX_OUTPUT
   ||!Array.isArray(body.messages)||body.messages.length>256)fail('The selected Flash/text/output bounds are required.');
  for(const message of body.messages)if(message.content!==null&&typeof message.content!=='string')fail('Image and file provider requests are unavailable in this pilot.');
  // Bound the ACTUAL serialized request. JSON bytes overestimate text tokens;
  // extra framing allowance covers role/tool separators. Every HTTP attempt,
  // including auxiliary calls/retries, reserves BEFORE fetch. Never refund an
  // uncertain attempt; retained charges survive process restart and key changes.
  reserve((bytes+4096)*INPUT_RATE+body.max_tokens*OUTPUT_RATE);
  return previous(input,{...init,redirect:'error'});
 };
 globalThis.fetch=guarded;
 const status=async()=>{try{
  if(!active||globalThis.fetch!==guarded||!ctx.llm.listProviders().some(p=>p.id==='deepseek-official'))return false;
  await configuredCredential();if(!active||globalThis.fetch!==guarded)return false;
  reserve(0,{available:true});return true;
 }catch{return false;}};
 ctx.provide('primeNativeInference',Object.freeze({status}));
 ctx.effect(()=>()=>{active=false;db?.close();db=undefined;},'native DeepSeek $10 budget');
 // Keep the deny-only fence after disposal: a late native continuation must
 // never regain an unbudgeted fetch during app shutdown. No hot reload exists.
}
