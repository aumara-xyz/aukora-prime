// Scoped acceptance against an explicitly named disposable preview; never records access material.
import assert from 'node:assert/strict';
import {mkdtempSync, chmodSync, symlinkSync, linkSync, rmSync, realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {privateDirectory, readPrivateJson, writePrivateJson, cleanOrigin} from './private-state.mjs';
const [accessPath, expectedPidText] = process.argv.slice(2);
assert(accessPath && /^[1-9]\d*$/.test(expectedPidText), 'explicit disposable descriptor and expected PID required');
const expectedPid = Number(expectedPidText);
const access = readPrivateJson(resolve(accessPath));
assert.deepEqual(Object.keys(access).sort(), ['pid','url']);
assert.equal(access.pid, expectedPid);
const url = new URL(access.url), origin = cleanOrigin(access.url);
assert.equal(url.searchParams.size, 1); assert(url.searchParams.has('token'));
const plain = await fetch(origin, {redirect:'manual'}); assert.equal(plain.status,401);
const exchanged = await fetch(access.url,{redirect:'manual'});
assert.equal(exchanged.status,303); assert.equal(exchanged.headers.get('location'),'/');
const header = exchanged.headers.get('set-cookie'); assert(header);
assert(/HttpOnly/i.test(header) && /SameSite=Strict/i.test(header) && !/Domain=/i.test(header));
const cookie = header.split(';',1)[0];
const headers = {cookie, 'content-type':'application/json'};
async function rpc(method,args) {
 const r = await fetch(origin+'api/'+method,{method:'POST',headers,redirect:'manual',
  body:JSON.stringify({type:'client-request',rpcId:'prime-disposable-check',method,payload:{args}})});
 return {status:r.status, value:r.headers.get('content-type')?.includes('json')?await r.json():null};
}
const cap = await fetch(origin+'api/prime/capabilities',{headers:{cookie},redirect:'manual'});
assert.equal(cap.status,200); const caps=await cap.json(); assert.equal(caps.runtime_pid,expectedPid);
assert.equal(caps.qualification,'PENDING'); assert(caps.unavailable_capabilities.includes('approved-shell'));
const onboarding = await rpc('settings/update',{ns:'ui-onboarding',patch:{welcomeNoticeVersion:'prime-disposable-check'}});
assert.equal(onboarding.status,200); assert.equal(onboarding.value?.result?.ok,true);
const theme=await rpc('settings/update',{ns:'ui-theme',patch:{preference:'dark'}});
assert.equal(theme.value?.result?.ok,true);
for(const [method,args] of [
 ['settings/update',{ns:'prime-inference',patch:{enabled:true}}],
 ['credentials/set',{ref:'test',value:'synthetic-not-a-key'}],
 ['directoryPicker/createDirectory',{path:'/tmp',name:'prime-must-not-create'}],
 ['session/create',{cwd:'/tmp'}],
]) {
 const r=await rpc(method,args); assert(r.status===404 || r.value?.result?.ok===false, 'effect route accepted');
}
const duplicate=await fetch(origin+'api/settings/update',{method:'POST',headers,redirect:'manual',body:'{"type":"client-request","type":"client-request"}'});
assert.equal(duplicate.status,400);
const contract=await fetch(origin+'prime/contracts/json.mjs',{headers:{cookie}}); assert.equal(contract.status,200);
assert.equal((await fetch(origin,{redirect:'manual'})).status,401);
const fixture=realpathSync(mkdtempSync(join(tmpdir(),'prime-private-state-check-')));
try {
 privateDirectory(fixture); const path=join(fixture,'state.json'); writePrivateJson(path,{fixture:true});
 assert.deepEqual(readPrivateJson(path),{fixture:true}); chmodSync(path,0o644);
 assert.throws(()=>readPrivateJson(path),/PRIVATE_STATE_REFUSED/); chmodSync(path,0o600);
 linkSync(path,join(fixture,'hard.json')); assert.throws(()=>readPrivateJson(path),/PRIVATE_STATE_REFUSED/);
 symlinkSync(path,join(fixture,'sym.json')); assert.throws(()=>readPrivateJson(join(fixture,'sym.json')),/PRIVATE_STATE_REFUSED/);
 chmodSync(fixture,0o755); assert.throws(()=>privateDirectory(fixture),/PRIVATE_STATE_REFUSED/); chmodSync(fixture,0o700);
} finally {rmSync(fixture,{recursive:true,force:true});}
console.log(JSON.stringify({status:'PASS',pid:expectedPid,scope:'disposable preview auth, bounded settings, effect refusals, strict HTTP ingress and private-state guards',qualification:'PENDING',credentials_recorded:false}));
