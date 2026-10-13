// SPDX-License-Identifier: AGPL-3.0-or-later
// claim.py and revoke-sessions.mjs refuse session widening and require a stopped harness for revocation.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import { homedir } from 'node:os'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const claimPath = join(root, 'ops/node-spawn/ingress/claim.py')
const revokePath = join(root, 'ops/node-spawn/ingress/revoke-sessions.mjs')

const court = String.raw`
import base64, hashlib, importlib.util, json, pathlib, sys, tempfile
spec = importlib.util.spec_from_file_location('claim_under_test', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
def refused(call, code):
    try: call()
    except m.ClaimRefusal as error:
        assert error.code == code, (error.code, code)
        return
    raise AssertionError('accepted ' + code)
with tempfile.TemporaryDirectory(dir=pathlib.Path.cwd()) as temporary:
    origin, authority, owner = 'https://node.example.test', 'node.example.test', 'owner.example.test'
    expected_name = '__Host-dsh-auth-' + base64.urlsafe_b64encode(hashlib.sha256(authority.encode()).digest()).decode().rstrip('=')
    assert m.cookie_name(authority) == expected_name
    for local in ['localhost:18735', '127.0.0.1:18735', '127.0.0.2:18735', '[::1]:18735']:
        assert m.cookie_name(local).startswith('dsh-auth-') and not m.cookie_name(local).startswith('__Host-')
    now, code = 1000, 'A' * 43
    headers = {'host':authority,'origin':origin,'sec-fetch-site':'same-origin','content-type':'text/plain'}
    def fresh(name):
        directory = pathlib.Path(temporary) / name
        directory.mkdir(mode=0o700)
        return m.ClaimStore(directory / 'claims.json', require_root=False)
    result = {'ok':True,'result':{'app_origin':origin,'node':'a'*64,'expires_at_ms':1030000}}
    exchanges, forwards = [], []
    store = fresh('signin')
    spent = False
    def proxy(method, target, forwarded, payload):
        global spent
        assert method == 'POST' and target == '/owner/signin/redeem'
        assert forwarded == {'origin':'https://' + owner,'content-type':'application/json','sec-fetch-site':'same-origin','sec-fetch-mode':'cors','sec-fetch-dest':'empty'}
        assert json.loads(payload) == {'code':code,'app_origin':origin}
        forwards.append(payload)
        if spent: return 403, [], b'{}'
        spent = True
        return 200, [], json.dumps(result).encode()
    app = m.ClaimApplication(store, origin, authority, owner, lambda:exchanges.append(1) or 'fixture', proxy, clock=lambda:now)
    refused(lambda:app.handle('POST',m.SIGNIN_PATH,{**headers,'host':'wrong.example.test'},code.encode()),'CLAIM_HOST_REFUSED')
    refused(lambda:app.handle('POST',m.SIGNIN_PATH,{**headers,'origin':'https://wrong.example.test'},code.encode()),'CLAIM_ORIGIN_REFUSED')
    refused(lambda:app.handle('POST',m.SIGNIN_PATH,{**headers,'sec-fetch-site':'cross-site'},code.encode()),'CLAIM_ORIGIN_REFUSED')
    refused(lambda:app.handle('POST',m.SIGNIN_PATH,{**headers,'content-type':'application/json'},code.encode()),'CLAIM_CONTENT_TYPE_REFUSED')
    refused(lambda:app.handle('POST',m.SIGNIN_PATH,headers,b'x'*129),'CLAIM_REQUEST_TOO_LARGE')
    refused(lambda:app.handle('POST',m.SIGNIN_PATH,headers,b'x'),'CLAIM_INVALID')
    try: status, _, _ = app.handle('POST',m.SIGNIN_PATH,headers,code.encode())
    except m.ClaimRefusal as error: raise AssertionError('valid signin refused ' + error.code)
    assert status == 204 and exchanges == [1]
    rows = json.loads(store.path.read_text())['claims']
    assert len(rows) == 1 and rows[0]['digest'] == 'sha256:' + hashlib.sha256(code.encode()).hexdigest()
    assert rows[0]['spent_at'] == now and rows[0]['expires_at'] == 1030 and code not in store.path.read_text()
    refused(lambda:app.handle('POST',m.SIGNIN_PATH,headers,code.encode()),'SIGNIN_REDEEM_REFUSED')
    refused(lambda:store.mint(authority,now,60,code=code),'CLAIM_SPENT')
    refused(lambda:m.ClaimStore(store.path,require_root=False).consume(code,authority,now),'CLAIM_SPENT')
    assert exchanges == [1]
    _, _, page = app.handle('GET',m.SIGNIN_PATH,{'host':authority},b'')
    _, _, script = app.handle('GET',m.SIGNIN_PATH+'.js',{'host':authority},b'')
    assert b'/__aukora/signin.js' in page and b'https://owner.example.test/owner/signin' in script
    assert b"history.replaceState(null, '', location.pathname)" in script and b"fetch('/__aukora/signin'" in script
    for name, response in [('status',(403,[],b'{}')),('json',(200,[],b'!')),('false',(200,[],b'{"ok":false}'))]:
        failed = m.ClaimApplication(fresh(name),origin,authority,owner,lambda:exchanges.append(2),lambda *_args,response=response:response,clock=lambda:now)
        refused(lambda:failed.handle('POST',m.SIGNIN_PATH,headers,code.encode()),'SIGNIN_REDEEM_REFUSED' if name == 'status' else 'SIGNIN_REDEEM_INVALID')
    for field, value in [('app_origin','https://other.example.test'),('node','x'),('node',7),('expires_at_ms',999999),('expires_at_ms',1060001),('expires_at_ms','1030000')]:
        response = {'ok':True,'result':{**result['result'],field:value}}
        failed = m.ClaimApplication(fresh(field+str(value).replace('/','_')),origin,authority,owner,lambda:exchanges.append(2),lambda *_args,response=response:(200,[],json.dumps(response).encode()),clock=lambda:now)
        refused(lambda:failed.handle('POST',m.SIGNIN_PATH,headers,code.encode()),'SIGNIN_REDEEM_INVALID')
        assert not failed.store.path.exists()
    assert exchanges == [1]
    limited = m.ClaimApplication(fresh('limited'),origin,authority,owner,lambda:None,proxy,limiter=m.RateLimiter(maximum=0),clock=lambda:now)
    refused(lambda:limited.handle('POST',m.SIGNIN_PATH,headers,code.encode()),'CLAIM_RATE_LIMITED')
    refused(lambda:app.handle('POST',m.SIGNOUT_PATH,{**headers,'origin':'https://wrong.example.test'},b''),'CLAIM_ORIGIN_REFUSED')
    refused(lambda:app.handle('POST',m.SIGNOUT_PATH,headers,b'cookie'),'SIGNOUT_BODY_REFUSED')
    status, response_headers, body = app.handle('POST',m.SIGNOUT_PATH,headers,b'')
    cleared = next(value for name,value in response_headers if name == 'Set-Cookie')
    assert status == 204 and body == b'' and cleared == m.cookie_name(authority) + '=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict'
    def cookie(payload=None, age=86400, audience=authority, name=None, flags='; Secure; HttpOnly; SameSite=Strict; Path=/'):
        payload = payload or {'version':1,'authority':audience,'issuedAt':now*1000,'expiresAt':now*1000+age*1000}
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        return (name or m.cookie_name(authority)) + '=v1.' + body + '.opaque; Max-Age=' + str(age) + flags
    assert m.bounded_cookie(cookie(),authority,now) == cookie()
    for invalid in [cookie(age=86401),cookie(age=1,audience=owner),cookie(name='dsh-auth-wrong'),cookie(flags='; HttpOnly; SameSite=Strict; Path=/'),cookie(flags='; Secure; SameSite=Strict; Path=/'),cookie(flags='; Secure; HttpOnly; SameSite=Lax; Path=/'),cookie(flags='; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=example.test'),cookie({'version':1,'authority':authority,'issuedAt':now*1000+5001,'expiresAt':now*1000+6001},age=1),cookie({'version':1,'authority':authority,'issuedAt':0,'expiresAt':1000},age=1),cookie({'version':1,'authority':authority,'issuedAt':now*1000,'expiresAt':now*1000+2000},age=1)]:
        refused(lambda invalid=invalid:m.bounded_cookie(invalid,authority,now),'HARNESS_COOKIE_INVALID')
    descriptor = pathlib.Path(temporary) / 'launch.json'
    descriptor.write_text(json.dumps({'url':'http://127.0.0.1:18735/?token=fixture-only'}))
    descriptor.chmod(0o600)
    class Response:
        status = 303
        def read(self, _limit): return b''
        def getheader(self,name): return cookie(age=86401) if name == 'Set-Cookie' else '/'
    class Connection:
        def __init__(self,host,port,timeout): assert host == '127.0.0.1' and port == 18735
        def request(self,*args,**kwargs): pass
        def getresponse(self): return Response()
        def close(self): pass
    m.http.client.HTTPConnection = Connection
    m.time.time = lambda:now
    refused(lambda:m.HarnessCookieExchange(descriptor,origin,authority,18735)(),'HARNESS_COOKIE_INVALID')
print('PASS browser signin/session: original code spent durably; host/origin/audience/expiry refusals; cookie bound; authority signout')
`

function runPython(source) {
  return spawnSync('/usr/bin/python3', ['-I', '-S', '-c', court, source], { cwd: root, encoding: 'utf8', timeout: 10000 })
}

test('returning signin, authority signout and signed session bound with guard mutations', t => {
  const baseline = runPython(claimPath)
  assert.equal(baseline.status, 0, baseline.stderr)
  t.diagnostic(baseline.stdout.trim())
  const source = readFileSync(claimPath, 'utf8')
  const mutants = [
    ['public cookie prefix', '("" if loopback else "__Host-")', '""'],
    ['loopback cookie prefix', '("" if loopback else "__Host-")', '"__Host-"'],
    ['same code spent', 'code=code)', 'code=None)'],
    ['duplicate import', 'if any(row.get("digest") == f"sha256:{digest}" for row in retained):', 'if False:'],
    ['redeem success', 'if status_code != 200:', 'if False:'],
    ['redeem audience', 'or redeemed.get("app_origin") != self.public_origin', 'or False'],
    ['redeem node', 'or re.fullmatch(r"[0-9a-f]{64}", redeemed.get("node", "")) is None', 'or False'],
    ['redeem expiry', 'or not now_ms + 1000 <= redeemed.get("expires_at_ms", 0) <= now_ms + 60000', 'or False'],
    ['signout body', 'if body:\n                raise ClaimRefusal("SIGNOUT_BODY_REFUSED", 400)', 'if False:\n                raise ClaimRefusal("SIGNOUT_BODY_REFUSED", 400)'],
    ['signout exact cookie', 'cleared = cookie_name(self.public_authority)', 'cleared = cookie_name(self.owner_authority)'],
    ['signed lifetime', 'or not 0 < lifetime <= SESSION_SECONDS * 1000\n            or not 0 < max_age <= SESSION_SECONDS', 'or False\n            or False'],
    ['cookie lifetime match', 'or max_age * 1000 != lifetime', 'or False'],
    ['cookie audience', 'or payload.get("authority") != authority', 'or False'],
    ['cookie name', 'name != cookie_name(authority)', 'False'],
    ['cookie secure', 'or "secure" not in attributes', 'or False'],
    ['cookie httpOnly', 'or "httponly" not in attributes', 'or False'],
    ['cookie sameSite', 'or attributes.get("samesite") != "Strict"', 'or False'],
    ['cookie hostOnly', 'or "domain" in attributes', 'or False'],
    ['cookie future', 'issued > int(now * 1000) + 5000', 'False'],
    ['cookie expired', 'or expires <= int(now * 1000)', 'or False'],
    ['exchange signed bound', 'return bounded_cookie(cookie, self.authority, time.time())', 'return cookie'],
  ]
  const scratch = mkdtempSync(join(root, '.signin-mutants-'))
  try {
    for (const [name, before, after] of mutants) {
      assert.equal(source.split(before).length, 2, name)
      const file = join(scratch, name.replaceAll(' ', '-') + '.py')
      writeFileSync(file, source.replace(before, after))
      const result = runPython(file)
      assert.notEqual(result.status, 0, `surviving mutant ${name}`)
      assert.match(result.stderr, /AssertionError/u, name)
    }
  } finally { rmSync(scratch, { recursive: true, force: true }) }
  t.diagnostic(`MUTATION browser signin/session: ${mutants.length}/${mutants.length} killed`)
})

const revokeCourt = String.raw`
import assert from 'node:assert/strict'
import {mkdtempSync,writeFileSync,readFileSync,chmodSync,linkSync,symlinkSync,rmSync,renameSync,mkdirSync} from 'node:fs'
import {createRequire} from 'node:module'
import {join} from 'node:path'
import {pathToFileURL} from 'node:url'
const sourcePath=process.argv[1], harnessRoot=process.argv[2]
process.argv[1]='fixture-eval'
const m = await import(pathToFileURL(sourcePath))
const require = createRequire(join(harnessRoot,'packages/credentials/credentials-local/package.json'))
const {parseDocument} = require('yaml')
const {BrowserAuth} = await import(pathToFileURL(join(harnessRoot,'packages/client/connection/lib/types/browser-auth.js')))
const scratch = mkdtempSync(join(process.cwd(),'.revoke-fixture-'))
try {
  const file = join(scratch,'.credentials.yaml')
  const codeTree=join(scratch,'code'); mkdirSync(codeTree,{mode:0o755})
  const nested=join(codeTree,'nested'); mkdirSync(nested,{mode:0o755})
  const child=join(nested,'module.js'); writeFileSync(child,'export const synthetic=true\n',{mode:0o644})
  m.protectedCodeTree(codeTree,false)
  chmodSync(nested,0o777);assert.throws(()=>m.protectedCodeTree(codeTree,false),/SESSION_CODE_TREE_REFUSED/);chmodSync(nested,0o755)
  chmodSync(child,0o666);assert.throws(()=>m.protectedCodeTree(codeTree,false),/SESSION_FILE_REFUSED/);chmodSync(child,0o644)
  const codeLink=join(nested,'link.js');symlinkSync(child,codeLink);assert.throws(()=>m.protectedCodeTree(codeTree,false),/SESSION_PATH_REFUSED/);rmSync(codeLink)
  const record = {kind:'grant',payload:{version:1,secret:Buffer.alloc(32,1).toString('base64url')}}
  const data = {version:1,refs:{SYNTHETIC_MODEL_KEY:'fixture-only'},records:{'client-connection/browser-session':record,other:{kind:'grant',payload:{fixture:true}}}}
  const reset = () => writeFileSync(file,JSON.stringify(data)+'\n',{mode:0o600})
  reset()
  const provider = () => ({modifyRecord:async (_key,mutate) => { const current=parseDocument(readFileSync(file,'utf8')).toJS().records['client-connection/browser-session']; return await mutate(current) ?? current }})
  const before = await BrowserAuth.create({},provider(),1)
  let cookie
  before.authorizeIndex({method:'GET',url:new URL(before.authenticatedUrl('https://node.example.test')).pathname+new URL(before.authenticatedUrl('https://node.example.test')).search,headers:{host:'node.example.test'}},{writeHead:(_status,headers)=>{cookie=headers['set-cookie']},end:()=>{}})
  const request = {headers:{host:'node.example.test',cookie:cookie.split(';')[0]}}
  assert.equal(before.isAuthenticated(request),true)
  const calls=[]
  const lifecycle={stop:()=>{calls.push('stop');return true},inactive:()=>{calls.push('inactive');return true},start:()=>{calls.push('start');return true},active:()=>{calls.push('active');return true}}
  m.revokeAll(file,parseDocument,lifecycle,false)
  assert.deepEqual(calls,['stop','inactive','start','active'])
  const changed = parseDocument(readFileSync(file,'utf8')).toJS()
  assert.notEqual(changed.records['client-connection/browser-session'].payload.secret,record.payload.secret)
  assert.deepEqual(changed.refs,data.refs)
  assert.deepEqual(changed.records.other,data.records.other)
  assert.equal(before.isAuthenticated(request),true,'loaded old secret remains until restart')
  const after = await BrowserAuth.create({},provider(),1)
  assert.equal(after.isAuthenticated(request),false,'fresh activation rejects pre-rotation cookie')
  const args=['--harness-root','/opt/harness']
  m.validateInvocation('v24.11.1','linux',0,args)
  assert.throws(()=>m.validateInvocation('v24.11.2','linux',0,args),/SESSION_NODE_VERSION_REFUSED/)
  assert.throws(()=>m.validateInvocation('v24.11.1','darwin',0,args),/SESSION_ROOT_LINUX_REQUIRED/)
  assert.throws(()=>m.validateInvocation('v24.11.1','linux',501,args),/SESSION_ROOT_LINUX_REQUIRED/)
  assert.throws(()=>m.validateInvocation('v24.11.1','linux',0,[]),/SESSION_ARGUMENTS_REFUSED/)
  const unit='{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 scripts/launch-dsh.py --release /opt/release --state-root /home/aukora-host/genesis/state --foreground ; ignore_errors=no ; }'
  assert.equal(m.credentialsForUnit(unit),'/home/aukora-host/genesis/state/home/.credentials.yaml')
  assert.throws(()=>m.credentialsForUnit(unit.replace('/home/aukora-host/genesis/state','/home/other/state')),/SESSION_SERVICE_CONFIG_REFUSED/)
  assert.throws(()=>m.credentialsForUnit(unit.replace('scripts/launch-dsh.py','other.py')),/SESSION_SERVICE_CONFIG_REFUSED/)
  assert.throws(()=>m.credentialsForUnit(unit.replace('--foreground','--state-root /home/other/state')),/SESSION_SERVICE_CONFIG_REFUSED/)
  for (const [field,code] of [['stop','SESSION_HARNESS_STOP_FAILED'],['inactive','SESSION_HARNESS_STILL_RUNNING'],['start','SESSION_HARNESS_RESTART_FAILED'],['active','SESSION_HARNESS_RESTART_UNVERIFIED']]) {
    reset(); assert.throws(()=>m.revokeAll(file,parseDocument,{...lifecycle,[field]:()=>false},false),new RegExp(code))
    if (field === 'stop' || field === 'inactive') assert.deepEqual(parseDocument(readFileSync(file,'utf8')).toJS(),data)
  }
  reset(); chmodSync(file,0o644); assert.throws(()=>m.rotateSecret(file,parseDocument,false),/SESSION_FILE_REFUSED/); chmodSync(file,0o600)
  const linked=join(scratch,'hardlink'); linkSync(file,linked)
  assert.throws(()=>m.rotateSecret(file,parseDocument,false),/SESSION_FILE_REFUSED/); rmSync(linked)
  const symlink=join(scratch,'symlink'); symlinkSync(file,symlink)
  assert.throws(()=>m.rotateSecret(symlink,parseDocument,false),/SESSION_PATH_REFUSED/)
  chmodSync(scratch,0o777)
  try { assert.throws(()=>m.rotateSecret(file,parseDocument,true),/SESSION_PATH_REFUSED/) }
  finally { chmodSync(scratch,0o700) }
  writeFileSync(file,'version: 1\nversion: 2\n'); assert.throws(()=>m.rotateSecret(file,parseDocument,false),/SESSION_DOCUMENT_INVALID/)
  reset(); const invalid={...data,records:{'client-connection/browser-session':{kind:'grant',payload:{version:2,secret:'A'.repeat(43)}}}};writeFileSync(file,JSON.stringify(invalid));assert.throws(()=>m.rotateSecret(file,parseDocument,false),/SESSION_RECORD_INVALID/)
  writeFileSync(file,'version: 1\nrecords:\n  client-connection/browser-session: &shared\n    kind: grant\n    payload:\n      version: 1\n      secret: '+record.payload.secret+'\n  other: *shared\n')
  assert.throws(()=>m.rotateSecret(file,parseDocument,false),/SESSION_OTHER_CREDENTIALS_CHANGED/)
  reset(); const oversized=' '.repeat(1024*1024+1);writeFileSync(file,oversized);assert.throws(()=>m.rotateSecret(file,parseDocument,false),/SESSION_FILE_CHANGED/)
  reset(); let switched=false
  const raceParser=(...args)=>{const doc=parseDocument(...args);return {errors:doc.errors,toJS:()=>doc.toJS(),setIn:(...args)=>{doc.setIn(...args);renameSync(file,file+'.old');reset();switched=true},toString:()=>String(doc)}}
  assert.throws(()=>m.rotateSecret(file,raceParser,false),/SESSION_FILE_CHANGED/);assert.equal(switched,true)
  console.log('PASS pinned harness session revocation: old loaded key accepts; stop/rotate/restart activation rejects prior cookie; unrelated credentials preserved')
} finally {rmSync(scratch,{recursive:true,force:true})}
`

function builtHarness() {
  for (const directory of [join(root, 'vendor/dsh'), join(homedir(), 'aukora-genesis/vendor/dsh')]) {
    if (!existsSync(join(directory, 'packages/client/connection/lib/types/browser-auth.js'))) continue
    try {
      createRequire(join(directory, 'packages/credentials/credentials-local/package.json')).resolve('yaml')
      return directory
    } catch {}
  }
}

function runRevoke(source, harnessRoot) {
  return spawnSync(process.execPath, ['--input-type=module', '-e', revokeCourt, source, harnessRoot], { cwd: root, encoding: 'utf8', timeout: 10000 })
}

test('root session rotation uses the pinned harness format and requires restart, with guard mutations', t => {
  const harnessRoot = builtHarness()
  if (!harnessRoot) return t.skip('UNPERFORMED: pinned built harness browser auth and YAML dependency unavailable')
  const baseline = runRevoke(revokePath, harnessRoot)
  assert.equal(baseline.status, 0, baseline.stderr)
  t.diagnostic(baseline.stdout.trim())
  const source = readFileSync(revokePath,'utf8')
  const mutants = [
    ['node version', "if (version !== 'v24.11.1')", 'if (false)'],
    ['root Linux', "if (platform !== 'linux' || uid !== 0)", 'if (false)'],
    ['arguments', "if (arguments_.length !== 2 || arguments_[0] !== '--harness-root')", 'if (false)'],
    ['service launcher', "argv[1] !== 'scripts/launch-dsh.py'", 'false'],
    ['service state root', 'argv[index + 1] !== STATE_ROOT', 'false'],
    ['one state root', "argv.filter(value => value === '--state-root').length !== 1", 'false'],
    ['actual credentials path', "return join(STATE_ROOT, 'home/.credentials.yaml')", "return join(STATE_ROOT, '.credentials.yaml')"],
    ['code directory nonwritable', '(info.mode & 0o022)\n    || (rootOnly', 'false\n    || (rootOnly'],
    ['code closure recursion', 'protectedCodeTree(path, rootOnly)', 'void path'],
    ['stop', 'if (!lifecycle.stop())', 'if (false)'],
    ['inactive', 'if (!lifecycle.inactive())', 'if (false)'],
    ['restart', 'if (!lifecycle.start())', 'if (false)'],
    ['active', 'if (!lifecycle.active())', 'if (false)'],
    ['hardlink', '|| info.nlink !== 1', ''],
    ['private file', '(privateFile && (info.mode & 0o077))', 'false'],
    ['canonical path', 'realpathSync(path) !== path', 'false'],
    ['protected ancestry', "if (!ancestor.isDirectory() || ancestor.isSymbolicLink() || (ancestor.mode & 0o022)\n        || ![0, privateFile ? info.uid : 0].includes(ancestor.uid))", 'if (false)'],
    ['document', 'if (document.errors.length)', 'if (false)'],
    ['record version', 'record.payload.version !== 1', 'false'],
    ['bounded read', '|| opened.size > 1024 * 1024', ''],
    ['write race', 'if (current.ino !== original.ino || current.dev !== original.dev)', 'if (false)'],
    ['unrelated credentials', "if (!isDeepStrictEqual(document.toJS(), expected))", 'if (false)'],
    ['actual rotation', "const secret = randomBytes(32).toString('base64url')", 'const secret = record.payload.secret'],
  ]
  const scratch = mkdtempSync(join(root,'.revoke-mutants-'))
  try {
    for (const [name,before,after] of mutants) {
      assert.equal(source.split(before).length,2,name)
      const file=join(scratch,name.replaceAll(' ','-')+'.mjs')
      writeFileSync(file,source.replace(before,after))
      const result=runRevoke(file, harnessRoot)
      assert.notEqual(result.status,0,`surviving mutant ${name}`)
      assert.match(result.stderr,/AssertionError/u,name)
    }
  } finally {rmSync(scratch,{recursive:true,force:true})}
  t.diagnostic(`MUTATION root session revocation: ${mutants.length}/${mutants.length} killed`)
})
