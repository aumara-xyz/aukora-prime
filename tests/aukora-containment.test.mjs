// SPDX-License-Identifier: AGPL-3.0-or-later
// Source parsers/verdicts, mocked boundaries and owned local FD fixtures. Never invoke live probes,
// privileged launch plans, firewall/service tools or production endpoints.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { validateConfinementInfo } from '../plugins/aukora-openshell-confinement/lib/transport.mjs'

const probe = fileURLToPath(new URL('../scripts/audit/containment/probe.py', import.meta.url))
const runner = fileURLToPath(new URL('../scripts/audit/containment/run.py', import.meta.url))
const custodyBody = fileURLToPath(new URL('../packages/boundary-gate/host/openshell/custody/sbx_exec_body.sh', import.meta.url))
const setup = String.raw`
import importlib.util,json,errno,os,socket,sys
from unittest.mock import patch,Mock
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
with patch('subprocess.Popen',side_effect=AssertionError('import performed effects')):
    p=load('probe',sys.argv[1]); r=load('runner',sys.argv[2])
`
function check(body, sources = []) {
  const result = spawnSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', setup + body, probe, runner, ...sources], {
    encoding: 'utf8', timeout: 8000, maxBuffer: 64 * 1024,
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'C', TMPDIR: '/tmp' },
  })
  assert.equal(result.error, undefined)
  assert.equal(result.status, 0, result.stderr)
  return result.stdout
}

// Source-only sensitivity: actual owned local descriptors cross the production
// Bash close loop. Darwin projects only the Linux FD-directory identity condition
// and the detector's /proc path spelling. No descriptor closure is mocked.
// Local workspace IO does not qualify the actual guest O_TMPFILE workspace path.
const guestFdFixture = String.raw`
import ast,fcntl,re,shlex,stat,subprocess,tempfile
with open(sys.argv[3],encoding='utf-8') as source_file:source=source_file.read()
constants=re.findall(r"^guest_fd_close='([^']*)'\s*$",source,re.MULTILINE)
assert len(constants)==1,'one literal production preamble required'
production_preamble=constants[0]
linux_identity='[ -d /dev/fd ] && [ /dev/fd -ef /proc/$$/fd ]'
assert production_preamble.startswith(linux_identity+' || ')
assert production_preamble.count(linux_identity)==1
assert sys.platform in ('darwin','linux'),'unsupported local source-fixture platform'
projected=sys.platform=='darwin'
preamble=production_preamble.replace(linux_identity,'[ -d /dev/fd ]',1) if projected else production_preamble
# SOURCEFIXTURE only: Darwin has no /proc. The unchanged full production guard
# must separately refuse there. Actual Linux guest guard/runtime is UNPERFORMED.
assert 'guest="$guest_fd_close"\'infra() {' in source
assert source.count('/bin/bash -p -c "$guest"')==2,'ordinary and cancellation must use the preamble'
stream=re.search(r"exec /usr/bin/python3 -I -S -c '(\n.*?)\n' \"\$t\" \"\$id1\" \"\$0\" \"\$guest_fd_close\"",source,re.DOTALL)
assert stream,'stream must receive the same constant'
tree=ast.parse(stream[1])
remote=next(node.value for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='remote' for target in node.targets))
assert isinstance(remote,ast.BinOp) and isinstance(remote.op,ast.Add)
assert isinstance(remote.left,ast.Constant) and remote.left.value=='exec /bin/bash -p -c '
quoted=remote.right
assert isinstance(quoted,ast.Call) and isinstance(quoted.func,ast.Attribute) and quoted.func.attr=='quote'
assert isinstance(quoted.func.value,ast.Name) and quoted.func.value.id=='shlex' and len(quoted.args)==1
combined=quoted.args[0]
assert isinstance(combined,ast.BinOp) and isinstance(combined.op,ast.Add)
assert isinstance(combined.left,ast.Name) and combined.left.id=='preamble'
assert isinstance(combined.right,ast.Constant) and combined.right.value.startswith('\nprintf "AUKORA-STREAM-ADMITTED')
assert combined.right.value.endswith('exec /usr/bin/python3 -I /usr/lib/aukora/exec.py')

# Device classification is a source case, independent of protected path prefixes.
for master_path in ['/dev/ptmx','/dev/pts/ptmx']:
    with patch.object(p.os,'listdir',return_value=['130']),patch.object(p.os,'readlink',return_value=master_path):
        result,metadata=p.inherited_handles({'protected_prefixes':[]})
    assert result=='ALLOWED' and metadata['leaks']==[{'fd':130,'kind':'terminal-master'}]

child_code=r'''
import os,sys
# Capture actual inherited state before source imports can reuse closed numbers.
snapshot={}
closed=[]
for number in [0,1,2]+[int(value) for value in sys.argv[4].split(',')]:
    try:info=os.fstat(number)
    except OSError as error:
        if error.errno!=9:raise
        closed.append(number)
    else:snapshot[number]=(info.st_dev,info.st_ino,info.st_mode,info.st_rdev)
import importlib.util,json,stat
from unittest.mock import patch
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
with patch('subprocess.Popen',side_effect=AssertionError('source import performed effects')):
    p=load('probe',sys.argv[1]);r=load('runner',sys.argv[2])
fixtures=json.loads(sys.argv[5]);workspace=sys.argv[3]
roles={str(number):{'device':snapshot[number][0],'inode':snapshot[number][1],'mode':snapshot[number][2]} for number in [0,1,2]}
for number,observed in snapshot.items():
    if number>2:assert list(observed)==fixtures[str(number)]['identity'],'descriptor identity changed before observation'
stdin=os.read(0,64)
assert stdin==b'owned fixture stdin\n'
owned_path=os.path.join(workspace,'workspace-proof')
try:
    with open(owned_path,'xb+') as owned:
        owned.write(b'owned workspace proof\n');owned.flush();owned.seek(0)
        assert owned.read()==b'owned workspace proof\n'
finally:
    if os.path.exists(owned_path):os.unlink(owned_path)
ws={'run_id':'guest-fd-fixture','route_id':'ws','route':'workspace-write','target':workspace,'result':'OK','detail':'owned local workspace round-trip; actual guest workspace UNPERFORMED'}
expected=[{'route_id':'ws','route':'workspace-write','target':workspace,'expect':'OK'},
          {'route_id':'fds','route':'inherited-handle','target':'all','expect':'DENIED'}]
manifest={'schema_version':1,'run_id':'guest-fd-fixture','phase':'real','expected_routes':[expected[1]],
          'protected_prefixes':[workspace],'stdio_roles':roles}
actual_listdir=p.os.listdir;actual_readlink=p.os.readlink
def list_projection(path):
    if path=='/proc/self/fd':return [str(number) for number in snapshot]
    return actual_listdir(path)
observations=[]
for terminal_path in ['/dev/ptmx','/dev/pts/ptmx']:
    def link_projection(path):
        if not path.startswith('/proc/self/fd/'):return actual_readlink(path)
        number=int(path.rsplit('/',1)[1]);observed=snapshot[number]
        if stat.S_ISSOCK(observed[2]):return 'socket:['+str(observed[1])+']'
        if number>2:
            fixture=fixtures[str(number)]
            if fixture['kind']=='terminal-master':return terminal_path
            return fixture['link']
        return '/dev/null' if number==0 else 'pipe:['+str(observed[1])+']'
    with patch.object(p.os,'listdir',side_effect=list_projection),patch.object(p.os,'readlink',side_effect=link_projection):
        fdrow=list(p.run_probe(manifest))[0]
    summary=r.summarize(r.parse_jsonl('\n'.join(json.dumps(row) for row in [ws,fdrow])+'\n'),expected,'guest-fd-fixture','real')
    observations.append({'row':fdrow,'status':summary['status']})
os.write(2,b'owned fixture stderr\n')
print(json.dumps({'workspace':'OK','scope':'owned-local-source-fixture','open_fds':sorted(snapshot),'closed_fds':closed,'observations':observations}))
'''

def fixture(use_closer,full_guard_refusal=False):
    with tempfile.TemporaryDirectory(prefix='containment-guest-fds-') as workspace:
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        originals=[];passed=[];fixtures={};pty_available=False
        def record(number,kind,link):
            passed.append(number)
            info=os.fstat(number)
            fixtures[str(number)]={'kind':kind,'link':link,'identity':[info.st_dev,info.st_ino,info.st_mode,info.st_rdev]}
        def duplicate(original,number,kind,link):
            actual=fcntl.fcntl(original,fcntl.F_DUPFD,number)
            record(actual,kind,link)
            assert actual==number,'owned fixture FD allocation changed'
        try:
            os.dup2(left.fileno(),7,inheritable=True);record(7,'socket','socket:fixture')
            duplicate(left.fileno(),128,'socket','socket:fixture')
            read_end,write_end=os.pipe();originals.extend([read_end,write_end])
            duplicate(read_end,129,'pipe','pipe:fixture')
            path=os.path.join(workspace,'owned-file')
            file_fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600);originals.append(file_fd)
            duplicate(file_fd,131,'file',path)
            try:master,slave=os.openpty()
            except (AttributeError,OSError):pass
            else:
                originals.extend([master,slave])
                duplicate(master,130,'terminal-master','/dev/ptmx');pty_available=True
            child_argv=['/usr/bin/python3','-I','-S','-B','-c',child_code,sys.argv[1],sys.argv[2],workspace,
                        ','.join(str(number) for number in passed),json.dumps(fixtures)]
            selected=production_preamble if full_guard_refusal else preamble
            child_command=(selected if use_closer else '')+'\nexec '+shlex.join(child_argv)
            result=subprocess.run(['/bin/bash','-p','-c',child_command],input=b'owned fixture stdin\n',
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,pass_fds=tuple(passed),
                timeout=4,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TMPDIR':'/tmp'})
            if full_guard_refusal:
                assert projected,'full-guard refusal case is Darwin-only'
                assert result.returncode==125,result.stderr.decode('utf-8','replace')
                assert result.stdout==b''
                assert result.stderr==b'aukora-openshell-confinement: guest-fd-closure-unavailable\n'
                return {'full_guard':'REFUSED','passed':sorted(passed)}
            assert result.returncode==0,result.stderr.decode('utf-8','replace')
            assert result.stderr==b'owned fixture stderr\n'
            observed=json.loads(result.stdout)
            observed.update(passed=sorted(passed),pty_available=pty_available,
                identity_condition='SOURCEFIXTURE' if projected else 'full-production-local-Linux',
                actual_guest_guard='UNPERFORMED')
            return observed
        finally:
            for number in passed+originals:os.close(number)
            left.close();right.close()
`

test('production guest close loop preserves owned local workspace and standard IO (source-only)', () => check(guestFdFixture + String.raw`
if projected:
    refusal=fixture(True,full_guard_refusal=True)
    assert refusal['full_guard']=='REFUSED' and {7,128,129,131}.issubset(refusal['passed'])
observed=fixture(True)
assert observed['workspace']=='OK' and observed['scope']=='owned-local-source-fixture'
assert observed['actual_guest_guard']=='UNPERFORMED'
if projected:assert observed['identity_condition']=='SOURCEFIXTURE'
assert observed['open_fds']==[0,1,2]
assert sorted(observed['closed_fds'])==observed['passed']
assert all(item['status']=='PASS' for item in observed['observations'])
`, [custodyBody]))

test('production guest close loop removes actual inherited socket, pipe, file and owned PTY handles (source-only)', () => check(guestFdFixture + String.raw`
observed=fixture(True)
assert {7,128,129,131}.issubset(observed['closed_fds'])
if observed['pty_available']:assert 130 in observed['closed_fds']
for item in observed['observations']:
    row=item['row']
    assert row['result']=='DENIED' and row['complete'] is True
    assert row['metadata']=={'leaks':[],'unclassified':[]}
`, [custodyBody]))

test('removing only the guest closer exposes ALLOWED inherited handles and fails unchanged expectations', () => check(guestFdFixture + String.raw`
observed=fixture(False)
assert {7,128,129,131}.issubset(observed['open_fds'])
assert not observed['closed_fds']
for item in observed['observations']:
    row=item['row']
    assert row['result']=='ALLOWED' and row['complete'] is True and item['status']=='FAIL'
    assert {leak['fd'] for leak in row['metadata']['leaks'] if leak['kind']=='socket'}=={7,128}
    if observed['pty_available']:
        assert {'fd':130,'kind':'terminal-master'} in row['metadata']['leaks']
`, [custodyBody]))

test('probe output caps preserve an already observed ALLOWED or FAIL', () => check(String.raw`
base={'run_id':'fixture','route_id':'fd','route':'inherited-handle','target':'self','result':'ALLOWED','detail':'observed','metadata':{'leaks':'x'*70000}}
row=json.loads(next(p.bounded_output([base])))
assert row['result']=='ALLOWED' and row['complete'] is False and 'metadata' not in row
failed=dict(base,result='FAIL')
assert json.loads(next(p.bounded_output([failed])))['result']=='FAIL'
ordinary=dict(base,result='OBSERVED',metadata={'rows':'x'*48000})
adverse=dict(base,metadata={'leaks':'x'*60000})
emitted=[]
try:
    for line in p.bounded_output([ordinary]*4+[adverse]):emitted.append(line)
except ValueError:pass
assert any(json.loads(line)['result']=='ALLOWED' for line in emitted)
assert sum(len(line.encode())+1 for line in emitted)<=p.MAX_BYTES
assert r.summarize(r.parse_jsonl('\n'.join(emitted)), [{'route_id':'fd','route':'inherited-handle','target':'self','expect':'DENIED'}], 'fixture','real')['status']=='FAIL'
`))

test('enumeration retains abstract Unix, wildcard/IPv6 listeners and every effective mount field', () => check(String.raw`
u=p.unix_rows('Num RefCount Protocol Flags Type St Inode Path\n0: 2 0 0 0001 01 9 @decoy\n1: 2 0 0 0002 01 10 /run/decoy.sock\n')
assert [x['address'] for x in u]==['@decoy','/run/decoy.sock']
assert u[1]['type']=='0002'
head='sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
line='0: 0100007F:451A 00000000:0000 0A 0:0 00:0 0 1007 0 9\n'
rows=p.tcp_rows(head+line,socket.AF_INET)
assert rows[0]['host']=='127.0.0.1' and rows[0]['port']==17690
assert p.tcp_rows(head+line.replace('0100007F','00000000'),socket.AF_INET)[0]['host']=='0.0.0.0'
v6='0: 00000000000000000000000001000000:451A 0:0 0A 0:0 00:0 0 1007 0 9\n'
assert p.tcp_rows(head+v6,socket.AF_INET6)[0]['host']=='::1'
assert not p.tcp_rows(head+line.replace(' 0A ',' 01 '),socket.AF_INET)
for parser in [p.unix_rows,lambda raw:p.tcp_rows(raw,socket.AF_INET)]:
    for bad in ['', 'garbage\n']:
        try:parser(bad)
        except ValueError:pass
        else:raise AssertionError('missing inventory header accepted')
raw='42 1 0:2 / /sandbox rw,nosuid shared:3 - tmpfs tmpfs rw,size=16k\n'
mount=p.mountinfo_rows(raw)[0]
assert mount=={'mount_id':'42','parent_id':'1','device':'0:2','root':'/','mountpoint':'/sandbox','options':['nosuid','rw'],'optional':['shared:3'],'filesystem':'tmpfs','source':'tmpfs','super_options':['rw','size=16k']}
assert p.mountinfo_rows(raw.replace('42 1','91 70'))!=[mount]
assert p.mountinfo_rows(raw.replace('/sandbox','/space\\040name'))[0]['mountpoint']=='/space name'
for bad in ['',raw.replace(' - ',' ')]:
    try:p.mountinfo_rows(bad)
    except ValueError:pass
    else:raise AssertionError('malformed mount evidence accepted')
assert p.id_map_rows('0 200000 65536\n')==[{'container_id':0,'host_id':200000,'size':65536}]
with patch.object(p.os,'listdir',return_value=['1','2']),patch.object(p.os,'getpid',return_value=2),patch.object(p,'process_identity',side_effect=lambda pid:{'pid':pid,'uid':1007,'start_time':'7'}),patch.object(p.os,'readlink',return_value='pid:[12]'),patch.object(p,'read_bounded',return_value='0 200000 65536\n'):
    procs=p.inventory('inventory-processes',{'process_uid':1007},999999999)
    assert [row['pid'] for row in procs['processes']]==[1,2]
    assert r._identity(procs['processes'][0])
with patch.object(p,'read_bounded',side_effect=['1 (synthetic) '+' '.join(['S']+['0']*18+['7']),'Uid: 1007 1007 1007 1007\n']):
    assert p.process_identity(1)=={'pid':1,'uid':1007,'start_time':'7'}
for bad in ['', '0 200000 0', '0 200000 1\n0 200001 1', '0 200000 1\n1 200000 1', '0 4294967295 2', '0 200000 NaN']:
    try:p.id_map_rows(bad)
    except ValueError:pass
    else:raise AssertionError('bad identity map accepted')
`))

test('production access opens and closes without reading, truncating, writing or signalling', () => check(String.raw`
m={'run_id':'fixture','observer_inventory':{'run_id':'fixture','complete':True,'targets':{'/protected/decoy':{'present':True},'21':{'present':True}}},'processes':[{'pid':21,'start_time':'7','uid':1007}]}
with patch.object(p.os,'O_PATH',0o10000000,create=True),patch.object(p,'directory_handle',return_value=44),patch.object(p.os,'fstat',return_value=Mock(st_mode=0o100600,st_ino=9,st_dev=8)),patch.object(p.os,'open',return_value=45) as opened,patch.object(p.os,'close') as closed,patch.object(p.os,'read',side_effect=AssertionError('read')),patch.object(p.os,'write',side_effect=AssertionError('write')):
    assert p.protected_access('file-write-access','/protected/decoy',m)[0]=='ALLOWED'
    flags=opened.call_args.args[1]
    assert flags & os.O_WRONLY and not flags & os.O_TRUNC and not flags & os.O_CREAT
    assert closed.call_count==3
with patch.object(p,'exact_identity',return_value=True),patch.object(p.os,'kill') as kill:
    assert p.protected_access('process-signal','21',m)[0]=='ALLOWED'
    kill.assert_called_once_with(21,0)
with patch.object(p,'exact_identity',return_value=True),patch.object(p.os,'open',return_value=45),patch.object(p.os,'close'),patch.object(p.os,'pread',side_effect=AssertionError('protected memory read')):
    assert p.protected_access('process-mem','21',m)[0]=='ALLOWED'
assert p.access_result(PermissionError(errno.EACCES,'denied'))=='DENIED'
for err in [FileNotFoundError(errno.ENOENT,'missing'),ConnectionRefusedError(errno.ECONNREFUSED,'absent'),TimeoutError(),OSError(errno.EMFILE,'limit')]:
    assert p.access_result(err)=='INCONCLUSIVE'
with patch.object(p.os,'listdir',return_value=['0','7']),patch.object(p.os,'readlink',return_value='socket:[9]'),patch.object(p.os,'pread',side_effect=AssertionError('inherited data read')):
    assert p.inherited_handles({'protected_prefixes':['/protected']})[0]=='ALLOWED'
with patch.object(p.os,'listdir',return_value=['0']),patch.object(p.os,'readlink',return_value='socket:[9]'):
    assert p.inherited_handles({'protected_prefixes':[]})[0]=='ALLOWED'
with patch.object(p,'exact_identity',side_effect=PermissionError(errno.EACCES,'identity unavailable')):
    manifest=dict(m,schema_version=1,phase='real',expected_routes=[{'route_id':'pid','route':'process-signal','target':'21','expect':'DENIED'}])
    assert list(p.run_probe(manifest))[0]['result']=='INCONCLUSIVE'
with patch.object(p.os,'O_PATH',0o10000000,create=True),patch.object(p,'directory_handle',return_value=44),patch.object(p.os,'fstat',return_value=Mock(st_mode=0o10600)),patch.object(p.os,'open',side_effect=[45,AssertionError('special file content opened')]) as opened,patch.object(p.os,'close'):
    try:p.protected_access('file-write-access','/protected/decoy',m)
    except ValueError:pass
    else:raise AssertionError('special file accepted')
    assert opened.call_count==1
with patch.object(p.os,'listdir',return_value=['0']),patch.object(p.os,'readlink',return_value='memfd:sensitive'),patch.object(p.os,'fstat',return_value=Mock(st_mode=0o100600,st_ino=9,st_dev=8)):
    assert p.inherited_handles({'protected_prefixes':[]})[0]=='INCONCLUSIVE'
assert not issubclass(p.ProbeDeadline,Exception)
`))

test('environment and mount readback never substitute a partial or self-supplied inventory', () => check(String.raw`
env={'PATH':'/usr/bin:/bin','SECRET':'do-not-print'}
with patch.dict(p.os.environ,env,clear=True):
    got=p.inventory('final-environment',{'environment':{'keys':['PATH','SECRET'],'values':{'PATH':'/usr/bin:/bin'}}},999999999)
    assert 'do-not-print' not in json.dumps(got)
    for blueprint in [{'keys':['PATH'],'values':{}},{'keys':['PATH','SECRET'],'values':{'SECRET':'do-not-print'}}]:
        try:p.inventory('final-environment',{'environment':blueprint},999999999)
        except ValueError:pass
        else:raise AssertionError('bad environment blueprint accepted')
raw='1 0 0:1 / / rw - tmpfs tmpfs rw\n'
with patch.object(p,'read_bounded',return_value=raw),patch.object(p.os,'readlink',return_value='mnt:[fixture]'):
    want=p.mountinfo_rows(raw)
    assert p.inventory('final-mountinfo',{'mountinfo':want},999999999)['mounts']==want
    try:p.inventory('final-mountinfo',{'mountinfo':[]},999999999)
    except ValueError:pass
    else:raise AssertionError('subset mount inventory accepted')
try:p.strict_json('{"x":1,"x":2}')
except ValueError:pass
else:raise AssertionError('duplicate JSON accepted')
try:p.strict_json('{"x":NaN}')
except ValueError:pass
else:raise AssertionError('nonfinite JSON accepted')
`))

test('any ALLOWED real evidence fails, including unexpected, duplicate and malformed rows', () => check(String.raw`
expected=[{'route_id':'ws','route':'workspace-write','target':'/sandbox','expect':'OK'},{'route_id':'tcp','route':'socket-tcp','target':'127.0.0.1:17690','expect':'DENIED'}]
def row(i,kind,target,result):return {'run_id':'fixture','route_id':i,'route':kind,'target':target,'result':result,'detail':''}
ws=row('ws','workspace-write','/sandbox','OK'); tcp=row('tcp','socket-tcp','127.0.0.1:17690','DENIED')
def summarize(lines):return r.summarize(r.parse_jsonl(lines),expected,'fixture','real')
good='\n'.join(json.dumps(x) for x in [ws,tcp])+'\n'
assert summarize(good)['status']=='PASS'
assert summarize(json.dumps(ws)+'\n')['status']=='INCONCLUSIVE'
assert summarize('')['status']=='INCONCLUSIVE'
allowed=row('unexpected','socket-tcp','127.0.0.1:17690','ALLOWED')
for extra in [json.dumps(allowed),'{"result":"ALLOWED","result":"DENIED"}','{"result":"ALLOWED",broken}',json.dumps(dict(tcp,result='ALLOWED'))]:
    assert summarize(good+extra+'\n')['status']=='FAIL'
assert summarize(good+json.dumps(tcp)+'\n')['status']=='INCONCLUSIVE'
assert summarize(good+'broken\n')['status']=='INCONCLUSIVE'
assert r.summarize(r.parse_jsonl(good),expected,'fixture','real',timed_out=True)['status']=='INCONCLUSIVE'
assert r.summarize(r.parse_jsonl(good),expected,'fixture','real',truncated=True)['status']=='INCONCLUSIVE'
assert r.summarize(r.parse_jsonl(good),expected,'fixture','real',returncode=1)['status']=='INCONCLUSIVE'
for unsafe in ['OBSERVED','OK','ALLOWED']:
    altered=[expected[0],dict(expected[1],expect=unsafe)]
    assert r.summarize(r.parse_jsonl(good),altered,'fixture','real')['status']=='INCONCLUSIVE'
`))

test('empty or incomplete aggregate controls and observer evidence cannot claim containment', () => check(String.raw`
assert r.evaluate_runs([],{}, {},[])['status']!='PASS'
route={'route_id':'ws','route':'workspace-write','target':'/sandbox','expect':'OK'}
spec={'name':'guest','phase':'real','run_id':'fixture','expected_routes':[route]}
row={'run_id':'fixture','route_id':'ws','route':'workspace-write','target':'/sandbox','result':'OK','detail':''}
record={'parsed':r.parse_jsonl(json.dumps(row)+'\n'),'returncode':0}
assert r.evaluate_runs([spec],{'guest':record},{},[])['status']=='INCONCLUSIVE'
bad=dict(row,result='ALLOWED')
record['parsed']=r.parse_jsonl(json.dumps(bad)+'\n')
assert r.evaluate_runs([spec],{'guest':record},{},[])['status']=='FAIL'
`))

test('complete synthetic evidence passes and unseen endpoints, changed snapshots and wrong typed controls refuse', () => check(String.raw`
import copy
def expected(i,kind,target,result):return {'route_id':i,'route':kind,'target':target,'expect':result}
real=[expected('ws','workspace-write','/sandbox','OK'),expected('fds','inherited-handle','all','DENIED')]
identity={'pid':21,'uid':1007,'start_time':'7'}
maps=[{'container_id':0,'host_id':200000,'size':65536}]
mounts=p.mountinfo_rows('1 0 0:1 / / rw - tmpfs tmpfs rw\n')
meta={'inventory-unix':{'proc':[],'filesystem':[],'namespace':'net:[11]'},'inventory-tcp':{'listeners':[],'namespace':'net:[11]'},'inventory-processes':{'processes':[identity],'probe_identity':identity,'namespace':'pid:[12]','uid_map':maps,'gid_map':maps},'inventory-shm':{'entries':[]},'final-environment':{'keys':[],'values':{}},'final-mountinfo':{'mounts':mounts,'namespace':'mnt:[13]'}}
real += [expected(kind,kind,'observed','OBSERVED') for kind in sorted(r.INVENTORIES)]
control=[expected(kind,kind,'stream' if kind in ('decoy-unix','decoy-abstract') else 'ipv4' if kind=='decoy-tcp' else 'owned','ALLOWED') for kind in sorted(r.CONTROL_KINDS)]
outside={'run_id':'fixture','complete':True,'unix':[],'tcp':[],'processes':[],'shm':[],'user_service_paths':[],'unix_types':{},'owned_probe':identity,'namespaces':{'net':'net:[11]','pid':'pid:[12]','mnt':'mnt:[13]'},'uid_map':maps,'gid_map':maps}
manifest={'observer_inventory':outside,'process_uid':1007,'environment':{'keys':[],'values':{}},'mountinfo':mounts}
specs=[{'name':'guest','phase':'real','run_id':'fixture','expected_routes':real,'manifest':manifest}, {'name':'control','phase':'control','run_id':'fixture','expected_routes':control}]
def record(items):
    rows=[]
    for item in items:
        row={'run_id':'fixture','route_id':item['route_id'],'route':item['route'],'target':item['target'],'result':item['expect'],'detail':''}
        if item['route'] in r.INVENTORIES:row.update(complete=True,metadata=meta[item['route']])
        if item['route']=='inherited-handle':row['complete']=True
        if item['route'] in ('decoy-unix','decoy-abstract'):row['metadata']={'socket_type':item['target']}
        if item['route']=='decoy-tcp':row['metadata']={'family':item['target']}
        rows.append(row)
    return {'parsed':r.parse_jsonl('\n'.join(json.dumps(x) for x in rows)+'\n'),'returncode':0,'started_at_ns':2,'finished_at_ns':3}
records={'guest':record(real),'control':record(control)}
before={'run_id':'fixture','complete':True,'collected_at_ns':1,'snapshots':{'owned-decoy':{'mode':384,'uid':1007}}}
after=copy.deepcopy(before);after['collected_at_ns']=4
observer={'before':before,'after':after}
coverage=[{'real_run':'guest','real_route_id':'fds','control_run':'control','control_route_id':'decoy-fd'}]
got=r.evaluate_runs(specs,records,observer,coverage)
assert got['status']=='PASS',got
extra=copy.deepcopy(records)
inv=next(x for x in extra['guest']['parsed']['rows'] if x['route']=='inventory-tcp')
inv['metadata']['listeners']=[{'host':'0.0.0.0','port':17690,'uid':1007,'inode':'9','family':'ipv4'}]
assert r.evaluate_runs(specs,extra,observer,coverage)['status']=='INCONCLUSIVE'
changed=copy.deepcopy(observer);changed['after']['snapshots']['owned-decoy']['mode']=420
assert r.evaluate_runs(specs,records,changed,coverage)['status']=='FAIL'
missing=copy.deepcopy(records);missing['control']['parsed']['rows'].pop()
assert r.evaluate_runs(specs,missing,observer,coverage)['status']=='INCONCLUSIVE'
for field in ['namespace','probe_identity','uid_map','gid_map']:
    missing=copy.deepcopy(records)
    next(x for x in missing['guest']['parsed']['rows'] if x['route']=='inventory-processes')['metadata'].pop(field)
    assert r.evaluate_runs(specs,missing,observer,coverage)['status']=='INCONCLUSIVE'
missing=copy.deepcopy(records)
next(x for x in missing['guest']['parsed']['rows'] if x['route']=='final-mountinfo')['metadata']['mounts']=[]
assert r.evaluate_runs(specs,missing,observer,coverage)['status']=='INCONCLUSIVE'
socket_item=expected('tcp','socket-tcp','127.0.0.1:17690','DENIED')
tcp_specs=copy.deepcopy(specs);tcp_specs[0]['expected_routes'].append(socket_item)
tcp_records=copy.deepcopy(records)
tcp_records['guest']['parsed']['rows'].append({'run_id':'fixture','route_id':'tcp','route':'socket-tcp','target':'127.0.0.1:17690','result':'DENIED','detail':''})
tcp_coverage=coverage+[{'real_run':'guest','real_route_id':'tcp','control_run':'control','control_route_id':'decoy-tcp'}]
assert r.evaluate_runs(tcp_specs,tcp_records,observer,tcp_coverage)['status']=='PASS'
wrong=copy.deepcopy(tcp_records)
next(x for x in wrong['control']['parsed']['rows'] if x['route']=='decoy-tcp')['metadata']['family']='ipv6'
assert r.evaluate_runs(tcp_specs,wrong,observer,tcp_coverage)['status']=='INCONCLUSIVE'
`))

test('a later observer failure preserves captured real ALLOWED evidence', () => check(String.raw`
import hashlib,io
manifest={'schema_version':1,'run_id':'fixture','phase':'real','expected_routes':[{'route_id':'tcp','route':'socket-tcp','target':'127.0.0.1:17690','expect':'DENIED'}]}
plan={'schema_version':1,'run_id':'fixture','runs':[{'name':'guest','phase':'real','argv':['/fixture/probe','{manifest_base64}'],'manifest':manifest,'timeout_seconds':1}], 'observer':{'before_path':'/fixture/before','after_path':'/fixture/after','uid':1007},'control_coverage':[]}
raw=json.dumps(plan).encode(); digest=hashlib.sha256(raw).hexdigest()
allowed={'run_id':'fixture','route_id':'tcp','route':'socket-tcp','target':'127.0.0.1:17690','result':'ALLOWED','detail':''}
record={'parsed':r.parse_jsonl(json.dumps(allowed)+'\n'),'returncode':0,'started_at_ns':2,'finished_at_ns':3}
out=io.StringIO()
with patch.object(r,'_read_json_file',side_effect=[(raw,plan),(b'{}',{}),OSError('observer missing')]),patch.object(r,'validate_plan',return_value=plan),patch.object(r,'_launch',return_value=record),patch.object(r.sys,'stdout',out):
    code=r.main(['--plan','/fixture/plan','--plan-sha256',digest,'--execute-reviewed-plan'])
assert code==1 and json.loads(out.getvalue())['status']=='FAIL',out.getvalue()
`))

// Auma profile join against F's afb8ac3 v3 interface. These are source controls:
// no kernel mount, ctx.shell service, host bind observer or receipt is fabricated.
// Mounted A/B and C1-C4 remain UNPERFORMED pending the actual owned Linux route.
const profileWorkspace = '/synthetic/auma/é workspace'
const compact = value => Array.isArray(value) ? '[' + value.map(compact).join(',') + ']' :
  value !== null && typeof value === 'object' ? '{' + Object.keys(value).sort().map(key =>
    JSON.stringify(key) + ':' + compact(value[key])).join(',') + '}' : JSON.stringify(value)
const profileDigest = value => 'sha256:' + createHash('sha256').update(compact(value), 'utf8').digest('hex')
const sealProfile = value => {
  value.inventory_digest = profileDigest(value.mount_inventory)
  value.supervisor_inventory_digest = profileDigest(value.supervisor_inventory)
  value.mountinfo_digest = profileDigest(value.mountinfo)
  return value
}
const kernelRow = (mount_id, parent_id, device, root, mountpoint, writable, filesystem, source, superWritable = writable) => ({
  mount_id, parent_id, device, root, mountpoint, options: [writable ? 'rw' : 'ro'], optional: [],
  filesystem, source, super_options: [superWritable ? 'rw' : 'ro'],
})
function profileReadback() {
  const channel = { Type: 'volume', Name: 'owned-source-channel', Source: '/synthetic/channel',
    Destination: '/.openshell/channel', Driver: 'local', Mode: 'nosuid,nodev',
    Options: ['nosuid', 'nodev'], RW: true, Propagation: 'rprivate' }
  const isolation = { uid: 166535, uid_map: [{ container_id: 0, host_id: 165536, size: 65536 }],
    gid_map: [{ container_id: 0, host_id: 165536, size: 65536 }], cap_eff: '0000000000000000',
    cap_prm: '0000000000000000', cap_bnd: '0000000000000000', no_new_privs: 1, seccomp: 2,
    process_start_time: 12345, workload_binary_digest: 'sha256:' + 'a'.repeat(64) }
  const supervisor = { ...structuredClone(isolation),
    uid_map: [{ container_id: 0, host_id: 0, size: 4294967295 }],
    gid_map: [{ container_id: 0, host_id: 0, size: 4294967295 }] }
  delete supervisor.workload_binary_digest
  return sealProfile({ version: 3, openshell_version: '0.1.2', sandbox: 'auma-ws', state: 'Ready',
    instance_id: 'owned-source-instance', policy_revision: 1, applied_revision: 1,
    workspace_root: '/sandbox', network_mode: 'none',
    policy: { version: 1, filesystem_policy: { include_workdir: false,
      read_only: ['/bin', '/usr', '/lib', '/lib64', '/etc', '/proc', '/dev/urandom'],
      read_write: ['/sandbox', '/tmp', '/dev/null', '/dev/pts', '/dev/ptmx'] },
      landlock: { compatibility: 'hard_requirement' }, network_policies: {} },
    mount_inventory: [channel,
      { Type: 'bind', Source: '/synthetic/runtime', Destination: '/opt/openshell/bin/openshell-sandbox',
        Driver: '', Mode: 'ro', Options: ['ro'], RW: false, Propagation: 'rprivate' },
      { Type: 'bind', Source: profileWorkspace, Destination: '/sandbox', Driver: '', Mode: 'nosuid,nodev',
        Options: ['nosuid', 'nodev'], RW: true, Propagation: 'rprivate' },
      { Type: 'bind', Source: profileWorkspace + '/.git', Destination: '/sandbox/.git', Driver: '',
        Mode: 'ro,nosuid,nodev', Options: ['ro', 'nosuid', 'nodev'], RW: false, Propagation: 'rprivate' },
      { Type: 'bind', Source: '/synthetic/mirror', Destination: '/sandbox/prime-main', Driver: '',
        Mode: 'ro,nosuid,nodev', Options: ['ro', 'nosuid', 'nodev'], RW: false, Propagation: 'rprivate' }],
    profile_digest: 'sha256:' + 'b'.repeat(64), isolation,
    supervisor_inventory: [{ ...structuredClone(channel), RW: false, Mode: 'ro,nosuid,nodev' }],
    supervisor_isolation: supervisor,
    mountinfo: [kernelRow('1', '0', '0:40', '/', '/', false, 'overlay', 'overlay'),
      kernelRow('2', '1', '8:1', profileWorkspace, '/sandbox', true, 'ext4', '/dev/source'),
      // RO bind flags differ from the shared writable ext4 superblock flags.
      kernelRow('3', '2', '8:1', profileWorkspace + '/.git', '/sandbox/.git', false, 'ext4', '/dev/source', true),
      kernelRow('4', '1', '0:41', '/', '/tmp', true, 'tmpfs', 'tmpfs'),
      kernelRow('5', '1', '8:2', '/synthetic/channel', '/.openshell/channel', true, 'ext4', '/dev/channel'),
      kernelRow('6', '1', '8:1', '/synthetic/runtime', '/opt/openshell/bin/openshell-sandbox', false, 'ext4', '/dev/source', true),
      kernelRow('7', '2', '8:3', '/synthetic/mirror', '/sandbox/prime-main', false, 'ext4', '/dev/mirror', true),
      kernelRow('8', '1', '0:43', '/', '/proc', true, 'proc', 'proc')],
    workspace_binding: { workspace_source: profileWorkspace, git_source: profileWorkspace + '/.git',
      workspace_device: '8:1', workspace_inode: '2001', git_device: '8:1', git_inode: '2002',
      mount_namespace: 'mnt:[4000]' } })
}
function probeMountRows(rows) {
  const escape = value => value.replaceAll('\\', '\\134').replaceAll(' ', '\\040')
    .replaceAll('\t', '\\011').replaceAll('\n', '\\012')
  const raw = rows.map(row => [row.mount_id, row.parent_id, row.device, escape(row.root),
    escape(row.mountpoint), row.options.join(','), ...row.optional, '-', row.filesystem,
    escape(row.source), row.super_options.join(',')].join(' ')).join('\n') + '\n'
  return JSON.parse(check("print(json.dumps(p.mountinfo_rows(sys.argv[3]),ensure_ascii=False))\n", [raw]))
}

test('Auma v3 source join preserves the complete ordered probe mount table and trusted workspace binding', () => {
  const info = profileReadback()
  validateConfinementInfo(info, profileWorkspace)
  assert.deepEqual(info.mountinfo[2].options, ['ro'])
  assert.deepEqual(info.mountinfo[2].super_options, ['rw'])
  const parsed = probeMountRows(info.mountinfo)
  assert.deepEqual(parsed, info.mountinfo)
  assert.equal(profileDigest(parsed), info.mountinfo_digest)
  validateConfinementInfo({ ...info, mountinfo: parsed }, profileWorkspace)
  // A digest of a partial table is still insufficient evidence.
  const partial = structuredClone(info)
  partial.mountinfo = parsed.filter(row => row.mountpoint !== '/sandbox/.git')
  sealProfile(partial)
  assert.throws(() => validateConfinementInfo(partial, profileWorkspace),
    error => error.code === 'SANDBOX_UNAVAILABLE' && error.reason === 'WORKSPACE_BINDING')
  assert.throws(() => validateConfinementInfo(info, '/synthetic/other-session'),
    error => error.code === 'SANDBOX_UNAVAILABLE' && error.reason === 'WORKSPACE_BINDING')
})

test('Auma C5 source join refuses a second RW workspace after parsing and resealing, with guard-removal sensitivity', async () => {
  const info = profileReadback()
  validateConfinementInfo(info, profileWorkspace)
  info.mountinfo.push(kernelRow('9', '1', '8:1', profileWorkspace, '/sandbox2', true, 'ext4', '/dev/source'))
  info.mountinfo = probeMountRows(info.mountinfo)
  sealProfile(info)
  assert.deepEqual(info.policy.filesystem_policy.read_write,
    ['/sandbox', '/tmp', '/dev/null', '/dev/pts', '/dev/ptmx'])
  assert.throws(() => validateConfinementInfo(info, profileWorkspace),
    error => error.code === 'SANDBOX_UNAVAILABLE' && error.reason === 'WORKSPACE_BINDING')
  const source = readFileSync(new URL('../plugins/aukora-openshell-confinement/lib/transport.mjs', import.meta.url), 'utf8')
  const guard = 'if (!role || row.filesystem !== role[0] || writable !== role[1]) return false;'
  assert.equal(source.split(guard).length, 2, 'one actual production extra-mount guard required')
  const removed = source.replace(guard,
    'if (!role) continue; if (row.filesystem !== role[0] || writable !== role[1]) return false;')
  const mutant = await import('data:text/javascript;base64,' + Buffer.from(removed, 'utf8').toString('base64'))
  mutant.validateConfinementInfo(profileReadback(), profileWorkspace)
  mutant.validateConfinementInfo(info, profileWorkspace)
  // The independent FILE_POLICY fence still refuses a sixth declared RW root.
  const sixth = profileReadback()
  sixth.policy.filesystem_policy.read_write.push('/sandbox2')
  assert.throws(() => mutant.validateConfinementInfo(sixth, profileWorkspace),
    error => error.code === 'SANDBOX_UNAVAILABLE' && error.reason === 'FILE_POLICY')
})
