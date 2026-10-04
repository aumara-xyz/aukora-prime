// SPDX-License-Identifier: AGPL-3.0-or-later
// Pure parsers/verdicts and mocked syscall boundaries. Never invoke live probes,
// privileged launch plans, firewall/service tools or production endpoints.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const probe = fileURLToPath(new URL('../scripts/audit/containment/probe.py', import.meta.url))
const runner = fileURLToPath(new URL('../scripts/audit/containment/run.py', import.meta.url))
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
function check(body) {
  const result = spawnSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', setup + body, probe, runner], {
    encoding: 'utf8', timeout: 8000, maxBuffer: 64 * 1024,
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' },
  })
  assert.equal(result.error, undefined)
  assert.equal(result.status, 0, result.stderr)
}

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
