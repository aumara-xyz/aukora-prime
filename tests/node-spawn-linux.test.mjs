// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise Linux orchestration with fake users, services, package checks and admission transport.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { createInvite, redeemInvite } from '../packages/invites/index.mjs'
import { randomSecretKey, publicKeyOf } from '../plugins/aukora-nostr/lib/event.mjs'
// Fixtures stand in for protected system paths. A login shell whose umask leaves group write on (Ubuntu's
// default 002) would make every directory this test creates look unprotected, so the mask is fixed here.
process.umask(0o022)

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const subject = path.join(repo, 'ops/node-spawn')
const shell = fs.readFileSync(path.join(subject, 'linux.sh'), 'utf8')
const host = fs.readFileSync(path.join(subject, 'configure-host.py'), 'utf8')
const hash = data => createHash('sha256').update(data).digest('hex')
function fixture(t, { script = shell, hostSource = host } = {}) {
  const base = fs.mkdtempSync(path.join(repo, '.node-spawn-linux-'))
  t.after(() => fs.rmSync(base, { recursive: true, force: true }))
  const root = path.join(base, 'root'), source = path.join(base, 'source'), bin = path.join(base, 'bin'), runner = path.join(base, 'runner')
  const write = (file, data, mode = 0o644) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, data, { mode }); fs.chmodSync(file, mode) }
  for (const dir of [root, source, bin, runner]) fs.mkdirSync(dir, { mode: 0o755 })
  const events = path.join(base, 'events'), configPath = path.join(base, 'config.json'), driver = path.join(base, 'driver.mjs')
  const env = { ...process.env, PATH: bin + ':' + process.env.PATH, SPAWN_TEST_ROOT: root, SPAWN_TEST_EVENTS: events,
    SPAWN_TEST_DB: path.join(base, 'authority.sqlite'), SPAWN_TEST_AUTHORITY_KEY: path.join(base, 'authority.key'), NODE_NO_WARNINGS: '1', PYTHONDONTWRITEBYTECODE: '1' }
  const exec = (command, args, options = {}) => spawnSync(command, args, { encoding: 'utf8', env, timeout: 30000, ...options })
  const must = result => assert.equal(result.status, 0, result.stderr)
  write(path.join(runner, 'linux.sh'), script)
  write(path.join(runner, 'configure-host.py'), hostSource)
  for (const file of ['stage.py', 'invite.mjs', 'configure.mjs']) fs.symlinkSync(path.join(subject, file), path.join(runner, file))
  const url = file => pathToFileURL(path.join(repo, file)).href
  write(driver, `import fs from 'node:fs'; import { DatabaseSync } from 'node:sqlite';
import { createDatabaseStore, verifyAdmission, createAdmissionRecord } from ${JSON.stringify(url('packages/invites/index.mjs'))};
import { runCli } from ${JSON.stringify(url('ops/node-spawn/invite.mjs'))};
import { writeDoor, verifyGateSigner } from ${JSON.stringify(url('ops/node-spawn/configure.mjs'))};
const args=process.argv.slice(2), log=(...v)=>fs.appendFileSync(process.env.SPAWN_TEST_EVENTS,JSON.stringify(v)+'\\n');
if(args[0]==='--version'){console.log('v24.11.1');process.exit(0)}
if(args[0].endsWith('/invite.mjs')) {
 const op=args[1];log(op);
 const fetchImpl=async(url,request)=>{const body=JSON.parse(request.body);const db=new DatabaseSync(process.env.SPAWN_TEST_DB);const state=createDatabaseStore(db);
  try {if(process.env.SPENT==='1')return Response.json({code:'invites:replay'},{status:409});
   if(url.endsWith('/preflight')){
    if(db.prepare('SELECT 1 FROM consumed WHERE inviteId=?').get(body.invite.id))return Response.json({code:'invites:replay'},{status:409});
    for(const prior of body.chain){if(!state.transaction(tx=>tx.admission(body.root,prior.redemption.pubkey)))return Response.json({code:'invites:unadmitted'},{status:403})}
    return Response.json({available:true,invite_id:body.invite.id});
   }
   db.exec('CREATE TABLE IF NOT EXISTS confirmations (id TEXT PRIMARY KEY, record TEXT NOT NULL) STRICT');
   let record=db.prepare('SELECT record FROM confirmations WHERE id=?').get(body.redemption.id)?.record;
   if(record) record=JSON.parse(record);
   else {const result=verifyAdmission({...body,state,now:Math.floor(Date.now()/1000)});
    record=createAdmissionRecord({root:body.root,secretKey:fs.readFileSync(process.env.SPAWN_TEST_AUTHORITY_KEY,'utf8').trim(),record:result.record,now:body.redemption.created_at});
    db.prepare('INSERT INTO confirmations VALUES (?,?)').run(body.redemption.id,JSON.stringify(record));}
   log('redemption',body.redemption.id);
   if(process.env.MISMATCH_REPLY==='1') {log('authority-record',record);return Response.json({admitted:true,record:{chain:[]}})}
   return Response.json({admitted:true,record});
  }catch(e){return Response.json({code:e.code},{status:403})}finally{state.close()}
 };
 process.exitCode=await runCli(args.slice(1),{fetchImpl});
}else if(args[0].endsWith('/configure.mjs')){
 log(args[1]);if(args[1]==='door'){writeDoor(...args.slice(2));console.log('DOOR_CONFIGURED')}
 else if(args[1]==='signer'){verifyGateSigner(...args.slice(2));console.log('SIGNER_OK')}
 else {if(process.env.FAIL_ACCEPT==='1')process.exit(1);console.log('fixture installed readback: PASS')}
}else throw Error('unexpected fixture command');
`)
  const runtime = `#!/bin/sh\nexec '${process.execPath}' '${driver}' "$@"\n`
  write(path.join(bin, 'node'), runtime, 0o755)
  const stub = path.join(base, 'commands.mjs')
  write(stub, `import fs from 'node:fs'; import path from 'node:path';
const [tool,...args]=process.argv.slice(2);fs.appendFileSync(process.env.SPAWN_TEST_EVENTS,JSON.stringify([tool,...args])+'\\n');
const root=process.env.SPAWN_TEST_ROOT;fs.mkdirSync(root+'/etc',{recursive:true});
if(tool==='groupadd')fs.appendFileSync(root+'/etc/group','skgate:x:1200:\\n');
if(tool==='useradd'){const user=args.at(-1);fs.appendFileSync(root+'/etc/passwd',user+':x:'+(user==='auma'?'1001':'1201')+':1201::/home/'+user+':/usr/sbin/nologin\\n');if(args.includes('--groups'))fs.writeFileSync(root+'/etc/group','skgate:x:1200:aukora-host\\n')}
if(tool==='install'){
 let mode=0o755,dirs=false,files=[];for(let i=0;i<args.length;i++){if(args[i]==='-d')dirs=true;else if(args[i]==='-m')mode=parseInt(args[++i],8);else if(['-o','-g'].includes(args[i]))i++;else files.push(args[i])}
 if(dirs)for(const file of files){fs.mkdirSync(file,{recursive:true,mode});fs.chmodSync(file,mode)}
 else{fs.copyFileSync(files[0],files[1]);fs.chmodSync(files[1],mode)}
}
if(tool==='systemctl'&&process.env.FAIL_SYSTEMCTL==='1')process.exit(1);
`)
  for (const tool of ['groupadd', 'useradd', 'install', 'systemctl']) write(path.join(bin, tool), `#!/bin/sh\nexec '${process.execPath}' '${stub}' '${tool}' "$@"\n`, 0o755)
  write(path.join(bin, 'runuser'), '#!/bin/sh\nshift 3\nexec "$@"\n', 0o755)
  const pylog = "import json,os,sys,pathlib\nwith open(os.environ['SPAWN_TEST_EVENTS'],'a') as f: f.write(json.dumps([LABEL]+sys.argv[1:])+'\\n')\n"
  const bootstrap = pylog.replace('LABEL', "'bootstrap'") + `
root=pathlib.Path(os.environ['SPAWN_TEST_ROOT'])
if sys.argv[1:3]==['approval','install']:
 if os.environ.get('PENDING')=='1': sys.exit(1)
 floor=root/'etc/aukora-approvals/release-floor.json';floor.parent.mkdir(parents=True,exist_ok=True);floor.write_text('{}')
if sys.argv[1:3]==['floor','check'] and not (root/'etc/aukora-approvals/release-floor.json').exists():sys.exit(1)
print('FIXTURE_VERIFIED')
`
  write(path.join(source, 'packages/boundary-gate/host/install/gate-bootstrap.py'), bootstrap)
  write(path.join(source, 'packages/boundary-gate/host/sbx-exec'), '# fixture\n')
  write(path.join(source, 'packages/boundary-gate/host/openshell/check'), '# fixture\n')
  write(path.join(source, 'packages/boundary-gate/host/systemd/selfcheck-with-retry'), '# fixture\n')
  for (const unit of ['aukora-boundary-gate.service', 'aukora-genesis.service', 'aukora-selfcheck.service', 'aukora-selfcheck-periodic.service', 'aukora-selfcheck.timer']) write(path.join(source, 'packages/boundary-gate/host/systemd', unit), '[Service]\nGroup=SKGATE_GID\n')
  write(path.join(source, 'packages/owner-key/source'), 'fixture owner package\n')
  write(path.join(source, 'packages/boundary-gate/host/install/generate-manifest.py'), pylog.replace('LABEL', "'manifest'") + "pathlib.Path(sys.argv[sys.argv.index('--output')+1]).write_text('{}')\n")
  write(path.join(source, 'scripts/build-dsh.py'), pylog.replace('LABEL', "'build'") + "assert sys.argv[1]=='--verify-built'\n")
  write(path.join(source, 'scripts/materialize-aukora-release.py'), pylog.replace('LABEL', "'materialize'") + "import subprocess\ntarget=pathlib.Path(sys.argv[sys.argv.index('--to')+1]);(target/'.dsh-build').mkdir(parents=True)\ncommit=subprocess.check_output(['git','-C',str(pathlib.Path(__file__).resolve().parents[1]),'rev-parse','HEAD']).decode().strip()\n(target/'.dsh-build/genesis-artifacts.json').write_text(json.dumps({'producer':{'genesisCommit':commit}}))\n")
  const archive = path.join(base, 'node.tar'), archiveDir = path.join(base, 'archive')
  write(path.join(archiveDir, 'node-v24.11.1-linux-x64/bin/node'), runtime, 0o755)
  must(exec('python3', ['-I', '-S', '-c', "import sys,tarfile\nwith tarfile.open(sys.argv[1],'w') as archive: archive.add(sys.argv[2],arcname='node-v24.11.1-linux-x64/bin/node')", archive, path.join(archiveDir, 'node-v24.11.1-linux-x64/bin/node')]))
  write(path.join(source, 'vendor/dsh-source.tar.gz'), 'fixture archive')
  write(path.join(source, 'upstream-dsh.json'), JSON.stringify({ archiveSha256: hash('fixture archive') }))
  for (const name of ['invite.mjs', 'configure.mjs']) write(path.join(source, 'ops/node-spawn', name), '// Fixture dispatch uses the real installer helper with an injected transport.\n')
  must(exec('git', ['init', '-q', source])); must(exec('git', ['-C', source, 'add', '-A']))
  must(exec('git', ['-C', source, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture: source']))
  const commit = exec('git', ['-C', source, 'rev-parse', 'HEAD']).stdout.trim()
  const key = randomSecretKey(), network = publicKeyOf(key), now = Math.floor(Date.now() / 1000)
  write(env.SPAWN_TEST_AUTHORITY_KEY, key + '\n', 0o600)
  const offers = [path.join(base, 'offer.json'), path.join(base, 'auma-offer.json')]
  for (const file of offers) write(file, JSON.stringify({ invite: createInvite({ root: network, secretKey: key, now }), chain: [] }), 0o600)
  const template = path.join(base, 'door.json'); write(template, JSON.stringify({ channel: '00000000-0000-0000-0000-000000000001', sessionId: 'member-chat' }), 0o600)
  const gateKey = generateKeyPairSync('ed25519')
  const epochs = path.join(base, 'epochs.json'); write(epochs, JSON.stringify({ version: 1, kind: 'aukora-signer-epochs/v1', epochs: [{ epoch: 1, gate_pubkey_sha256: hash(gateKey.publicKey.export({ type: 'spki', format: 'der' })) }] }))
  const built = path.join(base, 'built'); fs.mkdirSync(built)
  const config = { version: 1, node: 'member-node', source_checkout: source, release_commit: commit,
    node_archive: archive, node_archive_sha256: hash(fs.readFileSync(archive)), public_signer_epochs: epochs,
    offer: offers[0], auma_offer: offers[1], root: network, admission: 'http://127.0.0.1:39999', door_config: template, built_harness: built }
  write(configPath, JSON.stringify(config), 0o600)
  write(path.join(root, 'etc/aukora-boundary-gate/owner-state.json'), '{}')
  for (const name of ['usr/bin/openshell', 'usr/bin/openshell-gateway', 'etc/aukora-boundary-gate/openshell-workspace.json', 'etc/aukora-boundary-gate/openshell-inventory.json', 'etc/sudoers.d/aukora-boundary', 'etc/systemd/system/aukora-auma-local-deny.service', 'etc/systemd/system/aukora-auma-podman.service', 'etc/systemd/system/aukora-openshell-gateway.service', 'etc/systemd/system/aukora-auma-sandbox.service', 'home/aukora-gate/owner-secret.json']) write(path.join(root, name), 'fixture prerequisite; not a usable owner state or sandbox\n')
  write(path.join(root, 'home/aukora-gate/receipt-ed25519.pem'), gateKey.privateKey.export({ type: 'pkcs8', format: 'pem' }), 0o600)
  for (const name of ['etc/subuid', 'etc/subgid']) write(path.join(root, name), 'auma:165536:65536\n')
  for (const name of ['home/aukora-host/genesis/state', 'home/aukora-host/genesis/support', 'var/lib/aukora-boundary/targets']) fs.mkdirSync(path.join(root, name), { recursive: true, mode: 0o755 })
  const run = (extra = {}, dry = false) => exec('bash', ['-c', 'umask 077; exec bash "$@"', 'fixture', path.join(runner, 'linux.sh'), '--linux', ...(dry ? ['--dry-run'] : []), '--config', configPath, '--root', root], { env: { ...env, ...extra } })
  return { base, root, source, config, configPath, offers, key, network, now, run, write,
    events: () => fs.existsSync(events) ? fs.readFileSync(events, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : [] }
}
const refused = (result, code) => { assert.notEqual(result.status, 0); assert.match(result.stderr, new RegExp('REFUSED ' + code)) }
function snapshot(root) {
  const files = []
  const walk = directory => { for (const name of fs.readdirSync(directory).sort()) { const file = path.join(directory, name), st = fs.lstatSync(file); if (st.isDirectory()) walk(file); else if (!file.includes('/.git/')) files.push([path.relative(root, file), hash(fs.readFileSync(file)), st.mode, st.mtimeMs]) } }
  walk(root); return files
}
function checkOrder(t, script = shell) {
  const f = fixture(t, { script }), result = f.run(); assert.equal(result.status, 0, result.stderr)
  const events = f.events(), first = name => events.findIndex(row => row[0] === name)
  for (const [before, after] of [['preflight', 'useradd'], ['useradd', 'build'], ['build', 'materialize'], ['materialize', 'manifest'], ['manifest', 'key'], ['key', 'redeem'], ['redeem', 'door'], ['door', 'acceptance']]) assert.ok(first(before) < first(after), before + ' before ' + after)
  assert.equal(events.filter(row => row[0] === 'preflight').length, 2)
  assert.equal(events.filter(row => row[0] === 'redeem').length, 2)
  assert.ok(events.find(row => row[0] === 'useradd' && row.at(-1) === 'aukora-host').includes('--groups'))
  const approval = events.filter(row => row[0] === 'bootstrap' && row[1] === 'approval').map(row => row[2])
  assert.deepEqual(approval, ['show', 'raise', 'install'])
  assert.ok(events.findIndex(row => row[0] === 'bootstrap' && row[1] === 'floor') < events.findIndex(row => row[0] === 'systemctl' && row.includes('aukora-genesis.service') && row.includes('enable')))
  assert.ok(fs.existsSync(path.join(f.root, 'opt/aukora-genesis/src/.git')))
  assert.equal(fs.statSync(path.join(f.root, 'opt/aukora-genesis/release-' + f.config.release_commit.slice(0, 7))).mode & 0o777, 0o755, 'release readable by service users despite operator umask')
  const record = JSON.parse(fs.readFileSync(path.join(f.root, 'home/aukora-member/.config/aukora-node/admission.json')))
  const door = JSON.parse(fs.readFileSync(path.join(f.root, 'home/aukora-host/.config/aukora-buzz/door.json')))
  assert.deepEqual(door.admit, [record.chain.at(-1).redemption.pubkey]); assert.equal(door.ownerPubkey, undefined)
  return f
}
test('real mode fake root orders admission, staged install, keys, spending and acceptance; second run writes nothing', t => {
  const f = checkOrder(t), before = snapshot(f.root), count = f.events().length
  const result = f.run(); assert.equal(result.status, 0, result.stderr); assert.deepEqual(snapshot(f.root), before)
  assert.ok(f.events().slice(count).every(row => ['verify', 'bootstrap', 'systemctl', 'acceptance'].includes(row[0])))
})
test('dry run prints executable commands and performs no provisioning', t => {
  const f = fixture(t), before = snapshot(f.root), result = f.run({}, true)
  assert.equal(result.status, 0, result.stderr); assert.deepEqual(f.events(), []); assert.deepEqual(snapshot(f.root), before)
  for (const token of ['preflight', 'useradd', '--verify-built', 'generate-manifest.py', 'publish', 'check-package', 'key', 'redeem', 'approval show', 'approval raise', 'approval install', 'floor check', 'acceptance']) assert.ok(result.stdout.includes(token), token)
  assert.ok(!result.stdout.includes(f.network)); assert.ok(!result.stdout.includes(f.config.admission))
})
test('expiry, spent invite, nonmember, commit mismatch and preexisting key stop before users', t => {
  for (const kind of ['expired', 'spent', 'nonmember', 'commit', 'key']) {
    const f = fixture(t); let code, env = {}
    if (kind === 'expired') { f.write(f.offers[0], JSON.stringify({ invite: createInvite({ root: f.network, secretKey: f.key, now: f.now - 172801 }), chain: [] })); code = 'invites:expired' }
    if (kind === 'spent') { env.SPENT = '1'; code = 'invites:replay' }
    if (kind === 'nonmember') { f.write(f.offers[0], JSON.stringify({ invite: createInvite({ root: f.network, secretKey: randomSecretKey(), now: f.now }), chain: [] })); code = 'invites:chain' }
    if (kind === 'commit') { f.config.release_commit = 'a'.repeat(40); f.write(f.configPath, JSON.stringify(f.config)); code = 'SPAWN_SOURCE_RELEASE_MISMATCH' }
    if (kind === 'key') { f.write(path.join(f.root, 'home/aukora-member/.config/aukora-node/node-key'), 'existing key', 0o600); code = 'SPAWN_KEY_EXISTS' }
    refused(f.run(env), code); assert.ok(!f.events().some(row => row[0] === 'useradd'), kind)
  }
})
test('owner enrollment pause spends nothing and resumes; approval pause preserves keys and raises once', t => {
  const f = fixture(t), owner = path.join(f.root, 'etc/aukora-boundary-gate/owner-state.json'); fs.unlinkSync(owner)
  refused(f.run(), 'OWNER_ENROLLMENT_REQUIRED'); assert.ok(!f.events().some(row => row[0] === 'key' || row[0] === 'redeem'))
  f.write(owner, '{}'); refused(f.run({ PENDING: '1' }), 'OWNER_APPROVAL_REQUIRED')
  const count = f.events().length, result = f.run(); assert.equal(result.status, 0, result.stderr)
  assert.ok(!f.events().slice(count).some(row => ['key', 'redeem', 'materialize'].includes(row[0]) || row[0] === 'bootstrap' && row[2] === 'raise'))
})
test('phase two spent mismatch replays the same request before availability checks and does not spend either identity twice', t => {
  const f = fixture(t)
  refused(f.run({ MISMATCH_REPLY: '1' }), 'INVITE_SPENT_NOT_CONFIRMED')
  const count = f.events().length
  refused(f.run({ MISMATCH_REPLY: '1' }), 'INVITE_SPENT_NOT_CONFIRMED')
  assert.ok(!f.events().slice(count).some(row => row[0] === 'preflight'), 'spent identity retries before availability')
  assert.equal(f.events().filter(row => row[0] === 'authority-record').length, 2)
  const record = f.events().find(row => row[0] === 'authority-record')[1]
  const memberHome = path.join(f.root, 'home/aukora-member')
  const keyFile = path.join(memberHome, '.config/aukora-node/node-key')
  const pendingFile = keyFile + '.invite-pending.json', expected = JSON.parse(fs.readFileSync(pendingFile))
  assert.deepEqual(record.chain, [...expected.offer.chain, { invite: expected.offer.invite, redemption: expected.redemption }])
  // A locally constructed path must not reconcile the unknown authority decision.
  const confirmation = path.join(f.base, 'confirmation.json')
  f.write(confirmation, JSON.stringify({ chain: record.chain }), 0o600)
  const args = ['redeem',
    '--config', path.join(memberHome, '.config/aukora-node/spawn-config.json'), '--offer', path.join(memberHome, '.config/aukora-node/offer.json'),
    '--key-file', keyFile, '--out', path.join(memberHome, '.config/aukora-node/admission.json'), '--resume-record', confirmation]
  const adapter = `import { runCli } from ${JSON.stringify(pathToFileURL(path.join(repo, 'ops/node-spawn/invite.mjs')).href)};
process.exitCode = await runCli(JSON.parse(process.argv[1]), { keyOptions: { home: process.argv[2] }, fetchImpl: async()=>{throw Error('unavailable fixture')} });`
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', adapter, JSON.stringify(args), memberHome], {
    encoding: 'utf8', timeout: 30000, env: { ...process.env, NODE_NO_WARNINGS: '1' },
  })
  assert.equal(result.status, 1)
  assert.equal(fs.existsSync(keyFile + '.invite-confirmed.json'), false)
  const resumed = f.run()
  assert.equal(resumed.status, 0, resumed.stderr)
  assert.equal(f.events().filter(row => row[0] === 'authority-record').length, 2)
  const redemptions = f.events().filter(row => row[0] === 'redemption').map(row => row[1])
  assert.equal(new Set(redemptions.slice(0, 3)).size, 1, 'member retries the same redemption')
  assert.equal(new Set(redemptions).size, 2, 'each identity has only one redemption')
})
test('reintroducing availability checks after spending blocks the resume regression', t => {
  const before = 'if [[ $phase -lt 2 ]]; then verify_invites; fi'
  assert.ok(shell.includes(before))
  const f = fixture(t, { script: shell.replace(before, 'if [[ $phase -lt 3 ]]; then verify_invites; fi') })
  refused(f.run({ MISMATCH_REPLY: '1' }), 'INVITE_SPENT_NOT_CONFIRMED')
  assert.throws(() => refused(f.run(), 'INVITE_SPENT_NOT_CONFIRMED'), { name: 'AssertionError' })
  t.diagnostic('MUTATION KILLED spent-resume-availability')
})
test('phase two resume still checks source inputs before recovery and its removal fails', t => {
  const guard = 'if [[ $phase -eq 2 ]]; then run python3 -I -S "$HERE/stage.py" precheck "$config" "${root:-/}"; fi'
  assert.ok(shell.includes(guard))
  for (const mutant of [false, true]) {
    const f = fixture(t, { script: mutant ? shell.replace(guard, ':') : shell })
    refused(f.run({ MISMATCH_REPLY: '1' }), 'INVITE_SPENT_NOT_CONFIRMED')
    f.write(path.join(f.source, 'packages/owner-key/source'), 'changed source input\n')
    if (mutant) assert.throws(() => refused(f.run(), 'SPAWN_SOURCE_DIRTY'), { name: 'AssertionError' })
    else refused(f.run(), 'SPAWN_SOURCE_DIRTY')
    assert.equal(f.events().filter(row => row[0] === 'authority-record').length, 1)
  }
  t.diagnostic('MUTATION KILLED spent-resume-precheck')
})
test('changed installed admission/config/key or original inputs refuse completed resume', t => {
  const f = checkOrder(t)
  for (const file of ['home/aukora-host/.config/aukora-buzz/spawn-config.json', 'home/aukora-member/.config/aukora-node/node-key', 'home/aukora-member/.config/aukora-node/admission.json']) {
    const target = path.join(f.root, file), original = fs.readFileSync(target)
    fs.appendFileSync(target, '\n'); refused(f.run(), 'SPAWN_RESUME_CONFLICT'); fs.writeFileSync(target, original)
  }
})
// The mutant cases take about as long as everything else in this file together. Run plainly (as CI runs every
// test file, under one time limit) the file leaves them out and says so; scripts/check.sh runs them by name.
const selectedByName = process.execArgv.some(argument => argument.startsWith('--test-name-pattern') || argument.startsWith('--test-skip-pattern'))
const mutantTest = (name, body) => selectedByName ? test(name, body) : undefined
if (!selectedByName) console.log('# node-spawn-linux: 3 mutant cases are not run in a plain run; scripts/check.sh runs them (--test-name-pattern=mutants)')
mutantTest('preload and preexisting key mutants fail regressions', t => {
  const preloadGuard = '[[ ${NODE_OPTIONS+x} != x && ${NODE_PATH+x} != x && ${LD_PRELOAD+x} != x && ${LD_LIBRARY_PATH+x} != x && ${LD_AUDIT+x} != x ]]'
  assert.ok(shell.includes(preloadGuard))
  for (const mutant of [false, true]) {
    const probe = fixture(t, { script: mutant ? shell.replace(preloadGuard, '[[ 1 == 1 ]]') : shell })
    const hook = path.join(probe.base, 'preload.mjs'), marker = path.join(probe.base, 'preloaded')
    probe.write(hook, `import fs from 'node:fs';fs.writeFileSync(${JSON.stringify(marker)},'fixture');process.exit(0)`)
    const result = probe.run({ NODE_OPTIONS: '--import=' + hook })
    if (!mutant) { refused(result, 'SPAWN_PRELOAD_FORBIDDEN'); assert.ok(!fs.existsSync(marker)); assert.deepEqual(probe.events(), []) }
    else assert.throws(() => assert.ok(!fs.existsSync(marker)), { name: 'AssertionError' })
  }
  t.diagnostic('MUTATION KILLED caller-preload')
  const existsGuard = '|| refuse SPAWN_KEY_EXISTS'
  const keyProbe = fixture(t, { script: shell.replace(existsGuard, '|| true') })
  keyProbe.write(path.join(keyProbe.root, 'home/aukora-member/.config/aukora-node/node-key'), 'preexisting fixture', 0o600)
  assert.throws(() => refused(keyProbe.run(), 'SPAWN_KEY_EXISTS'), { name: 'AssertionError' }); t.diagnostic('MUTATION KILLED key-preflight')
})
mutantTest('order and owner barrier mutants fail regressions', t => {
  for (const [name, before, after] of [
    ['verify-first', 'if [[ $phase -lt 2 ]]; then verify_invites; fi', ':'],
    ['owner-enrollment', '&& ! -f $(path /etc/aukora-boundary-gate/owner-state.json)', '&& 1 == 2'],
    ['owner-approval', 'then owner_next; refuse OWNER_APPROVAL_REQUIRED;', 'then owner_next; :;'],
  ]) {
    assert.ok(shell.includes(before), name)
    const f = fixture(t, { script: shell.replace(before, after) })
    if (name === 'owner-enrollment') fs.unlinkSync(path.join(f.root, 'etc/aukora-boundary-gate/owner-state.json'))
    const result = f.run(name === 'owner-approval' ? { PENDING: '1' } : {})
    if (name === 'verify-first') assert.throws(() => assert.ok(f.events().some(row => row[0] === 'preflight')), { name: 'AssertionError' })
    else assert.throws(() => refused(result, name === 'owner-enrollment' ? 'OWNER_ENROLLMENT_REQUIRED' : 'OWNER_APPROVAL_REQUIRED'), { name: 'AssertionError' })
    t.diagnostic('MUTATION KILLED ' + name)
  }
})
mutantTest('resume binding and installation policy mutants fail regressions', t => {
  const anchor = "if read(marker) != binding(config_path, config, root, number):"
  assert.ok(host.includes(anchor)); const f = fixture(t, { hostSource: host.replace(anchor, 'if False:') })
  assert.equal(f.run().status, 0); fs.appendFileSync(path.join(f.root, 'home/aukora-member/.config/aukora-node/node-key'), '\n')
  assert.throws(() => refused(f.run(), 'SPAWN_RESUME_CONFLICT'), { name: 'AssertionError' }); t.diagnostic('MUTATION KILLED resume-binding')
  for (const [name, before, after] of [['public-release', 'umask 022', 'umask 077'], ['host-propose-group', '--groups skgate', '']]) {
    assert.ok(shell.includes(before)); assert.throws(() => checkOrder(t, shell.replace(before, after)), { name: 'AssertionError' }); t.diagnostic('MUTATION KILLED ' + name)
  }
})
