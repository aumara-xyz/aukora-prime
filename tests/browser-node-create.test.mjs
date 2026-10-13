// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise argument, verified-input and fresh-container refusals without LXD.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import nodeTest from 'node:test';
import { fileURLToPath } from 'node:url';

const fast = process.env.AUKORA_BROWSER_CREATE_FAST === '1';
// Fast registration retains argument refusals, one real-Git install flow and shell syntax.
const quick = /^create (?:refuses (?:missing --|duplicate --|incomplete and unknown|--|matching proxy|non-Linux|LD_)|requests fresh restricted|shell parses)/;
function test(name, fn) { if (!fast || quick.test(name)) nodeTest(name, fn); }
if (fast) console.log('SOURCE-ONLY browser create fast registration; full input and LXD mutation court NOT RUN');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const script = path.join(root, 'ops/node-spawn/browser/create.sh');
const source = fs.readFileSync(script, 'utf8');
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const image = 'f'.repeat(64);
const bundles = new Map();
const shellQuote = value => "'" + String(value).replaceAll("'", "'\\''") + "'";
function bundle(options) {
  const key = JSON.stringify([options.pin ?? null, options.installer !== false, options.helper !== false, options.browserExtra ?? null, !!options.checkoutInvalid]);
  if (bundles.has(key)) return bundles.get(key);
  const checkout = fs.mkdtempSync(path.join(root, '.browser-create-template-'));
  try {
    fs.writeFileSync(path.join(checkout, 'upstream-dsh.json'), options.checkoutInvalid ? 'bad JSON' : JSON.stringify({ archiveSha256: options.pin ?? digest('synthetic harness') }));
    if (options.installer !== false) {
      fs.mkdirSync(path.join(checkout, 'ops/node-spawn/browser'), { recursive: true });
      fs.writeFileSync(path.join(checkout, 'ops/node-spawn/browser/install.sh'), '#!/bin/bash\nexit 0\n');
      if (options.browserExtra === 'directory') { fs.mkdirSync(path.join(checkout, 'ops/node-spawn/browser/nested')); fs.writeFileSync(path.join(checkout, 'ops/node-spawn/browser/nested/file'), 'fixture'); }
      if (options.browserExtra === 'symlink') fs.symlinkSync('install.sh', path.join(checkout, 'ops/node-spawn/browser/link.sh'));
      if (options.helper !== false) fs.writeFileSync(path.join(checkout, 'ops/node-spawn/stage.py'), '# synthetic helper\n');
    }
    const git = (...args) => {
      const result = spawnSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', '-C', checkout, ...args], { encoding: 'utf8', timeout: 10000, env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
      assert.equal(result.status, 0, result.stderr);
      return result.stdout.trim();
    };
    git('init', '--quiet');
    git('add', '-A');
    git('-c', 'user.name=Synthetic check', '-c', 'user.email=check@example.invalid', 'commit', '--quiet', '-m', 'fixture: verified inputs');
    const revision = git('rev-parse', 'HEAD');
    const archive = path.join(checkout, 'checkout.bundle');
    git('bundle', 'create', archive, '--all');
    const bytes = fs.readFileSync(archive);
    const tree = [];
    function collect(base = '') {
      for (const entry of fs.readdirSync(path.join(checkout, base), { withFileTypes: true })) {
        if (entry.name === '.git' || entry.name === 'checkout.bundle') continue;
        const name = path.join(base, entry.name);
        if (entry.isDirectory()) { tree.push({ name, directory: true }); collect(name); }
        else if (entry.isSymbolicLink()) tree.push({ name, link: fs.readlinkSync(path.join(checkout, name)) });
        else tree.push({ name, bytes: fs.readFileSync(path.join(checkout, name)) });
      }
    }
    collect();
    const result = { revision, bytes, sha: digest(bytes), tree };
    bundles.set(key, result);
    return result;
  } finally { fs.rmSync(checkout, { recursive: true, force: true }); }
}
function fixture(options = {}) {
  const dir = fs.mkdtempSync(path.join(root, '.browser-create-test-'));
  const inputs = path.join(dir, 'inputs');
  const bin = path.join(dir, 'bin');
  for (const name of [inputs, bin]) fs.mkdirSync(name, { mode: 0o700 });
  for (const [name, bytes] of [['node.tar.xz', 'synthetic node'], ['dependencies.tar.gz', 'synthetic dependencies'], ['dsh-source.tar.gz', 'synthetic harness']]) {
    fs.writeFileSync(path.join(inputs, name), bytes, { mode: 0o600 });
  }
  const cached = bundle(options);
  const revision = cached.revision;
  fs.writeFileSync(path.join(inputs, 'checkout.bundle'), cached.bytes, { mode: 0o600 });
  if (!options.realGit) {
    const template = path.join(dir, 'template');
    fs.mkdirSync(template, { mode: 0o700 });
    for (const entry of cached.tree) {
      const target = path.join(template, entry.name);
      if (entry.directory) fs.mkdirSync(target);
      else if (entry.link) fs.symlinkSync(entry.link, target);
      else fs.writeFileSync(target, entry.bytes);
    }
    fs.writeFileSync(path.join(bin, 'git'), `#!/bin/bash
while [[ \"\${1:-}\" == -c ]]; do shift 2; done
if [[ \"\${1:-}\" == clone ]]; then
  target=\"\${@: -1}\"
  mkdir -m 0700 \"$target\" || exit 1
  cp -R ${shellQuote(template + '/.')} \"$target/\" || exit 1
elif [[ \"\${1:-}\" == -C ]]; then
  shift 2
  case \"\${1:-}\" in
    checkout) [[ \"\${4:-}\" == ${shellQuote(revision)} ]] || exit 1 ;;
    rev-parse) printf '%s\\n' ${shellQuote(revision)} ;;
    *) exit 1 ;;
  esac
else exit 1
fi
`, { mode: 0o700 });
  }
  const log = path.join(dir, 'lxc.jsonl');
  const failures = options.failures ?? (options.failure ? [options.failure] : []);
  const failBranches = failures.map(failure => {
    const conditions = failure.map((value, index) => `\"\${${index + 1}:-}\" == ${shellQuote(value)}`).join(' && ');
    return `if [[ ${conditions} ]]; then printf 'private synthetic output\\n'; exit 1; fi`;
  }).join('\n');
  const mock = `#!/bin/bash
printf '%s\\0' \"$@\" >>\"$MOCK_LOG\"
printf '\\n' >>\"$MOCK_LOG\"
shift
${failBranches}
if [[ \"\${1:-}\" == query ]]; then
  case \"\${2:-}\" in
    /1.0/instances) printf '%s\\n' ${shellQuote(options.instances ?? JSON.stringify(options.existingNode ? ['/1.0/instances/C1'] : []))} ;;
    /1.0/profiles) printf '%s\\n' ${shellQuote(options.profiles ?? JSON.stringify(options.existingProfile ? ['/1.0/profiles/browser-C1'] : []))} ;;
    *) printf '%s\\n' ${shellQuote(options.image ?? JSON.stringify({ fingerprint: image, type: 'container', properties: { os: 'Ubuntu', release: 'noble' } }))} ;;
  esac
fi
if [[ \"\${1:-}\" == profile && \"\${2:-}\" == device && \"\${3:-}\" == get && \"\${4:-}\" == default ]]; then printf '%s\\n' ${shellQuote(options.pool ?? 'default')}; fi
if [[ \"\${1:-}\" == exec && \"\${4:-}\" == /bin/bash ]]; then printf 'PRIVATE_OWNER_TOKEN_SENTINEL\\n'; fi
`;
  fs.writeFileSync(path.join(bin, 'lxc'), mock, { mode: 0o700 });
  const wrapper = path.join(dir, 'run.sh');
  fs.writeFileSync(wrapper, `#!/bin/bash
mock_lxc() {
${mock.slice(mock.indexOf('\n') + 1).replaceAll('exit 1', 'return 1')}
}
command() {
  if [[ \"\${1:-}\" == lxc ]]; then shift; mock_lxc \"$@\"; else builtin command \"$@\"; fi
}
entry=$1
shift
source \"$entry\" \"$@\"
`, { mode: 0o700 });
  fs.writeFileSync(path.join(bin, 'uname'), '#!/bin/bash\nprintf "%s\\n" "${MOCK_SYSTEM:-Linux}"\n', { mode: 0o700 });
  const args = ['--name', 'C1', '--image', image, '--inputs', inputs, '--checkout-sha256', cached.sha, '--revision', revision, '--node-sha256', digest('synthetic node'), '--dependencies-sha256', digest('synthetic dependencies'), '--app-port', '28735', '--owner-port', '27792'];
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, MOCK_LOG: log };
  for (const key of ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT']) delete env[key];
  const call = (values = args, extra = {}, entry = script) => spawnSync('/bin/bash', [wrapper, entry, ...values], { cwd: root, env: { ...env, ...extra }, encoding: 'utf8', timeout: 15000 });
  const commands = () => fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').map(line => { const command = line.split('\0').slice(0, -1); assert.equal(command.shift(), '--force-local'); return command; }) : [];
  return { dir, inputs, bin, args, env, call, commands, close: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
function changed(args, option, value) {
  const result = [...args];
  result[result.indexOf(option) + 1] = value;
  return result;
}
function expectRefusal(f, code, args = f.args, extra = {}, entry = script) {
  const result = f.call(args, extra, entry);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, new RegExp(`REFUSED ${code}(?:\\n|$)`));
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE_OWNER_TOKEN_SENTINEL/);
  return result;
}
function within(options, fn) {
  const f = fixture(options);
  try { fn(f); } finally { f.close(); }
}

const flags = ['--name', '--image', '--inputs', '--checkout-sha256', '--revision', '--node-sha256', '--dependencies-sha256', '--app-port', '--owner-port'];
for (const flag of flags) {
  test(`create refuses missing ${flag}`, () => within({}, f => {
    const args = [...f.args];
    args.splice(args.indexOf(flag), 2);
    expectRefusal(f, 'BROWSER_CREATE_USAGE', args);
    assert.deepEqual(f.commands(), []);
  }));
  test(`create refuses duplicate ${flag}`, () => within({}, f => expectRefusal(f, 'BROWSER_CREATE_DUPLICATE_ARGUMENT', [...f.args, flag, f.args[f.args.indexOf(flag) + 1]])));
}
test('create refuses incomplete and unknown arguments', () => within({}, f => {
  expectRefusal(f, 'BROWSER_CREATE_USAGE', ['--name']);
  expectRefusal(f, 'BROWSER_CREATE_USAGE', [...f.args, '--unexpected', 'value']);
}));
const invalid = [
  ['--name', '-C1', 'NAME_INVALID'], ['--name', 'C1/path', 'NAME_INVALID'], ['--name', 'C'.repeat(64), 'NAME_INVALID'], ['--name', 'C1-', 'NAME_INVALID'],
  ['--image', 'ubuntu:24.04', 'IMAGE_INVALID'], ['--image', 'F'.repeat(64), 'IMAGE_INVALID'],
  ['--revision', '0'.repeat(39), 'REVISION_INVALID'],
  ['--checkout-sha256', 'g'.repeat(64), 'DIGEST_INVALID'], ['--node-sha256', '1'.repeat(63), 'DIGEST_INVALID'], ['--dependencies-sha256', 'F'.repeat(64), 'DIGEST_INVALID'],
  ['--inputs', 'relative', 'INPUTS_INVALID'], ['--inputs', '/', 'INPUTS_INVALID'], ['--inputs', '/tmp/\nsecret', 'INPUTS_INVALID'], ['--inputs', '/tmp/\rsecret', 'INPUTS_INVALID'],
];
for (const [flag, value, suffix] of invalid) test(`create refuses ${flag} ${JSON.stringify(value)}`, () => within({}, f => expectRefusal(f, `BROWSER_CREATE_${suffix}`, changed(f.args, flag, value))));
for (const flag of ['--app-port', '--owner-port']) for (const port of ['0', '80', '1023', '65536', '028735', '1e4', '-1', '18735:80', '999999999999999999999999']) {
  test(`create refuses ${flag} ${port}`, () => within({}, f => expectRefusal(f, 'BROWSER_CREATE_PORT_INVALID', changed(f.args, flag, port))));
}
test('create refuses matching proxy ports', () => within({}, f => expectRefusal(f, 'BROWSER_CREATE_PORT_CONFLICT', changed(f.args, '--owner-port', '28735'))));
test('create refuses non-Linux and missing tools', () => within({}, f => {
  expectRefusal(f, 'BROWSER_CREATE_LINUX_REQUIRED', f.args, { MOCK_SYSTEM: 'Darwin' });
  expectRefusal(f, 'BROWSER_CREATE_TOOL_REQUIRED', f.args, { PATH: f.bin });
}));
for (const key of ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT']) test(`create refuses ${key}`, () => within({}, f => expectRefusal(f, 'BROWSER_CREATE_PRELOAD_FORBIDDEN', f.args, { [key]: '' })));
for (const file of ['checkout.bundle', 'node.tar.xz', 'dependencies.tar.gz', 'dsh-source.tar.gz']) {
  test(`create refuses substituted ${file}`, () => within({}, f => {
    fs.appendFileSync(path.join(f.inputs, file), 'changed');
    expectRefusal(f, file === 'dsh-source.tar.gz' ? 'BROWSER_CREATE_HARNESS_DIGEST_MISMATCH' : 'BROWSER_CREATE_INPUT_DIGEST_MISMATCH');
    assert.deepEqual(f.commands(), []);
  }));
  test(`create refuses missing ${file}`, () => within({}, f => {
    fs.unlinkSync(path.join(f.inputs, file));
    expectRefusal(f, 'BROWSER_CREATE_INPUTS_UNAVAILABLE');
    assert.deepEqual(f.commands(), []);
  }));
}
test('create refuses input directory custody and symlinks', () => within({}, f => {
  fs.chmodSync(f.inputs, 0o777);
  expectRefusal(f, 'BROWSER_CREATE_INPUTS_CUSTODY');
  fs.chmodSync(f.inputs, 0o700);
  const link = path.join(f.dir, 'linked-inputs');
  fs.symlinkSync(f.inputs, link);
  expectRefusal(f, 'BROWSER_CREATE_INPUTS_CUSTODY', changed(f.args, '--inputs', link));
  expectRefusal(f, 'BROWSER_CREATE_INPUTS_CUSTODY', changed(f.args, '--inputs', `${f.inputs}/../inputs`));
}));
test('create refuses input file hardlinks, writable files, symlinks and directories', () => {
  for (const variant of ['hardlink', 'writable', 'symlink', 'directory']) within({}, f => {
    const file = path.join(f.inputs, 'node.tar.xz');
    if (variant === 'hardlink') fs.linkSync(file, path.join(f.dir, 'hardlink'));
    if (variant === 'writable') fs.chmodSync(file, 0o666);
    if (variant === 'symlink') { fs.renameSync(file, path.join(f.dir, 'linked-node')); fs.symlinkSync(path.join(f.dir, 'linked-node'), file); }
    if (variant === 'directory') { fs.unlinkSync(file); fs.mkdirSync(file); }
    expectRefusal(f, variant === 'symlink' ? 'BROWSER_CREATE_INPUTS_UNAVAILABLE' : 'BROWSER_CREATE_INPUT_FILE_CUSTODY');
  });
});
test('create refuses invalid bundle and unavailable revision', () => {
  within({ realGit: true }, f => {
    fs.writeFileSync(path.join(f.inputs, 'checkout.bundle'), 'not a bundle');
    expectRefusal(f, 'BROWSER_CREATE_BUNDLE_INVALID', changed(f.args, '--checkout-sha256', digest('not a bundle')));
  });
  within({ realGit: true }, f => expectRefusal(f, 'BROWSER_CREATE_REVISION_UNAVAILABLE', changed(f.args, '--revision', '1'.repeat(40))));
});
test('create refuses unexpected checked-out revision', () => within({}, f => {
  fs.writeFileSync(path.join(f.bin, 'git'), '#!/bin/bash\ncase " $* " in *" rev-parse HEAD "*) printf "%s\\n" ' + '0'.repeat(40) + ' ;; *) exec /usr/bin/git "$@" ;; esac\n', { mode: 0o700 });
  expectRefusal(f, 'BROWSER_CREATE_REVISION_MISMATCH');
}));
test('create refuses invalid harness pin and missing installer', () => {
  within({ pin: 'bad' }, f => expectRefusal(f, 'BROWSER_CREATE_HARNESS_PIN_INVALID'));
  within({ installer: false }, f => expectRefusal(f, 'BROWSER_CREATE_INSTALLER_REQUIRED'));
  within({ helper: false }, f => expectRefusal(f, 'BROWSER_CREATE_HELPER_REQUIRED'));
  within({ checkoutInvalid: true }, f => expectRefusal(f, 'BROWSER_CREATE_CHECKOUT_INVALID'));
  for (const browserExtra of ['directory', 'symlink']) within({ browserExtra }, f => expectRefusal(f, 'BROWSER_CREATE_INSTALLER_INVALID'));
});
for (const [options, code] of [
  [{ existingNode: true }, 'NODE_EXISTS'], [{ existingProfile: true }, 'PROFILE_EXISTS'],
  [{ instances: '{}' }, 'LXD_RESPONSE_INVALID'], [{ profiles: 'bad' }, 'LXD_RESPONSE_INVALID'],
  [{ image: JSON.stringify({ fingerprint: image, type: 'virtual-machine', properties: { os: 'Ubuntu', release: 'noble' } }) }, 'IMAGE_NOT_UBUNTU_24_04'],
  [{ image: JSON.stringify({ fingerprint: '0'.repeat(64), type: 'container', properties: { os: 'Ubuntu', release: 'noble' } }) }, 'IMAGE_NOT_UBUNTU_24_04'],
  [{ image: JSON.stringify({ fingerprint: image, type: 'container', properties: { os: 'Debian', release: 'noble' } }) }, 'IMAGE_NOT_UBUNTU_24_04'],
  [{ image: JSON.stringify({ fingerprint: image, type: 'container', properties: { os: 'Ubuntu', release: 'jammy' } }) }, 'IMAGE_NOT_UBUNTU_24_04'],
  [{ pool: '../storage' }, 'STORAGE_INVALID'], [{ pool: '' }, 'STORAGE_INVALID'],
]) test(`create refuses ${code} ${JSON.stringify(options)}`, () => within(options, f => {
  expectRefusal(f, `BROWSER_CREATE_${code}`);
  assert.ok(!f.commands().some(command => command[0] === 'launch' || command.slice(0, 2).join('|') === 'profile|create'));
}));
const failures = [
  [['query', '/1.0/instances'], 'LXD_UNAVAILABLE', false, false],
  [['query', `/1.0/images/${image}`], 'IMAGE_UNAVAILABLE', false, false],
  [['profile', 'device', 'get'], 'STORAGE_REQUIRED', false, false],
  [['profile', 'create'], 'PROFILE_FAILED', false, false],
  [['profile', 'set'], 'PROFILE_FAILED', true, false],
  [['profile', 'device', 'add'], 'PROFILE_FAILED', true, false],
  [['launch'], 'LAUNCH_FAILED', true, false],
  [['file', 'push'], 'COPY_FAILED', true, true],
  [['exec', 'C1', '--', 'mkdir'], 'COPY_FAILED', true, true],
  [['exec', 'C1', '--', '/bin/bash'], 'INSTALL_FAILED', true, true],
  [['config', 'device', 'add'], 'PROXY_FAILED', true, true],
];
for (const [failure, suffix, profile, container] of failures) test(`create aborts ${suffix} at ${failure.join(' ')}`, () => within({ failure }, f => {
  expectRefusal(f, `BROWSER_CREATE_${suffix}`);
  assert.equal(f.commands().some(command => command.slice(0, 2).join('|') === 'profile|delete'), profile);
  assert.equal(f.commands().some(command => command.slice(0, 2).join('|') === 'delete|--force'), container);
  assert.ok(!fs.readdirSync(f.inputs).some(name => name.startsWith('.browser-create-')));
}));
test('create names failed rollback without hiding the original failure', () => within({ failures: [['exec', 'C1', '--', '/bin/bash'], ['delete'], ['profile', 'delete']] }, f => {
  const result = expectRefusal(f, 'BROWSER_CREATE_INSTALL_FAILED');
  assert.match(result.stderr, /REFUSED BROWSER_CREATE_ROLLBACK_CONTAINER_FAILED/);
  assert.match(result.stderr, /REFUSED BROWSER_CREATE_ROLLBACK_PROFILE_FAILED/);
}));
function verifyCreated(f, entry = script) {
  const result = f.call(f.args, {}, entry);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'CREATED C1; harness stopped pending owner approval\n');
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE_OWNER_TOKEN_SENTINEL/);
  const commands = f.commands();
  assert.deepEqual(commands.find(command => command[0] === 'launch'), ['launch', image, 'C1', '--profile', 'browser-C1']);
  const settings = commands.filter(command => command.slice(0, 2).join('|') === 'profile|set').map(command => command.slice(3).join('='));
  assert.deepEqual(settings, ['security.privileged=false', 'security.nesting=false', 'security.idmap.isolated=true', 'security.devlxd=false', 'limits.cpu=2', 'limits.memory=4GiB', 'limits.memory.swap=false', 'limits.processes=512', 'boot.autostart=false']);
  assert.deepEqual(commands.find(command => command.slice(0, 3).join('|') === 'profile|device|add'), ['profile', 'device', 'add', 'browser-C1', 'root', 'disk', 'path=/', 'pool=default', 'size=20GiB']);
  const proxies = commands.filter(command => command.slice(0, 3).join('|') === 'config|device|add');
  assert.deepEqual(proxies, [
    ['config', 'device', 'add', 'C1', 'browser-app', 'proxy', 'listen=tcp:127.0.0.1:28735', 'connect=tcp:127.0.0.1:18735', 'bind=host', 'nat=false', 'security.uid=65534', 'security.gid=65534'],
    ['config', 'device', 'add', 'C1', 'browser-owner', 'proxy', 'listen=tcp:127.0.0.1:27792', 'connect=tcp:127.0.0.1:17792', 'bind=host', 'nat=false', 'security.uid=65534', 'security.gid=65534'],
  ]);
  assert.ok(commands.some(command => command.slice(0, 2).join('|') === 'file|push' && command[3] === 'C1/root/aukora-browser-installer/stage.py'));
  assert.ok(commands.filter(command => command.slice(0, 2).join('|') === 'file|push').every(command => command.includes('--uid') && command.includes('--gid') && command.includes('--mode')));
  assert.ok(!commands.some(command => command.includes('nic') || command.includes('start') || command.includes('restart') || command.includes('systemctl') || command[0] === 'delete'));
  assert.ok(!fs.readdirSync(f.inputs).some(name => name.startsWith('.browser-create-')));
}
test('create requests fresh restricted no-NIC profile, installs verified snapshots, and binds only host loopback', () => within({ realGit: true }, f => verifyCreated(f)));
test('create accepts the lowest and highest unprivileged proxy ports', () => within({}, f => {
  const args = changed(changed(f.args, '--app-port', '1024'), '--owner-port', '65535');
  assert.equal(f.call(args).status, 0);
}));
test('create shell parses', () => assert.equal(spawnSync('/bin/bash', ['-n', script], { timeout: 10000 }).status, 0));

test('create focused protection mutations fail their regressions', () => {
  const mutations = [
    ['required arguments', ']] || refuse BROWSER_CREATE_USAGE\n[[ ${#name}', ']] || true\n[[ ${#name}', f => expectRefusal(f, 'BROWSER_CREATE_USAGE', f.args.filter((_, index) => index !== 0 && index !== 1))],
    ['duplicate arguments', ']] || refuse BROWSER_CREATE_DUPLICATE_ARGUMENT', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_DUPLICATE_ARGUMENT', [...f.args, '--name', 'C1'])],
    ['name', ']] || refuse BROWSER_CREATE_NAME_INVALID', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_NAME_INVALID', changed(f.args, '--name', '-C1'))],
    ['image fingerprint syntax', ']] || refuse BROWSER_CREATE_IMAGE_INVALID', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_IMAGE_INVALID', changed(f.args, '--image', 'ubuntu:24.04'))],
    ['revision syntax', ']] || refuse BROWSER_CREATE_REVISION_INVALID', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_REVISION_INVALID', changed(f.args, '--revision', 'HEAD'))],
    ['digest syntax', ']] || refuse BROWSER_CREATE_DIGEST_INVALID', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_DIGEST_INVALID', changed(f.args, '--node-sha256', 'x'))],
    ['port range', ']] || refuse BROWSER_CREATE_PORT_INVALID', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_PORT_INVALID', changed(f.args, '--app-port', '80'))],
    ['port separation', ']] || refuse BROWSER_CREATE_PORT_CONFLICT', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_PORT_CONFLICT', changed(f.args, '--owner-port', '28735'))],
    ['input path', ']] || refuse BROWSER_CREATE_INPUTS_INVALID', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_INPUTS_INVALID', changed(f.args, '--inputs', 'relative'))],
    ['preloads', ']] || refuse BROWSER_CREATE_PRELOAD_FORBIDDEN', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_PRELOAD_FORBIDDEN', f.args, { LD_PRELOAD: '' })],
    ['Linux host', ']] || refuse BROWSER_CREATE_LINUX_REQUIRED', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_LINUX_REQUIRED', f.args, { MOCK_SYSTEM: 'Darwin' })],
    ['required tools', '|| refuse BROWSER_CREATE_TOOL_REQUIRED', '|| true', f => expectRefusal(f, 'BROWSER_CREATE_TOOL_REQUIRED', f.args, { PATH: f.bin })],
    ['flat installer files', ']] || refuse BROWSER_CREATE_INSTALLER_INVALID', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_INSTALLER_INVALID'), { browserExtra: 'directory' }],
    ['input directory custody', "raise ValueError('BROWSER_CREATE_INPUTS_CUSTODY')", 'pass', f => { fs.chmodSync(f.inputs, 0o777); expectRefusal(f, 'BROWSER_CREATE_INPUTS_CUSTODY'); }],
    ['input file custody', "os.close(fd)\n            raise ValueError('BROWSER_CREATE_INPUT_FILE_CUSTODY')", 'pass', f => { fs.chmodSync(path.join(f.inputs, 'node.tar.xz'), 0o666); expectRefusal(f, 'BROWSER_CREATE_INPUT_FILE_CUSTODY'); }],
    ['input symlink refusal', 'os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK', 'os.O_RDONLY | os.O_NONBLOCK', f => { const file = path.join(f.inputs, 'node.tar.xz'); fs.renameSync(file, path.join(f.dir, 'linked-node')); fs.symlinkSync(path.join(f.dir, 'linked-node'), file); expectRefusal(f, 'BROWSER_CREATE_INPUTS_UNAVAILABLE'); }],
    ['input digest', "raise ValueError('BROWSER_CREATE_INPUT_DIGEST_MISMATCH')", 'pass', f => { fs.appendFileSync(path.join(f.inputs, 'node.tar.xz'), 'changed'); expectRefusal(f, 'BROWSER_CREATE_INPUT_DIGEST_MISMATCH'); }],
    ['checked-out revision', ']] || refuse BROWSER_CREATE_REVISION_MISMATCH', ']] || true', f => { fs.writeFileSync(path.join(f.bin, 'git'), '#!/bin/bash\ncase " $* " in *" rev-parse HEAD "*) printf "%s\\n" ' + '0'.repeat(40) + ' ;; *) exec /usr/bin/git "$@" ;; esac\n', { mode: 0o700 }); expectRefusal(f, 'BROWSER_CREATE_REVISION_MISMATCH'); }],
    ['harness pin syntax', "raise ValueError('BROWSER_CREATE_HARNESS_PIN_INVALID')", 'pass', f => expectRefusal(f, 'BROWSER_CREATE_HARNESS_PIN_INVALID'), { pin: 'bad' }],
    ['harness digest', "raise ValueError('BROWSER_CREATE_HARNESS_DIGEST_MISMATCH')", 'pass', f => { fs.appendFileSync(path.join(f.inputs, 'dsh-source.tar.gz'), 'changed'); expectRefusal(f, 'BROWSER_CREATE_HARNESS_DIGEST_MISMATCH'); }],
    ['installer required', "raise ValueError('BROWSER_CREATE_INSTALLER_REQUIRED')", 'pass', f => expectRefusal(f, 'BROWSER_CREATE_INSTALLER_REQUIRED'), { installer: false }],
    ['staging helper required', "raise ValueError('BROWSER_CREATE_HELPER_REQUIRED')", 'pass', f => expectRefusal(f, 'BROWSER_CREATE_HELPER_REQUIRED'), { helper: false }],
    ['response structure', "raise ValueError('BROWSER_CREATE_LXD_RESPONSE_INVALID')", 'pass', f => expectRefusal(f, 'BROWSER_CREATE_LXD_RESPONSE_INVALID'), { instances: '{}' }],
    ['fresh node', "raise ValueError('BROWSER_CREATE_' + ('NODE_EXISTS' if kind == 'instances' else 'PROFILE_EXISTS'))", 'pass', f => expectRefusal(f, 'BROWSER_CREATE_NODE_EXISTS'), { existingNode: true }],
    ['fresh profile', "raise ValueError('BROWSER_CREATE_' + ('NODE_EXISTS' if kind == 'instances' else 'PROFILE_EXISTS'))", 'pass', f => expectRefusal(f, 'BROWSER_CREATE_PROFILE_EXISTS'), { existingProfile: true }],
    ['Ubuntu image identity', "raise ValueError('BROWSER_CREATE_IMAGE_NOT_UBUNTU_24_04')", 'pass', f => expectRefusal(f, 'BROWSER_CREATE_IMAGE_NOT_UBUNTU_24_04'), { image: JSON.stringify({ fingerprint: image, type: 'container', properties: { os: 'Debian', release: 'bookworm' } }) }],
    ['pool syntax', ']] || refuse BROWSER_CREATE_STORAGE_INVALID', ']] || true', f => expectRefusal(f, 'BROWSER_CREATE_STORAGE_INVALID'), { pool: '../storage' }],
    ...['security.privileged=false', 'security.nesting=false', 'security.idmap.isolated=true', 'security.devlxd=false', 'limits.cpu=2', 'limits.memory=4GiB', 'limits.memory.swap=false', 'limits.processes=512', 'boot.autostart=false'].map(setting => [`profile ${setting}`, ` ${setting}`, '', verifyCreated]),
    ['loopback app listener', 'listen=tcp:127.0.0.1:$app_port', 'listen=tcp:0.0.0.0:$app_port', verifyCreated],
    ['loopback owner listener', 'listen=tcp:127.0.0.1:$owner_port', 'listen=tcp:0.0.0.0:$owner_port', verifyCreated],
    ['host proxy namespace', 'bind=host nat=false', 'bind=container nat=false', verifyCreated],
    ['proxy NAT refused', 'bind=host nat=false', 'bind=host nat=true', verifyCreated],
    ['proxy privilege', 'security.uid=65534 security.gid=65534', 'security.uid=0 security.gid=0', verifyCreated],
    ['local LXD socket', 'command lxc --force-local', 'command lxc', verifyCreated],
    ['sole restricted profile', '--profile "$profile"', '--profile default', verifyCreated],
  ];
  for (const [label, before, after, check, options = {}] of mutations) within(options, f => {
    assert.ok(source.includes(before), label);
    const entry = path.join(f.dir, 'mutant.sh');
    fs.writeFileSync(entry, source.replace(before, after));
    const adapted = Object.create(f);
    adapted.call = (args = f.args, extra = {}) => f.call(args, extra, entry);
    assert.throws(() => check(adapted), assert.AssertionError, label);
  });
  console.log(`SOURCE-ONLY browser create guard mutations: ${mutations.length}/${mutations.length} killed; mocked LXD only`);
});
