// Release recall uses copied release files, fresh processes and loopback HTTP.
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { chmodSync, closeSync, constants, cpSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createOpenVikingHttpFixture, loopbackListenUnavailable } from './support/openviking-http.mjs'

const ROOT = fileURLToPath(new URL('..', import.meta.url)), probeFile = join(ROOT, 'scripts/kira/release-recall-probe.mjs')
const work = mkdtempSync(join(ROOT, 'tests/.release-recall-'))
const subject = `aukora:1:${'3c'.repeat(32)}`
let passed = 0, killed = 0, fixture
const check = async (name, action) => { await action(); passed++; console.log(`PASS ${name}`) }
const refuse = async (action, code) => assert.rejects(async () => action(), error => error.code === `kira.release-probe:${code}`, code)
const empty = name => { const path = join(work, name); mkdirSync(path, { recursive: true, mode: 0o700 }); return path }
function mutantModule(source, target, name, replacement = 'void 0') {
  assert.ok(source.includes(target), `${name}: mutation target missing`)
  const path = join(work, `${name}.mjs`)
  writeFileSync(path, source.replaceAll(target, replacement)
    .replace("'../lib/is-main.mjs'", JSON.stringify(pathToFileURL(join(ROOT, 'scripts/lib/is-main.mjs')).href)))
  return import(pathToFileURL(path).href)
}

function composition(release, args = []) {
  const materializer = join(ROOT, 'scripts/materialize-aukora-release.py')
  const made = spawnSync('python3', ['-B', '-c', `
import ast, json, sys
from pathlib import Path
from types import SimpleNamespace
path, release = sys.argv[1:3]
source = sys.stdin.read()
ns = dict(__file__=path, __name__='materializer_test')
exec(compile(source, path, 'exec'), ns)
main = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
arguments = []
for node in main.body:
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == 'assert_harness_clean':
        break
    arguments.append(node)
sys.argv = [path, '--to', release, *sys.argv[3:]]
exec(compile(ast.Module(body=arguments, type_ignores=[]), path, 'exec'), ns)
ns.update(target=Path(release), default_patch=SimpleNamespace(read_text=lambda **kw: ''), release_root=release)
for node in ast.walk(main):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'write_text' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'default_patch':
        print(eval(compile(ast.Expression(node.args[0]), path, 'eval'), ns), end='')
`, materializer, release, ...args], { input: readFileSync(materializer, 'utf8'), encoding: 'utf8' })
  assert.equal(made.status, 0, made.stderr)
  assert.match(made.stdout, /- id: aukora-kira\n/u)
  writeFileSync(join(release, 'aukora-composition.patch.yml'), made.stdout)
  return made.stdout
}

function copyRuntime(harness, release) {
  for (const path of ['plugins/aukora-kira', 'plugins/aukora-aumlok', 'vendor/aukora-packages', 'vendor/authority', 'packages/contracts']) {
    cpSync(join(ROOT, path), join(release, path), { recursive: true, dereference: true })
  }
  for (const path of ['vendor/include', 'vendor/loader', 'packages/util/home-paths']) {
    mkdirSync(join(release, path), { recursive: true })
    cpSync(join(harness, path, 'lib'), join(release, path, 'lib'), { recursive: true, dereference: true })
    cpSync(join(harness, path, 'package.json'), join(release, path, 'package.json'))
  }
  const require = createRequire(join(harness, 'vendor/include/lib/index.js'))
  for (const name of ['@deepseek-ai/cordis-plugin-loader', '@deepseek-ai/cordis', '@deepseek-ai/cosmokit', 'js-yaml', 'argparse']) {
    const resolvePackage = name === 'argparse' ? createRequire(require.resolve('js-yaml')) : require
    let source = dirname(realpathSync(resolvePackage.resolve(name)))
    while (!existsSync(join(source, 'package.json')) || JSON.parse(readFileSync(join(source, 'package.json'), 'utf8')).name !== name) {
      assert.notEqual(source, dirname(source), `package root missing: ${name}`)
      source = dirname(source)
    }
    cpSync(source, join(release, 'node_modules', name), { recursive: true, dereference: true,
      filter: path => !relative(source, path).split('/').includes('node_modules') })
  }
  writeFileSync(join(release, 'package.json'), '{"type":"module"}\n')
}

function runProbe(release, scratch, { script = probeFile, env = {} } = {}) {
  return new Promise((resolve, reject) => {
    const childEnv = { ...process.env, DSH_HOME: join(work, 'node-home'), AUKORA_STATE: join(work, 'support'),
      AUKORA_ROOM_LOG: join(work, 'absent-room'), AUKORA_OPENVIKING_HOME: join(work, 'wrong-default'), ...env }
    delete childEnv.NODE_OPTIONS; delete childEnv.AUKORA_SUPPORT_ROOT
    const child = spawn(process.execPath, [script, release, '--scratch-state', scratch], { env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = '', stderr = ''
    child.stdout.on('data', chunk => { stdout += chunk }); child.stderr.on('data', chunk => { stderr += chunk })
    child.on('error', reject)
    child.on('close', status => resolve({ status, stdout, stderr }))
  })
}

try {
  const probe = await import(pathToFileURL(probeFile).href)
  const source = readFileSync(probeFile, 'utf8'), realState = empty('real-state'), scratch = empty('scratch')
  const relativeScratch = relative(ROOT, scratch), regularFile = join(work, 'not-directory')
  writeFileSync(regularFile, '')
  const nonempty = empty('nonempty'); writeFileSync(join(nonempty, 'keep'), 'synthetic untouched')
  const descendant = empty('real-state/child'), alias = join(work, 'real-state-alias'); symlinkSync(realState, alias, 'dir')
  const publicState = empty('public-state'); chmodSync(publicState, 0o755)
  const cases = [
    ['scratch-not-absolute', module => module.validateScratch(relativeScratch, realState)],
    ['scratch-not-directory', module => module.validateScratch(regularFile, realState)],
    ['scratch-not-empty', module => module.validateScratch(nonempty, realState)],
    ['scratch-not-owned', module => module.validateScratch(scratch, realState, { uid: statSync(scratch).uid + 1 })],
    ['scratch-not-private', module => module.validateScratch(publicState, realState)],
    ['scratch-real-state', module => module.validateScratch(realState, realState)],
  ]
  await check('scratch guards refuse relative, missing, file, nonempty, wrong owner and public paths', async () => {
    assert.equal(await probe.validateScratch(scratch, realState), realpathSync(scratch))
    for (const [code, action] of cases) await refuse(() => action(probe), code)
    await refuse(() => probe.validateScratch(join(work, 'missing'), realState), 'scratch-not-directory')
  })
  await check('real memory and descendants refuse through canonical symlink aliases', async () => {
    await refuse(() => probe.validateScratch(descendant, realState), 'scratch-real-state')
    await refuse(() => probe.validateScratch(alias, realState), 'scratch-real-state')
    await refuse(() => probe.validateScratch(join(alias, 'child'), realState), 'scratch-real-state')
    assert.equal(readFileSync(join(nonempty, 'keep'), 'utf8'), 'synthetic untouched')
  })
  await check('argument guards refuse relative release and malformed arguments', async () => {
    await refuse(() => probe.probeArgs(['relative', '--scratch-state', scratch]), 'release-not-absolute')
    for (const args of [[], [ROOT], [ROOT, '--other', scratch], [ROOT, '--scratch-state', scratch, '--extra']]) {
      await assert.rejects(async () => probe.probeArgs(args))
    }
  })
  await check('argument and scratch refusal mutants fail their protection checks', async () => {
    for (const [code, action] of [...cases,
      ['release-not-absolute', module => module.probeArgs(['relative', '--scratch-state', scratch])],
      ['usage', module => module.probeArgs([ROOT, '--other', scratch])],
    ]) {
      const target = `fail('${code}')`
      const module = await mutantModule(source, target, code)
      await assert.rejects(async () => refuse(() => action(module), code), undefined, `${code}: survived`)
      killed++
    }
    console.log(`kira-release-recall-probe-test: ${killed}/${killed} argument and scratch refusal mutants killed`)
  })
  await check('the held scratch directory refuses replacement, and its mutant fails that check', async () => {
    const path = empty('held-state'), held = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY)
    try {
      assert.doesNotThrow(() => probe.validateHeldScratch(path, held))
      renameSync(path, `${path}-old`); mkdirSync(path, { mode: 0o700 })
      await refuse(() => probe.validateHeldScratch(path, held), 'scratch-replaced')
      const mutant = await mutantModule(source, "fail('scratch-replaced')", 'scratch-replaced')
      await assert.rejects(async () => refuse(() => mutant.validateHeldScratch(path, held), 'scratch-replaced'), undefined, 'scratch-replaced: survived')
      killed++
      rmSync(path, { recursive: true }); writeFileSync(path, '')
      await refuse(() => probe.validateHeldScratch(path, held), 'scratch-replaced')
    } finally { closeSync(held) }
  })

  const harness = [process.env.AUKORA_DSH_BUILD, join(ROOT, 'vendor/dsh')].filter(Boolean)
    .find(path => existsSync(join(path, 'vendor/include/lib/index.js')) && existsSync(join(path, 'vendor/loader/lib/index.js')))
  if (!harness) {
    console.log('UNPERFORMED: kira-release-recall-probe built release parser unavailable; no HTTP checks ran')
    process.exitCode = 2
  } else {
    const release = empty('release'), home = empty('openviking'), support = empty('support')
    copyRuntime(harness, release)
    writeFileSync(join(support, 'kira-deployment-overlay.patch.yml'), `- id: aukora-kira\n  config:\n    memoryOwner:\n      subject: ${subject}\n`)
    const patch = composition(release, ['--kira-openviking-home', home])
    const originalDshHome = process.env.DSH_HOME
    process.env.DSH_HOME = join(work, 'node-home')
    try {
      await check('real materializer rows use the release parser and retain exact Kira configuration', async () => {
        const config = (await probe.readReleaseConfig(release)).config
        assert.equal(config.retrieval, 'lexical'); assert.equal(config.openVikingHome, home)
        assert.equal(config.memoryOwner.stateDir, join(work, 'node-home/kira-memory'))
        assert.equal(config.memoryOwner.subject, 'aumlok:subject:owner')
        assert.deepEqual(config.memoryOwner.permittedPrivacy, ['local'])
        const project = '/synthetic/kira "projects".json'
        composition(release, ['--kira-openviking-home', home, '--kira-project-map', project])
        assert.equal((await probe.readReleaseConfig(release)).config.projectIdentityFile, project)
        writeFileSync(join(release, 'aukora-composition.patch.yml'), patch)
      })
      await check('malformed composition and disabled, duplicate or changed Kira rows refuse', async () => {
        const file = join(release, 'aukora-composition.patch.yml')
        for (const invalid of ['greeting: yes\n', '[null]\n', '[\n']) {
          writeFileSync(file, invalid)
          await refuse(() => probe.readReleaseConfig(release), 'composition-invalid')
        }
        for (const changed of [
          ...['true', '!!js true', `!!js "'yes'"`].map(disabled => patch.replace('    - id: aukora-kira\n', `    - id: aukora-kira\n      disabled: ${disabled}\n`)),
          patch.replace('./plugins/aukora-kira/lib/gate-capture-host.mjs', './plugins/aukora-kira/lib/index.js'),
          patch + '- insert:\n    - id: aukora-kira\n      name: ./plugins/aukora-kira/lib/gate-capture-host.mjs\n      config: {}\n',
          patch.replace('        memoryOwner:\n', '        otherOwner:\n'),
        ]) {
          assert.notEqual(changed, patch, 'row protection fixture must change the materialized bytes')
          writeFileSync(file, changed)
          await refuse(() => probe.readReleaseConfig(release), 'kira-row-invalid')
        }
        writeFileSync(file, patch)
      })
      await check('release modules cannot point outside the release through a symlink', async () => {
        const file = join(release, 'plugins/aukora-kira/lib/index.js'), saved = readFileSync(file)
        rmSync(file); symlinkSync(join(ROOT, 'plugins/aukora-kira/lib/index.js'), file)
        await refuse(() => probe.readReleaseConfig(release), 'release-file-outside')
        const mutant = await mutantModule(source, "fail('release-file-outside')", 'release-file-outside')
        await assert.rejects(async () => refuse(() => mutant.readReleaseConfig(release), 'release-file-outside'), undefined, 'release-file-outside: survived')
        killed++; rmSync(file); writeFileSync(file, saved)
      })
      await check('composition and Kira row refusal mutants fail their protection checks', async () => {
        const file = join(release, 'aukora-composition.patch.yml')
        for (const [code, changed] of [
          ['composition-invalid', 'greeting: yes\n'],
          ['kira-row-invalid', patch.replace('    - id: aukora-kira\n', '    - id: aukora-kira\n      disabled: true\n')],
        ]) {
          writeFileSync(file, changed)
          const mutant = await mutantModule(source, `fail('${code}')`, code)
          await assert.rejects(async () => refuse(() => mutant.readReleaseConfig(release), code), undefined, `${code}: survived`)
          killed++
        }
        writeFileSync(file, patch.replace('    - id: aukora-kira\n', `    - id: aukora-kira\n      disabled: !!js "'yes'"\n`))
        const disabledTarget = 'Boolean(interpolate({ dshHomePath }, matches[0].disabled))'
        assert.equal(source.split(disabledTarget).length, 2, 'interpolated disabled mutation target')
        const disabledMutant = await mutantModule(source, disabledTarget, 'disabled-expression', 'matches[0].disabled === true')
        await assert.rejects(async () => refuse(() => disabledMutant.readReleaseConfig(release), 'kira-row-invalid'), undefined, 'disabled-expression: survived')
        killed++
        writeFileSync(file, patch)
      })
    } finally {
      if (originalDshHome === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = originalDshHome
    }
    composition(release)
    await check('the operator command refuses unsafe scratch stores before any memory operation', async () => {
      const nodeState = empty('node-home/kira-memory'), child = empty('node-home/kira-memory/child')
      const nodeAlias = join(work, 'node-state-alias'); symlinkSync(nodeState, nodeAlias, 'dir')
      for (const [path, code] of [
        [relativeScratch, 'scratch-not-absolute'], [join(work, 'missing'), 'scratch-not-directory'],
        [regularFile, 'scratch-not-directory'], [nonempty, 'scratch-not-empty'], [publicState, 'scratch-not-private'],
        [nodeState, 'scratch-real-state'], [child, 'scratch-real-state'], [nodeAlias, 'scratch-real-state'],
        [join(nodeAlias, 'child'), 'scratch-real-state'],
      ]) {
        const result = await runProbe(release, path)
        assert.equal(result.status, 1, `${result.stdout}${result.stderr}`)
        assert.ok(result.stderr.includes(`kira.release-probe:${code}`), `${code}: ${result.stderr}`)
      }
      assert.equal(readFileSync(join(nonempty, 'keep'), 'utf8'), 'synthetic untouched')
      rmSync(join(work, 'node-home'), { recursive: true }); rmSync(nodeAlias)
      const target = 'const path = validateScratch(scratch, rawState)'
      assert.equal(source.split(target).length, 2, 'scratch validation wiring mutation target')
      const script = join(work, 'scratch-wiring.mjs')
      writeFileSync(script, source.replace(target, 'const path = realpathSync(scratch)')
        .replace("'../lib/is-main.mjs'", JSON.stringify(pathToFileURL(join(ROOT, 'scripts/lib/is-main.mjs')).href)))
      const mutant = await runProbe(release, nonempty, { script })
      assert.equal(mutant.status, 2, `${mutant.stdout}${mutant.stderr}`)
      assert.match(mutant.stdout, /UNPERFORMED: .*no OpenViking home/u)
      killed++
    })
    await check('unconfigured release reports which OpenViking path is unperformed', async () => {
      const result = await runProbe(release, empty('unconfigured-scratch'))
      assert.equal(result.status, 2, `${result.stdout}${result.stderr}`)
      assert.match(result.stdout, /UNPERFORMED: .*no OpenViking home/u)
      writeFileSync(join(release, 'aukora-composition.patch.yml'), patch)
    })
    writeFileSync(join(home, 'root.key'), 'synthetic-key', { mode: 0o600 })
    writeFileSync(join(home, 'aukora-bridge.json'), JSON.stringify({ url: 'http://127.0.0.1:1', account: 'aukora', user: 'owner', timeoutMs: 1000, syncBatch: 8 }))
    writeFileSync(join(home, 'ov.conf'), JSON.stringify({ embedding: { dense: { provider: 'openai', api_base: 'http://127.0.0.1:1934/v1' } } }))
    await check('unreachable configured OpenViking reports unperformed without printing its key', async () => {
      const result = await runProbe(release, empty('unreachable-scratch'))
      assert.equal(result.status, 2, `${result.stdout}${result.stderr}`)
      assert.match(result.stdout, /UNPERFORMED: .*OpenViking unreachable/u)
      assert.doesNotMatch(`${result.stdout}${result.stderr}`, /synthetic-key/u)
    })
    await check('child output and provider errors cannot expose a root key, and a noisy-output mutant fails', async () => {
      const bridge = join(release, 'plugins/aukora-kira/lib/recall-openviking.mjs'), original = readFileSync(bridge, 'utf8')
      const target = 'const available = async () => {'
      assert.equal(original.split(target).length, 2, 'noisy provider fixture target')
      writeFileSync(bridge, original.replace(target, `${target}\n    console.log(config.key); console.error(config.key); throw Error(config.key)`))
      try {
        const secretSuppressed = result => {
          assert.equal(result.status, 1)
          assert.doesNotMatch(`${result.stdout}${result.stderr}`, /synthetic-key/u)
        }
        secretSuppressed(await runProbe(release, empty('noisy-provider-scratch')))
        const stdio = "stdio: ['ignore', 'ignore', 'ignore', 'ipc']"
        assert.equal(source.split(stdio).length, 2, 'child output mutation target')
        const script = join(work, 'child-output.mjs')
        writeFileSync(script, source.replace(stdio, "stdio: ['ignore', 'inherit', 'inherit', 'ipc']")
          .replace("'../lib/is-main.mjs'", JSON.stringify(pathToFileURL(join(ROOT, 'scripts/lib/is-main.mjs')).href)))
        const mutant = await runProbe(release, empty('noisy-output-mutant-scratch'), { script })
        assert.throws(() => secretSuppressed(mutant), undefined, 'child-output: survived')
        killed++
      } finally { writeFileSync(bridge, original) }
    })
    const semanticPairs = []
    try {
      fixture = await createOpenVikingHttpFixture({ semanticMatch: (content, query) => {
        semanticPairs.push({ content, query })
        return content.startsWith('Scarlet bicycle ') && query.includes('two-wheeler')
      } })
    } catch (error) {
      if (!loopbackListenUnavailable(error)) throw error
      console.log(`UNPERFORMED: kira-release-recall-probe loopback listen refused (${error.code}); no HTTP checks ran`)
      process.exitCode = 2
    }
    if (fixture) {
      writeFileSync(join(home, 'aukora-bridge.json'), JSON.stringify({ url: fixture.url, account: 'aukora', user: 'owner', timeoutMs: 1000, syncBatch: 8 }))
      await check('release remembers, recalls by meaning and words, forgets and proves both absent', async () => {
        const result = await runProbe(release, empty('operator-scratch'))
        assert.equal(result.status, 0, `${result.stdout}${result.stderr}`)
        for (const line of [
          'PASS remember',
          'PASS semantic-recall: method=openviking-semantic degraded=false sentence=true',
          'PASS lexical-recall: method=lexical-bm25-bigram degraded=false sentence=true',
          'PASS forget', 'PASS absent-semantic', 'PASS absent-lexical',
          'kira-release-recall-probe: 6 passed, 0 failed',
        ]) assert.ok(result.stdout.includes(line), `missing step: ${line}\n${result.stdout}`)
        assert.doesNotMatch(`${result.stdout}${result.stderr}`, /synthetic-key/u)
        assert.equal(fixture.files.size, 0); assert.equal(fixture.vectors.size, 0)
        assert.ok(fixture.calls.some(call => call.path === '/api/v1/content/write'))
        assert.ok(fixture.calls.some(call => call.path === '/api/v1/search/find'))
        const pair = semanticPairs.find(({ content, query }) => content.startsWith('Scarlet bicycle ') && query.includes('two-wheeler'))
        assert.ok(pair, 'the semantic query never reached OpenViking')
        const words = text => text.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean)
        assert.equal(words(pair.content).some(word => words(pair.query).includes(word)), false, 'meaning question shares a lexical word')
        const pids = [...result.stdout.matchAll(/ process=(\d+)$/gmu)].map(match => Number(match[1]))
        assert.equal(pids.length, 6); assert.equal(new Set(pids).size, 6)
        assert.equal(pids.includes(process.pid), false, 'probe operations used the test process')
        assert.equal(existsSync(join(work, 'node-home/kira-memory')), false, 'real node memory was written')
      })
      await check('mutating the release to lexical retrieval fails the semantic step', async () => {
        const index = join(release, 'plugins/aukora-kira/lib/index.js'), original = readFileSync(index, 'utf8')
        const before = "const lexicalOnly = normalized.retrieval === 'lexical' && normalized.openVikingHome === undefined"
        assert.equal(original.split(before).length, 2, 'lexical mutation target')
        writeFileSync(index, original.replace(before, 'const lexicalOnly = true'))
        const result = await runProbe(release, empty('lexical-mutant-scratch'))
        assert.equal(result.status, 1, `${result.stdout}${result.stderr}`)
        assert.match(result.stdout, /FAIL semantic-recall: method=lexical-bm25-bigram/u)
        assert.doesNotMatch(result.stdout, /kira-release-recall-probe: 6 passed, 0 failed/u)
        writeFileSync(index, original); killed++
      })
    }
  }
  console.log(`kira-release-recall-probe-test: ${passed} passed, 0 failed; ${killed} mutants killed`)
} finally {
  if (fixture) await fixture.close()
  rmSync(work, { recursive: true, force: true })
}
