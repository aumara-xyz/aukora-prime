// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise real Cordis realms with synthetic providers; no guest process launches.
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

if (process.argv.length !== 3) {
  throw new Error('usage: node checks/scopes.mjs <existing-built-cordis-index.js>');
}
const { Context, Service } = await import(pathToFileURL(resolve(process.argv[2])).href);
const root = new Context();
const guestLabel = Symbol('model-execution');
const guestCtx = root.isolate('subprocess', guestLabel);
let readFileHelper;
let readPtc;
let createAgent;
let readPersistentTerminal;

class PtcProvider extends Service {
  static inject = ['subprocess'];
  constructor(ctx) { super(ctx, 'ptcRuntime'); }
  read() { return this.ctx.subprocess.world; }
}

class AgentFactory extends Service {
  constructor(ctx) {
    super(ctx, 'agentLoop');
    this.runtime = { ctx };
  }
  create() { return { ctx: this.runtime.ctx.extend() }; }
}

const browserExecution = (agent) => {
  const subprocess = agent.ctx.get('subprocess');
  if (subprocess === undefined) throw new Error('missing execution provider');
  return subprocess.world;
};

try {
  await root.plugin({
    name: 'scope-check-native-provider',
    apply(ctx) { ctx.provide('subprocess', { world: 'host-native' }); },
  });
  await root.plugin({
    name: 'scope-check-file-helper', inject: ['subprocess'],
    apply(ctx) { readFileHelper = () => ctx.subprocess.world; },
  });
  await guestCtx.plugin({
    name: 'scope-check-guest-provider',
    apply(ctx) { ctx.provide('subprocess', { world: 'openshell-guest' }); },
  });
  await guestCtx.plugin(PtcProvider);
  await guestCtx.plugin(AgentFactory);
  await guestCtx.plugin({
    name: 'scope-check-terminal-backend', inject: ['subprocess'],
    apply(ctx) { readPersistentTerminal = () => ctx.subprocess.world; },
  });
  await root.plugin({
    name: 'scope-check-consumers', inject: ['ptcRuntime', 'agentLoop'],
    apply(ctx) {
      readPtc = () => ctx.get('ptcRuntime').read();
      createAgent = () => ctx.get('agentLoop').create();
    },
  });

  assert.equal(root.get('subprocess').world, 'host-native');
  assert.equal(readFileHelper(), 'host-native');
  assert.equal(readPtc(), 'openshell-guest');
  assert.equal(readPersistentTerminal(), 'openshell-guest');
  const agent = createAgent();
  assert.equal(agent.ctx.get('subprocess').world, 'openshell-guest');
  assert.equal(browserExecution(agent), 'openshell-guest');
  assert.equal(root.isolate('subprocess', guestLabel).get('subprocess').world,
    'openshell-guest');
  const unmounted = root.isolate('subprocess');
  assert.equal(unmounted.get('subprocess'), undefined);
  assert.throws(() => browserExecution({ ctx: unmounted }), /missing execution provider/);
  assert.equal(readFileHelper(), 'host-native');
} finally {
  await root.fiber.dispose();
}
process.stdout.write('PASS: real Cordis native helpers, guest execution, and absent-realm refusal\n');
