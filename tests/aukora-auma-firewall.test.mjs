// SPDX-License-Identifier: AGPL-3.0-or-later
// Read the actual nft source as data. This bounded interpreter checks its stated
// packet cases, not Linux/nft syntax or installed filtering. No sockets, nft,
// services, credentials, sudo, dependency build or live probes are invoked.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const source = readFileSync(new URL('../host/auma-local-deny/auma-local-deny.nft', import.meta.url), 'utf8')
const TABLE = 'aukora_auma_local'

function members(raw) {
  return raw.replace(/^\{|\}$/gu, '').split(',').map(value => value.trim())
}
function numericMatch(raw, value) {
  return members(raw).some(member => {
    const match = /^(\d+)(?:-(\d+))?$/u.exec(member)
    assert.ok(match, 'numeric selector must use the supported literal grammar')
    const low = Number(match[1]), high = Number(match[2] ?? match[1])
    assert.ok(Number.isSafeInteger(low) && Number.isSafeInteger(high) && low <= high)
    return Number.isSafeInteger(value) && value >= low && value <= high
  })
}

function parseRule(line) {
  let rest = line
  const selectors = []
  for (let budget = 0; budget < 16; budget++) {
    let match
    if ((match = /^meta skuid (\{[^}]+\}|\d+(?:-\d+)?)/u.exec(rest))) {
      selectors.push(flow => numericMatch(match[1], flow.uid))
    } else if ((match = /^ct state (\{[^}]+\}|[a-z]+)/u.exec(rest))) {
      selectors.push(flow => members(match[1]).includes(flow.state))
    } else if ((match = /^fib daddr type ([a-z]+)/u.exec(rest))) {
      selectors.push(flow => (flow.local ? 'local' : 'unicast') === match[1])
    } else if ((match = /^ip daddr (\{[^}]+\}|[\d.]+)/u.exec(rest))) {
      selectors.push(flow => !flow.address.includes(':') && members(match[1]).includes(flow.address))
    } else if ((match = /^meta l4proto (\{[^}]+\}|[a-z]+)/u.exec(rest))) {
      selectors.push(flow => members(match[1]).includes(flow.protocol))
    } else if ((match = /^(tcp|th) dport (\{[^}]+\}|\d+(?:-\d+)?)/u.exec(rest))) {
      selectors.push(flow => (match[1] === 'tcp' ? flow.protocol === 'tcp' : ['tcp', 'udp'].includes(flow.protocol))
        && numericMatch(match[2], flow.port))
    } else if ((match = /^counter\b/u.exec(rest))) {
      // Counters do not decide a packet verdict.
    } else {
      const action = /^(accept|reject(?: with tcp reset)?|jump [a-z_]+)$/u.exec(rest)?.[1]
      assert.ok(action, `unsupported rule text: ${rest}`)
      return { selectors, action }
    }
    // Each iteration's match has its own lexical binding for the captured selector.
    rest = rest.slice(match[0].length).trim()
  }
  assert.fail('rule parser budget exhausted')
}

function parsePolicy(text) {
  const lines = text.split('\n').map(line => line.replace(/#.*$/u, '').trim()).filter(Boolean)
  assert.equal(lines[0], `table inet ${TABLE}`, 'replacement may create only its own table')
  assert.equal(lines[1], `delete table inet ${TABLE}`, 'replacement may delete only its own table')
  assert.equal(lines[2], `table inet ${TABLE} {`)
  assert.equal(lines.at(-1), '}')
  const chains = new Map()
  let current = null
  for (const line of lines.slice(3, -1)) {
    const chain = /^chain ([a-z_]+) \{$/u.exec(line)?.[1]
    if (chain !== undefined) {
      assert.equal(current, null, 'chains cannot nest')
      assert.ok(!chains.has(chain), 'duplicate chain')
      current = { rules: [] }; chains.set(chain, current)
    } else if (line === '}') {
      assert.ok(current); current = null
    } else {
      assert.ok(current, 'all statements must stay in the owned chains')
      const base = /^type ([a-z]+) hook ([a-z]+) priority ([a-z\d-]+); policy ([a-z]+);$/u.exec(line)
      if (base) {
        assert.equal(current.hook, undefined, 'duplicate base-chain declaration')
        Object.assign(current, { type: base[1], hook: base[2], priority: base[3], policy: base[4] })
      } else current.rules.push(parseRule(line))
    }
  }
  assert.equal(current, null)
  assert.deepEqual([...chains.keys()], ['output', 'auma_local'])
  return chains
}

function verdict(chains, flow) {
  const base = chains.get('output')
  if (base.hook !== 'output') return 'unchanged'
  const evaluate = (name, depth) => {
    assert.ok(depth < 3, 'only the bounded owned jump is supported')
    for (const rule of chains.get(name).rules) {
      if (!rule.selectors.every(selector => selector(flow))) continue
      if (rule.action.startsWith('jump ')) {
        const target = rule.action.slice(5)
        assert.ok(chains.has(target))
        const found = evaluate(target, depth + 1)
        if (found !== null) return found
      } else return rule.action.startsWith('reject') ? 'reject' : 'accept'
    }
    return null
  }
  return evaluate('output', 0) ?? base.policy
}

const flow = extra => ({ uid: 1001, state: 'new', local: true, address: '127.0.0.1', protocol: 'tcp', port: 18735, ...extra })
function assertContract(text) {
  const policy = parsePolicy(text)
  const base = policy.get('output')
  assert.equal(base.type, 'filter')
  assert.equal(base.hook, 'output')
  assert.equal(base.priority, 'filter')
  assert.equal(base.policy, 'accept', 'the added policy does not blanket-drop unrelated traffic')
  assert.deepEqual(Object.keys(policy.get('auma_local')), ['rules'], 'the jump target is a regular chain, not an unmodeled extra hook')
  let cases = 0
  const expect = (packet, expected, label) => { assert.equal(verdict(policy, flow(packet)), expected, label); cases++ }
  // These are reported protected listeners, not invented remote infrastructure.
  for (const uid of [1001, 165536, 166535, 231071]) {
    for (const port of [1933, 1934, 18731, 18732, 18733, 18734, 18735, 54783, 54784, 22, 111]) {
      expect({ uid, port }, 'reject', `new TCP by scoped socket uid ${uid} to protected local port ${port}`)
    }
    expect({ uid, protocol: 'udp', port: 18733 }, 'reject', 'non-TCP local traffic has a final refusal')
    expect({ uid, protocol: 'udp', port: 17690 }, 'reject', 'gateway exception is TCP only')
    expect({ uid, protocol: 'udp', port: 40000 }, 'reject', 'ephemeral exception is TCP only')
    expect({ uid, address: 'synthetic-local-address', port: 18735 }, 'reject', 'the deny covers other host-local addresses too')
    expect({ uid, port: 17690 }, [1001, 166535].includes(uid) ? 'accept' : 'reject',
      'gateway control traffic is restricted to the measured owner and supervisor socket UIDs')
    for (const address of ['127.0.0.53', '127.0.0.54']) for (const protocol of ['tcp', 'udp']) {
      expect({ uid, address, protocol, port: 53 }, 'accept', 'resolver stub remains available')
    }
    for (const port of [32768, 40000, 60999]) expect({ uid, port }, 'accept', 'ssh-proxy ephemeral range stays available')
    for (const port of [32767, 61000]) expect({ uid, port }, 'reject', 'ephemeral exception has bounded endpoints')
    for (const port of [17690, 18733, 18735, 40000]) expect({ uid, address: '::1', port }, 'reject', 'IPv4 exceptions do not open IPv6 local services')
  }
  // Other UIDs are synthetic distinct clients. Actual ubuntu/aukora-host UID values
  // are not invented here; the live readback must show they are outside the match.
  for (const uid of [0, 1000, 1002, 165535, 231072]) {
    for (const port of [22, 18733, 18735, 54783]) expect({ uid, port }, 'accept', 'other socket owners are unchanged by this policy')
  }
  for (const uid of [166534, 166536]) expect({ uid, port: 17690 }, 'reject', 'adjacent subuids do not share the gateway exception')
  expect({ local: false, address: 'nonlocal-fixture', port: 18735 }, 'accept', 'remote traffic remains outside host-local scope')
  return cases
}

test('actual firewall source refuses protected new routes while preserving reported transports', t => {
  t.diagnostic(`${assertContract(source)} in-memory verdict cases; no Linux or installed filtering claim`)
})

test('firewall ceilings stay explicit: established flows, arbitrary ephemeral listeners and socket owner', () => {
  const policy = parsePolicy(source)
  assert.equal(verdict(policy, flow({ state: 'established' })), 'accept', 'pre-existing self-opened connections are not revoked')
  assert.equal(verdict(policy, flow({ state: 'related' })), 'accept')
  assert.equal(verdict(policy, flow({ state: 'invalid' })), 'accept', 'the added policy only matches conntrack new')
  assert.equal(verdict(policy, flow({ state: 'untracked' })), 'accept')
  assert.equal(verdict(policy, flow({ port: 40000 })), 'accept', 'exception does not authenticate the ephemeral listener as ssh-proxy')
  assert.equal(verdict(policy, flow({ uid: 1002 })), 'accept', 'an inherited socket owned by another UID is not an auma skuid match')
  assert.equal(verdict(policy, flow({ local: false, address: 'nonlocal-fixture' })), 'accept', 'this is not an egress firewall')
})

test('guard mutations are caught by the kept deny and required-traffic controls', t => {
  const mutations = [
    ['owner selector removed', text => text.replace('meta skuid { 1001, 165536-231071 } ', '')],
    ['wrong primary uid', text => text.replace('meta skuid { 1001,', 'meta skuid { 1002,')],
    ['subuid range removed', text => text.replace('1001, 165536-231071', '1001')],
    ['wrong conntrack state', text => text.replace('ct state new', 'ct state established')],
    ['local restriction removed', text => text.replace('fib daddr type local ', '')],
    ['gateway exception removed', text => text.replace(/^\s*meta skuid \{ 1001, 166535 \} ip daddr 127\.0\.0\.1 tcp dport 17690 accept\n/mu, '')],
    ['gateway UID restriction removed', text => text.replace('meta skuid { 1001, 166535 } ip daddr', 'ip daddr')],
    ['gateway supervisor UID replaced', text => text.replace('meta skuid { 1001, 166535 } ip daddr', 'meta skuid { 1001, 166536 } ip daddr')],
    ['gateway exception widened to UDP', text => text.replace('tcp dport 17690 accept', 'th dport 17690 accept')],
    ['resolver exception removed', text => text.replace(/^\s*ip daddr \{ 127\.0\.0\.53, 127\.0\.0\.54 \}.*\n/mu, '')],
    ['ephemeral range opens all ports', text => text.replace('tcp dport 32768-60999', 'tcp dport 1-65535')],
    ['ephemeral exception widened to UDP', text => text.replace('tcp dport 32768-60999', 'th dport 32768-60999')],
    ['blocked ephemeral listeners admitted first', text => text.replace(
      /(\t\tip daddr 127\.0\.0\.1 tcp dport \{ 54783, 54784 \}[^\n]+\n)(\t\tip daddr 127\.0\.0\.1 tcp dport 32768-60999[^\n]+\n)/u, '$2$1')],
    ['TCP terminal refusal removed', text => text.replace('counter meta l4proto tcp reject with tcp reset', 'counter meta l4proto tcp accept')],
    ['generic terminal refusal removed', text => text.replace('counter reject\n', 'counter accept\n')],
    ['wrong hook', text => text.replace('hook output', 'hook input')],
    ['blanket default drop', text => text.replace('policy accept;', 'policy drop;')],
    ['jump target gains an extra hook', text => text.replace('chain auma_local {', 'chain auma_local {\n\t\ttype filter hook input priority filter; policy accept;')],
  ]
  for (const [label, mutate] of mutations) {
    const changed = mutate(source)
    assert.notEqual(changed, source, `${label} must change the actual source`)
    assert.throws(() => assertContract(changed), { code: 'ERR_ASSERTION' }, label)
  }
  t.diagnostic(`${mutations.length} source guard mutations detected`)
})
