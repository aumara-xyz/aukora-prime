import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { requireCondition, LIMITS, validateMessage, validateStatus } from './contract.mjs';

export function createClient({ baseUrl, token, transport = 'https' }) {
  const base = new URL(baseUrl);
  requireCondition(!base.username && !base.password && base.pathname === '/' && !base.search && !base.hash, 400, 'invalid_destination');
  requireCondition(['https', 'ssh-loopback'].includes(transport), 400, 'invalid_transport');
  requireCondition((transport === 'https' && base.protocol === 'https:') || (transport === 'ssh-loopback' && base.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(base.hostname)), 400, 'invalid_transport_destination');
  requireCondition(typeof token === 'string' && /^[A-Za-z0-9_-]{32,512}$/.test(token), 400, 'invalid_token');
  async function request(path, method = 'GET', input) {
    const body = input === undefined ? undefined : JSON.stringify(input);
    requireCondition(body === undefined || Buffer.byteLength(body) <= LIMITS.requestBytes, 400, 'request_too_large');
    const response = await fetch(new URL(path, base), {
      method, redirect: 'error', signal: AbortSignal.timeout(10000),
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, body,
    });
    const result = await response.json();
    if (!response.ok) { const error = new Error(`Relay HTTP ${response.status}: ${result.error ?? 'request_failed'}`); error.status = response.status; throw error; }
    return result;
  }
  return {
    whoami: () => request('/v1/whoami'),
    read: (after = '0', limit = 50) => request(`/v1/messages?after=${encodeURIComponent(after)}&limit=${encodeURIComponent(limit)}`),
    post: input => request('/v1/messages', 'POST', validateMessage(input)),
    status: () => request('/v1/status'),
    setStatus: doing => request('/v1/status', 'PUT', validateStatus({ doing })),
  };
}
async function main() {
  const tokenPath = process.env.RELAY_TOKEN_FILE;
  requireCondition(typeof tokenPath === 'string', 400, 'private_token_file_required');
  const stat = statSync(tokenPath);
  requireCondition(stat.isFile() && stat.size <= 1024 && (stat.mode & 0o077) === 0 && stat.uid === process.getuid(), 400, 'private_token_file_required');
  const client = createClient({ baseUrl: process.env.RELAY_URL, token: readFileSync(tokenPath, 'utf8').trim(), transport: process.env.RELAY_TRANSPORT ?? 'https' });
  const [command, argument = '0', limit = '50'] = process.argv.slice(2);
  let result;
  if (command === 'whoami') result = await client.whoami();
  else if (command === 'read') result = await client.read(argument, limit);
  else if (command === 'status') result = await client.status();
  else if (command === 'post' || command === 'set-status') {
    const chunks = []; let bytes = 0;
    for await (const chunk of process.stdin) { bytes += chunk.length; requireCondition(bytes <= LIMITS.requestBytes, 400, 'request_too_large'); chunks.push(chunk); }
    const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    result = command === 'post' ? await client.post(input) : await client.setStatus(validateStatus(input).doing);
  } else throw new Error('Usage: node client.mjs whoami | read [cursor] [limit] | status | post < message.json | set-status < status.json');
  console.log(JSON.stringify(result, null, 2));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => { console.error('Relay request failed. Check the command, approved transport/destination, participant access, and payload.'); process.exitCode = 1; });
}
