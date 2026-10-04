// SPDX-License-Identifier: AGPL-3.0-or-later
// Implements the existing DSH subprocess seam in the OpenShell guest world.
import { Writable } from 'node:stream';
import { openGuestStream } from './stream.mjs';
import { readConfinementInfo, unavailable } from './transport.mjs';

const ownObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = value => typeof value === 'string' && !value.includes('\0') && value.isWellFormed();
const bounded = value => Number.isSafeInteger(value) && value > 0 && value <= 64 * 1024 * 1024;
const signals = new Set(['SIGINT', 'SIGTERM', 'SIGKILL', 'SIGTSTP', 'SIGHUP']);
const envNames = new Set(['LANG', 'LC_ALL', 'TERM', 'PS1', 'PROMPT_COMMAND',
  'DSH_SESSION_ID', 'DSH_PTY_SESSION_ID', 'DSH_HOME', 'DSH_SHELL',
  'NO_COLOR', 'PAGER', 'GIT_PAGER', 'BASH_SILENCE_DEPRECATION_WARNING']);

function guestEnvironment(input) {
  if (input === undefined) return {};
  if (!ownObject(input)) throw unavailable('ENVIRONMENT', 'invalid guest environment');
  const result = {};
  for (const [key, value] of Object.entries(input)) {
    // Native PTC deliberately tombstones ordinary inherited host entries.
    if (value === undefined) continue;
    if (!envNames.has(key) || !text(value) || Buffer.byteLength(value) > 8192
      || key === 'DSH_HOME' && value !== '/sandbox'
      || key === 'DSH_SHELL' && value !== '1'
      || ['NO_COLOR', 'BASH_SILENCE_DEPRECATION_WARNING'].includes(key) && value !== '1'
      || ['PAGER', 'GIT_PAGER'].includes(key) && value !== 'cat') {
      throw unavailable('ENVIRONMENT', 'unsupported guest environment entry');
    }
    result[key] = value;
  }
  return result;
}

export function validateGuestPolicy(policy, settings, signal) {
  signal?.throwIfAborted();
  if (!ownObject(policy) || Object.keys(policy).some(key => !['mode', 'workspaceRoot', 'sessionId'].includes(key))
    || policy.mode !== 'workspace-write' || (policy.workspaceRoot !== settings.workspaceRoot
      && (settings.hostWorkspaceRoot === undefined || policy.workspaceRoot !== settings.hostWorkspaceRoot))
    || policy.sessionId !== undefined && (!text(policy.sessionId) || !policy.sessionId || policy.sessionId.length > 256)) {
    throw unavailable('POLICY', 'the exact supported guest policy is required');
  }
}

/** Positive route selection; model Node programs arrive through the existing FD7 protocol. */
export function validateGuestArgv(argv, settings, paths) {
  if (!Array.isArray(argv) || !argv.length || argv.length > 16 || argv.some(value => !text(value))
    || Buffer.byteLength(JSON.stringify(argv)) > 256 * 1024) throw unavailable('ARGV', 'invalid guest argv');
  const [program, ...args] = argv;
  const bash = ['bash', '/bin/bash', '/usr/bin/bash', paths.get('bash')].includes(program);
  if (bash && args.length === 2 && args[0] === '-c') return;
  if (bash && [[], ['-l'], ['-i'], ['--noprofile', '--norc', '-i']]
    .some(shape => shape.length === args.length && shape.every((value, index) => args[index] === value))) return;
  if (program === paths.get('node') && args.length === 3
    && /^--max-old-space-size=[1-9][0-9]{0,3}$/.test(args[0])
    && Number(args[0].split('=')[1]) <= 4096 && args[1] === settings.bootstrapPath
    && /^[1-9][0-9]{0,8}$/.test(args[2]) && Number(args[2]) <= 134217728) return;
  throw unavailable('ARGV', 'the guest executable or launch shape is unsupported');
}

function mode(input) {
  if (input === 'pipe' || input === 'inherit') return input;
  if (!ownObject(input) || Object.keys(input).some(key => !['maxBytes', 'spill'].includes(key))
    || !bounded(input.maxBytes) || input.spill !== undefined && (!ownObject(input.spill)
      || Object.keys(input.spill).length !== 1 || !bounded(input.spill.maxBytes))) {
    throw unavailable('STDIO', 'invalid guest output disposition');
  }
  return input;
}

/** One provider and one non-replayable preparation map for the same context. */
export function createGuestExecution(settings, layout) {
  const admissions = new WeakMap(), paths = new Map(), live = new Set();
  let unknownRange = false;
  const requireKnownRange = () => {
    if (unknownRange) throw unavailable('GUEST_CLEANUP_UNKNOWN', 'guest cleanup requires trusted reconciliation before another launch');
  };
  const prepare = async (argv, policy, signal) => {
    requireKnownRange();
    validateGuestPolicy(policy, settings, signal); validateGuestArgv(argv, settings, paths);
    await readConfinementInfo(layout, signal);
    requireKnownRange();
    signal?.throwIfAborted();
    const prepared = Object.freeze([...argv]);
    admissions.set(prepared, { ...policy });
    return Object.freeze({ argv: prepared, enforcement: 'full', denialSignatures: [], runnerFailureRules: [] });
  };
  const admit = spec => {
    requireKnownRange();
    spec.signal?.throwIfAborted();
    const policy = admissions.get(spec.argv);
    if (!policy) throw unavailable('ADMISSION', 'guest launch requires its original prepared argv');
    // Consume before validating or starting a carrier. A failed launch cannot replay.
    admissions.delete(spec.argv);
    validateGuestPolicy(policy, settings, spec.signal); validateGuestArgv(spec.argv, settings, paths);
    const sameWorkspace = spec.cwd === settings.workspaceRoot || (settings.hostWorkspaceRoot !== undefined
      && policy.workspaceRoot === settings.hostWorkspaceRoot && spec.cwd === settings.hostWorkspaceRoot);
    if (!sameWorkspace || !Number.isFinite(spec.graceMs)
      || spec.graceMs <= 0 || spec.graceMs > 10_000) throw unavailable('WORKSPACE', 'invalid guest launch scope');
    return guestEnvironment(spec.env);
  };
  const track = session => {
    live.add(session);
    session.empty.then(() => live.delete(session), () => { unknownRange = true; });
    return session;
  };
  const request = (kind, argv, env, spec = {}) => ({ type: 'launch', version: 1, kind,
    argv, cwd: settings.workspaceRoot, env, stdin: spec.stdin ?? 'ignore', control: spec.control ?? false,
    grace_ms: Math.ceil(spec.graceMs ?? 1000), rows: spec.rows ?? 0, cols: spec.cols ?? 0,
    terminal_type: spec.terminalType ?? '' });

  function provider(Runtime, OutputCollector, prepareManagedProcessBinding, NotFoundError) {
    return class GuestSubprocessRuntime extends Runtime {
      constructor(ctx) {
        super(ctx);
        ctx.effect(() => async () => {
          const active = [...live];
          await Promise.all(active.map(session => session.terminate()));
        });
      }
      async resolveExecutable(command, env, signal) {
        requireKnownRange();
        signal?.throwIfAborted();
        guestEnvironment(env);
        if (!['bash', '/bin/bash', '/usr/bin/bash', settings.nodeExecutable].includes(command)) {
          throw new NotFoundError('The configured guest executable is not supported');
        }
        await readConfinementInfo(layout, signal);
        requireKnownRange();
        const session = track(openGuestStream(request('lookup', [command], {}), settings, layout, signal));
        const path = await session.resolved;
        await session.empty;
        paths.set(command === settings.nodeExecutable ? 'node' : 'bash', path);
        return path;
      }
      async terminalEnvironment(signal) {
        const defaultShell = await this.resolveExecutable('/bin/bash', undefined, signal);
        return { platform: 'posix', defaultShell };
      }
      spawn(spec) {
        const env = admit(spec);
        if (!ownObject(spec.stdio) || Object.keys(spec.stdio).some(key => !['stdin', 'stdout', 'stderr', 'control'].includes(key))
          || spec.stdio.control !== undefined && spec.stdio.control !== 'pipe') throw unavailable('STDIO', 'invalid guest stdio');
        const outMode = mode(spec.stdio.stdout), errMode = mode(spec.stdio.stderr), input = spec.stdio.stdin;
        if (input !== 'ignore' && input !== 'pipe' && (!ownObject(input) || Object.keys(input).length !== 1 || !text(input.data))) {
          throw unavailable('STDIO', 'invalid guest stdin disposition');
        }
        const storage = typeof outMode === 'object' || typeof errMode === 'object' ? prepareManagedProcessBinding() : undefined;
        const out = typeof outMode === 'object' ? new OutputCollector(outMode.maxBytes, outMode.spill?.maxBytes, 'stdout', storage.spillDir) : undefined;
        const err = typeof errMode === 'object' ? new OutputCollector(errMode.maxBytes, errMode.spill?.maxBytes, 'stderr', storage.spillDir) : undefined;
        const session = track(openGuestStream(request('process', spec.argv, env, {
          stdin: input === 'ignore' ? 'ignore' : 'pipe', control: spec.stdio.control === 'pipe', graceMs: spec.graceMs,
        }), settings, layout, spec.signal));
        if (out) session.stdout.on('data', chunk => out.push(chunk));
        else if (outMode === 'inherit') session.stdout.pipe(process.stdout, { end: false });
        if (err) session.stderr.on('data', chunk => err.push(chunk));
        else if (errMode === 'inherit') session.stderr.pipe(process.stderr, { end: false });
        const stdin = input === 'pipe' ? new Writable({
          write(chunk, encoding, callback) { session.writeStdin(chunk).then(() => callback(), error => callback(error)); },
          final(callback) { session.endStdin().then(() => callback(), error => callback(error)); },
        }) : undefined;
        stdin?.on('error', () => { void session.terminate().catch(() => {}); });
        if (ownObject(input)) session.ready.then(async () => {
          await session.writeStdin(input.data); await session.endStdin();
        }).catch(() => {});
        const done = session.done.finally(() => { out?.seal(); err?.seal(); });
        done.catch(() => {});
        return { stdin, stdout: outMode === 'pipe' ? session.stdout : undefined,
          stderr: errMode === 'pipe' ? session.stderr : undefined,
          control: spec.stdio.control === 'pipe' ? session.control : undefined,
          collected: { ...(out ? { stdout: out } : {}), ...(err ? { stderr: err } : {}) }, done,
          terminate() { void session.terminate().catch(() => {}); },
          async waitForExit(signal) {
            if (!signal) return session.empty;
            if (signal.aborted) return false;
            let abort;
            const cancelled = new Promise(resolve => { abort = () => resolve(false); signal.addEventListener('abort', abort, { once: true }); });
            try { return await Promise.race([session.empty, cancelled]); }
            finally { signal.removeEventListener('abort', abort); }
          },
        };
      }
      async spawnTerminal(spec) {
        const env = admit(spec);
        if (!Number.isSafeInteger(spec.rows) || spec.rows < 1 || spec.rows > 1000
          || !Number.isSafeInteger(spec.cols) || spec.cols < 1 || spec.cols > 1000
          || !['dumb', 'xterm-256color'].includes(spec.terminalType)) throw unavailable('PTY', 'invalid guest terminal dimensions');
        const session = track(openGuestStream(request('terminal', spec.argv, env, {
          stdin: 'pipe', graceMs: spec.graceMs, rows: spec.rows, cols: spec.cols, terminalType: spec.terminalType,
        }), settings, layout, spec.signal));
        let pid;
        try {
          pid = await session.ready;
          spec.signal?.throwIfAborted();
          session.detachAllocationSignal();
        } catch (error) {
          await session.terminate();
          throw error;
        }
        return { pid, output: session.output, done: session.done,
          write: data => session.writeStdin(data),
          resize: (cols, rows) => {
            if (!Number.isSafeInteger(cols) || cols < 1 || cols > 1000 || !Number.isSafeInteger(rows) || rows < 1 || rows > 1000)
              return Promise.reject(unavailable('PTY', 'invalid guest terminal dimensions'));
            return session.rpc('resize', { cols, rows }).then(() => {});
          },
          async inspectForeground() {
            const value = await session.rpc('foreground');
            if (value === null) return undefined;
            if (!ownObject(value) || Object.keys(value).length !== 2 || !Number.isSafeInteger(value.processGroupId)
              || value.processGroupId <= 1 || typeof value.inputWaiting !== 'boolean') throw unavailable('PTY', 'invalid guest foreground facts');
            return value;
          },
          async signalForeground(signal) {
            if (!signals.has(signal)) throw unavailable('PTY', 'unsupported guest terminal signal');
            const pgid = await session.rpc('signal', { signal });
            if (!Number.isSafeInteger(pgid) || pgid <= 1) throw unavailable('PTY', 'invalid guest signal acknowledgment');
            return pgid;
          },
          terminate: () => session.terminate(),
        };
      }
    };
  }
  return Object.freeze({ confine: prepare, provider });
}
