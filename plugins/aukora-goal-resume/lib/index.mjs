// Re-arm declared goal services once at mount; only clean disposal writes a clean-stop marker.
import { existsSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { bootGoalResume } from './resume.mjs';

export const name = 'aukora-goal-resume';
export const inject = ['goals', 'agents'];

/** The marker path, derived from the goals state directory so no new configuration is invented. */
export const markerFor = (stateDir) => join(stateDir, 'goal-resume.clean');

export function resolveStateDir(config, { throwIfMissing = true } = {}) {
  const stateDir = config?.stateDir;
  if (typeof stateDir === 'string' && stateDir !== '') return stateDir;
  if (throwIfMissing === false) return null;
  throw new Error('aukora-goal-resume: config.stateDir is required — without it the clean/unclean marker has no home '
    + 'and the plugin would mount and do nothing (the failure this refusal exists to prevent)');
}

export function apply(ctx, config = {}) {
  let logger;
  const warn = (reason) => {
    try { (logger?.warn ? logger : console).warn(`aukora-goal-resume: ${reason} — INERT`); } catch { /* logging cannot abort mount */ }
  };
  try {
    logger = ctx.logger;
    const stateDir = resolveStateDir(config, { throwIfMissing: false });
    if (stateDir === null) {
      warn('state-dir-missing: NO config.stateDir');
      return;
    }
    const goals = ctx.goals;
    const agents = ctx.agents;
    if (typeof goals?.get !== 'function' || typeof goals?.resume !== 'function'
        || typeof agents?.roots !== 'function' || typeof agents?.get !== 'function') {
      warn('services-unavailable');
      return;
    }
    const marker = markerFor(stateDir);
    ctx.effect(() => {
      void bootGoalResume({
        markerPath: marker,
        exists: () => existsSync(marker),
        remove: () => rmSync(marker, { force: true }),
        write: () => { /* only clean disposal may write the marker */ },
        sessions: agents.roots().map((agent) => ({ id: agent.sessionId ?? agent.id, agent })),
        goalFor: (sessionId) => {
          const agent = agents.get(sessionId);
          return agent === undefined ? null : goals.get(agent) ?? null;
        },
        resume: (sessionId, goalId) => {
          const agent = agents.get(sessionId);
          const view = agent === undefined ? undefined : goals.get(agent);
          return goals.resume(agent, { id: goalId, revision: view?.revision });
        },
        log: (line) => { try { logger?.info?.(line); } catch { /* logging cannot abort boot */ } },
      }).catch(() => warn('boot-failed'));
      return () => {
        try { mkdirSync(dirname(marker), { recursive: true }); writeFileSync(marker, `${new Date().toISOString()}\n`); } catch { /* best-effort */ }
      };
    }, 'aukora-goal-resume: one re-arm at process start');
  } catch { warn('apply-failed'); }
}
