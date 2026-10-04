// Which targets the production gate entry allowlists, and how it stores them: the reviewed declarative
// allowlist (theme accent only) on the gate-owned target root, through the symlink-refusing fs store.
import { allowlist } from './targets.mjs'
import { fsStore } from './fs-store.mjs'

export function gateTargets(targetRoot, opts = {}) { return allowlist(targetRoot, opts) }
export function gateStore({ gid = 0 } = {}) { return fsStore({ gid }) }
