// SPDX-License-Identifier: AGPL-3.0-or-later
// Copied into packages/api/workspace-controller/lib/prime-host.mjs.
import {WorkspaceController} from './index.js';
export const name='prime-workspace';
export const inject=['typert','workspaceRegistry'];
export async function apply(ctx){
 // The CLI's guarded, owner-private workspace is the one selectable path.
 // Registering it writes only native app metadata, never project files.
 await ctx.workspaceRegistry.create(process.cwd(),'Prime CPU workspace');
 ctx.plugin(WorkspaceController);
}
