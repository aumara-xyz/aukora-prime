// SPDX-License-Identifier: AGPL-3.0-or-later
// Copied into packages/api/workspace-controller/lib/prime-host.mjs.
import {WorkspaceController} from './index.js';
import {isAbsolute} from 'node:path';
export const name='prime-workspace';
export const inject=['typert','workspaceRegistry'];
export async function apply(ctx,config={}){
 // These values come from the trusted host mount configuration, never a
 // conversation request. Snapshot them before asynchronous registration.
 const homeSession=config.homeSession===undefined?'':config.homeSession;
 const workspaceRoot=config.workspaceRoot===undefined?process.cwd():config.workspaceRoot;
 if(typeof homeSession!=='string'||homeSession!==homeSession.trim()||homeSession.length>256||/[\u0000-\u001f\u007f]/u.test(homeSession))
  throw new Error('PRIME_HOME_SESSION_INVALID');
 if(typeof workspaceRoot!=='string'||!isAbsolute(workspaceRoot)||workspaceRoot!==workspaceRoot.trim()||/[\u0000-\u001f\u007f]/u.test(workspaceRoot))
  throw new Error('PRIME_WORKSPACE_ROOT_INVALID');
 if(homeSession!==''&&config.workspaceRoot===undefined)throw new Error('PRIME_HOME_WORKSPACE_REQUIRED');
 // The CLI's guarded, owner-private workspace is the one selectable path.
 // Registering it writes only native app metadata, never project files.
 const workspace=await ctx.workspaceRegistry.create(workspaceRoot,'Prime CPU workspace');
 await ctx.plugin(WorkspaceController);
 // No configured identity means registration only. Native create/adopt keeps
 // its immutable-cwd check: a mismatched existing home is refused unchanged.
 if(homeSession==='')return;
 // A dependency-pending child is not a ready home. Qualification observes
 // the native session/header and workspace membership after creation.
 await ctx.inject(['sessionController'],async host=>{
  const created=await host.sessionController.create({sessionId:homeSession,workspaceId:workspace.id});
  if(created.sessionId!==homeSession)throw new Error('PRIME_HOME_SESSION_ID_MISMATCH');
 });
}
