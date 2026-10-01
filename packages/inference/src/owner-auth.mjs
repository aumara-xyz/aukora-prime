import { id, integer, refuse } from './policy.mjs';

/** Trusted private C facade only. This creates no owner, session, listener or credential. */
export function createAuthorityOwnerAuthenticator({ authority, sessionToken } = {}) {
  if (typeof authority?.authenticateSession !== 'function' || typeof sessionToken !== 'function') refuse('OWNER_AUTH_UNAVAILABLE');
  return async context => {
    let token;
    try { token = await sessionToken(context); } catch { refuse('OWNER_AUTH_REQUIRED'); }
    if (typeof token !== 'string' || !/^[a-f0-9]{64}$/u.test(token)) refuse('OWNER_AUTH_REQUIRED');
    let result;
    try { result = await authority.authenticateSession({ session_token: token }); } catch { refuse('OWNER_AUTH_REQUIRED'); }
    // Match the current C public read result; do not forward raw C reasons or token material.
    if (!result || Object.keys(result).sort().join(',') !== 'authorization_epoch,expiry,ok,owner_id,subject'
        || result.ok !== true || !id(result.owner_id) || !/^aukora:1:[a-f0-9]{64}$/u.test(result.subject)
        || !integer(result.authorization_epoch) || typeof result.expiry !== 'string'
        || !Number.isFinite(Date.parse(result.expiry)) || Date.parse(result.expiry) <= Date.now()) refuse('OWNER_AUTH_REQUIRED');
    return { owner_id: result.owner_id, subject: result.subject,
      authorization_epoch: result.authorization_epoch, expiry: result.expiry };
  };
}
