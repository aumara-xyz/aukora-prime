// SPDX-License-Identifier: AGPL-3.0-or-later
// Unmounted root assembly. Protected channel/release pins and the existing
// connection/origin guards are host inputs; no qualification is created here.
import {createOwnerMemoryIpcBoundary} from './owner-memory-ipc.mjs';
import {createOwnerMemoryHttpRoutes} from './owner-memory-transport.mjs';

export function createOwnerMemoryHost({connection,guardRequest,contracts,channel,deployment}={}) {
 const publicBoundary=createOwnerMemoryIpcBoundary({channel,deployment});
 const routes=createOwnerMemoryHttpRoutes({connection,guardRequest,contracts,publicBoundary});
 return Object.freeze({publicBoundary,routes:Object.freeze(routes)});
}
