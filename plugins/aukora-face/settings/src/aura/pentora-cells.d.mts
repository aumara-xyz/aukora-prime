// SPDX-License-Identifier: AGPL-3.0-or-later
import type { PentoraHash } from './pentora.mjs';
export function pentoraCells(head32: Uint8Array, sha256?: PentoraHash): Promise<Uint8Array>;
