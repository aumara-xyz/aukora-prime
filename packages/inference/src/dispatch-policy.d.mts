import type { LocalRoute, LocalTask, ProviderRequest } from './index.mjs';
export const PRIVATE_NOTE_SYSTEM_TEXT: string;
/** Does not authorize, consume a grant, reserve spend, access a key or make a network request. */
export function verifyPrivateDispatch(request: Omit<ProviderRequest,'signal'>, route: LocalRoute, task: LocalTask): {
  route: LocalRoute; task: LocalTask; input_bound: number; token_reservation: number; cost_reservation: number;
};
