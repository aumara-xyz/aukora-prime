export function refused(message: string, code?: string): Error & { code: string }
export function validateSpec(spec: unknown, settings?: unknown): unknown
export function guestPolicy(mode: string): unknown
export function guestEnvironment(spec: unknown): Record<string, string>
