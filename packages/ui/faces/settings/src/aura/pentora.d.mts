// Types for the byte-identical Pentora display derivation.
export type PentoraHash = (bytes: Uint8Array) => Uint8Array | ArrayBuffer | Promise<Uint8Array | ArrayBuffer>;
export const PENTORA: {
  centre: number;
  mutable: number[];
  points: [number, number, number][];
  edges: [number, number][];
  cubes: number[][];
};
export function pentoraDigest(head32: Uint8Array, sha256: PentoraHash): Promise<Uint8Array>;
export function pentoraDigits(head32: Uint8Array, sha256: PentoraHash): Promise<Uint8Array>;
