import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { freezeData } from './bytes.mjs';

// Approved DATA only. Never load implementations, translation tables or W8 code.
const pins = Object.freeze({
  'geometry_index_table_v1.json': '96b27c9b4de41cd961612be5b1e88d40e973a2fded16bd320415b3e15e3b8c61',
  'golay_generator.json': '9985bebd088f927412df127bd35927adc2b458ab9ec47f77efbaeb3d66544add',
});

export function readPinnedData(name) {
  if (!Object.hasOwn(pins, name)) throw new TypeError('unrecognized Pentora data source');
  const bytes = readFileSync(new URL(`../../spec/pentora-v1/data/${name}`, import.meta.url));
  if (createHash('sha256').update(bytes).digest('hex') !== pins[name]) {
    throw new Error(`Pentora source pin mismatch: ${name}`);
  }
  return freezeData(JSON.parse(bytes.toString('utf8')));
}
