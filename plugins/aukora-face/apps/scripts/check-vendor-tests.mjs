#!/usr/bin/env node
// Carried TypeScript tests run through installed Vitest; missing tooling is unperformed.
import { spawnSync } from 'node:child_process'
import { readFileSync, readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const directories = ['vendor/auma-lingwa/tooling/core/tests', 'vendor/auma-live/original-closure/core/tests']
const files = directories.flatMap(directory => readdirSync(join(root, directory)).filter(name => name.endsWith('.test.ts'))
  .sort().map(name => join(root, directory, name)))
const require = createRequire(join(root, 'package.json'))
let cli
try {
  const manifest = require.resolve('vitest/package.json')
  const bin = JSON.parse(readFileSync(manifest, 'utf8')).bin
  cli = resolve(dirname(manifest), typeof bin === 'string' ? bin : bin.vitest)
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error
  console.log(`UNPERFORMED: installed Vitest absent for ${files.length} carried TypeScript tests`)
  process.exit(2)
}
const result = spawnSync(process.execPath, [cli, 'run', ...files], { cwd: root, stdio: 'inherit' })
process.exit(result.error || result.signal ? 1 : result.status)
