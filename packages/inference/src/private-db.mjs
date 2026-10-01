import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, lstatSync, openSync, closeSync, fsyncSync } from 'node:fs';
import { dirname } from 'node:path';
import { refuse } from './policy.mjs';

export function openPrivateDatabase(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path === ':memory:') refuse('DURABLE_STORE_REQUIRED');
  mkdirSync(dirname(path),{ recursive: true, mode: 0o700 });
  const directory = lstatSync(dirname(path));
  if (!directory.isDirectory() || (directory.mode & 0o077)) refuse('DURABLE_STORE_NOT_PRIVATE');
  try { const fd = openSync(path,'wx',0o600); try { fsyncSync(fd); } finally { closeSync(fd); } }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  const file = lstatSync(path);
  if (!file.isFile() || (file.mode & 0o077)) refuse('DURABLE_STORE_NOT_PRIVATE');
  const fd = openSync(dirname(path),'r'); try { fsyncSync(fd); } finally { closeSync(fd); }
  const db = new DatabaseSync(path);
  db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
  return db;
}
export function transaction(db, callback) {
  db.exec('BEGIN IMMEDIATE');
  try { const result = callback(); db.exec('COMMIT'); return result; }
  catch (error) { db.exec('ROLLBACK'); throw error; }
}
