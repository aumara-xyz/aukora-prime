import { constants, lstatSync, openSync, fstatSync, closeSync } from 'node:fs';
import { dirname, isAbsolute, parse, resolve, sep } from 'node:path';
import { requireCondition } from './contract.mjs';

// Protected ancestry prevents another principal from swapping a checked pathname.
// The running UID can still rewrite its own files; this is not a separate-UID proof.
export function checkPrivateParent(path) {
  requireCondition(typeof path === 'string' && isAbsolute(path) && resolve(path) === path && !path.includes('\0'), 500, 'absolute_canonical_path_required');
  const parent = dirname(path); const root = parse(parent).root;
  const rootStat = lstatSync(root);
  requireCondition(rootStat.isDirectory() && !rootStat.isSymbolicLink() && (rootStat.mode & 0o022) === 0 && (rootStat.uid === 0 || rootStat.uid === process.getuid()), 500, 'protected_ancestors_required');
  let current = root;
  for (const part of parent.slice(root.length).split(sep).filter(Boolean)) {
    current = current === root ? root + part : current + sep + part;
    const stat = lstatSync(current);
    requireCondition(stat.isDirectory() && !stat.isSymbolicLink() && (stat.mode & 0o022) === 0 && (stat.uid === 0 || stat.uid === process.getuid()), 500, 'protected_ancestors_required');
  }
  const stat = lstatSync(parent);
  requireCondition(stat.uid === process.getuid() && (stat.mode & 0o777) === 0o700, 500, 'private_parent_required');
  return parent;
}

export function checkPrivateFile(path, maxBytes = Number.MAX_SAFE_INTEGER) {
  checkPrivateParent(path);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd); const named = lstatSync(path);
    requireCondition(stat.isFile() && !named.isSymbolicLink() && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o600 && stat.nlink === 1 && stat.size <= maxBytes && stat.dev === named.dev && stat.ino === named.ino, 500, 'private_regular_file_required');
    return { dev: stat.dev, ino: stat.ino };
  } finally { closeSync(fd); }
}

export function samePrivateFile(path, identity) {
  const checked = checkPrivateFile(path);
  requireCondition(checked.dev === identity.dev && checked.ino === identity.ino, 503, 'store_identity_changed');
}
