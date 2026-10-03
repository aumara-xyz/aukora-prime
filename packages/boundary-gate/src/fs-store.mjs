// Filesystem store for allowlisted targets, used only inside the gate process (gate user). Refuses any
// symlink component, opens with O_NOFOLLOW, writes via an exclusive temp file + fsync + rename, fsyncs the
// directory, and gives the file mode 0640 with the shared group so the harness can read but not write.
import fs from 'node:fs'
import path from 'node:path'

export function noSymlinks(p) {
  let cur = '/'
  for (const part of p.split('/').filter(Boolean)) {
    cur = path.join(cur, part)
    try { if (fs.lstatSync(cur).isSymbolicLink()) throw Object.assign(new Error(`symlink in target path (${cur}); refused`), { code: 'ESYMLINK' }) }
    catch (e) { if (e.code !== 'ENOENT') throw e }
  }
}

export function fsStore({ gid = 0 } = {}) {
  return {
    read(_name, s) {
      noSymlinks(s.file); let fd
      try { fd = fs.openSync(s.file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW) } catch (e) { if (e.code === 'ENOENT') return null; throw e }
      try { if (!fs.fstatSync(fd).isFile()) throw new Error('target is not a regular file; refused'); return fs.readFileSync(fd) } finally { fs.closeSync(fd) }
    },
    write(_name, s, bytes, id) {
      const dir = path.dirname(s.file)
      noSymlinks(dir); fs.mkdirSync(dir, { recursive: true, mode: 0o750 }); noSymlinks(dir)
      const tmp = `${s.file}.tmp-${String(id).replace(/[^0-9a-f-]/gi, '')}`
      const fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o640)
      try { fs.writeSync(fd, bytes); if (gid) fs.fchownSync(fd, process.getuid(), gid); fs.fchmodSync(fd, 0o640); fs.fsyncSync(fd) } catch (e) { try { fs.closeSync(fd) } catch {} try { fs.unlinkSync(tmp) } catch {} throw e }
      fs.closeSync(fd)
      noSymlinks(s.file)
      fs.renameSync(tmp, s.file)
      const dfd = fs.openSync(dir, 'r'); try { fs.fsyncSync(dfd) } finally { fs.closeSync(dfd) }
    },
  }
}
