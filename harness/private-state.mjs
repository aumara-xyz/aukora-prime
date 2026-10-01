import {constants,lstatSync,statSync,mkdirSync,openSync,closeSync,fstatSync,readFileSync,writeFileSync,fsyncSync,renameSync,unlinkSync,realpathSync} from 'node:fs';
import {resolve,dirname,parse,join} from 'node:path';
import {randomUUID} from 'node:crypto';
const uid=process.getuid?.();
const refuse=()=>{throw Object.assign(new Error('PRIVATE_STATE_REFUSED'),{code:'PRIVATE_STATE_REFUSED'});};
export function privateDirectory(path,{create=false}={}) {
 path=resolve(path); const root=parse(path).root; let current=root;
 const parts=path.slice(root.length).split('/').filter(Boolean);
 for(let i=0;i<parts.length;i++) {
  current=join(current,parts[i]); let s;
  try{s=lstatSync(current);}catch(e){if(e.code!=='ENOENT'||!create)throw e;mkdirSync(current,{mode:0o700});s=lstatSync(current);}
  if(!s.isDirectory()||s.isSymbolicLink())refuse();
  // Existing sticky system temporary roots are allowed ancestors, never the private leaf.
  if((s.mode&0o022)&&!((s.mode&0o1000)&&s.uid===0&&i<parts.length-1))refuse();
  if(i===parts.length-1&&(s.uid!==uid||(s.mode&0o077)))refuse();
 }
 if(realpathSync(path)!==path)refuse(); return path;
}
function fileStat(path) {
 let s;try{s=lstatSync(path);}catch(e){if(e.code==='ENOENT')return;throw e;}
 if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.uid!==uid||(s.mode&0o077))refuse(); return s;
}
export function readPrivateJson(path,{maxBytes=65536}={}) {
 path=resolve(path);privateDirectory(dirname(path));const before=fileStat(path);if(!before)return;
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{const s=fstatSync(fd);if(s.dev!==before.dev||s.ino!==before.ino||s.size>maxBytes)refuse();return JSON.parse(readFileSync(fd,'utf8'));}finally{closeSync(fd);}
}
export function writePrivateJson(path,value) {
 path=resolve(path);const dir=privateDirectory(dirname(path));fileStat(path);
 const tmp=join(dir,'.prime-write-'+randomUUID());let fd;
 try{fd=openSync(tmp,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fsyncSync(fd);closeSync(fd);fd=undefined;fileStat(path);renameSync(tmp,path);const d=openSync(dir,constants.O_RDONLY);try{fsyncSync(d);}finally{closeSync(d);}}
 finally{if(fd!==undefined)closeSync(fd);try{unlinkSync(tmp);}catch(e){if(e.code!=='ENOENT')throw e;}}
}
export function cleanOrigin(value) {
 const u=new URL(value);if(u.protocol!=='http:'||u.hostname!=='127.0.0.1'||u.username||u.password||u.hash||u.pathname!=='/')refuse();return u.origin+'/';
}
