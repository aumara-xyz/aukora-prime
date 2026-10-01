// Materialize only the locked PostgreSQL driver into a fresh explicitly named directory.
import {mkdir,copyFile,readFile,rm} from 'node:fs/promises';
import {resolve,dirname,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const [flag,destination,...extra]=process.argv.slice(2);
if(flag!=='--into'||!isAbsolute(destination??'')||extra.length)throw new Error('Usage: node scripts/materialize-pg.mjs --into /absolute/new-directory');
const into=resolve(destination);
await mkdir(into,{mode:0o700}); // Existing paths are refused, including prior partial attempts.
for(const name of ['package.json','package-lock.json'])await copyFile(resolve(root,'runtime-dependencies/pg',name),resolve(into,name));
const home=resolve(into,'.install-home');await mkdir(home,{mode:0o700});
const install=spawnSync('npm',['ci','--ignore-scripts','--no-audit','--no-fund','--userconfig=/dev/null'],{cwd:into,env:{PATH:process.env.PATH,HOME:home},stdio:'inherit'});
await rm(home,{recursive:true,force:true});
if(install.status!==0)throw new Error('PG_CLOSURE_INSTALL_FAILED: preserve this named attempt for inspection');
const metadata=JSON.parse(await readFile(resolve(into,'node_modules/pg/package.json'),'utf8'));
if(metadata.version!=='8.16.3')throw new Error('PG_CLOSURE_VERSION_MISMATCH');
console.log(JSON.stringify({status:'MATERIALIZED',pg:metadata.version,lifecycle_scripts:false,postgresql_acceptance:'UNPERFORMED'}));
