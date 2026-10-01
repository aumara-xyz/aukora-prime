import {readFile,writeFile,mkdir,readdir,cp} from 'node:fs/promises'
import {createRequire} from 'node:module'
import {dirname,resolve,join} from 'node:path'
import {fileURLToPath} from 'node:url'
const flags={};for(let i=2;i<process.argv.length;i+=2)flags[process.argv[i]]=process.argv[i+1]
for(const name of ['--dsh','--client-dist','--contracts','--output'])if(!flags[name])throw new Error('render-fixture requires '+name)
const output=resolve(flags['--output']);await mkdir(output,{recursive:true});if((await readdir(output)).length)throw new Error('fixture output must be empty')
const require=createRequire(join(resolve(flags['--dsh']),'node_modules/.pnpm/node_modules/prime-ui-fixture.cjs'))
const react=dirname(require.resolve('react/package.json')),dom=dirname(require.resolve('react-dom/package.json'))
const reactMeta=JSON.parse(await readFile(join(react,'package.json'))),domMeta=JSON.parse(await readFile(join(dom,'package.json')))
if(reactMeta.version!=='18.3.1'||domMeta.version!=='18.3.1')throw new Error('fixture React pin mismatch')
await mkdir(join(output,'deps'));await mkdir(join(output,'contracts'))
await cp(join(react,'umd/react.production.min.js'),join(output,'deps/react.js'))
await cp(join(dom,'umd/react-dom.production.min.js'),join(output,'deps/react-dom.js'))
await cp(join(react,'LICENSE'),join(output,'deps/REACT-LICENSE'))
await cp(join(dom,'LICENSE'),join(output,'deps/REACT-DOM-LICENSE'))
const jsx=await readFile(join(react,'cjs/react-jsx-runtime.production.min.js'),'utf8')
await writeFile(join(output,'deps/jsx.js'),`{const m={exports:{}};((module,exports,require)=>{${jsx}\n})(m,m.exports,name=>window.__fixtureModules[name]);window.__fixtureModules['react/jsx-runtime']=m.exports;}`)
await cp(flags['--layout-bundle'] ? resolve(flags['--layout-bundle']) : fileURLToPath(new URL('../../faces/layout/lib/client.js',import.meta.url)),join(output,'layout.js'))
await cp(join(resolve(flags['--client-dist']),'prime-authority/client.js'),join(output,'owner.js'))
for(const name of ['browser.mjs','shared.mjs','json.mjs'])await cp(join(resolve(flags['--contracts']),name),join(output,'contracts',name))
await cp(fileURLToPath(new URL('./fixture.mjs',import.meta.url)),join(output,'fixture.mjs'))
await writeFile(join(output,'index.html'),`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Prime owner UI disposable fixture</title>
<style>body{margin:0;font-family:system-ui;background:var(--aukora-background);color:var(--aukora-text)}#view{height:100vh}#fixture-controls{position:fixed;z-index:100;right:10px;top:10px;background:var(--aukora-surface);padding:8px;border:1px solid var(--aukora-border);border-radius:var(--aukora-radius)}#fixture-controls button{margin:3px}</style>
<body data-ds-dark-theme><div id="fixture-controls" aria-label="Disposable fixture controls"><span>UI fixture only</span><button id="fresh">Fresh fixture</button><button id="unknown">Unknown reply fixture</button><button id="expire">Expire review fixture</button><button id="pending">Pending login fixture</button><button id="release">Release fixture login</button></div><div id="view"></div>
<script src="/deps/react.js"></script><script src="/deps/react-dom.js"></script>
<script>window.__fixtureModules={'react':React,'@deepseek-ai/dsh-client-store':{}};window.__fixtureFactories={};window.__ModuleLoader__={load:({id,factory})=>{window.__fixtureFactories[id]=factory}};</script>
<script src="/deps/jsx.js"></script><script src="/layout.js"></script><script src="/owner.js"></script>
<script type="module">
import * as contracts from '/contracts/browser.mjs';import {createOwnerUiFixture} from '/fixture.mjs';
const modules=window.__fixtureModules;const get=name=>{if(name in modules)return modules[name];const id=name.endsWith('/client')?name.slice(0,-7):name;if(!window.__fixtureFactories[id])throw Error('Fixture module unavailable: '+name);return modules[name]=window.__fixtureFactories[id](get)};
get('@aukora/face-layout/client');const ui=get('@aukora/prime-authority-ui/client');const root=ReactDOM.createRoot(document.getElementById('view'));
let controller,clock=Date.now(),expire,release;function fresh(outcome='approved',pending=false){controller?.dispose();clock=Date.now();let loginGate;if(pending)loginGate=new Promise(r=>{release=r});const binding=createOwnerUiFixture(contracts,{now:()=>clock,outcome,loginGate});controller=ui.createPrimeOwnerController({now:()=>clock,schedule:fn=>{expire=fn;return 1},unschedule:()=>{}});controller.connect(binding);root.render(React.createElement(ui.OwnerSurface,{activeSurface:'prime-owner',controller}));}
document.getElementById('fresh').onclick=()=>fresh();document.getElementById('unknown').onclick=()=>fresh('unknown');document.getElementById('pending').onclick=()=>fresh('approved',true);document.getElementById('release').onclick=()=>release?.();document.getElementById('expire').onclick=()=>{clock+=121000;expire?.()};fresh();
</script></body></html>`)
await writeFile(join(output,'fixture-build.json'),JSON.stringify({version:1,result:'GENERATED',react:reactMeta.version,react_dom:domMeta.version,
  source:'Native production OwnerSurface and controller, frozen layout primitives; explicit synthetic authority only',real_credentials:false,effects:false},null,2)+'\n')
console.log(JSON.stringify({result:'GENERATED',output,real_credentials:false,effects:false}))
