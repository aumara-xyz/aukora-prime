import {createHash} from 'node:crypto'
import {constants} from 'node:fs'
import {lstat,open,realpath} from 'node:fs/promises'
import {join,resolve} from 'node:path'

const donor='645d3213b8aede3b544269b4224ae09df06b0a42'
export const selectedStaticHtml=Object.freeze({
 '/stock-apps/auma-lingwa.html':'vendor/auma-lingwa/runtime/auma-lingwa.html',
 '/stock-apps/auma-live.html':'vendor/auma-live/runtime/auma-live.html',
 '/stock-apps/zeta-harp/index.html':'vendor/zeta-harp/index.html',
 '/stock-apps/zeta-harp/fold.html':'vendor/zeta-harp/fold.html',
 '/stock-apps/dakini-code/index.html':'vendor/dakini-code/index.html',
 '/stock-apps/human-graph/index.html':'assets/human-graph/index.html',
})
// Preserve B's existing Graph policy exactly. In particular, never add inline styles/scripts.
export const graphStaticCsp="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
function fail(reason,path=''){const error=new Error(`PRIME_STATIC_CSP:${reason}${path?':'+path:''}`);error.code='PRIME_STATIC_CSP';error.reason=reason;throw error}
const sha=bytes=>createHash('sha256').update(bytes).digest('hex')
const scriptHash=text=>`'sha256-${createHash('sha256').update(text,'utf8').digest('base64')}'`

async function verifiedHtml(root,path,entry){
 let location=root
 for(const segment of path.split('/')){if(!segment||segment==='.'||segment==='..'||segment.includes('\\'))fail('path-refused',path);location=join(location,segment);if((await lstat(location)).isSymbolicLink())fail('symlink-refused',path)}
 const before=await lstat(location)
 if(!before.isFile())fail('not-regular-file',path)
 const handle=await open(location,constants.O_RDONLY|constants.O_NOFOLLOW)
 let bytes
 try{const after=await handle.stat();if(!after.isFile()||before.dev!==after.dev||before.ino!==after.ino)fail('file-replaced',path);bytes=await handle.readFile()}finally{await handle.close()}
 if(bytes.length!==entry.bytes||sha(bytes)!==entry.sha256)fail('baseline-changed',path)
 const html=bytes.toString('utf8')
 if(!Buffer.from(html).equals(bytes))fail('html-utf8',path)
 // HTML normalizes CR/CRLF while parsing script text. Frozen selected pages are LF-only.
 // Refuse a new representation rather than accidentally hashing a different browser preimage.
 if(html.includes('\r'))fail('html-line-ending-unhandled',path)
 return html
}

function decodedAttribute(value){
 return value.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);?/gi,(whole,entity)=>{
  if(entity[0]==='#'){const hex=entity[1].toLowerCase()==='x';const point=Number.parseInt(entity.slice(hex?2:1),hex?16:10);if(!Number.isSafeInteger(point)||point<0||point>0x10ffff)fail('attribute-entity-unhandled');return String.fromCodePoint(point)}
  const known={amp:'&',quot:'"',apos:"'",lt:'<',gt:'>',colon:':',tab:'\t',newline:'\n'}
  if(!Object.hasOwn(known,entity.toLowerCase()))fail('attribute-entity-unhandled')
  return known[entity.toLowerCase()]
 })
}
function attributes(text){
 const result=new Map();let position=0
 while(position<text.length){while(/\s/.test(text[position]??'')&&position<text.length)position++;if(position===text.length||text.slice(position).trim()==='/')break
  const name=/^[^\s=/>]+/.exec(text.slice(position))?.[0]
  if(!name||!/^[a-z_:][a-z0-9_.:-]*$/i.test(name))fail('html-attribute-unhandled')
  position+=name.length;const key=name.toLowerCase();if(result.has(key))fail('html-duplicate-attribute')
  while(/\s/.test(text[position]??'')&&position<text.length)position++
  let value=''
  if(text[position]==='='){position++;while(/\s/.test(text[position]??'')&&position<text.length)position++;const quote=text[position]
   if(quote==='"'||quote==="'"){position++;const end=text.indexOf(quote,position);if(end<0)fail('html-attribute-unhandled');value=text.slice(position,end);position=end+1}
   else {const unquoted=/^[^\s>]+/.exec(text.slice(position))?.[0];if(!unquoted)fail('html-attribute-unhandled');value=unquoted;position+=unquoted.length}
  }
  result.set(key,decodedAttribute(value))
 }
 return result
}
function sameOriginUrl(value,{allowIconData=false}={}){
 const url=value.trim()
 if(/[\u0000-\u0020\u007f]/.test(url)||url.startsWith('\\')||url.includes('\\'))fail('resource-url-unhandled')
 if(allowIconData&&url==='data:,')return
 let parsed
 try{parsed=new URL(url,'https://prime.invalid/stock-apps/')}catch{fail('resource-url-unhandled')}
 if(parsed.origin!=='https://prime.invalid'||parsed.username||parsed.password)fail('external-resource-refused')
}
function inspectHtml(html,{documentLinks=[]}={}){
 const hashes=[];let inlineStyle=false,position=0
 while(position<html.length){const opening=html.indexOf('<',position);if(opening<0)break
  if(html.startsWith('<!--',opening)){const end=html.indexOf('-->',opening+4);if(end<0)fail('html-comment-unhandled');position=end+3;continue}
  let end=opening+1,quote
  for(;end<html.length;end++){const char=html[end];if(quote){if(char===quote)quote=undefined}else if(char==='"'||char==="'")quote=char;else if(char==='>')break}
  if(end===html.length)fail('html-tag-unhandled')
  const tag=html.slice(opening+1,end),match=/^([a-z][a-z0-9:-]*)([\s\S]*)$/i.exec(tag)
  position=end+1
  if(!match){if(tag.startsWith('/')||/^!doctype\s/i.test(tag))continue;fail('html-tag-unhandled')}
  const name=match[1].toLowerCase(),attrs=attributes(match[2])
  for(const key of attrs.keys())if(/^on[a-z]/i.test(key))fail('inline-event-handler-refused')
  if(attrs.has('srcdoc'))fail('srcdoc-refused')
  if(name==='base'||['object','embed','iframe'].includes(name))fail('embedded-resource-unhandled')
  if(name==='meta'&&attrs.has('http-equiv'))fail('http-equiv-refused')
  if(attrs.has('style'))inlineStyle=true
  for(const key of ['src','href','action','formaction','poster'])if(attrs.has(key)){
   // This exact frozen <a> URL is document navigation, never a script/style/frame
   // source. Do not extend the loaded-resource policy or rewrite donor HTML.
   if(name==='a'&&key==='href'&&documentLinks.includes(attrs.get(key)))continue
   sameOriginUrl(attrs.get(key),{allowIconData:name==='link'&&attrs.get('rel')?.toLowerCase()==='icon'&&key==='href'})
  }
  if(attrs.has('srcset'))fail('srcset-unhandled')
  if(name==='script'||name==='style'){
   const close=new RegExp(`</${name}\\s*>`,'ig');close.lastIndex=position;const closing=close.exec(html);if(!closing)fail('raw-text-element-unhandled')
   const text=html.slice(position,closing.index);position=close.lastIndex
   if(name==='style'){inlineStyle=true;continue}
   if(attrs.has('src')){if(text.trim())fail('external-script-inline-body-unhandled');continue}
   // Hash the literal body, including leading/trailing whitespace. Never rewrite it.
   hashes.push(scriptHash(text))
  }
 }
 return {hashes:[...new Set(hashes)],inlineStyle}
}

/** Derive route -> CSP from the complete exact, already frozen Apps HTML closure.
 * H must set these headers inside its connection-guarded native static routes.
 * This verifies static inputs; it does not establish browser/rendered acceptance.
 */
export async function buildStaticHtmlCsp({manifest,appRoot}){
 if(!manifest||manifest.commit!==donor||!Array.isArray(manifest.files))fail('donor-pin')
 const htmlPaths=manifest.files.filter(item=>typeof item.path==='string'&&item.path.startsWith('faces/apps/')&&item.path.endsWith('.html')).map(item=>item.path).sort()
 const expectedHtmlPaths=Object.values(selectedStaticHtml).map(path=>'faces/apps/'+path).sort()
 if(JSON.stringify(htmlPaths)!==JSON.stringify(expectedHtmlPaths))fail('served-html-coverage')
 const requested=resolve(appRoot),stat=await lstat(requested)
 if(!stat.isDirectory()||stat.isSymbolicLink())fail('root-refused')
 const root=await realpath(requested);if(root!==requested)fail('root-alias-refused')
 const policies={}
 for(const [route,path] of Object.entries(selectedStaticHtml)){
  const entries=manifest.files.filter(item=>item.path==='faces/apps/'+path)
  if(entries.length!==1)fail('manifest-html-entry-set',path)
  const entry=entries[0]
  if(!Number.isSafeInteger(entry.bytes)||entry.bytes<1||typeof entry.sha256!=='string'||!/^[a-f0-9]{64}$/.test(entry.sha256))fail('manifest-file-pin',path)
  const html=await verifiedHtml(root,path,entry),inspection=inspectHtml(html,{documentLinks:route==='/stock-apps/zeta-harp/fold.html'?['https://github.com/aumara-xyz/zeta-harp']:[]})
  if(route==='/stock-apps/human-graph/index.html'){
   if(inspection.hashes.length||inspection.inlineStyle)fail('graph-policy-expansion-refused')
   policies[route]=graphStaticCsp;continue
  }
  policies[route]=[
   "default-src 'none'",
   "script-src 'self'"+(inspection.hashes.length?' '+inspection.hashes.join(' '):''),
   "script-src-attr 'none'",
   "style-src 'self'"+(inspection.inlineStyle?" 'unsafe-inline'":''),
   "img-src 'self' data:","font-src 'self'","connect-src 'self'","media-src 'self'",
   "object-src 'none'","frame-src 'none'","base-uri 'none'","form-action 'none'","frame-ancestors 'self'",
  ].join('; ')
 }
 return Object.freeze(policies)
}
