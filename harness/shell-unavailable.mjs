// Pinned defaults reused without constructing the host executor.
import {ShellExecutor} from '../packages/shell/shell/lib/index.js';
import {LocalBashExecutor} from '../packages/shell/bash-local/lib/index.js';
import {createDshOpenShellExecutor} from '../prime-packages/execution/src/bash.mjs';
const unavailable=()=>{throw Object.assign(new Error('UNAVAILABLE: owned OpenShell image/runtime and trusted authority join are unqualified'),{code:'UNAVAILABLE'});};
const executor=Object.freeze({capability:'unavailable',execute:unavailable});
export default createDshOpenShellExecutor({
 ShellExecutor,executor,resolveOperation:unavailable,
 resolveSpec:request=>LocalBashExecutor.prototype.resolve.call({config:{timeoutMs:30000,maxTimeoutMs:30000,maxOutputBytes:65536}},request),
});
