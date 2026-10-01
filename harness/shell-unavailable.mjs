import { ShellExecutor } from '../packages/shell/shell/lib/index.js';
export default class PrimeUnavailableShell extends ShellExecutor {
 resolve(request) { return {...request,workdir:request.workdir??process.cwd(),timeoutMs:Math.min(request.timeoutMs??30000,30000),stdoutMaxBytes:Math.min(request.stdoutMaxBytes??65536,65536),sandboxPolicy:request.sandboxPolicy}; }
 async run() { throw Object.assign(new Error('UNAVAILABLE: OpenShell owned lifecycle is not qualified; host execution refused'),{code:'UNAVAILABLE'}); }
 async start() { throw Object.assign(new Error('UNAVAILABLE: SDK/background child launcher is not qualified'),{code:'UNAVAILABLE'}); }
}

