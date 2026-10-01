# AUKORA Prime Preview

Separate local Electron window onto the existing Prime UI. The shell does not start,
stop or install a backend and carries no UI implementation. Keep the existing strict
SSH tunnel to Linux Prime at `127.0.0.1:18731` running.

From the repository root:

```sh
node packages/desktop/run.cjs --access-file /private/launch-url.json --expected-pid REMOTE_PID
```

H supplies the current absolute launch descriptor path and remote process PID. The
descriptor must be an owner-only regular file named `launch-url.json`, inside an
owner-only directory, with exact `{url,pid}` fields. It is read once. Its private token
URL is exchanged only in the main process using the existing DSH `303 Location: /`
handshake. The validated host-only HttpOnly, SameSite=Strict cookie stays in the new
in-memory Electron session. The renderer loads only the clean base URL. No raw launch
URL, token or cookie is logged or stored by the shell. Remote PID equality checks the
named launch descriptor; it is not independent remote process attestation.

The default origin is exactly `http://127.0.0.1:18731`, trusted through that existing
SSH tunnel. A future trusted HTTPS deployment can be selected explicitly with
`--origin https://preview.example`. That origin must serve the same launch handshake
with a Secure cookie. TLS validation remains enabled. HTTPS has not been deployed or
verified by this desktop change.

The official existing Electron 44.4.3 distribution was copied intact to the ignored
`packages/desktop/.runtime/electron` directory for this local preview. Its MIT and
Chromium licenses remain with it. `PROVENANCE.json` records the selected dependency
lock closure and observed binary hash. A fresh machine can use the exact npm closure:

```sh
cd packages/desktop
npm ci --no-audit --no-fund
```

Only the pinned official Electron installer is needed; no global install, app signing,
Applications-folder change, launch agent, key, OS setting or firewall change occurs.
The runner removes inherited Electron/Node option variables and passes no remote
debugging switch. The runtime has no dependency on a donor checkout.

Every launch creates a private temporary profile and a unique nonpersistent session,
with cache disabled and a direct connection to the selected origin. The profile is
removed on normal quit; an OS crash can leave its noncredential temporary files.
Renderer sandbox and context isolation are enabled; Node integration, webviews and
DevTools are disabled. There is no preload, privileged IPC or external-browser hook.
Only same-origin requests and the corresponding WebSocket host/port are permitted.
Popups, external/frame navigation, downloads and all Electron permission/device
requests are denied. Existing media/copy features requiring web permission remain
unavailable. The shell does not grant owner authority or execute owner operations.

One scoped disposable check uses the actual Electron renderer and shipped guards:

```sh
node packages/desktop/run.cjs --check
```

It opens two temporary loopback-only synthetic listeners and a temporary profile,
checks the private launch exchange and renderer boundaries, and shuts them down.
It does not access the real backend or verify owner approval, executor containment,
durable memory or inference. Actual Linux UI rendering is checked separately in the
native window; a successful window-open message alone is not rendering proof.
