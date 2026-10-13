#!/usr/bin/env bash
# Read a named container and test approval-gated startup or its signed-in UI.
set -euo pipefail
[[ $# == 4 && $1 == --name && $3 == --phase && $2 =~ ^[A-Za-z][A-Za-z0-9-]{0,62}$ && ( $4 == before || $4 == after ) ]] || {
  printf 'REFUSED BROWSER_ACCEPTANCE_USAGE\n' >&2; exit 1;
}
# LXD 5.21 has no JSON form of "config show"; the instance API object carries the same expanded values.
config=$(lxc --force-local query "/1.0/instances/$2") || { printf 'REFUSED BROWSER_ACCEPTANCE_CONFIG\n' >&2; exit 1; }
printf '%s' "$config" | python3 -I -S -c '
import json,re,sys
try:
    value=json.load(sys.stdin);config=value["expanded_config"];devices=value["expanded_devices"]
    assert config.get("security.privileged")=="false" and config.get("security.nesting")=="false"
    assert config.get("security.idmap.isolated")=="true" and config.get("security.devlxd")=="false"
    assert set(devices)=={"root","browser-app","browser-owner","browser-claim"} and devices["root"]["type"]=="disk"
    ports=[]
    for name,target in [("browser-app","18735"),("browser-owner","17792"),("browser-claim","18736")]:
        device=devices[name]
        assert device["type"]=="proxy" and device.get("bind")=="host" and device.get("nat")=="false"
        assert device.get("security.uid")=="65534" and device.get("security.gid")=="65534"
        assert device["connect"]=="tcp:127.0.0.1:"+target
        match=re.fullmatch(r"tcp:127\.0\.0\.1:([1-9][0-9]{3,4})",device["listen"])
        assert match and 1024<=int(match[1])<=65535
        ports.append(match[1])
    assert len(set(ports))==3
except Exception:
    print("REFUSED BROWSER_ACCEPTANCE_TRANSPORT",file=sys.stderr);sys.exit(1)
'
exec lxc --force-local exec "$2" -- /usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py accept --phase "$4"
