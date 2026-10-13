# Linux voice runtime

The Linux sidecar is local CPU speech I/O. It binds `127.0.0.1:7512`; the
authenticated app route is its only browser bridge. Installing it does not
enable voice. The approved apps configuration must separately set
`voiceEnabled: true` and `voiceAutoStart: true`.

Pre-stage a root-owned, non-group/world-writable directory with this shape:

```text
/var/lib/aukora-voice-inputs/
  bootstrap/pip-24.2-py3-none-any.whl
  wheels/<all 54 filenames in wheels.lock.json>
  models/<all 6 paths in models.lock.json>
```

`wheels.lock.json` and `models.lock.json` are the exact name, byte-size and
SHA-256 inventory. The inputs total 353,763,994 bytes: 1,815,170 bootstrap,
153,282,561 wheels and 198,666,263 models. The operator must also record the
SHA-256 of the root-owned CPython 3.12.3 `/usr/bin/python3` on this node.

From the root-owned installed checkout, this one root command builds the absent
runtime with no index or network access, seals it root:`aukora-host` with 0750
directories and 0640/0750 files, and installs the environment and interpreter
pins only after verification:

```bash
sudo /usr/bin/python3 -I -B /opt/aukora-genesis/src/plugins/aukora-face/apps/vendor/auma-live/source/voice/install.py install \
  --artifacts /var/lib/aukora-voice-inputs \
  --runtime /opt/aukora-voice/runtime \
  --python /usr/bin/python3 \
  --python-sha256 OPERATOR_REVIEWED_64_HEX \
  --service-user aukora-host
```

Read back the complete pinned inventory and custody without starting the
sidecar:

```bash
sudo /usr/bin/python3 -I -B /opt/aukora-genesis/src/plugins/aukora-face/apps/vendor/auma-live/source/voice/install.py status \
  --runtime /opt/aukora-voice/runtime \
  --python /usr/bin/python3 \
  --service-user aukora-host
```

Success starts with `READY`; failure starts with `NOT READY` and a stable code.
This verifies bytes, pins, ownership and traversal. It does not probe model
loading, audio, browser permission, latency, network containment or a model
provider. After owner-approved activation, run `launch.py ... --probe` and the
browser observation separately.
