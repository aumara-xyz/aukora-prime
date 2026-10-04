#!/bin/sh
# OpenViking as Kira's retrieval layer: install the pinned release on macOS or Linux.
#
#   sh scripts/openviking-setup.sh install [HOME]   venv + pinned wheel + hash-locked closure, ov.conf,
#                                                   aukora-bridge.json, and the local embedding model (verified)
#   sh scripts/openviking-setup.sh serve   [HOME]   run the embedding server and OpenViking in the foreground
#   sh scripts/openviking-setup.sh status  [HOME]   say whether both answer
#
# HOME is where OpenViking lives. The default is the directory beside the Kira store the app names
# (`stateDir` in ~/Library/Application Support/AUKORA/kira-deployment-overlay.patch.yml, whose parent + /openviking),
# which is also where Kira looks for it; $AUKORA_OPENVIKING_HOME overrides both. Linux requires explicit HOME
# or AUKORA_OPENVIKING_HOME. HOME and its existing private root.key must already be provisioned by the owner/operator.
# This script never creates a credential or changes security permissions. Nothing here writes outside HOME.
#
# What is pinned (vendor/openviking/upstream-openviking.json): the openviking wheel by sha256, the whole dependency
# closure by `pip --require-hashes` (requirements-macos-arm64-py311.lock, itself checked by sha256; it contains
# the release's Linux artifact hashes too, and Linux keeps every exact version), and the embedding
# model by sha256. At serve time, the resolved llama-server entry and its complete b11381 file/symlink
# tree must match host/pins/llama-server-b11381.json before probing or launching it. The Python 3.11
# interpreter is not pinned here; the tree check alone does not establish installed custody.
# This manifest names the existing Linux CPU build; an unmatched Homebrew/macOS build is refused.
#
# Environment knobs for install: AUKORA_OPENVIKING_PORT (default 1933), AUKORA_OPENVIKING_EMBED_PORT (1934),
# AUKORA_OPENVIKING_MODEL (an existing Qwen3-Embedding-0.6B-Q8_0.gguf to use in place; its sha256 is checked).
# For serve: AUKORA_OPENVIKING_EMBED_RSS_MIB (positive integer, default 1536) limits both RSS and
# macOS physical footprint or Linux process-group RSS+swap, sampled every two seconds. Exceeding it
# restarts only the owned embedder. This is sampled protection; the launcher owns a hard memory cap.
# Linux runs the existing llama-server on CPU with AUKORA_OPENVIKING_EMBED_THREADS (default 2, maximum 4).
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PIN="$REPO/vendor/openviking/upstream-openviking.json"
LOCK="$REPO/vendor/openviking/requirements-macos-arm64-py311.lock"

die() { printf 'openviking-setup: %s\n' "$*" >&2; exit 1; }
say() { printf 'openviking-setup: %s\n' "$*"; }

pin() { # pin <python expression over m, the manifest>
    python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$PIN" "$1"
}
sha256_of() {
    python3 -c 'import hashlib,sys
h=hashlib.sha256()
with open(sys.argv[1], "rb") as f:
    for block in iter(lambda:f.read(1024*1024), b""): h.update(block)
print(h.hexdigest())' "$1"
}

default_home() {
    if [ -n "${AUKORA_OPENVIKING_HOME:-}" ]; then printf '%s\n' "$AUKORA_OPENVIKING_HOME"; return; fi
    case "$(uname -s)" in
        Darwin) app_state=${AUKORA_STATE:-$HOME/Library/Application Support/AUKORA} ;;
        Linux) die "Linux requires explicit HOME or AUKORA_OPENVIKING_HOME naming the existing durable host state" ;;
        *) die "only macOS and Linux are supported" ;;
    esac
    overlay="$app_state/kira-deployment-overlay.patch.yml"
    [ -f "$overlay" ] || die "no HOME given and no app overlay at $overlay; pass the directory: $0 $1 <dir>"
    store=$(sed -n 's/^[[:space:]]*stateDir:[[:space:]]*//p' "$overlay" | head -n 1 | tr -d "\"'")
    [ -n "$store" ] || die "the app overlay names no stateDir; pass the directory explicitly"
    printf '%s/openviking\n' "$(dirname -- "$store")"
}

cmd=${1:-}
case "$cmd" in
    door|mcp) shift; exec node "$REPO/scripts/kira/viking-$cmd.mjs" "$@" ;;
esac
[ -n "$cmd" ] || die "usage: $0 install|serve|status [HOME], or door|mcp --installed (or --state-dir PATH --subject SUBJECT)"
H=${2:-}
[ -n "$H" ] || H=$(default_home "$cmd")
case "$H" in /*) ;; *) die "HOME must be an absolute path: $H" ;; esac

conf_get() { # conf_get <key> from aukora-bridge.json
    python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); v=c
for k in sys.argv[2].split("."): v=v[k]
print(v)' "$H/aukora-bridge.json" "$1"
}

validate_home() {
    python3 -c 'import os,pathlib,stat,sys
home=pathlib.Path(sys.argv[1])
try:
    hs=home.lstat(); key=home/"root.key"; ks=key.lstat()
    if not stat.S_ISDIR(hs.st_mode) or hs.st_mode & 0o077 or hs.st_uid != os.getuid(): raise ValueError("home")
    if not stat.S_ISREG(ks.st_mode) or ks.st_mode & 0o077 or ks.st_uid != os.getuid() or not 1 <= ks.st_size <= 4096: raise ValueError("key")
    value=key.read_text().strip()
    if not value or "\n" in value or "\r" in value: raise ValueError("key")
except (OSError,ValueError):
    print("openviking-setup: HOME and root.key must already exist, be private, and belong to the service user; operator setup required",file=sys.stderr)
    sys.exit(1)' "$H"
}

check_download_capacity() {
    # Inspect current local capacity before wheel/closure/model downloads. No large
    # model or build is copied, and an existing verified model stays in place.
    python3 -c 'import os,pathlib,shutil,sys
home=pathlib.Path(sys.argv[1]); model=pathlib.Path(sys.argv[2]); model_bytes=int(sys.argv[3])
needed=2*1024**3 + (0 if model.is_file() else model_bytes)
if shutil.disk_usage(home).free < needed:
    sys.exit("openviking-setup: insufficient free disk for pinned wheel/closure/model; at least 2 GiB plus any missing model required")
if sys.platform == "linux":
    info=dict(line.split(":",1) for line in pathlib.Path("/proc/meminfo").read_text().splitlines())
    available=int(info["MemAvailable"].split()[0])*1024
    value=os.environ.get("AUKORA_OPENVIKING_EMBED_RSS_MIB","1536")
    if not value.isdecimal() or int(value)<1: sys.exit("openviking-setup: AUKORA_OPENVIKING_EMBED_RSS_MIB must be a positive integer")
    if available < (int(value)+256)*1024**2:
        sys.exit("openviking-setup: insufficient current MemAvailable for bounded embedder plus 256 MiB headroom")' "$H" "$1" "$2"
}

install_home() {
    validate_home
    # Every newly written runtime file remains private without changing any
    # existing file/directory permissions or minting a new key.
    umask 077

    # 1. The lock and the wheel are what the manifest says, byte for byte.
    want_lock=$(pin 'm["lock"]["sha256"]')
    [ "$(sha256_of "$LOCK")" = "$want_lock" ] || die "the dependency lock does not match its pin ($LOCK)"
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) platform=darwin-arm64 ;;
        Linux-x86_64) platform=linux-x86_64 ;;
        Linux-aarch64|Linux-arm64) platform=linux-aarch64 ;;
        *) die "supported platforms are macOS arm64 and Linux x86_64/aarch64 with Python 3.11" ;;
    esac
    case "$platform" in
        linux-*) python3 -c 'import os,re,sys
value=os.confstr("CS_GNU_LIBC_VERSION") or ""
match=re.fullmatch(r"glibc ([0-9]+)\.([0-9]+)",value)
if not match or tuple(map(int,match.groups())) < (2,31):
    sys.exit("openviking-setup: the pinned Linux wheel requires glibc >= 2.31; no source build fallback")' ;;
    esac
    case "$platform" in
        linux-x86_64)
            # Official PyPI 0.4.21 artifacts; both hashes already appear in the
            # unchanged Genesis lock. No new version, source build or resolver.
            wheel=openviking-0.4.21-cp310-abi3-manylinux_2_31_x86_64.whl
            wheel_url=https://files.pythonhosted.org/packages/a0/50/69d75daa9dcacf9a7680ddbd803b7fe3c815d0f6eeb1574f212789f7b62d/$wheel
            wheel_sha=e223518bd33b50bbd6b1c7860e4856cd7c477eb8656afdbe7871ff59355b37a6 ;;
        linux-aarch64)
            wheel=openviking-0.4.21-cp310-abi3-manylinux_2_31_aarch64.whl
            wheel_url=https://files.pythonhosted.org/packages/8a/b8/42fa99dd53cf6614f6559ce09683903fce2509c8f840794baf23cda002d3/$wheel
            wheel_sha=2aaa5ac920f3862346012e19c48fa5d2749f41dab690200fbc1c6d84ce4c7a88 ;;
        *)
            wheel=$(pin "[w for w in m['wheels'] if w['platform']=='$platform'][0]['filename']")
            wheel_url=$(pin "[w for w in m['wheels'] if w['platform']=='$platform'][0]['url']")
            wheel_sha=$(pin "[w for w in m['wheels'] if w['platform']=='$platform'][0]['sha256']") ;;
    esac
    [ "$(pin 'm["version"]')" = 0.4.21 ] || die "Linux artifact support is pinned to OpenViking 0.4.21"
    python3 -c 'import sys
if ("--hash=sha256:"+sys.argv[2]) not in open(sys.argv[1]).read(): sys.exit("openviking-setup: wheel hash is absent from the pinned closure")' "$LOCK" "$wheel_sha"
    py=$(command -v python3.11 || true)
    [ -n "$py" ] || die "existing Python 3.11 is required; the installer does not fetch an interpreter"
    "$py" -c 'import sys; assert sys.version_info[:2] == (3,11), "Python 3.11 is required"'
    model_sha=$(pin 'm["embeddingModel"]["sha256"]')
    model="${AUKORA_OPENVIKING_MODEL:-$H/models/$(pin 'm["embeddingModel"]["file"]')}"
    [ -z "${AUKORA_OPENVIKING_MODEL:-}" ] || [ -f "$model" ] || die "AUKORA_OPENVIKING_MODEL names no existing file"
    check_download_capacity "$model" "$(pin 'm["embeddingModel"]["bytes"]')"
    mkdir -p "$H/downloads" "$H/data" "$H/models"
    if [ ! -f "$H/downloads/$wheel" ] || [ "$(sha256_of "$H/downloads/$wheel")" != "$wheel_sha" ]; then
        say "downloading $wheel"
        curl -fsSL --retry 2 -o "$H/downloads/$wheel.part" "$wheel_url"
        mv "$H/downloads/$wheel.part" "$H/downloads/$wheel"
    fi
    got=$(sha256_of "$H/downloads/$wheel")
    [ "$got" = "$wheel_sha" ] || die "downloaded wheel differs from its pinned sha256; refusing installation"
    say "wheel verified: $wheel sha256 $got"

    # 2. The closure, every file hash-checked, then the verified wheel itself with no index and no dependencies.
    python3 -c 'import sys
out, skip = [], False
for line in open(sys.argv[1]):
    if line.startswith("openviking=="): skip = True; continue
    if skip and line.startswith("    "): continue
    skip = False; out.append(line)
open(sys.argv[2], "w").write("".join(out))' "$LOCK" "$H/downloads/closure.lock"
    if command -v uv >/dev/null 2>&1; then
        [ -x "$H/venv/bin/python" ] || "$py" -m venv "$H/venv"
        "$H/venv/bin/python" -c 'import sys; assert sys.version_info[:2] == (3,11), "existing venv must use Python 3.11"'
        uv pip install --quiet --python "$H/venv/bin/python" --index-url https://pypi.org/simple --only-binary :all: --require-hashes --no-deps -r "$H/downloads/closure.lock"
        uv pip install --quiet --python "$H/venv/bin/python" --no-deps --no-index "$H/downloads/$wheel"
        uv pip check --python "$H/venv/bin/python"
    else
        [ -x "$H/venv/bin/python" ] || "$py" -m venv "$H/venv"
        "$H/venv/bin/python" -c 'import sys; assert sys.version_info[:2] == (3,11), "existing venv must use Python 3.11"'
        "$H/venv/bin/python" -m pip install --quiet --disable-pip-version-check --isolated --index-url https://pypi.org/simple --only-binary :all: --require-hashes --no-deps -r "$H/downloads/closure.lock"
        "$H/venv/bin/python" -m pip install --quiet --disable-pip-version-check --no-deps --no-index "$H/downloads/$wheel"
        "$H/venv/bin/python" -m pip check
    fi
    installed=$("$H/venv/bin/python" -c 'import importlib.metadata as m; print(m.version("openviking"))')
    [ "$installed" = "$(pin 'm["version"]')" ] || die "installed openviking $installed, pinned $(pin 'm["version"]')"
    say "openviking $installed installed in $H/venv"

    # 3. The embedding model: an existing file checked in place, or the pinned download.
    if [ ! -f "$model" ]; then
        [ -z "${AUKORA_OPENVIKING_MODEL:-}" ] || die "AUKORA_OPENVIKING_MODEL names no file: $model"
        say "downloading the embedding model ($(pin 'm["embeddingModel"]["bytes"]') bytes)"
        curl -fsSL --retry 2 -o "$model.part" "$(pin 'm["embeddingModel"]["url"]')"
        mv "$model.part" "$model"
    fi
    got=$(sha256_of "$model")
    [ "$got" = "$model_sha" ] || die "$model sha256 $got != pinned $model_sha"
    say "embedding model verified: $model"
    command -v llama-server >/dev/null 2>&1 || say "NOTE: serve requires the existing CPU release's llama-server on PATH; this installer does not download/build it"

    # 4. Configuration. Written once; an existing file is kept so an owner's edits survive a re-install.
    port=${AUKORA_OPENVIKING_PORT:-1933}
    embed_port=${AUKORA_OPENVIKING_EMBED_PORT:-1934}
    if [ ! -f "$H/ov.conf" ]; then
        cat > "$H/ov.conf" <<EOF
{
  "server": {"host": "127.0.0.1", "port": $port, "auth_mode": "trusted", "root_api_key": "\${AUKORA_OPENVIKING_ROOT_KEY}", "cors_origins": []},
  "storage": {"workspace": "\${AUKORA_OPENVIKING_HOME}/data", "vectordb": {"name": "context", "backend": "local"}, "agfs": {"backend": "local"}},
  "embedding": {"max_input_tokens": 2000, "dense": {"provider": "openai", "api_base": "http://127.0.0.1:$embed_port/v1", "api_key": "local", "model": "qwen3-embedding-0.6b", "dimension": 1024, "encoding_format": "float"}}
}
EOF
    fi
    if [ ! -f "$H/aukora-bridge.json" ]; then
        # What Kira reads (plugins/aukora-kira/lib/recall-openviking.mjs) and what `serve` starts. The thresholds were
        # measured on ten notes with this model (see the commit that added this file); tune them here, not in code.
        python3 -c 'import json,sys
json.dump({
  "url": "http://127.0.0.1:%s" % sys.argv[2], "account": "aukora", "user": "owner",
  "scoreThreshold": 0.4, "window": 0.1, "limit": 3,
  "queryInstruction": "Instruct: Given a question from the owner, retrieve the memory notes that answer it\nQuery: ",
  "embedding": {"model": sys.argv[3], "port": int(sys.argv[4]), "context": 2048},
}, open(sys.argv[1], "w"), indent=2)' "$H/aukora-bridge.json" "$port" "$model" "$embed_port"
    fi
    say "installed in $H. Run: sh $0 serve \"$H\""
}

serve_home() {
    [ -x "$H/venv/bin/openviking-server" ] || die "not installed in $H; run: sh $0 install \"$H\""
    validate_home
    command -v llama-server >/dev/null 2>&1 || die "existing llama-server is not on PATH; operator setup required"
    exec python3 "$REPO/scripts/openviking-supervisor.py" "$H"
}

status_home() {
    [ -f "$H/aukora-bridge.json" ] || { say "not installed in $H"; exit 1; }
    url=$(conf_get url)
    embed_port=$(conf_get embedding.port)
    ok=0
    if curl -fs -m 3 "http://127.0.0.1:$embed_port/health" >/dev/null 2>&1; then say "embedding: up on 127.0.0.1:$embed_port"; else say "embedding: DOWN on 127.0.0.1:$embed_port"; ok=1; fi
    if answer=$(curl -fs -m 3 "$url/health" 2>/dev/null); then say "openviking: $answer"; else say "openviking: DOWN at $url"; ok=1; fi
    exit "$ok"
}

case "$cmd" in
    install) install_home ;;
    serve) serve_home ;;
    status) status_home ;;
    *) die "usage: $0 install|serve|status [HOME], or door|mcp --installed (or --state-dir PATH --subject SUBJECT)" ;;
esac
