#!/usr/bin/env bash
# Rebuild canonical face bundles against the verified pinned harness.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
dsh="$root/vendor/dsh"
while (($#)); do
  case "$1" in
    --dsh)
      if (($# < 2)); then echo 'face-build-usage: --dsh requires a built harness path' >&2; exit 1; fi
      dsh="$2"
      shift 2
      ;;
    --help|-h)
      echo 'Usage: scripts/build-face-bundles.sh [--dsh vendor/dsh]'
      echo 'Requires Node v24.11.1 and pinned pnpm on PATH; Linux may use PATH=/mnt/tools:$PATH.'
      echo 'Verifies the built harness, copies an overlay, installs offline, runs tsc and tsdown,'
      echo 'then publishes canonical bundles with source/output manifests and SHA256 lines.'
      exit 0
      ;;
    *) echo "face-build-usage: unknown argument $1" >&2; exit 1 ;;
  esac
done

cd -- "$root"
actual_node=$(node --version)
if [[ "$actual_node" != v24.11.1 ]]; then
  echo "face-build-node-version: expected v24.11.1, got $actual_node" >&2
  exit 1
fi
dsh=$(python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$dsh")
echo 'FACE STEP prerequisite: verify built pinned commit, complete patch set and artifact inventory'
python3 scripts/build-dsh.py --root "$root" --verify-built --source "$dsh"

expected_pnpm=$(python3 -c 'import json; print(json.load(open("upstream-dsh.json"))["packageManager"].removeprefix("pnpm@"))')
actual_pnpm=$(pnpm --version)
if [[ "$actual_pnpm" != "$expected_pnpm" ]]; then
  echo "face-build-pnpm-version: expected $expected_pnpm, got $actual_pnpm" >&2
  exit 1
fi
export AUKORA_PINNED_DSH="$dsh"
export NODE_ENV=production TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=0
echo 'FACE STEP build: fresh private overlay; frozen NEXT snapshots stay historical'
python3 scripts/build-face.py --fresh
