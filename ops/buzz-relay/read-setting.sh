#!/usr/bin/env bash
# Service-owned settings are data, never commands in the administrator's shell.
set -euo pipefail
SETTING="${1:?usage: read-setting.sh PORT|INTENDED_MEMBERSHIP|IMAGE}"
value=""
while IFS= read -r line || [ -n "$line" ]; do
  case "$SETTING:$line" in
    PORT:PORT=*|INTENDED_MEMBERSHIP:INTENDED_MEMBERSHIP=*|IMAGE:IMAGE=*)
      [ -z "$value" ] || { echo "duplicate $SETTING setting" >&2; exit 2; }
      value="${line#*=}"
      [ -n "$value" ] || { echo "empty $SETTING setting" >&2; exit 2; }
      ;;
    PORT:INTENDED_MEMBERSHIP=*|INTENDED_MEMBERSHIP:PORT=*) ;;
    IMAGE:SOURCE_SHA=*)
      [[ "${line#*=}" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid SOURCE_SHA setting" >&2; exit 2; }
      ;;
    *) echo "invalid $SETTING settings file" >&2; exit 2 ;;
  esac
done
case "$SETTING" in
  PORT)
    [[ "$value" =~ ^[0-9]{1,5}$ ]] || { echo "PORT must contain digits only (1-65535)" >&2; exit 2; }
    value=$((10#$value))
    [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || { echo "PORT must be 1-65535" >&2; exit 2; }
    if [ "$value" -ge 32768 ] && [ "$value" -le 60999 ]; then
      echo "PORT 32768-60999 is forbidden: the sandbox firewall permits that ephemeral range" >&2; exit 2
    fi
    ;;
  INTENDED_MEMBERSHIP)
    [[ "$value" = closed || "$value" = open-acknowledged ]] || { echo 'INTENDED_MEMBERSHIP must be closed or open-acknowledged' >&2; exit 2; }
    ;;
  IMAGE)
    [[ "$value" =~ ^localhost/aukora-buzz-relay:[0-9a-f]{12}$ ]] \
      || { echo "IMAGE must be localhost/aukora-buzz-relay:<12 lowercase hex>" >&2; exit 2; }
    ;;
  *) echo "unknown setting" >&2; exit 2 ;;
esac
printf '%s\n' "$value"
