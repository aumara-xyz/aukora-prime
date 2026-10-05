#!/bin/bash
# prints the live accent via the authenticated route (cookie jar kept 0600, deleted after)
T=$(sudo cat /home/aukora-host/genesis/state/launch-url.json | python3 -c "import sys,json;print(json.load(sys.stdin)[\"token\"])"); J=$(mktemp); chmod 600 $J
curl -s -o /dev/null -c $J -b $J -L "http://127.0.0.1:18735/?token=$T"; curl -s -b $J http://127.0.0.1:18735/api/aukora/theme; echo; rm -f $J
