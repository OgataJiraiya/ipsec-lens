#!/bin/sh
set -eu
/usr/lib/ipsec/charon &
charon_pid=$!
trap 'kill "$charon_pid" 2>/dev/null || true' EXIT INT TERM
attempt=0
while [ ! -S /var/run/charon.vici ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -gt 50 ]; then
    echo "charon VICI socket unavailable" >&2
    exit 1
  fi
  sleep 0.1
done
swanctl --load-all --file /etc/swanctl/swanctl.conf
wait "$charon_pid"
