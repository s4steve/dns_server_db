#!/usr/bin/env bash
# Stage 3 end-to-end check: control plane + two DNS nodes in Docker.
#   1. A change made through the API is answered by both nodes within 5 seconds.
#   2. With the control plane gone, nodes keep serving until the zone's SOA EXPIRE passes,
#      then SERVFAIL. When it comes back, they catch up and serve again.
set -euo pipefail
cd "$(dirname "$0")/.."

API=http://127.0.0.1:8054
NODES=(5301 5302)
ZONE="mn$(date +%s).test."
EXPIRE=8

fail() { echo "FAIL: $*" >&2; exit 1; }
api() { curl -sf -H 'content-type: application/json' "$@"; }
ask() { dig @127.0.0.1 -p "$1" +norec +tries=1 +time=1 "$2" A; }
status() { ask "$1" "$2" | sed -n 's/.*status: \([A-Z]*\).*/\1/p'; }
answer() { dig @127.0.0.1 -p "$1" +norec +tries=1 +time=1 +short "$2" A; }

# Waits up to $1 seconds for `$2...` to succeed; prints the elapsed time.
wait_for() {
  local limit=$1 start=$SECONDS; shift
  until "$@"; do
    (( SECONDS - start >= limit )) && return 1
    sleep 0.2
  done
  echo "$(( SECONDS - start ))s"
}

all_answer() {
  local node
  for node in "${NODES[@]}"; do [[ "$(answer "$node" "$1")" == "$2" ]] || return 1; done
}
all_status() {
  local node
  for node in "${NODES[@]}"; do [[ "$(status "$node" "$1")" == "$2" ]] || return 1; done
}

echo "== starting postgres, control plane, node1, node2"
docker compose --profile multinode up -d --build --wait
wait_for 30 api "$API/zones" -o /dev/null >/dev/null || fail "control plane not reachable"

echo "== zone $ZONE (SOA expire ${EXPIRE}s)"
api -X POST "$API/zones" -d "{\"name\":\"$ZONE\",\"ns\":[\"ns1.$ZONE\"],\"soa\":{\"expire\":$EXPIRE}}" >/dev/null

echo "== propagation: add www, then time until both nodes answer"
api -X POST "$API/zones/$ZONE/changes" \
  -d '{"changes":[{"action":"add","name":"www","type":"A","data":"192.0.2.10"}]}' >/dev/null
t=$(wait_for 5 all_answer "www.$ZONE" 192.0.2.10) || fail "not on both nodes within 5s"
echo "   both nodes answered after $t"

echo "== update: change www, time again"
api -X POST "$API/zones/$ZONE/changes" -d '{"changes":[
  {"action":"delete","name":"www","type":"A"},
  {"action":"add","name":"www","type":"A","data":"198.51.100.7"}]}' >/dev/null
t=$(wait_for 5 all_answer "www.$ZONE" 198.51.100.7) || fail "update not on both nodes within 5s"
echo "   both nodes answered after $t"

echo "== cut off: stop the control plane"
docker compose stop control-plane >/dev/null
stopped=$SECONDS
sleep 2
all_answer "www.$ZONE" 198.51.100.7 || fail "nodes stopped serving before EXPIRE"
echo "   still serving 2s later (within EXPIRE)"
wait_for $(( EXPIRE + 5 )) all_status "www.$ZONE" SERVFAIL >/dev/null || fail "nodes still serving past EXPIRE"
echo "   both nodes SERVFAIL $(( SECONDS - stopped ))s after the control plane stopped (EXPIRE ${EXPIRE}s)"

echo "== reconnect: start the control plane"
docker compose start control-plane >/dev/null
t=$(wait_for 40 all_answer "www.$ZONE" 198.51.100.7) || fail "nodes did not recover"
echo "   both nodes serving again after $t"

api -X DELETE "$API/zones/$ZONE" >/dev/null
echo "PASS"
