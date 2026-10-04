#!/usr/bin/env bash
# Stage 3 end-to-end check: control plane + two DNS nodes in Docker.
#   1. A change made through the API is answered by both nodes within 5 seconds.
#   2. SOA REFRESH: a node whose copy of a zone drifts (here: edited behind its back) is
#      repaired within REFRESH, and a zone the control plane doesn't have is removed.
#   3. With the control plane gone, nodes keep serving until the zone's SOA EXPIRE passes,
#      then SERVFAIL. When it comes back, they catch up and serve again.
set -euo pipefail
cd "$(dirname "$0")/.."

API=http://127.0.0.1:8054
NODES=(5301 5302)
ZONE="mn$(date +%s).test."
EXPIRE=8
REFRESH=3
RETRY=2

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

echo "== zone $ZONE (SOA refresh ${REFRESH}s, retry ${RETRY}s, expire ${EXPIRE}s)"
api -X POST "$API/zones" -d "{\"name\":\"$ZONE\",\"ns\":[\"ns1.$ZONE\"],
  \"soa\":{\"refresh\":$REFRESH,\"retry\":$RETRY,\"expire\":$EXPIRE}}" >/dev/null

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

# Loads zone-file text from stdin into a node's LMDB behind the follower's back.
load_on() { docker compose exec -T "$1" sh -c 'cat > /tmp/z.zone && dns-server load /data /tmp/z.zone' >/dev/null; }

echo "== refresh: overwrite node1's copy of the zone with stale data (serial 1)"
load_on node1 <<EOF
\$ORIGIN $ZONE
@   300 IN SOA ns1.$ZONE hostmaster.$ZONE 1 $REFRESH $RETRY $EXPIRE 300
@   300 IN NS  ns1.$ZONE
www 300 IN A   203.0.113.66
EOF
[[ "$(answer 5301 "www.$ZONE")" == 203.0.113.66 ]] || fail "tampering didn't take"
t=$(wait_for $(( REFRESH + 5 )) all_answer "www.$ZONE" 198.51.100.7) || fail "node1 not repaired within REFRESH"
echo "   node1 repaired after $t (REFRESH ${REFRESH}s)"

echo "== refresh: a zone only node2 has is removed"
load_on node2 <<EOF
\$ORIGIN rogue.test.
@   300 IN SOA ns1.rogue.test. hostmaster.rogue.test. 1 3600 600 86400 300
@   300 IN NS  ns1.rogue.test.
www 300 IN A   203.0.113.99
EOF
[[ "$(answer 5302 www.rogue.test.)" == 203.0.113.99 ]] || fail "rogue zone didn't load"
t=$(wait_for $(( REFRESH + 5 )) bash -c '[[ "$(dig @127.0.0.1 -p 5302 +norec +tries=1 +time=1 www.rogue.test. A | sed -n "s/.*status: \([A-Z]*\).*/\1/p")" == REFUSED ]]') \
  || fail "rogue zone not removed"
echo "   removed after $t"

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
