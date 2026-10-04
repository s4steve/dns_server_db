#!/usr/bin/env bash
# Stage 3 end-to-end check: control plane + two DNS nodes in Docker.
#   1. A change made through the API is answered by both nodes within 5 seconds.
#   2. SOA REFRESH: a node whose copy of a zone drifts (here: edited behind its back) is
#      repaired within REFRESH, and a zone the control plane doesn't have is removed.
#   3. LUA scripts run on every node: per-node answers (q.node) and per-subnet answers (ECS).
#   4. Ops: /health and /metrics on each node; a DNS cookie from one node validates on the
#      other (shared --cookie-secret, as behind anycast).
#   5. With the control plane gone, nodes keep serving until the zone's SOA EXPIRE passes,
#      then SERVFAIL (and count the zone as expired). When it comes back, they catch up.
set -euo pipefail
cd "$(dirname "$0")/.."

API=http://127.0.0.1:8054
TOKEN=dnsdb_dev_admin_token_do_not_use_in_production # dev-only, see docker-compose.yml
NODES=(5301 5302)
ZONE="mn$(date +%s).test."
EXPIRE=8
REFRESH=3
RETRY=2

fail() { echo "FAIL: $*" >&2; exit 1; }
api() { curl -sf -H 'content-type: application/json' -H "authorization: Bearer $TOKEN" "$@"; }
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

status=$(curl -s -o /dev/null -w '%{http_code}' "$API/zones")
[[ "$status" == 401 ]] || fail "unauthenticated request got $status, not 401"
echo "== access control: no token -> 401; nodes authenticate with their read-only token"

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

echo "== LUA: per-node and per-subnet answers"
api -X POST "$API/zones/$ZONE/changes" -d @- >/dev/null <<'EOF'
{"changes":[
  {"action":"add","name":"whoami","type":"LUA","data":"TXT return '\"' .. q.node .. '\"'"},
  {"action":"add","name":"geo","type":"LUA","data":"A if in_cidr(q.client, '10.0.0.0/8') then return '192.0.2.10' end return '192.0.2.20'"}]}
EOF
txt() { dig @127.0.0.1 -p "$1" +norec +tries=1 +time=1 +short "whoami.$ZONE" TXT; }
both_named() { [[ "$(txt 5301)" == '"node1"' && "$(txt 5302)" == '"node2"' ]]; }
t=$(wait_for 5 both_named) || fail "whoami: got $(txt 5301) / $(txt 5302)"
echo "   whoami: node1 says $(txt 5301), node2 says $(txt 5302) (after $t)"
inside=$(dig @127.0.0.1 -p 5301 +short +subnet=10.1.2.0/24 "geo.$ZONE" A)
outside=$(dig @127.0.0.1 -p 5301 +short +subnet=203.0.113.0/24 "geo.$ZONE" A)
scope=$(dig @127.0.0.1 -p 5301 +subnet=10.1.2.0/24 "geo.$ZONE" A | grep -o 'CLIENT-SUBNET: [0-9./]*')
[[ "$inside" == 192.0.2.10 && "$outside" == 192.0.2.20 ]] || fail "geo: got $inside / $outside"
echo "   geo: 10.1.2.0/24 gets $inside, 203.0.113.0/24 gets $outside ($scope)"

echo "== ops: health, metrics, cookies across nodes"
for port in 9301 9302; do
  curl -sf "127.0.0.1:$port/health" | grep -q '"healthy":true' || fail "node on $port not healthy"
done
curl -sf 127.0.0.1:9301/metrics | grep -q '^dns_queries_total{transport="udp",rcode="NOERROR"} [1-9]' || fail "no query metrics"
echo "   both nodes healthy; metrics exported"
# macOS's dig predates +cookie, so speak COOKIE (EDNS option 10) from Python: get a server
# cookie from node1, present it to node2, and watch node2 count it as valid.
cookie_query() { python3 - "$@" <<'PYEOF'
import socket, struct, sys
port, name, cookie = int(sys.argv[1]), sys.argv[2], bytes.fromhex(sys.argv[3])
qname = b"".join(bytes([len(l)]) + l.encode() for l in name.rstrip(".").split(".")) + b"\0"
opt = b"\0" + struct.pack(">HHIH", 41, 1232, 0, 4 + len(cookie)) + struct.pack(">HH", 10, len(cookie)) + cookie
msg = struct.pack(">HHHHHH", 0x1234, 0, 1, 0, 0, 1) + qname + struct.pack(">HH", 1, 1) + opt
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(msg, ("127.0.0.1", port))
resp = s.recv(4096)
i = resp.find(b"\x00\x0a\x00\x18" + cookie[:8])
print(resp[i + 4:i + 28].hex() if i >= 0 else "")
PYEOF
}
valid_cookies() { curl -sf "127.0.0.1:$1/metrics" | sed -n 's/^dns_cookies_valid_total //p'; }
cookie=$(cookie_query 5301 "www.$ZONE" 0102030405060708)
[[ ${#cookie} == 48 ]] || fail "no server cookie from node1 (got '$cookie')"
before=$(valid_cookies 9302)
cookie_query 5302 "www.$ZONE" "$cookie" >/dev/null
after=$(valid_cookies 9302)
(( after == before + 1 )) || fail "node2 didn't accept node1's cookie ($before -> $after)"
echo "   node1's server cookie is accepted by node2"
expired_before=$(curl -sf 127.0.0.1:9301/metrics | sed -n 's/^dns_zones_expired //p')

echo "== cut off: stop the control plane"
docker compose stop control-plane >/dev/null
stopped=$SECONDS
sleep 2
all_answer "www.$ZONE" 198.51.100.7 || fail "nodes stopped serving before EXPIRE"
echo "   still serving 2s later (within EXPIRE)"
wait_for $(( EXPIRE + 5 )) all_status "www.$ZONE" SERVFAIL >/dev/null || fail "nodes still serving past EXPIRE"
echo "   both nodes SERVFAIL $(( SECONDS - stopped ))s after the control plane stopped (EXPIRE ${EXPIRE}s)"
expired_now=$(curl -sf 127.0.0.1:9301/metrics | sed -n 's/^dns_zones_expired //p')
(( expired_now > expired_before )) || fail "dns_zones_expired didn't rise ($expired_before -> $expired_now)"
echo "   dns_zones_expired: $expired_before -> $expired_now"

echo "== reconnect: start the control plane"
docker compose start control-plane >/dev/null
t=$(wait_for 40 all_answer "www.$ZONE" 198.51.100.7) || fail "nodes did not recover"
echo "   both nodes serving again after $t"

api -X DELETE "$API/zones/$ZONE" >/dev/null
echo "PASS"
