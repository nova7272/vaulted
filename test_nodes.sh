#!/bin/bash
echo "=== XRPL Testnet Node Health Check v2 ==="
echo ""

nodes=(
  "https://s.altnet.rippletest.net:51234"
  "https://clio.altnet.rippletest.net:51234"
  "https://s.devnet.rippletest.net:51234"
  "https://xrplcluster.com"
  "https://testnet.xrpl-labs.com"
  "https://testnet-clio.xrpl-labs.com"
)

best_node=""
best_avg=99999

for node in "${nodes[@]}"; do
  ok=0; fail=0; total_ms=0
  for i in $(seq 1 5); do
    start=$(date +%s%3N)
    code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 --max-time 5 \
      -X POST "$node" \
      -H "Content-Type: application/json" \
      -d '{"method":"server_info","params":[{}]}' 2>/dev/null)
    end=$(date +%s%3N)
    ms=$((end - start))
    if [ "$code" = "200" ]; then
      ok=$((ok+1)); total_ms=$((total_ms + ms))
    else
      fail=$((fail+1))
    fi
  done
  if [ $ok -gt 0 ]; then
    avg=$((total_ms / ok))
    printf "%-55s ✅ %d/5 OK  avg=%dms  fails=%d\n" "$node" "$ok" "$avg" "$fail"
    if [ $ok -ge 4 ] && [ $avg -lt $best_avg ]; then
      best_avg=$avg
      best_node=$node
    fi
  else
    printf "%-55s ❌ 0/5 — all failed\n" "$node"
  fi
done
echo ""
if [ -n "$best_node" ]; then
  echo "🏆 Best node: $best_node (avg ${best_avg}ms)"
  echo ""
  echo "To update .env:"
  echo "  sed -i 's|XRPL_NODE_URL=.*|XRPL_NODE_URL=$best_node|' ~/xrpl-vault/.env"
else
  echo "⚠️  All nodes failed! XRPL testnet may be down."
fi
echo ""
echo "=== Done ==="