#!/usr/bin/env bash
# 把 data/ 下的二进制推送到 Cloudflare Workers KV（供 123ip.cc 运行时读取）
set -euo pipefail
API=https://api.cloudflare.com/client/v4
: "${CF_EMAIL:?}"; : "${CF_KEY:?}"; : "${CF_ACC:?}"; : "${KV_IPSEG:?}"; : "${KV_RISK:?}"

push() { # namespace  key  file
  code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    "$API/accounts/$CF_ACC/storage/kv/namespaces/$1/values/$2" \
    -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" --data-binary @"$3")
  echo "  $2 -> $code"
}

echo "推送到 KV_IPSEG:"
push "$KV_IPSEG" dc4  data/dc4.b64
push "$KV_IPSEG" dc6  data/dc6.b64
push "$KV_IPSEG" vpn4 data/vpn4.b64
push "$KV_IPSEG" vpn6 data/vpn6.b64
echo "推送到 KV_RISK:"
push "$KV_RISK" risk_ips  data/risk_ips.b64
push "$KV_RISK" risk_nets data/risk_nets.b64
echo "完成（KV 全球生效约 60 秒内）"
