# 123ipxinxi

`123ip.cc` 的**公开数据仓库**：为 IP 检测站点提供「IP 段库」与「风控威胁情报」两类数据，**每日自动更新**。

> 数据全部来自公开来源，本仓库只做下载、清洗、格式压缩与分发，不对数据准确性作任何担保，仅供参考。

## 数据用途

| 用途 | 文件 | 说明 |
|---|---|---|
| IP 类型判定（IDC 机房 / 家庭宽带） | `data/dc4.b64` `data/dc6.b64` | 机房段库（IPv4 / IPv6） |
| 代理 / VPN 标签 | `data/vpn4.b64` `data/vpn6.b64` | VPN/代理段库 |
| 风控值（恶意 IP） | `data/risk_ips.b64` | 恶意 IP + 命中黑名单数权重 |
| 风控值（恶意网段） | `data/risk_nets.b64` | 恶意/劫持网段 |
| 元信息 | `data/stats.json` | 生成时间、各源条数 |

## 数据来源（均为公开、免费）

- [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) — datacenter / vpn 段（IPv4 + IPv6）
- [AWS ip-ranges](https://ip-ranges.amazonaws.com/ip-ranges.json) — 官方云段
- [GCP cloud.json](https://www.gstatic.com/ipranges/cloud.json) — 官方云段
- [Cloudflare ips-v4 / ips-v6](https://www.cloudflare.com/ips) — 官方段
- [stamparm/ipsum](https://github.com/stamparm/ipsum) — 恶意 IP 聚合（含命中黑名单数）
- [Spamhaus DROP](https://www.spamhaus.org/drop/) — 恶意 / 被劫持网段
- [firehol/blocklist-ipsets](https://github.com/firehol/blocklist-ipsets) — firehol_level1

## 二进制格式

**段表**（`dc4/dc6/vpn4/vpn6`）：Base64 编码的紧凑二进制，条目按 network 升序排列，可直接二分匹配。

- IPv4：每条 **5 字节** = network（大端 uint32，4B）+ prefixlen（1B）
- IPv6：每条 **9 字节** = 前 64 位前缀（8B）+ prefixlen（1B），仅收录 /16 ~ /64

**恶意 IP 表**（`risk_ips`）：每条 **5 字节** = IP（大端 uint32，4B）+ 命中黑名单数（1B，1~255）

## 自动更新

`.github/workflows/update.yml` 每日 UTC 04:23（北京时间 12:23）自动执行：
下载全部来源 → 编译为上述格式 → 提交到本仓库 → 同步推送到 Cloudflare Workers KV（供 `123ip.cc` 运行时读取）。

也可在 Actions 页面手动触发（workflow_dispatch）。

## 使用

```bash
python3 scripts/build_ipseg.py   # 生成 data/dc*.b64 data/vpn*.b64
python3 scripts/build_risk.py    # 生成 data/risk_*.b64
```

数据文件可直接通过 raw 地址读取，例如：
`https://raw.githubusercontent.com/ip9988001/123ipxinxi/main/data/dc4.b64`
