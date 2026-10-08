#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""编译风控威胁情报为紧凑 Base64 二进制。

输入（当前目录）：ipsum.txt（IP<TAB>命中黑名单数）、drop.txt（Spamhaus DROP）、firehol_level1.netset
输出（OUT_DIR，默认 data/）：risk_ips.b64 risk_nets.b64 stats.json（合并写）
"""
import ipaddress, base64, struct, os, json, datetime

OUT = os.environ.get('OUT_DIR', 'data')
os.makedirs(OUT, exist_ok=True)


def load_ipsum(path):
    """IPsum: 每行 `ip\tscore`，score = 被多少个黑名单收录"""
    out = {}
    if not os.path.exists(path):
        return out
    for line in open(path, encoding='utf-8', errors='ignore'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            v = int(ipaddress.IPv4Address(parts[0]))
            out[v] = max(out.get(v, 0), min(255, int(parts[1])))
        except Exception:
            pass
    return out


def load_nets(path, strip_junk):
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path, encoding='utf-8', errors='ignore'):
        s = line.strip()
        if not s or s.startswith(('#', ';')):
            continue
        s = strip_junk(s).split()[0] if s.split() else s
        try:
            n = ipaddress.ip_network(s, strict=False)
            if n.version == 4:
                out.append(n)
        except Exception:
            pass
    return out


def merge(nets):
    items = sorted((int(n.network_address), n.prefixlen) for n in nets if 8 <= n.prefixlen <= 32)
    acc, prev_end = [], -1
    for net, plen in items:
        end = net + (1 << (32 - plen)) - 1
        if end <= prev_end:
            continue
        acc.append((net, plen))
        prev_end = end
    return acc


ips = load_ipsum('ipsum.txt')
nets = merge(load_nets('drop.txt', lambda s: s.split(';')[0]) + load_nets('firehol_level1.netset', lambda s: s))

b_ip = b''.join(struct.pack('>I', v) + bytes([w]) for v, w in sorted(ips.items()))
b_net = b''.join(struct.pack('>I', n) + bytes([p]) for n, p in nets)
open(os.path.join(OUT, 'risk_ips.b64'), 'w').write(base64.b64encode(b_ip).decode())
open(os.path.join(OUT, 'risk_nets.b64'), 'w').write(base64.b64encode(b_net).decode())

stats = {'generated_at': datetime.datetime.utcnow().isoformat() + 'Z', 'sets': {}}
try:
    sp = os.path.join(OUT, 'stats.json')
    if os.path.exists(sp):
        stats['sets'].update({k: v for k, v in json.load(open(sp)).get('sets', {}).items()
                              if not k.startswith('risk')})
except Exception:
    pass
stats['sets']['risk_ips.b64'] = {'entries': len(ips), 'bytes_b64': len(base64.b64encode(b_ip))}
stats['sets']['risk_nets.b64'] = {'entries': len(nets), 'bytes_b64': len(base64.b64encode(b_net))}
json.dump(stats, open(os.path.join(OUT, 'stats.json'), 'w'), ensure_ascii=False, indent=1)

print('风控: risk_ips=%d  risk_nets=%d' % (len(ips), len(nets)))
