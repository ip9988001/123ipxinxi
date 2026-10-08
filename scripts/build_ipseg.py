#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""编译 IP 段库（机房 / 代理）为紧凑 Base64 二进制。

输入（当前目录）：dc4.txt dc6.txt vpn4.txt vpn6.txt cf4.txt cf6.txt aws.json gcp.json
输出（OUT_DIR，默认 data/）：dc4.b64 dc6.b64 vpn4.b64 vpn6.b64 stats.json
"""
import ipaddress, base64, struct, os, json, datetime

OUT = os.environ.get('OUT_DIR', 'data')
os.makedirs(OUT, exist_ok=True)


def from_txt(path):
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path, encoding='utf-8', errors='ignore'):
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        try:
            out.append(ipaddress.ip_network(s, strict=False))
        except Exception:
            pass
    return out


def from_json(path, keys):
    out = []
    if not os.path.exists(path):
        return out
    try:
        data = json.load(open(path, encoding='utf-8'))
    except Exception:
        return out
    for it in data.get('prefixes', []):
        for k in keys:
            v = it.get(k)
            if not v:
                continue
            try:
                out.append(ipaddress.ip_network(v, strict=False))
            except Exception:
                pass
    return out


def merge(nets, ver, minp, maxp):
    items = sorted((int(n.network_address), n.prefixlen) for n in nets
                   if n.version == ver and minp <= n.prefixlen <= maxp)
    acc, prev_end = [], -1
    bits = 32 if ver == 4 else 128
    for net, plen in items:
        end = net + (1 << (bits - plen)) - 1
        if end <= prev_end:
            continue          # 已被前面的段完全覆盖
        acc.append((net, plen))
        prev_end = end
    return acc


def enc4(segs):
    return base64.b64encode(b''.join(struct.pack('>I', n) + bytes([p]) for n, p in segs)).decode()


def enc6(segs):
    return base64.b64encode(b''.join((n >> 64).to_bytes(8, 'big') + bytes([p]) for n, p in segs)).decode()


def write(name, segs, ver):
    data = enc4(segs) if ver == 4 else enc6(segs)
    with open(os.path.join(OUT, name), 'w') as f:
        f.write(data)
    return {'entries': len(segs), 'bytes_b64': len(data)}


aws4 = [n for n in from_json('aws.json', ['ip_prefix']) if n.version == 4]
aws6 = [n for n in from_json('aws.json', ['ipv6_prefix']) if n.version == 6]
gcp4 = [n for n in from_json('gcp.json', ['ipv4Prefix']) if n.version == 4]
gcp6 = [n for n in from_json('gcp.json', ['ipv6Prefix']) if n.version == 6]

dc4 = merge(from_txt('dc4.txt') + from_txt('cf4.txt') + aws4 + gcp4, 4, 8, 32)
dc6 = merge(from_txt('dc6.txt') + from_txt('cf6.txt') + aws6 + gcp6, 6, 16, 64)
vpn4 = merge(from_txt('vpn4.txt'), 4, 8, 32)
vpn6 = merge(from_txt('vpn6.txt'), 6, 16, 64)

stats = {'generated_at': datetime.datetime.utcnow().isoformat() + 'Z', 'sets': {}}
for name, segs, ver in (('dc4.b64', dc4, 4), ('dc6.b64', dc6, 6),
                        ('vpn4.b64', vpn4, 4), ('vpn6.b64', vpn6, 6)):
    stats['sets'][name] = write(name, segs, ver)

try:
    sp = os.path.join(OUT, 'stats.json')
    if os.path.exists(sp):
        stats['sets'].update({k: v for k, v in json.load(open(sp)).get('sets', {}).items()
                              if k.startswith('risk')})
except Exception:
    pass

with open(os.path.join(OUT, 'stats.json'), 'w') as f:
    json.dump(stats, f, ensure_ascii=False, indent=1)

print('段库: ' + ', '.join('%s=%d' % (k, v['entries']) for k, v in stats['sets'].items() if k.startswith(('dc', 'vpn'))))
