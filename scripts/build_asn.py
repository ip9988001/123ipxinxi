#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""构建 ASN → IP 段 分片库 + ASN 元数据（多源合并去重）

数据源（全部公开免费）：
  1. iptoasn.com   —— BGP 实际宣告（主源）：ip2asn-v4.tsv / ip2asn-v6.tsv
  2. NRO delegated —— 五大 RIR 官方分配记录（校验：ASN 是否存在）
  3. PeeringDB API —— ASN 元数据：正式名称 / 官网 / 类型 / 国家（分页全量，可选）
  4. ipverse/asn-ip —— 交叉验证（可选，默认不拉，文件太碎）

输出：
  data/asn/<shard>.b64     256 个分片（按 ASN % 256），每片含该片全部 ASN 的元数据 + 段
  data/asn_stats.json      统计信息

二进制格式（每片，base64 编码，全部大端）：
  [1B ver=1][4B meta_n][4B seg4_n][4B seg6_n]
  meta:  4B asn | 1B name_len | name(utf8) | 1B site_len | site(utf8) | 2B cc
  seg4:  4B start | 4B end | 4B asn
  seg6:  16B prefix | 1B plen | 4B asn
"""
import base64, gzip, io, ipaddress, json, os, struct, sys, time, urllib.error, urllib.request

OUT = os.environ.get('OUT_DIR', 'data')
SHARDS = int(os.environ.get('ASN_SHARDS', '256'))
PDB_MAX = int(os.environ.get('PEERINGDB_MAX', '0'))   # 0 = 不限量（全量拉取）
os.makedirs(os.path.join(OUT, 'asn'), exist_ok=True)


def norm_asn(s):
    s = str(s).strip().upper().lstrip('AS')
    try:
        return int(s)
    except Exception:
        return None


def load_iptoasn_v4(path):
    segs, meta = [], {}
    if not os.path.exists(path):
        return segs, meta
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) < 5:
                continue
            asn = norm_asn(p[2])
            if not asn:          # ASN 0 = Not routed，跳过
                continue
            try:
                a = int(ipaddress.IPv4Address(p[0])); b = int(ipaddress.IPv4Address(p[1]))
            except Exception:
                continue
            if b < a:
                continue
            segs.append((a, b, asn))
            if asn not in meta:
                meta[asn] = {'name': p[4] or '', 'cc': (p[3] if p[3] != 'None' else '')}
    return segs, meta


def load_iptoasn_v6(path):
    segs, meta = [], {}
    if not os.path.exists(path):
        return segs, meta
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) < 5:
                continue
            asn = norm_asn(p[2])
            if not asn:
                continue
            if asn not in meta:
                meta[asn] = {'name': p[4] or '', 'cc': (p[3] if p[3] != 'None' else '')}
            try:
                a = ipaddress.IPv6Address(p[0]); b = ipaddress.IPv6Address(p[1])
                for n in ipaddress.summarize_address_range(a, b):
                    segs.append((int(n.network_address), n.prefixlen, asn))
            except Exception:
                continue
    return segs, meta


def load_nro(path):
    """NRO delegated-stats: registry|cc|type|start|value|date|status"""
    exist, cnt = set(), 0
    if not os.path.exists(path):
        return exist, cnt
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            p = line.rstrip('\n').split('|')
            if len(p) < 5:
                continue
            cnt += 1
            if p[2].strip() == 'asn':
                a = norm_asn(p[3])
                if a:
                    exist.add(a)
    return exist, cnt


def load_peeringdb():
    """分页拉取 PeeringDB net 记录 → {asn: {site, name, type, cc}}
    带退避重试（PeeringDB 对无认证请求限速，约 40 次/分钟）"""
    out, skip, fails = {}, 0, 0
    while True:
        url = 'https://www.peeringdb.com/api/net?limit=250&skip=%d&depth=0' % skip
        data = None
        for attempt in range(4):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': '123ip-data-bot/1.0 (+https://123ip.cc)'})
                data = json.load(urllib.request.urlopen(req, timeout=60))
                break
            except urllib.error.HTTPError as e:
                if e.code in (429, 503):
                    time.sleep(8 * (attempt + 1))
                    continue
                print('PeeringDB HTTP %s（skip=%d），结束' % (e.code, skip)); return out
            except Exception as e:
                fails += 1
                time.sleep(3 * (attempt + 1))
        if data is None:
            print('PeeringDB 多次失败（skip=%d），已获取 %d 条' % (skip, len(out))); break
        rows = data.get('data') or []
        for r in rows:
            a_ = r.get('asn')
            if not a_:
                continue
            out[int(a_)] = {
                'site': (r.get('website') or '').strip(),
                'name': (r.get('name') or '').strip(),
                'type': (r.get('info_type') or '').strip(),
                'cc': (r.get('country') or '').strip(),
            }
        skip += len(rows)
        if not rows or (PDB_MAX and skip >= PDB_MAX):
            break
        if skip % 5000 == 0:
            print('  PeeringDB 进度:', skip, '条')
        time.sleep(1.5)
    return out


def main():
    print('读取 iptoasn v4 ...')
    seg4, meta = load_iptoasn_v4('ip2asn-v4.tsv')
    print('  v4 段:', len(seg4), ' ASN:', len(meta))
    print('读取 iptoasn v6 ...')
    seg6, meta6 = load_iptoasn_v6('ip2asn-v6.tsv')
    for a, m in meta6.items():
        meta.setdefault(a, m)
    print('  v6 段:', len(seg6), ' ASN(合并后):', len(meta))

    exist_asns, nro_lines = load_nro('nro-delegated-stats')
    print('NRO 记录:', nro_lines, ' 有 ASN 记录:', len(exist_asns))

    print('拉取 PeeringDB（可跳过）...')
    pdb = load_peeringdb() if os.environ.get('SKIP_PEERINGDB') != '1' else {}
    print('  PeeringDB net:', len(pdb))

    # ---- 合并元数据：iptoasn 的 AS 名 + PeeringDB 的官网/类型/正式名 ----
    all_asns = set(meta) | set(pdb)
    rich = {}
    for a in all_asns:
        m = meta.get(a, {})
        q = pdb.get(a, {})
        rich[a] = {
            'name': q.get('name') or m.get('name') or '',
            'site': q.get('site') or '',
            'type': q.get('type') or '',
            'cc': (q.get('cc') or m.get('cc') or '').upper()[:2],
            'nro': 1 if (not exist_asns or a in exist_asns) else 0,
        }

    # ---- 去重（同 (start,end,asn)）+ 分组到分片 ----
    seg4 = sorted(set(seg4))
    seg6 = sorted(set(seg6))
    print('去重后 v4:', len(seg4), ' v6:', len(seg6))

    shards4, shards6 = {}, {}
    for a, b, asn in seg4:
        shards4.setdefault(asn % SHARDS, []).append((a, b, asn))
    for pfx, plen, asn in seg6:
        shards6.setdefault(asn % SHARDS, []).append((pfx, plen, asn))

    shard_meta = {}
    for a in all_asns:
        shard_meta.setdefault(a % SHARDS, []).append(a)

    written = 0
    for s in range(SHARDS):
        ms = sorted(shard_meta.get(s, []))
        s4 = shards4.get(s, [])
        s6 = shards6.get(s, [])
        buf = io.BytesIO()
        buf.write(bytes([1]))
        buf.write(struct.pack('>III', len(ms), len(s4), len(s6)))
        for a in ms:
            r = rich[a]
            nm = r['name'].encode('utf-8')[:255]
            st = r['site'].encode('utf-8')[:255]
            cc = (r['cc'] + '  ')[:2].encode('ascii', 'ignore') or b'  '
            flags = (1 if r['type'] else 0) | (2 if r['nro'] else 0)
            t = r['type'].encode('utf-8')[:255]
            buf.write(struct.pack('>I', a) + bytes([len(nm)]) + nm + bytes([len(st)]) + st
                      + cc + bytes([flags, len(t)]) + t)
        for a, b, asn in s4:
            buf.write(struct.pack('>III', a, b, asn))
        for pfx, plen, asn in s6:
            buf.write(pfx.to_bytes(16, 'big') + bytes([plen]) + struct.pack('>I', asn))
        raw = buf.getvalue()
        open(os.path.join(OUT, 'asn', '%d.b64' % s), 'w').write(base64.b64encode(raw).decode())
        written += 1

    stats = {
        'shards': SHARDS,
        'asn_total': len(all_asns),
        'asn_with_segments': len(set(x[2] for x in seg4) | set(x[2] for x in seg6) | set(meta) | set(pdb)),
        'asn_no_meta': len((set(x[2] for x in seg4) | set(x[2] for x in seg6)) - set(meta) - set(pdb)),
        'seg4': len(seg4), 'seg6': len(seg6),
        'peeringdb_net': len(pdb),
        'nro_lines': nro_lines,
        'asn_not_in_nro': len([a for a in meta if exist_asns and a not in exist_asns]),
        'shard_files': written,
    }
    json.dump(stats, open(os.path.join(OUT, 'asn_stats.json'), 'w'), ensure_ascii=False, indent=1)
    print('分片完成:', json.dumps(stats, ensure_ascii=False))


if __name__ == '__main__':
    main()
