#!/usr/bin/env python3
"""IP 归属地统一补全（入库前末段处理）。

规则（方案 docs/asset-media-geo-plan.md §4）：
  - location 非空（在线接口已提供）→ 跳过；
  - 内网/保留地址 → 标「内网地址」；
  - 其余查 ip2region.xdb（--xdb，缺省 {script}/../data/ip2region.xdb）；
  - xdb 缺失/查询失败 → 留空，不阻断管线。

用法：
  python3 geo_resolve.py --input assets_final.jsonl --out assets_final.jsonl [--shard-size 500]
（--input 与 --out 可同路径，原地重写；--shard-size > 0 时重新生成 part 分片）
"""
import argparse
import glob
import ipaddress
import os
import sys

import igcommon as ig

try:
    from xdb_searcher import XdbSearcher, format_location
except ImportError:  # vendor 缺失时整体降级
    XdbSearcher = None
    format_location = None

INTRANET_LABEL = "内网地址"


def is_intranet(ip):
    """内网/保留/环回/链路本地地址判定（stdlib ipaddress）。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def main():
    ap = argparse.ArgumentParser(description="IP 归属地统一补全（ip2region.xdb）")
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--xdb", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                "..", "data", "ip2region.xdb"))
    ap.add_argument("--shard-size", type=int, default=0,
                    help="分片大小（>0 时基于 out 重新生成 part_NNN 分片）")
    args = ap.parse_args()

    rows = ig.read_jsonl(args.input)
    searcher = None
    if XdbSearcher and os.path.isfile(args.xdb):
        try:
            searcher = XdbSearcher(args.xdb)
        except (OSError, ValueError) as e:
            print("[warn] xdb 加载失败，归属地跳过: %s" % e, file=sys.stderr)
    else:
        print("[warn] ip2region.xdb 缺失（%s），仅标注内网地址" % args.xdb, file=sys.stderr)

    filled = intranet = skipped = 0
    for row in rows:
        ips = row.get("ips") or []
        host = str(row.get("host") or "").strip()
        if not ips and ig.is_ip(host):
            # IP 型 host 兜底：host 本身就是 IP（无 DNS 解析阶段 ips 为空）
            ips = [host]
            row["ips"] = ips
        if not ips:
            continue
        locs = list(row.get("locations") or [])
        locs += [""] * (len(ips) - len(locs))  # 对齐长度
        for i, ip in enumerate(ips):
            if i < len(locs) and locs[i]:
                skipped += 1  # 在线接口已提供
                continue
            if is_intranet(ip):
                locs[i] = INTRANET_LABEL
                intranet += 1
                continue
            if searcher:
                loc = format_location(searcher.search(ip) or "")
                if loc:
                    locs[i] = loc
                    filled += 1
        row["locations"] = locs

    ig.write_jsonl(args.out, rows)
    shards = 0
    if args.shard_size > 0:
        base = os.path.splitext(os.path.abspath(args.out))[0]
        # 清理旧分片（merge 阶段可能已生成过，避免陈旧分片重复入库）
        for old in glob.glob(base + ".part_*.jsonl"):
            os.unlink(old)
        for i in range(0, len(rows), args.shard_size):
            part = "%s.part_%03d.jsonl" % (base, i // args.shard_size + 1)
            ig.write_jsonl(part, rows[i:i + args.shard_size])
            shards += 1
    print("[ok] 归属地补全：查询 %d，内网 %d，已有 %d，分片 %d → %s"
          % (filled, intranet, skipped, shards, args.out))


if __name__ == "__main__":
    sys.exit(main())
