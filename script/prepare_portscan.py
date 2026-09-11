#!/usr/bin/env python3
"""portscan 阶段目标制备：汇聚 target/online/resolve 三处产物，归一化去重，
CDN/云过滤，CIDR 展开，输出扫描目标清单。

该脚本承接原 Observer Go 侧的执行处理逻辑（原则：执行下沉脚本，系统只做编排）：
  - host 归一化（剥 scheme/路径/端口，igcommon.normalize_host）
  - 跨来源目标去重（同一 IP 在 online/resolve 产物中重复出现只保留一次）
  - CDN/云过滤：resolve 产物读 is_cdn/is_cloud 标记；online 产物按 server
    字段启发式识别知名 CDN（cloudflare/akamai/fastly 等）；
    --include-cdn 可关闭过滤
  - CIDR 展开：≤4096 主机的 v4 前缀展开为逐 IP；更大前缀原样保留
    （nmap 原生支持 CIDR）

用法：
  python3 prepare_portscan.py --shared-dir shared/info-gather --out targets.jsonl

输出 JSONL：{"ip":"..."}
"""
import argparse
import ipaddress
import os
import sys

import igcommon as ig

# CIDR 展开上限（超过则原样保留由扫描工具原生处理）
CIDR_EXPAND_MAX = 4096

# online 产物 server 字段的 CDN 启发式识别（小写 contains 匹配）
CDN_SERVER_HINTS = ("cloudflare", "akamai", "fastly", "cloudfront", "cdn77",
                    "stackpath", "incapsula", "sucuri")


def is_cdn_row(row):
    """online/resolve 行 CDN 判定：显式标记优先，其次 server 启发式。"""
    if row.get("is_cdn") or row.get("is_cloud"):
        return True
    server = str(row.get("server", "")).lower()
    return any(h in server for h in CDN_SERVER_HINTS)


def expand_cidr(value):
    """CIDR 展开（v4 ≤CIDR_EXPAND_MAX）；其余原样返回。"""
    if "/" not in value:
        return [value]
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return [value]
    if net.version != 4 or net.num_addresses > CIDR_EXPAND_MAX:
        return [value]
    return [str(ip) for ip in net]


def main():
    ap = argparse.ArgumentParser(description="portscan 目标制备（汇聚/去重/CDN 过滤/CIDR 展开）")
    ap.add_argument("--shared-dir", required=True, help="shared/info-gather 目录")
    ap.add_argument("--include-cdn", action="store_true", help="不过滤 CDN/云 IP")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    host_set = set()
    cdn_filtered = 0

    # 1. target 清单：ip/cidr 类型目标直接纳入（用户显式授权目标不过滤）
    for row in ig.read_jsonl(os.path.join(args.shared_dir, "target", "targets.jsonl")):
        t, v = row.get("type", ""), ig.normalize_host(row.get("value", ""))
        if t in ("ip", "cidr") and v:
            host_set.add(v)

    # 2. resolve 产物：is_cdn/is_cloud=true 的 IP 过滤（CDN 边缘扫描无价值）
    for row in ig.read_jsonl_dir(args.shared_dir, "resolve"):
        ips = list(row.get("ips") or [])
        if row.get("ip"):
            ips.append(row["ip"])
        if is_cdn_row(row):
            cdn_filtered += len(ips)
            continue
        for ip in ips:
            ip = ig.normalize_host(ip)
            if ip and ig.is_ip(ip):
                host_set.add(ip)

    # 3. online 产物：CDN 启发式过滤（server: cloudflare 等）
    for row in ig.read_jsonl_dir(args.shared_dir, "online"):
        ips = []
        if row.get("ip"):
            ips.append(row["ip"])
        ips.extend(row.get("ips") or [])
        h = ig.normalize_host(row.get("host", ""))
        if h and ig.is_ip(h):
            ips.append(h)
        if not args.include_cdn and is_cdn_row(row):
            cdn_filtered += len(ips)
            continue
        for ip in ips:
            ip = ig.normalize_host(ip)
            if ip and ig.is_ip(ip):
                host_set.add(ip)

    # 4. CIDR 展开 + 最终去重排序（确定性输出）
    targets = set()
    for h in host_set:
        targets.update(expand_cidr(h))
    rows = [{"ip": ip} for ip in sorted(targets)]
    ig.write_jsonl(args.out, rows)
    print("[ok] portscan 目标制备完成：%d 目标（CDN/云过滤 %d 个 IP）→ %s"
          % (len(rows), cdn_filtered, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
