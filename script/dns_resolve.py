#!/usr/bin/env python3
"""批量 DNS 解析 + CDN/云判定（dig 循环，量大时可由调用方分批）。

用法：
  python3 dns_resolve.py --input subs.jsonl --bin-dir {BASE}/bin --out OUT.jsonl

输入：--input 为 JSONL 文件或目录（目录读取全部 .jsonl，自动合并去重）。
行格式：{"subdomain":"..."} 或 {"host":"..."}（host 带 URL/端口形式自动归一化，
同一主机名只解析一次——DNS 解析与端口无关，host:port 形式不产生新目标）
输出 JSONL：{"host","ips":[],"cname","is_cdn","is_cloud"}
"""
import argparse
import os
import subprocess
import sys

import igcommon as ig

# CDN/云厂商 CNAME 特征（小写子串匹配）
CDN_HINTS = ("cdn", "cloudflare", "akamai", "fastly", "aliyun", "tencent", "qcloud",
             "cloudfront", "cdn77", "edgekey", "edgesuite", "wscdns", "lxdns")
CLOUD_HINTS = ("amazonaws", "azure", "googlecloud", "aliyun", "huaweicloud", "tencent")


def resolve(host):
    """dig 解析 A/CNAME。失败返回空。"""
    ips, cname = [], ""
    try:
        out = subprocess.run(["dig", "+short", "A", host],
                             capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines():
            line = line.strip().rstrip(".")
            if not line:
                continue
            if ig.is_ip(line):
                ips.append(line)
            else:
                cname = line.lower()
    except Exception:
        pass
    return ips, cname


def main():
    ap = argparse.ArgumentParser(description="批量 DNS 解析 + CDN/云判定")
    ap.add_argument("--input", required=True, help="输入 JSONL 文件或目录（subdomain 或 host 字段）")
    ap.add_argument("--bin-dir", default="/opt/tools/info-gather/bin")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if os.path.isdir(args.input):
        input_rows = []
        for name in sorted(os.listdir(args.input)):
            if name.endswith(".jsonl"):
                input_rows.extend(ig.read_jsonl(os.path.join(args.input, name)))
    else:
        input_rows = ig.read_jsonl(args.input)

    rows = []
    seen = set()
    for entry in input_rows:
        host = ig.normalize_host(entry.get("subdomain") or entry.get("host") or "").lower()
        if not host or ig.is_ip(host) or host in seen:
            continue
        seen.add(host)
        ips, cname = resolve(host)
        hint_src = cname or host
        rows.append({
            "host": host, "ips": ips, "cname": cname,
            "is_cdn": any(h in hint_src for h in CDN_HINTS),
            "is_cloud": any(h in hint_src for h in CLOUD_HINTS),
        })
    ig.write_jsonl(args.out, rows)
    alive = sum(1 for r in rows if r["ips"])
    print("[ok] 解析完成：%d 域名，%d 存活 → %s" % (len(rows), alive, args.out))


if __name__ == "__main__":
    sys.exit(main())
