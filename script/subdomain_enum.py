#!/usr/bin/env python3
"""子域名枚举编排：subfinder + crt.sh 证书透明度，去重输出。

用法：
  python3 subdomain_enum.py --domain example.com --bin-dir {BASE}/bin --out OUT.jsonl

输出 JSONL：{"subdomain":"..."}
"""
import argparse
import json
import subprocess
import sys

import igcommon as ig


def enum_subfinder(domain, bin_dir):
    """subfinder 枚举（工具缺失时返回 None 表示降级）。"""
    import os
    exe = os.path.join(bin_dir, "subfinder")
    if not os.path.isfile(exe):
        return None
    out = subprocess.run([exe, "-d", domain, "-silent"],
                         capture_output=True, text=True, timeout=600)
    return [l.strip().lower() for l in out.stdout.splitlines() if l.strip()]


def enum_crtsh(domain):
    """crt.sh 证书透明度枚举（网络失败返回空）。"""
    try:
        _, body = ig.http_get("https://crt.sh/?q=%%25.%s&output=json" % domain, timeout=30)
        subs = set()
        for entry in json.loads(body):
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain):
                    subs.add(name)
        return sorted(subs)
    except Exception:
        return []


def main():
    ap = argparse.ArgumentParser(description="子域名枚举（subfinder + crt.sh）")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--bin-dir", default="/opt/tools/info-gather/bin")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    subs = {args.domain.lower()}
    degraded = []

    r = enum_subfinder(args.domain, args.bin_dir)
    if r is None:
        degraded.append("subfinder 缺失")
    else:
        subs.update(r)
    subs.update(enum_crtsh(args.domain))

    rows = [{"subdomain": s} for s in sorted(subs)]
    ig.write_jsonl(args.out, rows)
    if degraded:
        print("[warn] 降级: %s" % "; ".join(degraded), file=sys.stderr)
    print("[ok] %s 子域枚举完成：%d 个 → %s" % (args.domain, len(rows), args.out))


if __name__ == "__main__":
    sys.exit(main())
