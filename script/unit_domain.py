#!/usr/bin/env python3
"""单位名称 → 域名反查（ICP 备案类接口，对齐 nemo_go chinaz/beianx 模式）。

用法：
  python3 unit_domain.py --unit "某某科技有限公司" --config {BASE}/config.yaml --out OUT.jsonl

输出 JSONL：{"domain":"...","source":"chinaz|beianx"}
key 未配置时退出码 3（不可用），由调用方降级跳过。
"""
import argparse
import json
import sys
import urllib.parse

import igcommon as ig


def query_chinaz(unit, key):
    """站长之家 ICP 反查。"""
    if not key:
        ig.fail("icp key 未配置（config.yaml: icp.key）", 3)
    url = "https://apidata.chinaz.com/CallAPI/ICPReverse?key=%s&keyword=%s" % (
        key, urllib.parse.quote(unit))
    _, body = ig.http_get(url, timeout=30)
    data = json.loads(body)
    rows = []
    for item in data.get("Result") or []:
        domain = (item.get("Domain") or "").strip().lower()
        if domain:
            rows.append({"domain": domain, "source": "chinaz"})
    return rows


def query_beianx(unit, key):
    """beianx.cn ICP 反查（备用源）。"""
    if not key:
        ig.fail("beianx key 未配置（config.yaml: beianx.key）", 3)
    url = "https://api.beianx.cn/api/icp/reverse?key=%s&keyword=%s" % (
        key, urllib.parse.quote(unit))
    _, body = ig.http_get(url, timeout=30)
    data = json.loads(body)
    rows = []
    for item in data.get("data") or []:
        domain = (item.get("domain") or "").strip().lower()
        if domain:
            rows.append({"domain": domain, "source": "beianx"})
    return rows


def main():
    ap = argparse.ArgumentParser(description="单位名称 → 域名反查（ICP 备案类）")
    ap.add_argument("--unit", required=True, help="单位/组织名称")
    ap.add_argument("--config", default="", help="config.yaml 路径")
    ap.add_argument("--out", required=True, help="输出 JSONL 路径")
    args = ap.parse_args()

    cfg = ig.load_config(args.config)
    rows, errors = [], []
    for source, fn, key in (
        ("chinaz", query_chinaz, (cfg.get("icp") or {}).get("key", "")),
        ("beianx", query_beianx, (cfg.get("beianx") or {}).get("key", "")),
    ):
        try:
            rows.extend(fn(args.unit, key))
        except SystemExit as e:
            if e.code != 3:  # 3=未配置，跳过；其余视为失败
                errors.append(source)
        except Exception as e:  # 网络/解析异常不阻断其他源
            errors.append("%s: %s" % (source, e))

    # 域名去重
    seen, uniq = set(), []
    for r in rows:
        if r["domain"] not in seen:
            seen.add(r["domain"])
            uniq.append(r)
    ig.write_jsonl(args.out, uniq)
    if errors:
        print("[warn] 部分源失败: %s" % "; ".join(errors), file=sys.stderr)
    print("[ok] 单位反查完成：%s → %d 个域名 → %s" % (args.unit, len(uniq), args.out))


if __name__ == "__main__":
    sys.exit(main())
