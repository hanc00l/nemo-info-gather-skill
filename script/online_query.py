#!/usr/bin/env python3
"""在线资产平台查询（fofa/hunter/quake）。

用法：
  python3 online_query.py --query 'domain="example.com"' --platform fofa \
      --config {BASE}/config.yaml --out OUT.jsonl [--limit 500]

输出 JSONL：{"host","ip","port","title","server","service","app":[],"platform","location"}
（location 为平台返回的归属地，fofa region / hunter province+city / quake location，
供 geo_resolve.py 跳过重复解析）
平台 key 未配置时退出码 3（不可用），由调用方降级跳过。
"""
import argparse
import base64
import json
import sys

import igcommon as ig

PLATFORMS = ("fofa", "hunter", "quake")


def query_fofa(query, key, limit):
    """fofa API：key 支持 email:key 或仅 apikey（实测仅 key 可用）。"""
    if not key:
        ig.fail("fofa key 未配置", 3)
    q64 = base64.b64encode(query.encode()).decode()
    auth = "email=%s&key=%s" % tuple(key.split(":", 1)) if ":" in key else "key=%s" % key
    url = ("https://fofa.info/api/v1/search/all?%s&qbase64=%s&size=%d"
           "&fields=host,ip,port,title,server,region" % (auth, q64, min(limit, 10000)))
    _, body = ig.http_get(url, timeout=30)
    data = json.loads(body)
    if data.get("error"):
        ig.fail("fofa 查询失败: %s" % data.get("errmsg", "unknown"), 2)
    rows = []
    for r in data.get("results", []):
        host, ip, port, title, server, region = (list(r) + [""] * 6)[:6]
        rows.append({"host": host or ip, "ip": ip, "port": int(port or 0),
                     "title": title, "server": server, "platform": "fofa",
                     "location": str(region or "").strip()[:64]})
    return rows


def query_hunter(query, key, limit):
    """hunter API。"""
    if not key:
        ig.fail("hunter key 未配置", 3)
    url = ("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=%d"
           % (key, base64.b64encode(query.encode()).decode(), min(limit, 100)))
    _, body = ig.http_get(url, timeout=30)
    data = json.loads(body)
    if data.get("code") != 200:
        ig.fail("hunter 查询失败: %s" % data.get("message", "unknown"), 2)
    rows = []
    for r in (data.get("data") or {}).get("arr") or []:
        loc = ("%s%s" % (r.get("province") or "", r.get("city") or "")).strip()
        rows.append({"host": r.get("domain") or r.get("ip", ""), "ip": r.get("ip", ""),
                     "port": int(r.get("port") or 0), "title": r.get("web_title", ""),
                     "server": r.get("server", ""), "service": r.get("protocol", ""),
                     "platform": "hunter", "location": loc[:64]})
    return rows


def query_quake(query, key, limit):
    """quake API。"""
    if not key:
        ig.fail("quake key 未配置", 3)
    _, body = ig.http_post_json(
        "https://quake.360.net/api/v3/search/quake-service",
        {"query": query, "start": 0, "size": min(limit, 500)},
        headers={"X-QuakeToken": key}, timeout=30)
    data = json.loads(body)
    if data.get("code") != 0:
        ig.fail("quake 查询失败: %s" % data.get("message", "unknown"), 2)
    rows = []
    for r in data.get("data") or []:
        svc = r.get("service") or {}
        http = svc.get("http") or {}
        gl = r.get("location") or {}
        loc = " ".join(p for p in [gl.get("country_cn") or "",
                                   (gl.get("province_cn") or "") + (gl.get("city_cn") or ""),
                                   gl.get("isp") or ""] if p).strip()
        rows.append({"host": r.get("ip", ""), "ip": r.get("ip", ""),
                     "port": int(r.get("port") or 0),
                     "title": (http.get("title") or ""), "server": (http.get("server") or ""),
                     "service": svc.get("name", ""), "platform": "quake", "location": loc[:64]})
    return rows


def main():
    ap = argparse.ArgumentParser(description="在线资产平台查询（fofa/hunter/quake）")
    ap.add_argument("--query", required=True, help="平台查询语法")
    ap.add_argument("--platform", required=True, choices=PLATFORMS)
    ap.add_argument("--config", default="", help="config.yaml 路径（含各平台 key）")
    ap.add_argument("--out", required=True, help="输出 JSONL 路径")
    ap.add_argument("--limit", type=int, default=500)
    args = ap.parse_args()

    cfg = ig.load_config(args.config)
    key = (cfg.get(args.platform) or {}).get("key", "")
    fn = {"fofa": query_fofa, "hunter": query_hunter, "quake": query_quake}[args.platform]
    rows = fn(args.query, key, args.limit)
    ig.write_jsonl(args.out, rows)
    print("[ok] %s 查询完成：%d 条 → %s" % (args.platform, len(rows), args.out))


if __name__ == "__main__":
    sys.exit(main())
