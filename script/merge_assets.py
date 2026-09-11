#!/usr/bin/env python3
"""汇总各阶段 JSONL 产物 → 规范化资产清单（authority=host[:port] 去重合并）。

用法：
  python3 merge_assets.py --input-dir shared/info-gather --out assets_final.jsonl [--shard-size 500]

扫描 input-dir 下 target/online/resolve/portscan/fingerprint/vulnscan 子目录的
全部 .jsonl，按 authority 合并为 save_asset 兼容的资产记录。
--shard-size > 0 时额外输出分片文件 assets_final.part_001.jsonl …（供 report 阶段
分批 save_asset 提交，避免一次性读入超大清单）。
"""
import argparse
import glob
import os
import sys

import igcommon as ig


def norm_host(host):
    """归一化 host：剥 scheme/path，拆内嵌 :port（返回 (host, port或0)）。
    online 等来源的 host 常带 https:// 前缀或 host:port 后缀，不归一会导致
    同一 authority 分裂成多条资产（t687b5437 实证：385 行中 96 带 scheme）。"""
    h = str(host).strip()
    for p in ("https://", "http://"):
        if h.lower().startswith(p):
            h = h[len(p):]
            break
    h = h.split("/")[0].rstrip("/")
    port = 0
    if h.count(":") == 1:
        base, _, p = h.partition(":")
        if p.isdigit() and 0 < int(p) <= 65535:
            return base, int(p)
    return h, port


def merge(assets, host, port, **fields):
    """按 authority 合并资产字段（新值非空才覆盖）。"""
    host, embedded = norm_host(host)
    if not port and embedded:
        port = embedded
    key = "%s:%d" % (host, port) if port else host
    a = assets.setdefault(key, {"host": host, "port": port, "ips": [], "apps": [], "_loc": {}})
    for k, v in fields.items():
        if v in (None, "", [], 0, False):
            continue
        if k == "ips":
            for ip in v:
                if ip and ip not in a["ips"]:
                    a["ips"].append(ip)
        elif k == "ip_loc":
            # {ip: location}：登记 IP 并记录首个非空归属地（在线接口来源）
            for ip, loc in v.items():
                if not ip:
                    continue
                if ip not in a["ips"]:
                    a["ips"].append(ip)
                if loc and ip not in a["_loc"]:
                    a["_loc"][ip] = loc
        elif k == "apps":
            for app in v:
                if app and app not in a["apps"]:
                    a["apps"].append(app)
        else:
            a[k] = v
    return a


def finalize(rows):
    """输出前收尾：_loc 映射 → locations 平行数组（与 ips 等长，未知为空串）。
    IP 型 host 兜底入 ips（host 本身就是 IP 时无 DNS 解析阶段，ips 会为空，
    导致 geo_resolve 归属地查询跳过——td039399c 实证 Agent 需手工补 ips 重跑）。"""
    out = []
    for a in rows:
        loc_map = a.pop("_loc", {})
        ips = a.get("ips") or []
        host = a.get("host") or ""
        if ig.is_ip(host) and host not in ips:
            ips.append(host)
            a["ips"] = ips
        if ips:
            a["locations"] = [loc_map.get(ip, "") for ip in ips]
        out.append(a)
    return out


def main():
    ap = argparse.ArgumentParser(description="合并各阶段产物为规范化资产清单")
    ap.add_argument("--input-dir", required=True, help="shared/info-gather 目录")
    ap.add_argument("--out", required=True, help="输出 assets_final.jsonl")
    ap.add_argument("--shard-size", type=int, default=0,
                    help="分片大小（>0 时输出 assets_final.part_NNN.jsonl 分片）")
    args = ap.parse_args()

    assets = {}
    vulns = []

    # target：目标本体（domain/ip 各建行）
    for t in ig.read_jsonl(os.path.join(args.input_dir, "target", "targets.jsonl")):
        v, ty = t.get("value", ""), t.get("type", "")
        if ty in ("ip", "domain"):
            # value 可能为 host:port（target 阶段显式端口入库），分类前剥离端口
            hv, _ = norm_host(v)
            merge(assets, v, 0,
                  asset_kind="ip" if ty == "ip" else "domain",
                  category="ipv4" if ig.is_ip(hv) else "domain")

    # online：在线平台资产（host+port 级，location 为平台返回的归属地）
    for row in ig.read_jsonl_dir(args.input_dir, "online"):
        host = row.get("host") or row.get("ip", "")
        host, embedded = norm_host(host)
        port = int(row.get("port") or 0) or embedded
        if host:
            # asset_kind：有端口=port（fingerprint 命中后升级 web）；无端口按域名层级
            if port:
                kind = "port"
            elif ig.is_ip(host):
                kind = "ip"
            else:
                kind = "subdomain" if host.count(".") > 1 else "domain"
            merge(assets, host, port, service=row.get("service", ""),
                  server=row.get("server", ""), title=row.get("title", ""),
                  ip_loc={row["ip"]: row.get("location", "")} if row.get("ip") else {},
                  asset_kind=kind,
                  category="ipv4" if ig.is_ip(host) else "domain")

    # resolve：域名解析（ips/cname/cdn）
    for row in ig.read_jsonl_dir(args.input_dir, "resolve"):
        host = row.get("host", "")
        if host:
            merge(assets, host, 0, ips=row.get("ips") or [],
                  cname=row.get("cname", ""),
                  is_cdn=row.get("is_cdn", False), is_cloud=row.get("is_cloud", False),
                  asset_kind="subdomain" if host.count(".") > 1 else "domain",
                  category="domain")

    # portscan：开放端口
    for row in ig.read_jsonl_dir(args.input_dir, "portscan"):
        host, port = row.get("host", ""), int(row.get("port") or 0)
        if host and port:
            merge(assets, host, port, service=row.get("service", ""),
                  banner=row.get("banner", ""),
                  asset_kind="port", category="ipv4" if ig.is_ip(host) else "domain")

    # fingerprint：Web 指纹
    for row in ig.read_jsonl_dir(args.input_dir, "fingerprint"):
        host, port = row.get("host", ""), int(row.get("port") or 0)
        if not host:
            continue
        protocol = row.get("protocol", "")
        if protocol in ("http", "https"):
            # Web 端口：深度指纹全量透传（含响应头/favicon/证书/媒体文件路径）
            merge(assets, host, port, http_status=row.get("http_status", ""),
                  title=row.get("title", ""), server=row.get("server", ""),
                  apps=row.get("apps") or [], cname=row.get("cname", ""),
                  cert=row.get("cert", ""),
                  service=protocol,
                  http_headers=row.get("http_headers", ""),
                  icon_hash=str(row.get("icon_hash") or ""),
                  icon_path=row.get("icon_path", ""),
                  icon_mime=row.get("icon_mime", ""),
                  screenshot_path=row.get("screenshot_path", ""),
                  thumb_path=row.get("thumb_path", ""),
                  asset_kind="web")
        else:
            # 非 Web 端口（nerva 协议识别）：协议+banner，不按 web 建行
            # （tb9041a1a 实证：octra:22 ssh 曾被误标 web，Agent 手工修正）
            merge(assets, host, port, service=protocol,
                  banner=row.get("banner", ""),
                  asset_kind="port",
                  category="ipv4" if ig.is_ip(host) else "domain")

    # vulnscan：命中单独输出（不入资产，由 report 阶段写 Fact）
    for row in ig.read_jsonl_dir(args.input_dir, "vulnscan"):
        if row.get("template_id"):
            vulns.append(row)

    rows = finalize(list(assets.values()))
    ig.write_jsonl(args.out, rows)
    if vulns:
        vuln_out = os.path.join(os.path.dirname(os.path.abspath(args.out)), "vulns_final.jsonl")
        ig.write_jsonl(vuln_out, vulns)
    shards = 0
    if args.shard_size > 0:
        base = os.path.splitext(os.path.abspath(args.out))[0]
        # 清理旧分片（上一轮可能更多分片，残留会导致重复入库）
        for old in glob.glob(base + ".part_*.jsonl"):
            os.unlink(old)
        for i in range(0, len(rows), args.shard_size):
            part = "%s.part_%03d.jsonl" % (base, i // args.shard_size + 1)
            ig.write_jsonl(part, rows[i:i + args.shard_size])
            shards += 1
    print("[ok] 合并完成：%d 资产，%d 漏洞命中，%d 分片 → %s"
          % (len(rows), len(vulns), shards, args.out))


if __name__ == "__main__":
    sys.exit(main())
