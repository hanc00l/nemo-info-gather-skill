#!/usr/bin/env python3
"""漏洞扫描编排：poc_map 指纹驱动，仅扫命中的 POC，禁止全范围模板扫描。

参考 nemo_go pkg/core/pocmap.go：指纹（app/server/protocol）与 poc_map 条目
小写 contains 匹配，命中后仅用对应 nuclei 模板扫描该目标；指纹未命中 POC
的目标跳过（done 文件记录 skipped），不提供全模板目录扫描入口。

用法：
  python3 vuln_scan.py --input fingerprint.jsonl --bin-dir {BASE}/bin \
      --data-dir {BASE}/data --out OUT.jsonl

输入：--input 为 fingerprint 阶段产物（JSONL 文件或目录，目录读取全部 .jsonl）。
行格式：{"host","port","protocol","server","apps":[],...}
输出 JSONL：{"template_id","severity","name","target","matched_at","matched_fingerprint"}
断点续跑：已扫目标记录在 OUT.done（JSONL {"target": ...}），重跑自动跳过。
退出码：0 完成；2 参数错误；3 nuclei/poc_map 缺失。
"""
import argparse
import json
import os
import subprocess
import sys

import igcommon as ig

# poc_map 中 source 到模板根目录名的映射（相对 --templates-root 布局）
SOURCE_DIRS = {
    "nuclei-template": "nuclei-templates",
    "some_nuclei_templates": "some_nuclei_templates",
    "private_nuclei_templates": "private_nuclei_templates",
}

# 单目标 nuclei 超时上限（秒）；超出记 timeout 跳过
PER_TARGET_TIMEOUT = 600

# 单目标命中 POC 模板数上限（指纹过泛时截断，按路径序取前 N 个）
MAX_POC_PER_TARGET = 50


def load_poc_map(data_dir):
    """加载 poc_map（nemo_go web_poc_map_v2.json 格式：Name/Fingerprint/Poc）。"""
    path = os.path.join(data_dir, "web_poc_map_v2.json")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def match_pocs(tags, poc_map):
    """指纹标签匹配 POC 模板路径列表（对齐 nemo_go matchSingle：小写 contains）。"""
    matched = set()
    hit_by = set()
    for tag in tags:
        t = tag.lower()
        if not t:
            continue
        for entry in poc_map:
            for fp in entry.get("Fingerprint", []):
                if fp.lower() in t:
                    for poc in entry.get("Poc", []):
                        root = SOURCE_DIRS.get(poc.get("Source", ""))
                        for p in poc.get("Path", []):
                            if root:
                                matched.add(os.path.join(root, p))
                    hit_by.add(fp.lower())
                    break
    return sorted(matched), sorted(hit_by)


def parse_hit(line, matched_by):
    """解析 nuclei -jsonl 输出行为标准命中记录。"""
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        return None
    info = r.get("info") or {}
    return {
        "template_id": r.get("template-id", ""),
        "severity": info.get("severity", ""),
        "name": info.get("name", ""),
        "target": r.get("host", ""),
        "matched_at": r.get("matched-at", ""),
        "matched_fingerprint": ",".join(matched_by),
    }


def main():
    ap = argparse.ArgumentParser(description="漏洞扫描（poc_map 指纹驱动，仅扫命中 POC）")
    ap.add_argument("--input", required=True, help="fingerprint 阶段产物 JSONL")
    ap.add_argument("--bin-dir", default="/opt/tools/info-gather/bin")
    ap.add_argument("--data-dir", default="/opt/tools/info-gather/data")
    ap.add_argument("--out", required=True)
    ap.add_argument("--rate", type=int, default=50, help="nuclei 限速（请求/秒）")
    ap.add_argument("--templates-root", default="",
                    help="模板库父目录（含 nuclei-templates 等 source 目录；"
                         "缺省 $KB_DIR 或 /opt/kb）")
    args = ap.parse_args()

    exe = os.path.join(args.bin_dir, "nuclei")
    if not os.path.isfile(exe):
        ig.fail("nuclei 缺失：%s" % exe, 3)
    poc_map = load_poc_map(args.data_dir)
    if poc_map is None:
        ig.fail("poc_map 缺失：%s（指纹驱动扫描不可用，禁止全范围扫描降级）"
                % os.path.join(args.data_dir, "web_poc_map_v2.json"), 3)

    # 模板库根：参数 > KB_DIR 环境变量 > /opt/kb
    templates_root = args.templates_root or os.environ.get("KB_DIR", "/opt/kb")

    if not os.path.isfile(args.out):
        ig.write_jsonl(args.out, [])
    done_path = args.out + ".done"
    done = {r.get("target") for r in ig.read_jsonl(done_path) if r.get("target")}

    # --input 支持目录：汇聚目录下全部 JSONL（fingerprint 产物目录直接消费）
    if os.path.isdir(args.input):
        input_rows = []
        for name in sorted(os.listdir(args.input)):
            if name.endswith(".jsonl"):
                input_rows.extend(ig.read_jsonl(os.path.join(args.input, name)))
    else:
        input_rows = ig.read_jsonl(args.input)

    hits = 0
    scanned = 0
    skipped = 0
    missing_tpl = 0
    seen_targets = set()
    for row in input_rows:
        host = ig.normalize_host(row.get("host", ""))
        port = row.get("port", 0)
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if not host or port <= 0:
            continue
        # 仅 Web 资产进入 POC 扫描（poc_map 全部面向 http 模板）
        protocol = str(row.get("protocol", "")).lower()
        if protocol and protocol not in ("http", "https"):
            continue
        scheme = "https" if (protocol == "https" or port == 443 or row.get("tls")) else "http"
        url = "%s://%s:%d" % (scheme, host, port)
        if url in done or url in seen_targets:
            continue
        seen_targets.add(url)

        # 指纹归集：apps ∪ server ∪ title ∪ banner ∪ protocol
        # - title 常含指纹（httpx 未检出 apps 时 title="Apache Tomcat/8.5.19"
        #   可被 poc_map Fingerprint "tomcat" contains 命中）；
        # - banner 来自 nerva（如 "nginx/1.18.0" 可匹配 "nginx"）；
        # - protocol 提供兜底（当前 poc_map 无 "http" 指纹，预留扩展）。
        tags = list(row.get("apps") or [])
        if row.get("server"):
            tags.append(row["server"])
        if row.get("title"):
            tags.append(row["title"])
        if row.get("banner"):
            tags.append(row["banner"])
        if protocol:
            tags.append(protocol)
        pocs, hit_by = match_pocs(tags, poc_map)
        if not pocs:
            skipped += 1
            ig.append_jsonl(done_path, {"target": url, "skipped": "no_poc_matched"})
            continue
        # 模板路径校验：只保留实际存在的模板
        tpl_paths = []
        for rel in pocs:
            full = os.path.join(templates_root, rel)
            if os.path.isfile(full):
                tpl_paths.append(full)
            else:
                missing_tpl += 1
        if not tpl_paths:
            skipped += 1
            ig.append_jsonl(done_path, {"target": url, "skipped": "poc_template_missing"})
            continue
        tpl_paths = tpl_paths[:MAX_POC_PER_TARGET]

        try:
            out = subprocess.run(
                [exe, "-u", url, "-jsonl", "-rate-limit", str(args.rate), "-silent",
                 "-t", ",".join(tpl_paths)],
                capture_output=True, text=True, timeout=PER_TARGET_TIMEOUT)
            for line in out.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                hit = parse_hit(line, hit_by)
                if hit:
                    ig.append_jsonl(args.out, hit)
                    hits += 1
            ig.append_jsonl(done_path, {"target": url})
            scanned += 1
        except subprocess.TimeoutExpired:
            print("[warn] 目标扫描超时（%ds），标记跳过：%s" % (PER_TARGET_TIMEOUT, url),
                  file=sys.stderr)
            ig.append_jsonl(done_path, {"target": url, "timeout": True})

    print("[ok] 漏洞扫描完成：%d 目标命中 POC 并扫描，%d 目标无匹配跳过，%d 条命中；"
          "缺失模板引用 %d 条 → %s" % (scanned, skipped, hits, missing_tpl, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
