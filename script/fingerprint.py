#!/usr/bin/env python3
"""服务/应用指纹识别编排：nerva 协议识别 + httpx Web 深度指纹（两段式）。

策略（对齐 nemo_go fingerprint 编排思路，fingerprintx 替换为 nerva）：
  阶段1：nerva 对全部开放端口做协议识别（--scan-depth fast），
         输出 host/port/protocol/tls/banner；
  阶段2：从 nerva 结果中筛出 protocol 为 http/https 的端口交 httpx
         深度识别（title/tech/server/cname）；其余端口仅保留 nerva 结果，
         不再对非 Web 端口发 HTTP 探测。

用法：
  python3 fingerprint.py --input ports.jsonl --bin-dir {BASE}/bin --out OUT.jsonl

输入：--input 可为单个 JSONL 文件或目录（目录读取其中全部 .jsonl，
用于直接消费 shared/info-gather/portscan/ 产物；.done 标记文件自动跳过）。
行格式：{"host":"...","port":80}（portscan 产物）
输出 JSONL：{"host","port","protocol","tls","banner",
             "http_status","title","server","apps":[],"cname","cert",
             "icon_path","icon_mime","screenshot_path","thumb_path"}
（后 10 项仅 Web 端口；cert 为 TLS 证书摘要，仅 https 端口非空；
  icon/screenshot/thumb 为媒体文件路径，相对 shared/info-gather 根，
  截图原图由 httpx -screenshot 产出，thumb 为 120×75 缩略图（Pillow，
  保持宽度只裁高度、高度不足允许拉伸），详见 docs/asset-media-geo-plan.md）
"""
import argparse
import concurrent.futures
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

import igcommon as ig

# nerva 默认限速：全局 50 次/秒、单主机 4 并发（指纹识别属探测流量，避免触发防护）
NERVA_RATE = 50
NERVA_HOST_CONN = 4

# favicon 抓取约束（图标大小不设上限；首页 HTML 仅为解析 icon link，限 512KB）
HTML_MAX_BYTES = 512 * 1024
MEDIA_FETCH_TIMEOUT = 5
# 缩略图固定尺寸（120×75）：裁剪高 = W × 75/120，只裁高度保留宽度，不足则拉伸
THUMB_W, THUMB_H = 120, 75

# HTTPS 目标自签证书常见，favicon 抓取不校验证书
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def nerva_scan(targets, exe, rate, host_conn):
    """nerva 批量协议识别，返回 {(host,port): row}。"""
    results = {}
    if not targets:
        return results
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets) + "\n")
        target_file = f.name
    try:
        out = subprocess.run(
            [exe, "--json", "-l", target_file, "--scan-depth", "fast",
             "-R", str(rate), "-H", str(host_conn)],
            capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        print("[warn] nerva 批次超时，解析已产出部分", file=sys.stderr)
        return results
    finally:
        os.unlink(target_file)
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = ig.normalize_host(r.get("ip") or r.get("host") or "")
        port = r.get("port", 0)
        if not host or not port:
            continue
        meta = r.get("metadata") or {}
        results[(host, int(port))] = {
            "host": host, "port": int(port),
            "protocol": r.get("protocol", ""),
            "tls": bool(r.get("tls", False)),
            "banner": str(meta.get("banner", "") or "").strip(),
        }
    return results


def httpx_scan(targets, exe, shots_dir=""):
    """httpx Web 深度识别，返回 {(host,port): row}。

    -irh 输出响应头（header 对象）、-favicon 输出 favicon mmh3 哈希，
    供资产库 http_headers/icon_hash 字段与前端详情展示。
    shots_dir 非空时追加 -screenshot -srd 截图（-system-chrome 在支持时使用），
    原始截图路径暂存 row["_shot"]，由调用方归档。"""
    results = {}
    if not targets:
        return results
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets) + "\n")
        target_file = f.name
    cmd = [exe, "-l", target_file, "-json", "-status-code", "-title",
           "-tech-detect", "-server", "-cname", "-tls-grab", "-irh",
           "-favicon", "-silent"]
    if shots_dir:
        os.makedirs(shots_dir, exist_ok=True)
        cmd += ["-screenshot", "-srd", shots_dir]
        if httpx_has_flag(exe, "-system-chrome"):
            cmd.append("-system-chrome")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        print("[warn] httpx 批次超时，解析已产出部分", file=sys.stderr)
        return results
    finally:
        os.unlink(target_file)
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = ig.normalize_host(r.get("host", ""))
        port = r.get("port", 0)
        if not host:
            continue
        results[(host, int(port) if str(port).isdigit() else 0)] = {
            "http_status": str(r.get("status_code", "")),
            "title": r.get("title", ""),
            "server": r.get("webserver", ""),
            "apps": [t.lower() for t in r.get("tech", [])],
            "cname": (r.get("cnames") or [""])[0] if r.get("cnames") else "",
            "cert": cert_summary(r.get("tls")),
            "http_headers": headers_json(r.get("header")),
            "icon_hash": str(r.get("favicon")) if r.get("favicon") is not None else "",
            "_shot": r.get("screenshot_path") or r.get("screenshot_path_rel") or "",
        }
    return results


def httpx_has_flag(exe, flag):
    """探测 httpx 是否支持某 flag（-system-chrome 为 v1.3.3+ 新增，旧版传参会报错）。"""
    try:
        out = subprocess.run([exe, "-h"], capture_output=True, text=True, timeout=30)
        return flag in (out.stdout + out.stderr)
    except (OSError, subprocess.TimeoutExpired):
        return False


def safe_name(host, port):
    """host+port → 文件安全名。"""
    return "%s_%d" % (re.sub(r"[^A-Za-z0-9_.-]", "_", host), port)


def sniff_icon_mime(data):
    """魔数嗅探 favicon MIME，无法识别返回空串。"""
    if data[:4] == b"\x00\x00\x01\x00":
        return "image/x-icon"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    head = data[:256].lstrip()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head[:512]):
        return "image/svg+xml"
    return ""


_MIME_EXT = {"image/x-icon": ".ico", "image/png": ".png", "image/jpeg": ".jpg",
             "image/gif": ".gif", "image/webp": ".webp", "image/svg+xml": ".svg"}


def fetch_bytes(url, limit):
    """抓取 URL 内容（不校验 TLS 证书），失败返回 None。limit<=0 不限大小。"""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    })
    try:
        with urllib.request.urlopen(req, timeout=MEDIA_FETCH_TIMEOUT, context=_SSL_CTX) as resp:
            data = resp.read(limit + 1) if limit > 0 else resp.read()
    except Exception:
        return None
    if not data or (limit > 0 and len(data) > limit):
        return None
    return data


_ICON_LINK_RE = re.compile(
    r'<link[^>]+rel=["\'][^"\']*(?:icon|apple-touch-icon)[^"\']*["\'][^>]*>', re.I)
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)


def fetch_favicon(scheme, host, port, dst_prefix):
    """抓取 favicon：/favicon.ico → HTML <link rel="icon"> 回退。
    成功写入 dst_prefix+扩展名，返回 (文件路径, MIME)；失败返回 ("", "")。"""
    default_port = 443 if scheme == "https" else 80
    authority = host if port == default_port else "%s:%d" % (host, port)
    base = "%s://%s" % (scheme, authority)
    candidates = [base + "/favicon.ico"]
    # 回退：解析首页 HTML 中的 icon link（相对路径拼接）
    html = fetch_bytes(base + "/", HTML_MAX_BYTES)
    if html:
        try:
            text = html.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        for m in _ICON_LINK_RE.finditer(text):
            href = _HREF_RE.search(m.group(0))
            if href:
                candidates.append(urllib.parse.urljoin(base + "/", href.group(1)))
                break
    for url in candidates:
        data = fetch_bytes(url, 0)  # icon 大小不设限
        if not data:
            continue
        mime = sniff_icon_mime(data)
        if not mime:
            continue
        path = dst_prefix + _MIME_EXT[mime]
        with open(path, "wb") as f:
            f.write(data)
        return path, mime
    return "", ""


def load_pil():
    """Pillow 导入回退链：系统 PIL → script/vendor（离线 vendored wheel）。
    均不可用返回 None（缩略图整体跳过，原图不受影响）。"""
    try:
        from PIL import Image
        return Image
    except ImportError:
        pass
    vendor = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
    if os.path.isdir(vendor) and vendor not in sys.path:
        sys.path.insert(0, vendor)
    try:
        from PIL import Image
        return Image
    except ImportError:
        return None


def make_thumb(Image, src, dst):
    """120×75 缩略图：保持原宽度只裁高度（保留顶部，裁剪高 = W×75/120）；
    高度不足裁剪高时不补齐，直接整体拉伸至 120×75（允许变形）。"""
    try:
        img = Image.open(src)
        img.load()
        w, h = img.size
        if w <= 0 or h <= 0:
            return False
        crop_h = min(h, w * THUMB_H // THUMB_W)
        if 0 < crop_h < h:
            img = img.crop((0, 0, w, crop_h))
        img = img.resize((THUMB_W, THUMB_H), Image.LANCZOS)
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        img.save(dst, "PNG", optimize=True)
        return True
    except Exception as e:
        print("[warn] 缩略图生成失败 %s: %s" % (src, e), file=sys.stderr)
        return False


def resolve_shot(shots_dir, raw):
    """httpx 输出的截图路径 → 实际文件（兼容绝对/相对/仅文件名三种形态）。"""
    if not raw:
        return ""
    for cand in (raw, os.path.join(shots_dir, raw), os.path.join(shots_dir, os.path.basename(raw))):
        if cand and os.path.isfile(cand):
            return cand
    return ""


def enrich_media(rows, media_dir, shared_root, shots_dir):
    """Web 资产媒体采集：favicon 抓取 + 截图归档 + 120×75 缩略图（线程池并发）。
    结果写回 row 的 icon_path/icon_mime/screenshot_path/thumb_path（相对 shared_root）。"""
    web = [r for r in rows if r.get("protocol") in ("http", "https")]
    if not web:
        return
    icons_dir = os.path.join(media_dir, "icons")
    shots_out = os.path.join(media_dir, "screenshots")
    thumbs_dir = os.path.join(media_dir, "thumbs")
    for d in (icons_dir, shots_out, thumbs_dir):
        os.makedirs(d, exist_ok=True)
    Image = load_pil()
    if Image is None:
        print("[warn] Pillow 不可用（系统与 script/vendor 均无），缩略图跳过", file=sys.stderr)

    def rel(p):
        return os.path.relpath(p, shared_root).replace(os.sep, "/")

    def work(row):
        host, port = row["host"], row["port"]
        name = safe_name(host, port)
        icon_file, mime = fetch_favicon(row["protocol"], host, port,
                                        os.path.join(icons_dir, name))
        if icon_file:
            row["icon_path"], row["icon_mime"] = rel(icon_file), mime
        raw_shot = row.pop("_shot", "")
        shot_src = resolve_shot(shots_dir, raw_shot) if shots_dir else ""
        if shot_src:
            shot_dst = os.path.join(shots_out, name + ".png")
            shutil.move(shot_src, shot_dst)
            row["screenshot_path"] = rel(shot_dst)
            if Image is not None:
                thumb_dst = os.path.join(thumbs_dir, name + ".png")
                if make_thumb(Image, shot_dst, thumb_dst):
                    row["thumb_path"] = rel(thumb_dst)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(work, web))


def headers_json(header):
    """httpx -irh 的 header 对象 → 紧凑 JSON 字符串（键值均为字符串，限长防爆）。"""
    if not isinstance(header, dict) or not header:
        return ""
    cleaned = {}
    for k, v in header.items():
        key = str(k).strip()
        if not key:
            continue
        cleaned[key] = str(v)[:512]
    out = json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"))
    return out[:4096]


def cert_summary(tls):
    """httpx -tls-grab 的 tls 对象 → 证书摘要字符串（CN/签发者/有效期）。

    非 TLS 端口或抓取失败返回空串，保证产物 cert 字段缺失即无证书。
    """
    if not isinstance(tls, dict) or not tls.get("probe_status"):
        return ""
    cn = tls.get("subject_cn", "")
    issuer = tls.get("issuer_cn", "")
    nb = str(tls.get("not_before", ""))[:10]
    na = str(tls.get("not_after", ""))[:10]
    if not cn:
        return ""
    parts = ["CN=%s" % cn]
    san = [s for s in (tls.get("subject_an") or []) if s and s != cn]
    if san:
        parts.append("SAN=%s" % ",".join(san))
    if issuer:
        parts.append("签发=%s" % issuer)
    if nb or na:
        parts.append("有效期 %s~%s" % (nb, na))
    return "，".join(parts)


def main():
    ap = argparse.ArgumentParser(description="指纹识别（nerva 协议识别 + httpx Web 深度识别）")
    ap.add_argument("--input", required=True)
    ap.add_argument("--bin-dir", default="/opt/tools/info-gather/bin")
    ap.add_argument("--out", required=True)
    ap.add_argument("--rate", type=int, default=NERVA_RATE, help="nerva 全局限速（次/秒）")
    ap.add_argument("--host-conn", type=int, default=NERVA_HOST_CONN, help="nerva 单主机并发")
    ap.add_argument("--no-screenshot", action="store_true",
                    help="禁用截图与媒体采集（缺省启用，需容器内 chromium）")
    args = ap.parse_args()

    nerva_exe = os.path.join(args.bin_dir, "nerva")
    if not os.path.isfile(nerva_exe):
        nerva_exe = "nerva"
    httpx_exe = os.path.join(args.bin_dir, "httpx")
    if not os.path.isfile(httpx_exe):
        ig.fail("httpx 缺失：%s" % httpx_exe, 3)

    targets = []
    seen = set()
    # --input 支持目录：汇聚目录下全部 JSONL（跨批次产物自动合并，输入侧去重）
    if os.path.isdir(args.input):
        input_rows = []
        for name in sorted(os.listdir(args.input)):
            if name.endswith(".jsonl"):
                input_rows.extend(ig.read_jsonl(os.path.join(args.input, name)))
    else:
        input_rows = ig.read_jsonl(args.input)
    for row in input_rows:
        # 规范化 host（剥 URL scheme/路径/端口）+ 输入去重
        host = ig.normalize_host(row.get("host", ""))
        port = row.get("port", 0)
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if host and port > 0 and (host, port) not in seen:
            seen.add((host, port))
            targets.append("%s:%d" % (host, port))
    if not targets:
        ig.write_jsonl(args.out, [])
        print("[ok] 无目标，输出空文件 → %s" % args.out)
        return 0

    # 阶段1：nerva 全端口协议识别
    nerva_rows = nerva_scan(targets, nerva_exe, args.rate, args.host_conn)
    if not nerva_rows:
        print("[warn] nerva 无结果（工具缺失或全部超时），输出空文件", file=sys.stderr)
        ig.write_jsonl(args.out, [])
        return 0

    # 阶段2：仅 http/https 协议端口交 httpx 深度识别，其余端口跳过
    web_targets = ["%s:%d" % (h, p) for (h, p), r in sorted(nerva_rows.items())
                   if r["protocol"] in ("http", "https")]

    # 媒体目录：{out 所在阶段目录}/media（截图原始落地区 + 归档目录）
    stage_dir = os.path.dirname(os.path.abspath(args.out))
    shared_root = os.path.dirname(stage_dir)
    media_dir = os.path.join(stage_dir, "media")
    shots_dir = "" if args.no_screenshot else os.path.join(media_dir, "_httpx_shots")

    httpx_rows = httpx_scan(web_targets, httpx_exe, shots_dir)

    rows = []
    for key in sorted(nerva_rows):
        row = dict(nerva_rows[key])
        if key in httpx_rows:
            row.update(httpx_rows[key])
        rows.append(row)

    # 阶段3：媒体采集（favicon + 截图归档 + 缩略图），仅 Web 资产；
    # --no-screenshot 时 shots_dir 为空，enrich_media 只抓 favicon
    enrich_media(rows, media_dir, shared_root, shots_dir)
    if shots_dir:
        # httpx 截图临时区清理（已归档的移走，残留的为失败产物）
        shutil.rmtree(shots_dir, ignore_errors=True)

    ig.write_jsonl(args.out, rows)
    print("[ok] 指纹识别完成：%d 端口（nerva），其中 Web %d 个（httpx）→ %s"
          % (len(rows), len(web_targets), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
