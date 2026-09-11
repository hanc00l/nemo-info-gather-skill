#!/usr/bin/env python3
"""资产媒体直传（icon 原图 / 截图缩略图 / 截图原图）→ Master API。

设计（docs/asset-media-geo-plan.md §3/§4）：
  - 二进制不走 MCP/LLM（token 成本），脚本经 MASTER_ADDR 直连 Master multipart 上传；
  - 必须在 save_asset 之后执行（媒体按 identity_key 落行，行不存在 Master 返回 404 跳过）；
  - 同机优化：媒体文件位于 PROJECT_WORKSPACE_DIR 下时先传 local_rel（Master 本地读取），
    Master 不可见（跨机）返回 404 → 自动降级 multipart 重传，无需预先探测。

用法：
  python3 upload_media.py --input assets_final.jsonl [--media-root DIR]
环境：MASTER_ADDR（必填）、PROJECT_ID（必填）、PROJECT_WORKSPACE_DIR（可选，同机优化）
"""
import argparse
import os
import sys

import igcommon as ig

# 媒体字段 → 上传 kind
MEDIA_FIELDS = (("icon_path", "icon"), ("thumb_path", "thumb"), ("screenshot_path", "screenshot"))


def authority_of(row):
    """与 save_asset 规范化一致的 identity_key = host[:port]。"""
    host = str(row.get("host") or "").strip()
    port = int(row.get("port") or 0)
    if not host:
        return ""
    return "%s:%d" % (host, port) if port > 0 else host


def local_rel_of(path, workspace):
    """文件在 workspace 内 → 相对 workspace 的路径（供 Master 本地读取）；否则 None。"""
    if not workspace:
        return None
    try:
        abs_file = os.path.realpath(path)
        abs_ws = os.path.realpath(workspace)
    except OSError:
        return None
    if abs_file == abs_ws or not abs_file.startswith(abs_ws + os.sep):
        return None
    return os.path.relpath(abs_file, abs_ws).replace(os.sep, "/")


def upload_one(url, identity_key, kind, fpath, workspace):
    """单文件上传：同机 local_rel 优先，404 降级 multipart。返回 (ok, via, err)。"""
    local_rel = local_rel_of(fpath, workspace)
    if local_rel:
        status, body = ig.http_post_form(url, {
            "identity_key": identity_key, "kind": kind, "local_rel": local_rel,
        })
        if status == 200:
            return True, "local", ""
        if status != 404:
            return False, "local", "%d %s" % (status, body[:200])
        # 404：Master 侧文件不可见（跨机部署）→ 降级 multipart
    status, body = ig.http_post_multipart(url, {
        "identity_key": identity_key, "kind": kind,
    }, "file", fpath)
    if status == 200:
        return True, "http", ""
    return False, "http", "%d %s" % (status, body[:200])


def main():
    ap = argparse.ArgumentParser(description="资产媒体直传 Master（icon/thumb/screenshot）")
    ap.add_argument("--input", required=True, help="资产清单 JSONL（含媒体路径字段）")
    ap.add_argument("--media-root", default="",
                    help="媒体相对路径的根目录（缺省 = input 上两级，即 shared/info-gather）")
    args = ap.parse_args()

    master = os.environ.get("MASTER_ADDR", "").rstrip("/")
    project = os.environ.get("PROJECT_ID", "")
    if not master or not project:
        ig.fail("环境变量 MASTER_ADDR / PROJECT_ID 未配置，媒体上传跳过", 0)
    workspace = os.environ.get("PROJECT_WORKSPACE_DIR", "")
    media_root = args.media_root or os.path.dirname(os.path.dirname(
        os.path.abspath(args.input)))
    url = "%s/api/v1/projects/%s/assets/media" % (master, project)

    rows = ig.read_jsonl(args.input)
    ok = skipped = failed = 0
    for row in rows:
        authority = authority_of(row)
        if not authority:
            continue
        for field, kind in MEDIA_FIELDS:
            rel = row.get(field) or ""
            if not rel:
                continue
            fpath = os.path.join(media_root, rel)
            if not os.path.isfile(fpath):
                print("[warn] 媒体文件缺失 %s（%s）" % (rel, authority), file=sys.stderr)
                skipped += 1
                continue
            success, via, err = upload_one(url, authority, kind, fpath, workspace)
            if success:
                ok += 1
            else:
                failed += 1
                print("[warn] 媒体上传失败 %s kind=%s %s: %s" % (authority, kind, via, err),
                      file=sys.stderr)
    print("[ok] 媒体上传完成：成功 %d，缺文件 %d，失败 %d" % (ok, skipped, failed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
