#!/usr/bin/env python3
"""info-gather 脚本公共库（仅 python3 标准库）。

与平台解耦：所有脚本输入为命令行参数/文件，输出为 JSONL（每行一个 JSON 对象）。
目录约定见 skills/info-gather/SKILL.md。
"""
import json
import os
import sys
import urllib.parse
import urllib.request
import urllib.error


def read_jsonl(path):
    """读取 JSONL 文件，解析失败行跳过。"""
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def read_jsonl_dir(base, subdir):
    """读取目录下全部 .jsonl 文件并合并。"""
    rows = []
    d = os.path.join(base, subdir)
    if not os.path.isdir(d):
        return rows
    for name in sorted(os.listdir(d)):
        if name.endswith(".jsonl"):
            rows.extend(read_jsonl(os.path.join(d, name)))
    return rows


def write_jsonl(path, rows):
    """写 JSONL 文件（自动建父目录）。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def append_jsonl(path, row):
    """追加一行 JSONL。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_config(path):
    """加载 YAML 配置（仅支持一层嵌套的 key: value 简化解析，避免依赖 PyYAML）。"""
    cfg = {}
    if not path or not os.path.isfile(path):
        return cfg
    section = ""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            raw = line.rstrip()
            if not raw or raw.lstrip().startswith("#"):
                continue
            if not raw.startswith((" ", "\t")) and raw.endswith(":"):
                section = raw[:-1].strip()
                cfg.setdefault(section, {})
                continue
            if ":" in raw:
                k, _, v = raw.partition(":")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if section and isinstance(cfg.get(section), dict):
                    cfg[section][k] = v
                else:
                    cfg[k] = v
    return cfg


def http_get(url, headers=None, timeout=15):
    """HTTP GET，返回 (status, body_text)。网络错误抛出异常由调用方处理。"""
    req = urllib.request.Request(url, headers=headers or {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


def http_post_json(url, payload, headers=None, timeout=15):
    """HTTP POST JSON。"""
    data = json.dumps(payload).encode("utf-8")
    h = {"Content-Type": "application/json",
         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


def http_post_form(url, fields, timeout=30):
    """application/x-www-form-urlencoded POST，返回 (status, body)。HTTP 错误码不抛异常。"""
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def http_post_multipart(url, fields, file_field, file_path, timeout=60):
    """multipart/form-data POST（stdlib 手工 boundary），返回 (status, body)。
    HTTP 错误码不抛异常（调用方按状态码处理降级）。"""
    import uuid
    boundary = "----ig" + uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                      % (boundary, k, v)).encode("utf-8"))
    with open(file_path, "rb") as f:
        data = f.read()
    fname = os.path.basename(file_path)
    parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
                  "Content-Type: application/octet-stream\r\n\r\n"
                  % (boundary, file_field, fname)).encode("utf-8"))
    parts.append(data)
    parts.append(("\r\n--%s--\r\n" % boundary).encode("utf-8"))
    req = urllib.request.Request(url, data=b"".join(parts), headers={
        "Content-Type": "multipart/form-data; boundary=" + boundary,
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def is_ip(s):
    """判断字符串是否为 IP 地址（v4/v6）。"""
    if not s:
        return False
    if s.count(".") == 3:
        parts = s.split(".")
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    return ":" in s


def normalize_host(v):
    """规范化 host 字段：剥 URL scheme 与路径（https://a.b.com/x → a.b.com）。

    在线资产平台（fofa 等）对 TLS 条目的 host 返回 URL 形式；不去噪会导致
    IP 误判、域名归类错误与跨源去重失效（"https://x.com" 与 "x.com" 无法去重）。

    同时剥离端口部分（api.example.com:8080 → api.example.com）：DNS 解析与
    域名归类均与端口无关，host:port 混用会产生大量伪主机（tf3ebc535 复盘）。
    IPv6 字面量（含 [::1]:8080 形式）保持完整。
    """
    if not v:
        return ""
    if "://" in v:
        v = v.split("://", 1)[1]
    for sep in "/?#":
        if sep in v:
            v = v.split(sep, 1)[0]
    v = v.strip()
    if v.startswith("[") and "]" in v:
        return v[1:v.index("]")]  # IPv6 字面量，去方括号与端口
    if v.count(":") == 1:
        host, _, port = v.rpartition(":")
        if host and port.isdigit():
            return host  # host:port → host
    return v


def fail(msg, code=1):
    """错误输出并退出。"""
    print(f"[error] {msg}", file=sys.stderr)
    sys.exit(code)
