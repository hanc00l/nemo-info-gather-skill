#!/usr/bin/env python3
"""端口扫描编排：nmap 单工具执行。

用法：
  python3 port_scan.py --targets ips.jsonl --port-range top-100 \
      --rate 1000 --bin-dir {BASE}/bin --out OUT.jsonl

参数：
  --tool       仅 nmap；传入 masscan 时告警并回退 nmap（兼容旧 Intent 描述）
  --tech       -sS（默认）/ -sT / -sV
  --rate       扫描速度（默认 1000）：nmap --min-rate
  --ping       允许 Ping 主机发现（缺省 -Pn 直接扫）
  --port-range top-N（默认 top-100，nmap --top-ports 原生支持任意 N）
               或范围（1-65535、80,443,8000-9000）

nmap 固定参数（对齐 nemo_go）：-T4 -n --open --randomize-hosts --min-rate <rate>
服务识别不在本阶段：--tech -sV 之外的扫描 service 字段为空，
协议/服务识别由 fingerprint 阶段 nerva 承担。

输入 JSONL：{"ip":"..."} 或 {"host":"..."}（CIDR 由 nmap 原生支持）
输出 JSONL：{"host","port","service","banner"}

断点续跑与时间预算：
  结果按块增量追加写 OUT；已扫描主机记录在 OUT.done（JSONL {"host": ...}），
  重跑同一命令自动跳过。--max-seconds >0 时预算耗尽以退出码 4 返回（部分完成）；
  默认 0 不限时（tmux 后台执行模式，进度随时可续）。退出码 0 才算完成。
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

import igcommon as ig

# 自定义端口范围格式（nmap TCP 写法）：80,443,8000-9000
PORT_RANGE_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
TOP_PORTS_RE = re.compile(r"^top-(\d+)$")

# nmap 单次调用的主机块大小（避免单命令超时过大）
NMAP_CHUNK_SIZE = 64

# 退出码：0=全部完成，2=参数错误，4=时间预算耗尽（部分完成，进度已保存）
EXIT_PARTIAL = 4

# 输入规范化统一走 igcommon.normalize_host（剥 URL scheme/路径/端口）
normalize_host = ig.normalize_host


class Budget:
    """运行时间预算；seconds<=0 表示不限时（tmux 后台执行模式）。"""

    def __init__(self, seconds):
        self.seconds = seconds
        self.start = time.monotonic()

    def expired(self):
        return self.seconds > 0 and time.monotonic() - self.start >= self.seconds

    def elapsed(self):
        return int(time.monotonic() - self.start)


def find_exe(bin_dir, name):
    """工具查找：bin 目录优先，系统 PATH 回退。"""
    exe = os.path.join(bin_dir, name)
    return exe if os.path.isfile(exe) else name


def parse_nmap_xml(path):
    """解析 nmap XML 输出。

    用 XML 解析替代 grepable 正则：grepable 格式在主机带 PTR 记录时
    （Host: 1.2.3.4 (ptr.name)）会整行漏解析（tf3ebc535 复盘确认的工具缺陷）。
    """
    rows = []
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        return rows
    for host_el in tree.getroot().iter("host"):
        addr = ""
        for a in host_el.iter("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        if not addr:
            continue
        for port_el in host_el.iter("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            if port_el.get("protocol", "tcp") != "tcp":
                continue
            svc = port_el.find("service")
            service = svc.get("name", "") if svc is not None else ""
            banner = ""
            if svc is not None:
                banner = " ".join(p for p in (svc.get("product", ""), svc.get("version", "")) if p)
            rows.append({
                "host": addr, "port": int(port_el.get("portid", "0")),
                "service": service, "banner": banner,
            })
    return rows


def nmap_scan(targets, port_range, tech, rate, ping, bin_dir, timeout=1800):
    """nmap 扫描（固定参数 -T4 -n --open --randomize-hosts --min-rate，-oX XML 输出）。"""
    exe = find_exe(bin_dir, "nmap")
    rows = []
    top_m = TOP_PORTS_RE.match(port_range)
    for i in range(0, len(targets), NMAP_CHUNK_SIZE):
        chunk = targets[i:i + NMAP_CHUNK_SIZE]
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(chunk) + "\n")
            target_file = f.name
        out_file = target_file + ".xml"
        args = [exe, tech, "-T4", "-n", "--open", "--randomize-hosts",
                "--min-rate", str(rate), "-oX", out_file, "-iL", target_file]
        if not ping:
            args.append("-Pn")
        if top_m:
            args += ["--top-ports", top_m.group(1)]
        else:
            args += ["-p", port_range]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            if proc.returncode != 0:
                err_tail = "\n".join((proc.stderr or "").splitlines()[-3:])
                print("[warn] nmap 批次退出码 %d（%d 主机）：%s" % (proc.returncode, len(chunk), err_tail),
                      file=sys.stderr)
        except subprocess.TimeoutExpired:
            print("[warn] nmap 批次超时（%d 主机），跳过" % len(chunk), file=sys.stderr)
        rows.extend(parse_nmap_xml(out_file))
        os.unlink(target_file)
        if os.path.exists(out_file):
            os.unlink(out_file)
    return rows


def load_done(done_path):
    """读取已扫描主机集合（断点续跑依据）。"""
    return {r.get("host") for r in ig.read_jsonl(done_path) if r.get("host")}


def mark_done(done_path, hosts):
    """追加已扫描主机标记。"""
    for h in hosts:
        ig.append_jsonl(done_path, {"host": h})


def main():
    # argparse 对 "--tech -sS" 空格写法会把 -sS 误判为新选项而报错，
    # 统一改写为 "--tech=-sS" 等价形式，兼容 Observer 模板与手工调用。
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a == "--tech" and i + 1 < len(argv) and argv[i + 1].startswith("-"):
            argv[i] = "--tech=" + argv[i + 1]
            del argv[i + 1]
            break
    ap = argparse.ArgumentParser(description="端口扫描（nmap 单工具，支持断点续跑）")
    ap.add_argument("--targets", required=True, help="目标 JSONL（ip/host 字段）")
    ap.add_argument("--port-range", default="top-100",
                    help="top-N（默认 top-100）或范围（1-65535、80,443,8000-9000）")
    ap.add_argument("--tool", default="nmap",
                    help="扫描工具（仅 nmap；masscan 已移除，传入时告警并回退 nmap）")
    ap.add_argument("--tech", choices=["-sS", "-sT", "-sV"], default="-sS",
                    help="扫描技术（默认 -sS）")
    ap.add_argument("--rate", type=int, default=1000, help="扫描速度（默认 1000）")
    ap.add_argument("--ping", action="store_true",
                    help="允许 Ping 主机发现（缺省 -Pn 直接扫）")
    ap.add_argument("--bin-dir", default="/opt/tools/info-gather/bin")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-seconds", type=int, default=0,
                    help="单次运行时间预算（秒），0=不限（tmux 后台模式默认）；"
                         ">0 时耗尽保存进度并以退出码 %d 返回" % EXIT_PARTIAL)
    args = ap.parse_args(argv)

    port_range = args.port_range.strip()
    top_m = TOP_PORTS_RE.match(port_range)
    if not top_m and not PORT_RANGE_RE.match(port_range):
        print("[error] 端口范围格式无效: %r（支持 top-N 或 80,443,8000-9000 形式）" % port_range,
              file=sys.stderr)
        return 2

    # 兼容旧 Intent 描述/元数据中的 --tool masscan：告警并回退 nmap
    if args.tool != "nmap":
        print("[warn] masscan 已移除（--tool %s），回退 nmap %s" % (args.tool, args.tech),
              file=sys.stderr)

    targets = []
    seen = set()
    for row in ig.read_jsonl(args.targets):
        v = normalize_host(row.get("ip") or row.get("host") or "")
        # 输入去重（规范化后同主机不重复扫描）
        if v and v not in seen:
            seen.add(v)
            targets.append(v)
    # 确保输出文件存在（无目标/无开放端口时也为合法空产物）
    if not os.path.isfile(args.out):
        ig.write_jsonl(args.out, [])
    if not targets:
        print("[ok] 无目标，输出空文件 → %s" % args.out)
        return 0

    done_path = args.out + ".done"
    done = load_done(done_path)
    pending = [t for t in targets if t not in done]
    if done:
        print("[info] 断点续跑：%d 主机已扫，剩余 %d" % (len(done), len(pending)))

    budget = Budget(args.max_seconds)
    remaining = 0
    for i in range(0, len(pending), NMAP_CHUNK_SIZE):
        if budget.expired():
            remaining = len(pending) - i
            break
        chunk = pending[i:i + NMAP_CHUNK_SIZE]
        for row in nmap_scan(chunk, port_range, args.tech, args.rate,
                             args.ping, args.bin_dir):
            ig.append_jsonl(args.out, row)
        mark_done(done_path, chunk)

    rows = ig.read_jsonl(args.out)
    hosts = {r["host"] for r in rows}
    if remaining > 0:
        print("[partial] 时间预算耗尽（%ds）：剩余 %d 主机未扫，进度已保存，重跑本命令继续 → %s"
              % (budget.elapsed(), remaining, args.out))
        return EXIT_PARTIAL
    print("[ok] 端口扫描完成（tool=%s %s rate=%d）：%d 主机，%d 开放端口 → %s"
          % ("nmap", port_range, args.rate, len(hosts), len(rows), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
