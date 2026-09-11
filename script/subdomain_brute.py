#!/usr/bin/env python3
"""子域名爆破：massdns + 字典，泛解析（wildcard）过滤。参考 nemo_go domainscan/massdns 实现。

用法：
  python3 subdomain_brute.py --domain example.com --bin-dir {BASE}/bin \
      --data-dir {BASE}/data --dict small --out OUT.jsonl

参数：
  --dict       small（默认，subnames.txt）/ medium（subnames_medium.txt）/ 字典绝对路径
  --resolvers  自定义 resolver 文件（缺省 {data}/resolver.txt，再缺省从 /etc/resolv.conf 生成）
  --threads    massdns 并发查询数（-s，默认 300，对齐 nemo_go Normal 性能模式）；
               公共 resolver 在高并发下普遍限速（SERVFAIL/丢包），严禁调大默认值
  --retries    单域名重试次数（massdns -c，默认 5，对齐 nemo_go shuffledns Retries）
  --no-probe   跳过 resolver 测速筛选（默认先 UDP 探活剔除不可用节点）

输出 JSONL：{"subdomain":"..."}（与 subdomain_enum.py 同构，便于合并去重）。
退出码：0 成功；2 参数错误；3 massdns/字典缺失（降级，调用方可继续）。
"""
import argparse
import os
import random
import socket
import string
import struct
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

import igcommon as ig

# 字典别名 → data 目录文件名
DICT_FILES = {"small": "subnames.txt", "medium": "subnames_medium.txt"}

# resolver 测速：探活查询的基准域名（稳定大站，任何公共 DNS 都应可解析）
PROBE_NAME = "www.aliyun.com"
# 探活并发与超时：612 个 resolver 约 20-40s 完成
PROBE_WORKERS = 64
PROBE_TIMEOUT = 2.0
# 测速后存活 resolver 低于该数时回退原始清单（宁可限速也不丢覆盖）
MIN_RESOLVERS = 8


def dns_probe(server, name=PROBE_NAME, timeout=PROBE_TIMEOUT):
    """对单个 resolver 发 UDP A 查询探活，返回延迟（秒）；失败返回 None。"""
    tid = random.randint(0, 0xFFFF)
    # 构造 DNS 查询报文：HEADER + QUESTION（A 记录）
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    packet = header + qname + struct.pack(">HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t0 = time.monotonic()
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(512)
        # 校验事务 ID 且 rcode=NOERROR(0) 或 NXDOMAIN(3) 均视为节点可用
        if len(data) >= 4 and struct.unpack(">H", data[:2])[0] == tid:
            rcode = struct.unpack(">H", data[2:4])[0] & 0xF
            if rcode in (0, 3):
                return time.monotonic() - t0
        return None
    except OSError:
        return None
    finally:
        sock.close()


def probe_resolvers(servers):
    """并发测速筛选：剔除超时/不可达 resolver，按延迟升序返回。"""
    if not servers:
        return []
    scored = []
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        for server, latency in zip(servers, pool.map(dns_probe, servers)):
            if latency is not None:
                scored.append((latency, server))
    scored.sort()
    alive = [s for _, s in scored]
    if len(alive) < MIN_RESOLVERS:
        print("[warn] resolver 测速存活仅 %d 个，回退原始清单（%d 个）" % (len(alive), len(servers)),
              file=sys.stderr)
        return servers
    print("[info] resolver 测速：%d/%d 存活（剔除 %d 个不可用节点）"
          % (len(alive), len(servers), len(servers) - len(alive)))
    return alive


def find_resolvers(data_dir, custom_path=None):
    """resolver 清单：--resolvers 自定义 > data/resolver.txt > /etc/resolv.conf 生成。"""
    path = custom_path or os.path.join(data_dir, "resolver.txt")
    if os.path.isfile(path):
        with open(path) as f:
            return [ln.strip() for ln in f
                    if ln.strip() and not ln.startswith("#") and ig.is_ip(ln.strip())]
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2 and parts[0] == "nameserver" and ig.is_ip(parts[1]):
                    servers.append(parts[1])
    except OSError:
        pass
    return servers or ["223.5.5.5", "119.29.29.29", "8.8.8.8"]


def massdns_query(names, resolver_file, exe, threads, retries, timeout=600):
    """massdns 批量 A 查询，返回 {name: [ip,...]}。

    -s 严格限制并发（默认 10000 会瞬间打满 socket 并触发公共 resolver 限速）；
    -c 限制单域名重试次数（默认 50 会在 resolver 失效时长时间挂起）。
    """
    if not names:
        return {}
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(names) + "\n")
        input_file = f.name
    out_file = input_file + ".out"
    try:
        subprocess.run(
            [exe, "-r", resolver_file, "-t", "A", "-o", "S", "-q",
             "-s", str(threads), "-c", str(retries),
             "-w", out_file, input_file],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print("[warn] massdns 查询超时，解析已产出部分", file=sys.stderr)
    finally:
        os.unlink(input_file)
    results = {}
    try:
        with open(out_file) as f:
            for line in f:
                # simple 输出: "name. A 1.2.3.4"
                parts = line.split()
                if len(parts) == 3 and parts[1] == "A" and ig.is_ip(parts[2]):
                    name = parts[0].rstrip(".").lower()
                    results.setdefault(name, []).append(parts[2])
    except OSError:
        pass
    finally:
        if os.path.exists(out_file):
            os.unlink(out_file)
    return results


def detect_wildcard(domain, resolver_file, exe, threads, retries):
    """泛解析检测：随机前缀可解析则返回通配 IP 集合，否则返回空集。"""
    token = "igw" + "".join(random.choice(string.ascii_lowercase) for _ in range(12))
    hits = massdns_query(["%s.%s" % (token, domain)], resolver_file, exe,
                         threads, retries, timeout=60)
    ips = set()
    for v in hits.values():
        ips.update(v)
    return ips


def main():
    ap = argparse.ArgumentParser(description="子域名爆破（massdns + 字典，泛解析过滤，并发受控）")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--bin-dir", default="/opt/tools/info-gather/bin")
    ap.add_argument("--data-dir", default="/opt/tools/info-gather/data")
    ap.add_argument("--dict", default="small", help="small/medium 或字典文件路径")
    ap.add_argument("--resolvers", default="", help="自定义 resolver 文件路径")
    ap.add_argument("--threads", type=int, default=300,
                    help="massdns 并发查询数（-s，默认 300；公共 resolver 高并发会限速，勿调大）")
    ap.add_argument("--retries", type=int, default=5,
                    help="单域名重试次数（massdns -c，默认 5）")
    ap.add_argument("--no-probe", action="store_true", help="跳过 resolver 测速筛选")
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=1800, help="massdns 整体超时（秒）")
    args = ap.parse_args()

    exe = os.path.join(args.bin_dir, "massdns")
    if not os.path.isfile(exe):
        exe = "massdns"
        if not any(os.path.isfile(os.path.join(p, exe))
                   for p in os.environ.get("PATH", "").split(os.pathsep)):
            print("[warn] massdns 缺失，爆破降级为空", file=sys.stderr)
            ig.write_jsonl(args.out, [])
            return 3

    wordlist = DICT_FILES.get(args.dict, args.dict)
    if not os.path.isabs(wordlist):
        wordlist = os.path.join(args.data_dir, wordlist)
    if not os.path.isfile(wordlist):
        print("[warn] 字典缺失: %s" % wordlist, file=sys.stderr)
        ig.write_jsonl(args.out, [])
        return 3

    domain = args.domain.strip().lower()
    servers = find_resolvers(args.data_dir, args.resolvers or None)
    if not args.no_probe:
        servers = probe_resolvers(servers)
    # 测速筛选后的清单落临时文件供 massdns 使用
    rf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    rf.write("\n".join(servers) + "\n")
    rf.close()
    resolver_file = rf.name
    try:
        # 泛解析检测（nemo_go StrictWildcard 对应实现：通配 IP 整组过滤）
        wildcard_ips = detect_wildcard(domain, resolver_file, exe, args.threads, args.retries)
        if wildcard_ips:
            print("[info] 检测到泛解析，通配 IP: %s" % ",".join(sorted(wildcard_ips)))

        with open(wordlist) as f:
            candidates = ["%s.%s" % (w.strip().lower(), domain)
                          for w in f if w.strip() and not w.startswith("#")]
        # 字典去重（大小写/空白归一后）
        candidates = sorted(set(candidates))
        print("[info] 字典 %s：%d 候选，resolver %d 个，并发 %d"
              % (os.path.basename(wordlist), len(candidates), len(servers), args.threads))

        hits = massdns_query(candidates, resolver_file, exe, args.threads,
                             args.retries, timeout=args.timeout)
        rows = []
        for name, ips in sorted(hits.items()):
            if wildcard_ips and set(ips) <= wildcard_ips:
                continue  # 泛解析命中，过滤
            rows.append({"subdomain": name})
        ig.write_jsonl(args.out, rows)
        print("[ok] %s 爆破完成：%d 候选，%d 命中（过滤泛解析后）→ %s"
              % (domain, len(candidates), len(rows), args.out))
        return 0
    finally:
        os.unlink(resolver_file)


if __name__ == "__main__":
    sys.exit(main())
