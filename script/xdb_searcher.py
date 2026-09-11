#!/usr/bin/env python3
"""ip2region xdb v2 只读查询器（纯标准库单文件 vendor，对齐官方 xdbSearcher 语义）。

xdb v2 文件结构：
  [0,256)      header（8B 起：startIndexPtr u32le，12B 起：endIndexPtr u32le）
  [256, ...)   vector 索引：256*256 项 x 8B（startPtr/endPtr u32le），
               键 = IP 前两字节 (ip>>16)&0xFFFF
  [startIndexPtr, endIndexPtr) 段索引：14B/项
               （sip u32le, eip u32le, dataLen u16le, dataPtr u32le）
  数据区：UTF-8 字符串 "country|region|province|city|isp"（"0" = 空段）

仅支持 IPv4（xdb v2 主库即 IPv4；IPv6 由调用方回退处理）。
"""
import ipaddress
import struct

_HEADER_LEN = 256
_VECTOR_INDEX_SIZE = 256 * 256 * 8
_SEGMENT_INDEX_SIZE = 14


class XdbSearcher:
    """全量加载 xdb 到内存（约 11MB），查询为内存二分。"""

    def __init__(self, path):
        with open(path, "rb") as f:
            self._buf = f.read()
        if len(self._buf) < _HEADER_LEN + _VECTOR_INDEX_SIZE:
            raise ValueError("xdb 文件过小，格式非法")
        self._seg_start = struct.unpack_from("<I", self._buf, 8)[0]
        self._seg_end = struct.unpack_from("<I", self._buf, 12)[0]
        if self._seg_start < _HEADER_LEN + _VECTOR_INDEX_SIZE or self._seg_end > len(self._buf):
            raise ValueError("xdb 段索引指针越界，格式非法")

    def search(self, ip):
        """查询 IPv4 归属地，返回 "country|region|province|city|isp" 原文；未命中返回 None。"""
        try:
            ip_int = int(ipaddress.IPv4Address(ip))
        except (ipaddress.AddressValueError, ValueError):
            return None
        # vector 索引定位段索引子区间
        vec_idx = ((ip_int >> 24) << 8) | ((ip_int >> 16) & 0xFF)
        vec_off = _HEADER_LEN + vec_idx * 8
        il0, il1 = struct.unpack_from("<II", self._buf, vec_off)
        # 段索引二分：找 sip <= ip <= eip
        lo, hi = 0, (il1 - il0) // _SEGMENT_INDEX_SIZE
        while lo <= hi:
            mid = (lo + hi) >> 1
            off = il0 + mid * _SEGMENT_INDEX_SIZE
            sip, eip = struct.unpack_from("<II", self._buf, off)
            if ip_int < sip:
                hi = mid - 1
            elif ip_int > eip:
                lo = mid + 1
            else:
                data_len, data_ptr = struct.unpack_from("<HI", self._buf, off + 8)
                raw = self._buf[data_ptr:data_ptr + data_len]
                return raw.decode("utf-8", errors="replace")
        return None


def format_location(region, limit=64):
    """xdb 区域串 → 展示串。
    v4 库格式 'country|province|city|isp|国家代码'（如 '中国|广东省|广州市|电信|CN'）；
    国家代码段（两位大写字母）丢弃，'0'/'Reserved' 空段丢弃；
    输出 '国家 省市 ISP'（省市连写，ISP 缺省省略）；全空返回 ''。"""
    if not region:
        return ""
    parts = region.split("|")
    if parts and len(parts[-1]) == 2 and parts[-1].isupper() and parts[-1].isascii():
        parts = parts[:-1]
    parts = ["" if p in ("0", "Reserved") else p for p in parts[:4]]
    country = parts[0] if parts else ""
    if not country:
        return ""
    province_city = (parts[1] + parts[2]) if len(parts) >= 3 else "".join(parts[1:])
    isp = parts[3] if len(parts) >= 4 else ""
    out = country
    if province_city:
        out += " " + province_city
    if isp:
        out += " " + isp
    return out.strip()[:limit]
