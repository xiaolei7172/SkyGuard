#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SkyGuard 自检：分别验证 DNS 过滤器与本地代理能否真正工作

设计约束（避免自检本身改变用户环境）：
  · 全部使用高位端口（DNS 15353 / 代理 17890 / 内核 API 19090），不需要管理员权限
  · 不改系统 DNS、不改 hosts、不设系统代理，跑完立即停服务并清理临时目录
  · 每项输出 ok / fail / skip + 说明 + 耗时，命令行与界面共用同一套逻辑
"""

import socket
import struct
import time
from dataclasses import dataclass

from core.dns_filter import (
    PROTO_DOH, PROTO_UDP, QTYPE_A, DnsFilter, Upstream, build_query,
)
from utils.logger import logger

OK, FAIL, SKIP = "ok", "fail", "skip"


@dataclass
class CheckItem:
    """一条自检结果。"""
    name: str
    status: str = OK
    detail: str = ""
    ms: int = 0

    @property
    def ok(self):
        return self.status == OK

    def to_dict(self):
        return {"name": self.name, "status": self.status,
                "detail": self.detail, "ms": self.ms}


# ----------------------------------------------------------------------
# 基础工具
# ----------------------------------------------------------------------
def _ms(started):
    return int((time.perf_counter() - started) * 1000)


def free_port(start, tries=12):
    """从 start 开始找一个 TCP+UDP 都能绑的本地端口。

    注意 Windows 上 SO_REUSEADDR 允许「抢占」已被占用的端口，会让占用检测失效，
    所以这里故意不设该选项，直接 bind 才能真实反映端口是否空闲。
    """
    for port in range(int(start), int(start) + tries):
        ok = True
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            s = socket.socket(socket.AF_INET, kind)
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                ok = False
            finally:
                s.close()
            if not ok:
                break
        if ok:
            return port
    return int(start)


def _skip_name(data, off):
    """跳过 DNS 报文里的域名（支持压缩指针）。"""
    while off < len(data):
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += length + 1
    return off


def parse_a_records(data):
    """从 DNS 应答里取出 (rcode, 答案数, A 记录列表)。"""
    if not data or len(data) < 12:
        return -1, 0, []
    rcode = data[3] & 0x0F
    qdcount, ancount = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qdcount):
        off = _skip_name(data, off) + 4
    ips = []
    for _ in range(ancount):
        off = _skip_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        if rtype == QTYPE_A and rdlen == 4:
            ips.append(socket.inet_ntoa(rdata))
        off += rdlen
    return rcode, ancount, ips


def query_local(port, domain, timeout=5.0, host="127.0.0.1"):
    """向本机 DNS 服务发一次 A 查询，返回 (rcode, ips, 耗时ms)。"""
    query = build_query(domain, QTYPE_A, 0x5A5A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    started = time.perf_counter()
    try:
        sock.sendto(query, (host, port))
        data, _addr = sock.recvfrom(4096)
        rcode, _count, ips = parse_a_records(data)
        return rcode, ips, _ms(started)
    finally:
        sock.close()


def summarize(items):
    """汇总：pass / fail / skip 计数与是否全部通过。"""
    counts = {OK: 0, FAIL: 0, SKIP: 0}
    for item in items:
        counts[item.status] = counts.get(item.status, 0) + 1
    return {
        "total": len(items),
        "passed": counts[OK],
        "failed": counts[FAIL],
        "skipped": counts[SKIP],
        "ok": counts[FAIL] == 0 and counts[OK] > 0,
    }


def format_report(items, title=""):
    """把结果格式化成可直接展示的文本。"""
    marks = {OK: "[通过]", FAIL: "[失败]", SKIP: "[跳过]"}
    lines = [f"== {title} =="] if title else []
    for item in items:
        extra = f"（{item.ms}ms）" if item.ms else ""
        detail = f"：{item.detail}" if item.detail else ""
        lines.append(f"{marks.get(item.status, item.status)} {item.name}{extra}{detail}")
    stat = summarize(items)
    lines.append(f"合计 {stat['total']} 项 · 通过 {stat['passed']} · "
                 f"失败 {stat['failed']} · 跳过 {stat['skipped']}")
    return "\n".join(lines)


# ----------------------------------------------------------------------
# DNS 自检
# ----------------------------------------------------------------------
# 广告 / 追踪域名基准样本：用来判断上游是不是「去广告 DNS」。
# 覆盖国内外主流广告与统计域名，命中率高、误判率低（这些域名本身没有正常用途）。
AD_PROBE_DOMAINS = (
    "doubleclick.net",
    "pagead2.googlesyndication.com",
    "pos.baidu.com",
    "gdt.qq.com",
    "umeng.com",
    "cnzz.com",
    "hm.baidu.com",
)


def make_upstream(spec):
    """把 字符串 / dict / Upstream 统一成 Upstream。

    字符串按内容猜协议：https:// 开头是 DoH，其余按 UDP（可带 :port）。
    """
    if isinstance(spec, Upstream):
        return spec
    if isinstance(spec, dict):
        return Upstream(spec.get("name") or "自检上游",
                        spec.get("proto") or PROTO_UDP,
                        spec.get("address") or "")
    text = str(spec or "").strip() or "223.5.5.5:53"
    if text.lower().startswith(("http://", "https://")):
        return Upstream("自检上游", PROTO_DOH, text)
    return Upstream("自检上游", PROTO_UDP, text)


def probe_ad_block(upstream, domains=None, timeout=6.0):
    """直接问上游一批广告域名，判断它是否做了拦截。

    返回 (blocked, allowed, failed)：
      - blocked：返回 0.0.0.0 / :: 或 NXDOMAIN（这就是「去广告 DNS」的效果）
      - allowed：正常返回了真实 IP
      - failed：超时 / 报错
    """
    up = make_upstream(upstream)
    blocked, allowed, failed = [], [], []
    for domain in (domains or AD_PROBE_DOMAINS):
        try:
            data = up.query(build_query(domain, QTYPE_A, 0x7A7A), timeout=timeout)
            rcode, _count, ips = parse_a_records(data)
        except Exception as e:
            failed.append((domain, f"{type(e).__name__}: {str(e)[:60]}"))
            continue
        if rcode == 3 or (ips and all(ip in ("0.0.0.0", "::") for ip in ips)):
            blocked.append(domain)
        elif ips:
            allowed.append(domain)
        else:
            failed.append((domain, f"rcode={rcode}，无 A 记录"))
    return blocked, allowed, failed


def check_dns(port=None, upstream="223.5.5.5:53", timeout=8.0, ad_probe=True):
    """验证 DNS 过滤器：监听、上游解析、上游广告拦截、本地应答、拦截、重写、缓存、日志。

    upstream 可以是 "223.5.5.5:53"、DoH URL、或 {"name","proto","address"} 字典。
    """
    items = []
    up = make_upstream(upstream)
    up_label = up.address
    listen_port = int(port or free_port(15353))
    flt = DnsFilter(listen_hosts=["127.0.0.1"], port=listen_port,
                    block_action="blackhole")
    flt.upstream_timeout = min(6.0, timeout)
    flt.set_upstreams([up], 0)
    flt.set_filter_sources(list_lines=[], custom_lines=["||selfcheck-block.invalid^"])
    flt.set_rewrites({"selfcheck.local": "10.20.30.40"})

    started = time.perf_counter()
    if not flt.start():
        detail = "；".join(flt.bind_errors) or "端口被占用"
        items.append(CheckItem(f"DNS 服务监听 127.0.0.1:{listen_port}",
                               FAIL, detail, _ms(started)))
        return items
    items.append(CheckItem(f"DNS 服务监听 127.0.0.1:{listen_port}", OK,
                           "UDP + TCP 均已就绪，无需管理员权限", _ms(started)))

    try:
        # 1) 上游直连（不经过本机服务，用来判断是网络问题还是服务问题）
        started = time.perf_counter()
        try:
            raw = up.query(build_query("www.baidu.com", QTYPE_A, 0x1111),
                           timeout=min(6.0, timeout))
            _rcode, _count, ips = parse_a_records(raw)
            if ips:
                items.append(CheckItem(f"上游 DNS 直连（{up.proto}）", OK,
                                       f"{up_label} 返回 {', '.join(ips[:2])}",
                                       _ms(started)))
            else:
                items.append(CheckItem(f"上游 DNS 直连（{up.proto}）", FAIL,
                                       f"{up_label} 无 A 记录应答", _ms(started)))
        except Exception as e:
            items.append(CheckItem(f"上游 DNS 直连（{up.proto}）", FAIL,
                                   f"{up_label} 查询失败：{e}", _ms(started)))

        # 1b) 上游广告拦截能力（判断这个 DNS 本身是否去广告）
        ad_blocked = []
        if ad_probe:
            started = time.perf_counter()
            try:
                blocked, allowed, failed = probe_ad_block(
                    up, timeout=min(6.0, timeout))
                ad_blocked = blocked
                total = len(blocked) + len(allowed) + len(failed)
                if blocked and len(blocked) * 2 >= total:
                    sample = "、".join(blocked[:3])
                    extra = f"，另有 {len(failed)} 个未应答" if failed else ""
                    items.append(CheckItem(
                        "上游广告拦截", OK,
                        f"拦截 {len(blocked)}/{total} 个广告域名（{sample}…）{extra}",
                        _ms(started)))
                elif blocked:
                    items.append(CheckItem(
                        "上游广告拦截", OK,
                        f"部分拦截 {len(blocked)}/{total}（"
                        + "、".join(blocked[:4]) + "）", _ms(started)))
                else:
                    items.append(CheckItem(
                        "上游广告拦截", SKIP,
                        f"该上游未拦截任何广告域名（{len(allowed)} 个正常解析），"
                        "属于普通递归 DNS，去广告需靠本地过滤器规则", _ms(started)))
            except Exception as e:
                items.append(CheckItem("上游广告拦截", SKIP,
                                       f"检测失败：{e}", _ms(started)))

        # 2) 经本机服务解析国内域名
        started = time.perf_counter()
        try:
            rcode, ips, _elapsed = query_local(listen_port, "www.baidu.com", timeout=timeout)
            if ips:
                items.append(CheckItem("本地解析 www.baidu.com", OK,
                                       f"返回 {', '.join(ips[:2])}", _ms(started)))
            else:
                items.append(CheckItem("本地解析 www.baidu.com", FAIL,
                                       f"rcode={rcode}，无 A 记录", _ms(started)))
        except Exception as e:
            items.append(CheckItem("本地解析 www.baidu.com", FAIL,
                                   f"查询超时或失败：{e}", _ms(started)))

        # 3) 拦截规则
        started = time.perf_counter()
        try:
            rcode, ips, _elapsed = query_local(listen_port, "ad.selfcheck-block.invalid",
                                               timeout=timeout)
            blocked = rcode == 3 or (ips and set(ips) <= {"0.0.0.0", "::"})
            items.append(CheckItem(
                "广告拦截规则生效", OK if blocked else FAIL,
                ("命中 ||selfcheck-block.invalid^，返回 " +
                 ("NXDOMAIN" if rcode == 3 else (ips[0] if ips else "空应答")))
                if blocked else f"未被拦截（rcode={rcode}, ips={ips}）",
                _ms(started)))
        except Exception as e:
            items.append(CheckItem("广告拦截规则生效", FAIL, str(e), _ms(started)))

        # 4) DNS 重写
        started = time.perf_counter()
        try:
            _rcode, ips, _elapsed = query_local(listen_port, "selfcheck.local",
                                                timeout=timeout)
            mapped = ips == ["10.20.30.40"]
            items.append(CheckItem(
                "DNS 重写生效", OK if mapped else FAIL,
                "selfcheck.local → 10.20.30.40" if mapped else f"实际返回 {ips}",
                _ms(started)))
        except Exception as e:
            items.append(CheckItem("DNS 重写生效", FAIL, str(e), _ms(started)))

        # 5) 缓存命中（再查一次同域名，应走缓存且计数增加）
        started = time.perf_counter()
        try:
            before = flt.stats.snapshot()["cache_hits"]
            query_local(listen_port, "www.baidu.com", timeout=timeout)
            after = flt.stats.snapshot()["cache_hits"]
            items.append(CheckItem(
                "应答缓存", OK if after > before else SKIP,
                f"缓存命中 {after} 次" if after > before else "未命中（TTL 过短或上游无缓存）",
                _ms(started)))
        except Exception as e:
            items.append(CheckItem("应答缓存", SKIP, str(e), _ms(started)))

        # 6) 查询日志
        size = flt.stats.query_log.size
        items.append(CheckItem("查询日志记录", OK if size >= 4 else FAIL,
                               f"已记录 {size} 条查询"))

        # 7) 上游拦截是否在本地链路与日志里被正确识别
        if ad_blocked:
            # 必须挑一个「本地过滤规则不会命中」的域名，否则本地规则先拦，
            # 测的就不是上游黑洞识别了
            candidates = [d for d in ad_blocked if not flt._match_block(d)]
            domain = (candidates or ad_blocked)[0]
            started = time.perf_counter()
            try:
                rcode, ips, _elapsed = query_local(listen_port, domain,
                                                   timeout=timeout)
                holed = rcode == 3 or (ips and set(ips) <= {"0.0.0.0", "::"})
                entries = flt.stats.query_log.snapshot(
                    result="upstream_blocked", limit=8)
                tagged = any(e["domain"] == domain for e in entries)
                if holed and tagged:
                    detail = (f"{domain} 经本地服务返回 "
                              f"{'NXDOMAIN' if rcode == 3 else ips[0]}，"
                              "日志已标记「上游拦截」")
                    status = OK
                elif holed:
                    detail = f"{domain} 已被拦，但日志未标记为「上游拦截」"
                    status = SKIP
                else:
                    detail = f"{domain} 未被拦截（返回 {ips or rcode}）"
                    status = FAIL
                items.append(CheckItem("上游拦截在日志可见", status, detail,
                                       _ms(started)))
            except Exception as e:
                items.append(CheckItem("上游拦截在日志可见", SKIP, str(e),
                                       _ms(started)))
        if flt.bind_errors:
            items.append(CheckItem("监听告警", SKIP, "；".join(flt.bind_errors)))
    finally:
        flt.stop()
        logger.debug(f"DNS 自检完成，端口 {listen_port} 已释放")

    return items


