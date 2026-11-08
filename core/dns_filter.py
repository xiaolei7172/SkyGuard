#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""DNS 过滤器核心（借鉴 AdGuard Home 的能力组合）。

本地 DNS 服务器（UDP + TCP）：
  - 上游支持 UDP / DoH / DoT 三种协议，可选「并行最快」或「顺序优先」策略
  - 应答缓存（按 TTL 过期，命中后逐条递减 TTL 回写；TTL 可设上下限）
  - 过滤规则：内置兜底 + 过滤器列表 + 自定义规则（@/@@ 例外、通配、正则）
  - DNS 重写：域名直出指定 IP（如把局域网服务改成短域名）
  - 查询日志：客户端 / 类型 / 结果 / 上游 / 耗时，供界面筛选与统计
  - 线程安全的统计计数与 Top 聚合

只依赖标准库 + requests（DoH），不引入额外打包依赖。
"""

import json
import os
import socket
import socketserver
import ssl
import struct
import threading
import time
from collections import Counter, deque

import requests

from core.dns_rules import RuleSet, compile_rules
from utils.logger import logger

# 常用记录类型
QTYPE_A = 1
QTYPE_AAAA = 28

QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY",
    52: "TLSA", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}

PROTO_UDP = "UDP"
PROTO_DOH = "DoH"
PROTO_DOT = "DoT"
SUPPORTED_PROTOCOLS = (PROTO_UDP, PROTO_DOH, PROTO_DOT)

STRATEGY_SEQUENTIAL = "sequential"
STRATEGY_PARALLEL = "parallel"

DEFAULT_BLOCKLIST = [
    # 出厂自带的兜底黑名单（少量高频广告域），完整规则可通过「更新订阅」拉取
    "ads." , "adservice", "adsserver", "analytics", "app-measurement.com",
    "adnxs.com", "adsrvr.org", "doubleclick.net", "googlesyndication.com",
    "googleadservices.com", "googletagmanager.com", "ads-twitter.com",
    "adcolony.com", "applovin.com", "chartboost.com", "unityads.unity3d.com",
    "adview.cn", "adxhi.com", "alphassl.cn", "tanx.com",
    "pos.baidu.com", "cpro.baidu.com", "hm.baidu.com", "click.bes.baidu.com",
    "data.bilibili.com", "mail.bilibili.com",
    "oth.eve.mdt.qq.com", "otheve.beacon.qq.com", "h.trace.qq.com",
    "pgdt.ugdtimg.com", "v.gdt.qq.com", "sdk.e.qq.com",
    "analytics.tiktok.com", "log.byteover.com", "tnc*.zijieapi.com",
]


def is_blocked_domain(domain, exact_set, suffix_set):
    """判断域名是否命中黑名单：全等或属于某条黑名单域的子域。"""
    if domain in exact_set:
        return True
    idx = 0
    while True:
        idx = domain.find(".", idx)
        if idx == -1:
            return False
        if domain[idx + 1:] in suffix_set:
            return True
        idx += 1


def qtype_name(qtype):
    return QTYPE_NAMES.get(int(qtype or 0), str(qtype))


def ip_to_rdata(text):
    """把 IPv4 / IPv6 文本转成应答 rdata；失败返回 None。"""
    text = (text or "").strip()
    if not text:
        return None
    try:
        if ":" in text:
            return (QTYPE_AAAA, socket.inet_pton(socket.AF_INET6, text))
        return (QTYPE_A, socket.inet_pton(socket.AF_INET, text))
    except OSError:
        return None


class Upstream:
    """一个上游 DNS 服务器。address 的写法：

    - UDP: "223.5.5.5:53" 或 "223.5.5.5"（默认 53）
    - DoH: 完整 URL，如 "https://dns.alidns.com/dns-query"
    - DoT: "223.5.5.5:853" 或 "dns.alidns.com:853"（默认 853）
    """

    def __init__(self, name, proto, address):
        self.name = name.strip() or f"{proto}-{address}"
        # 协议名归一化（DOT/DoT/dot 一律转成常量形式）
        norm = proto.strip().upper()
        self.proto = {"DOH": PROTO_DOH, "DOT": PROTO_DOT, "UDP": PROTO_UDP}.get(norm, PROTO_UDP)
        self.address = address.strip()
        self._doh_session = None
        self._lock = threading.Lock()

    # ---------------- 对外查询接口 ----------------
    def query(self, wire_query, timeout=4.0):
        """发送 DNS 报文，返回应答报文（bytes）。失败抛异常。"""
        if self.proto == PROTO_DOH:
            return self._query_doh(wire_query, timeout)
        if self.proto == PROTO_DOT:
            return self._query_dot(wire_query, timeout)
        return self._query_udp(wire_query, timeout)

    def _query_udp(self, wire_query, timeout):
        host, port = self._host_port(53)
        with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET,
                           socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(wire_query, (host, port))
            data, _ = s.recvfrom(4096)
        return data

    def _query_dot(self, wire_query, timeout):
        host, port = self._host_port(853)
        ctx = ssl.create_default_context()
        # DoT 常用 IP 直连（如 223.5.5.5），此时无法校验证书域名
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host if not host.replace(".", "").isdigit() else None) as tls:
                tls.settimeout(timeout)
                tls.sendall(struct.pack(">H", len(wire_query)) + wire_query)
                hdr = self._recv_exact(tls, 2)
                (length,) = struct.unpack(">H", hdr)
                return self._recv_exact(tls, length)

    def _query_doh(self, wire_query, timeout):
        with self._lock:
            if self._doh_session is None:
                self._doh_session = requests.Session()
                self._doh_session.headers.update({"Accept": "application/dns-message"})
        resp = self._doh_session.post(
            self.address,
            data=wire_query,
            headers={"Content-Type": "application/dns-message"},
            timeout=timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            raise ValueError("DoH 上游返回空报文")
        return resp.content

    # ---------------- 探测 ----------------
    def probe(self, timeout=3.0):
        """解析一个固定域名测延迟，返回毫秒数；失败返回 None。"""
        probe_packet = build_query("www.baidu.com", QTYPE_A, query_id=0x1234)
        start = time.monotonic()
        try:
            resp = self.query(probe_packet, timeout=timeout)
            # 简单校验：应答至少要有完整头部且 QR 位为 1
            if len(resp) < 12 or not (resp[2] & 0x80):
                return None
            return round((time.monotonic() - start) * 1000, 1)
        except Exception:
            return None

    # ---------------- 工具 ----------------
    def _host_port(self, default_port):
        addr = self.address
        if addr.lower().startswith("https://"):
            raise ValueError("该上游协议应为 DoH")
        if addr.startswith("["):  # [::1]:53 形式
            host, _, rest = addr[1:].partition("]")
            port = int(rest.lstrip(":")) if rest.lstrip(":") else default_port
            return host, port
        if ":" in addr:
            host, port_s = addr.rsplit(":", 1)
            if host.count(":") > 1:  # 裸 IPv6
                return addr, default_port
            return host, int(port_s)
        return addr, default_port

    @staticmethod
    def _recv_exact(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("DoT 连接被上游关闭")
            buf += chunk
        return buf

    def to_dict(self):
        return {"name": self.name, "proto": self.proto, "address": self.address}

    @classmethod
    def from_dict(cls, d):
        return cls(d.get("name", ""), d.get("proto", PROTO_UDP), d.get("address", ""))


def build_query(domain, qtype=QTYPE_A, query_id=0x0000):
    """构造一条标准 DNS 查询报文（递归期望位打开）。"""
    qname = b"".join(bytes([len(p)]) + p.encode("idna") if not p.isascii()
                     else bytes([len(p)]) + p.encode("ascii")
                     for p in domain.rstrip(".").split("."))
    qname += b"\x00"
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack(">HH", qtype, 1)


# ----------------------------------------------------------------------
# 查询日志（AdGuard Home 的 Query Log）
# ----------------------------------------------------------------------
RESULT_ALLOW = "allow"
RESULT_BLOCKED = "blocked"
RESULT_CACHED = "cached"
RESULT_REWRITE = "rewrite"
RESULT_FAIL = "fail"

RESULT_LABELS = {
    RESULT_ALLOW: "放行",
    RESULT_BLOCKED: "已拦截",
    RESULT_CACHED: "缓存命中",
    RESULT_REWRITE: "重写",
    RESULT_FAIL: "失败",
}


class QueryLog:
    """环形查询日志 + 即时 Top 聚合。总量有上限，长时间运行也不会涨内存。"""

    def __init__(self, size=800):
        self._lock = threading.Lock()
        self._items = deque(maxlen=max(50, int(size)))
        self.paused = False
        self.dropped = 0

    def add(self, client, domain, qtype, result, rule="", upstream="", ms=0.0):
        if self.paused:
            self.dropped += 1
            return
        entry = {
            "ts": time.time(),
            "time": time.strftime("%H:%M:%S"),
            "client": client or "-",
            "domain": domain,
            "qtype": qtype_name(qtype),
            "result": result,
            "result_label": RESULT_LABELS.get(result, result),
            "rule": rule,
            "upstream": upstream,
            "ms": round(float(ms or 0), 1),
        }
        with self._lock:
            self._items.appendleft(entry)

    def snapshot(self, result="all", search="", limit=200):
        """按结果类型与关键字筛选，返回最近的若干条（新的在前）。"""
        search = (search or "").strip().lower()
        out = []
        with self._lock:
            items = list(self._items)
        for e in items:
            if result != "all" and e["result"] != result:
                continue
            if search and search not in e["domain"].lower() and search not in e["client"].lower():
                continue
            out.append(e)
            if len(out) >= limit:
                break
        return out

    def aggregates(self, top_n=6):
        """Top 客户端 / 域名 / 被拦截域名 / 查询类型 / 24 小时分布。"""
        with self._lock:
            items = list(self._items)
        clients = Counter()
        domains = Counter()
        blocked = Counter()
        types = Counter()
        hourly = Counter()
        for e in items:
            clients[e["client"]] += 1
            domains[e["domain"]] += 1
            types[e["qtype"]] += 1
            if e["result"] == RESULT_BLOCKED:
                blocked[e["domain"]] += 1
            hourly[time.localtime(e["ts"]).tm_hour] += 1
        return {
            "size": len(items),
            "top_clients": clients.most_common(top_n),
            "top_domains": domains.most_common(top_n),
            "top_blocked": blocked.most_common(top_n),
            "by_type": types.most_common(top_n),
            "hourly": [(h, hourly.get(h, 0)) for h in range(24)],
        }

    def clear(self):
        with self._lock:
            self._items.clear()

    @property
    def size(self):
        with self._lock:
            return len(self._items)


class DnsStats:
    """线程安全统计。"""

    def __init__(self, log_size=300):
        self._lock = threading.Lock()
        self.total = 0
        self.blocked = 0
        self.cache_hits = 0
        self.failed = 0
        self.rewrites = 0
        self.upstreams = {}   # name -> {"ok": n, "fail": n, "latency_ms": float|None}
        self.log = deque(maxlen=log_size)  # 最近被拦截的域名
        self.query_log = QueryLog()

    def count_query(self):
        with self._lock:
            self.total += 1

    def count_blocked(self, name, rule, action):
        with self._lock:
            self.blocked += 1
            self.log.appendleft({"time": time.strftime("%H:%M:%S"), "domain": name,
                                 "rule": rule, "action": action})

    def count_cache(self):
        with self._lock:
            self.cache_hits += 1

    def count_failed(self):
        with self._lock:
            self.failed += 1

    def count_rewrite(self):
        with self._lock:
            self.rewrites += 1

    def count_upstream(self, name, ok, latency_ms=None):
        with self._lock:
            slot = self.upstreams.setdefault(name, {"ok": 0, "fail": 0, "latency_ms": None})
            if ok:
                slot["ok"] += 1
                slot["latency_ms"] = latency_ms
            else:
                slot["fail"] += 1

    def snapshot(self):
        with self._lock:
            return {
                "total": self.total,
                "blocked": self.blocked,
                "cache_hits": self.cache_hits,
                "failed": self.failed,
                "rewrites": self.rewrites,
                "blocked_log": list(self.log),
                "upstreams": {k: dict(v) for k, v in self.upstreams.items()},
                "log_size": self.query_log.size,
                "log_paused": self.query_log.paused,
            }

    def reset(self):
        with self._lock:
            self.total = self.blocked = self.cache_hits = self.failed = 0
            self.rewrites = 0
            self.log.clear()
            self.upstreams.clear()
        self.query_log.clear()


class DnsFilter:
    """本地 DNS 过滤服务器。start() 后在后台线程服务。"""

    CACHE_MAX = 4096

    def __init__(self, listen_hosts=("127.0.0.1", "0.0.0.0", "::1"), port=53,
                 blocklist_path=None, block_action="blackhole"):
        self.listen_hosts = list(listen_hosts)
        self.port = int(port)
        self.blocklist_path = blocklist_path
        self.block_action = block_action  # blackhole | nxdomain

        self.upstreams = []          # [Upstream]
        self.selected = 0            # 默认上游下标
        self.upstream_strategy = STRATEGY_SEQUENTIAL
        self.upstream_timeout = 4.0
        self.cache_min_ttl = 0
        self.cache_max_ttl = 86400
        self.rewrites = {}           # domain -> ip text
        self.stats = DnsStats()

        self._rules = RuleSet()
        self._file_lines = []
        self._extra_lines = []       # 过滤器列表 + 自定义规则
        self._cache = {}             # (name, qtype) -> (expires, resp, min_ttl)
        self._cache_lock = threading.Lock()
        self._servers = []
        self._threads = []
        self._running = False
        self._run_lock = threading.Lock()
        self._state_lock = threading.Lock()

        if blocklist_path and os.path.exists(blocklist_path):
            self.reload_blocklist()
        else:
            self._load_defaults()

    # ---------------- 生命周期 ----------------
    def start(self):
        with self._run_lock:
            if self._running:
                return True
            errors = []
            for host in self.listen_hosts:
                for label, maker in (("UDP", self._make_udp_server), ("TCP", self._make_tcp_server)):
                    try:
                        server = maker(host)
                        t = threading.Thread(target=server.serve_forever,
                                             kwargs={"poll_interval": 0.5}, daemon=True)
                        self._servers.append(server)
                        self._threads.append(t)
                        t.start()
                    except OSError as e:
                        errors.append(f"{host} {label}: {e}")
                        logger.warning(f"DNS 监听失败 {host} {label}: {e}")
            if not self._servers:
                self._running = False
                self._bind_errors = errors
                return False
            self._running = True
            self._bind_errors = errors
            logger.info(f"DNS 过滤器已启动，监听 {self.port} 端口（部分失败: {errors or '无'}）")
            return True

    def _server_class(self, base, host):
        """host 含冒号时用 IPv6 地址族；TCP 加 allow_reuse_address 防 TIME_WAIT。"""
        if ":" in host:
            class V6(base):
                address_family = socket.AF_INET6
            cls = V6
        else:
            cls = base

        class Reuse(cls):
            allow_reuse_address = True
        return Reuse

    def _make_udp_server(self, host):
        srv = self._server_class(socketserver.ThreadingUDPServer, host)(
            (host, self.port), self._udp_handler())
        srv.daemon_threads = True
        srv.dns_filter = self
        return srv

    def _udp_handler(self):
        dns_filter = self

        class HandlerUDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                resp = dns_filter.handle_query(data, client=self.client_address[0])
                if resp:
                    try:
                        sock.sendto(resp, self.client_address)
                    except OSError:
                        pass
        return HandlerUDP

    def _make_tcp_server(self, host):
        dns_filter = self

        class HandlerTCP(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    hdr = self._recv(2)
                    (length,) = struct.unpack(">H", hdr)
                    query = self._recv(length)
                    resp = dns_filter.handle_query(query, client=self.client_address[0])
                    if resp:
                        self.request.sendall(struct.pack(">H", len(resp)) + resp)
                except (OSError, struct.error):
                    pass

            def _recv(self, n):
                buf = b""
                while len(buf) < n:
                    chunk = self.request.recv(n - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                return buf

        srv = self._server_class(socketserver.ThreadingTCPServer, host)((host, self.port), HandlerTCP)
        srv.daemon_threads = True
        srv.dns_filter = self
        return srv

    def stop(self):
        with self._run_lock:
            if not self._running:
                return
            for srv in self._servers:
                srv.shutdown()
                srv.server_close()
            self._servers.clear()
            self._threads.clear()
            self._running = False
            logger.info("DNS 过滤器已停止")

    @property
    def running(self):
        return self._running

    @property
    def bind_errors(self):
        return getattr(self, "_bind_errors", [])

    # ---------------- 报文处理 ----------------
    def handle_query(self, data, client=""):
        """处理一条原始查询，返回应答报文或 None（无法解析）。"""
        if len(data) < 17 or not (data[2] & 0x01):  # 必须是查询（QR=0）
            return None
        query_id = struct.unpack(">H", data[:2])[0]
        try:
            name, qtype, _qclass, q_end = self._parse_question(data)
        except (IndexError, ValueError, struct.error):
            return None
        self.stats.count_query()
        name_l = name.rstrip(".").lower()
        question = data[12:q_end]

        # 1. 过滤规则（例外优先，由 RuleSet 保证）
        rule = self._match_block(name_l)
        if rule:
            action = "返回黑洞地址" if self.block_action == "blackhole" else "返回 NXDOMAIN"
            self.stats.count_blocked(name_l, rule, action)
            self.stats.query_log.add(client, name_l, qtype, RESULT_BLOCKED, rule=rule)
            return self._build_blocked(query_id, question, qtype)

        # 2. DNS 重写
        target = self._match_rewrite(name_l)
        if target:
            self.stats.count_rewrite()
            self.stats.query_log.add(client, name_l, qtype, RESULT_REWRITE,
                                     rule=f"重写 → {target}")
            resp = self._build_rewrite(query_id, question, qtype, target)
            if resp:
                return resp

        # 3. 缓存
        cache_key = (name_l, qtype)
        now = time.monotonic()
        with self._cache_lock:
            cached = self._cache.get(cache_key)
        if cached and cached[0] > now:
            _expires, resp, min_ttl = cached
            self.stats.count_cache()
            self.stats.query_log.add(client, name_l, qtype, RESULT_CACHED)
            # 把缓存期间流逝的秒数从各应答 TTL 里扣掉
            stored_at = _expires - min_ttl
            elapsed = max(0, now - stored_at)
            return self._patch_id_adjust_ttl(resp, query_id, elapsed)
        if cached:
            with self._cache_lock:
                self._cache.pop(cache_key, None)

        # 4. 上游（顺序优先 / 并行最快）
        start = time.monotonic()
        resp, used = self._query_upstreams(data)
        elapsed_ms = round((time.monotonic() - start) * 1000, 1)
        if resp is None:
            self.stats.count_failed()
            self.stats.query_log.add(client, name_l, qtype, RESULT_FAIL,
                                     ms=elapsed_ms, upstream=used)
            return self._build_servfail(query_id, question)
        self._store_cache(cache_key, resp, q_end)
        self.stats.query_log.add(client, name_l, qtype, RESULT_ALLOW,
                                 upstream=used, ms=elapsed_ms)
        return self._patch_id(resp, query_id)

    def _query_upstreams(self, data):
        """按策略查询上游，返回 (应答报文|None, 上游名)。"""
        ordered = self._ordered_upstreams()
        if not ordered:
            return None, ""
        if self.upstream_strategy == STRATEGY_PARALLEL and len(ordered) > 1:
            return self._query_parallel(ordered, data)
        for up in ordered:
            resp = self._query_one(up, data)
            if resp is not None:
                return resp, up.name
        return None, ""

    def _query_one(self, up, data):
        start = time.monotonic()
        try:
            resp = up.query(data, timeout=self.upstream_timeout)
        except Exception as e:
            logger.debug(f"上游 {up.name}({up.proto}) 查询失败: {e}")
            self.stats.count_upstream(up.name, False)
            return None
        if len(resp) < 12:
            self.stats.count_upstream(up.name, False)
            return None
        latency = round((time.monotonic() - start) * 1000, 1)
        self.stats.count_upstream(up.name, True, latency)
        return resp

    def _query_parallel(self, ordered, data):
        """并发问前几个上游，谁先回有效应答就用谁（AdGuard 的并行请求策略）。"""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        workers = min(3, len(ordered))
        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dns-up")
        try:
            futures = {pool.submit(self._query_one, up, data): up for up in ordered[:workers]}
            for fut in as_completed(futures, timeout=self.upstream_timeout + 2):
                up = futures[fut]
                try:
                    resp = fut.result()
                except Exception:
                    continue
                if resp is not None:
                    return resp, up.name
        except Exception as e:
            logger.debug(f"并行上游查询异常: {e}")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return None, ""

    def _ordered_upstreams(self):
        with self._state_lock:
            ups = list(self.upstreams)
            sel = self.selected
        if not ups:
            return []
        sel = min(sel, len(ups) - 1)
        return [ups[sel]] + ups[:sel] + ups[sel + 1:]

    def set_upstreams(self, upstream_list, selected=0):
        with self._state_lock:
            self.upstreams = list(upstream_list)
            self.selected = max(0, min(selected, len(self.upstreams) - 1)) if self.upstreams else 0

    def get_selected_upstream(self):
        with self._state_lock:
            if not self.upstreams:
                return None
            return self.upstreams[min(self.selected, len(self.upstreams) - 1)]

    # ---------------- 过滤规则 ----------------
    def _load_defaults(self):
        lines = [d.strip().lower().rstrip(".") for d in DEFAULT_BLOCKLIST
                 if d.strip() and not any(ch in d for ch in "* /")]
        self._file_lines = lines
        self._rebuild_rules()

    def _apply_blocklists(self, exact, suffix):
        """兼容旧接口：直接给定精确集与后缀集，重建规则。"""
        self._file_lines = sorted({d.strip().lower().rstrip(".") for d in (exact | suffix) if d})
        self._rebuild_rules()

    def _rebuild_rules(self):
        rules = compile_rules(self._file_lines, self._extra_lines)
        self._rules = rules
        logger.info(f"DNS 过滤规则已加载：{rules.count} 条"
                    f"（后缀 {rules.suffix_count}，例外 {rules.allow_count}）")
        return rules

    def set_filter_sources(self, list_lines=None, custom_lines=None):
        """替换「过滤器列表 + 自定义规则」并重建规则集。"""
        lines = list(list_lines or []) + list(custom_lines or [])
        self._extra_lines = lines
        return self._rebuild_rules()

    def reload_blocklist(self):
        """从 blocklist_path 重新加载黑名单。支持 hosts / 纯域名 / AdGuard 语法。"""
        try:
            if self.blocklist_path and os.path.exists(self.blocklist_path):
                with open(self.blocklist_path, "r", encoding="utf-8", errors="ignore") as f:
                    self._file_lines = [ln.strip() for ln in f
                                        if ln.strip() and not ln.strip().startswith("#")]
            else:
                self._load_defaults()
                return self._rules
        except Exception as e:
            logger.error(f"加载 DNS 黑名单失败: {e}")
            return self._rules
        return self._rebuild_rules()

    def _match_block(self, domain):
        blocked, rule = self._rules.match(domain)
        return rule if blocked else None

    @property
    def rules(self):
        return self._rules

    # ---------------- DNS 重写 ----------------
    def set_rewrites(self, mapping):
        """mapping: {domain: ip}；支持 *.example.com 形式的通配。"""
        clean = {}
        for host, ip in (mapping or {}).items():
            host = (host or "").strip().lower().rstrip(".")
            if not host or not ip_to_rdata(ip):
                continue
            clean[host] = (ip or "").strip()
        with self._state_lock:
            self.rewrites = clean
        return len(clean)

    def _match_rewrite(self, domain):
        with self._state_lock:
            mapping = self.rewrites
        if not mapping:
            return None
        if domain in mapping:
            return mapping[domain]
        idx = domain.find(".")
        while idx != -1:
            parent = domain[idx + 1:]
            if f"*.{parent}" in mapping:
                return mapping[f"*.{parent}"]
            idx = domain.find(".", idx + 1)
        return None

    # ---------------- 缓存 ----------------
    def _store_cache(self, key, resp, q_end):
        try:
            min_ttl, _ = self._walk_answers(resp, q_end, rewrite=False)
            if min_ttl is None:
                min_ttl = 300
            if min_ttl <= 0:
                return
            min_ttl = max(int(self.cache_min_ttl), min(int(self.cache_max_ttl), int(min_ttl)))
            with self._cache_lock:
                if len(self._cache) >= self.CACHE_MAX:
                    self._cache.clear()
                self._cache[key] = (time.monotonic() + min_ttl, resp, min_ttl)
        except Exception:
            pass

    def clear_cache(self):
        with self._cache_lock:
            self._cache.clear()

    def cache_size(self):
        with self._cache_lock:
            return len(self._cache)

    def _walk_answers(self, data, q_end, rewrite, elapsed=0.0):
        """遍历应答记录。rewrite=True 时把 TTL 就地减去 elapsed。
        返回 (最小 TTL, 记录条数)。"""
        if len(data) < 12:
            return None, 0
        _id, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        off = q_end
        min_ttl = None
        count = 0
        for _ in range(an):
            if off >= len(data):
                break
            _name, off = self._read_name(data, off)
            if off + 10 > len(data):
                break
            (rr_type,) = struct.unpack(">H", data[off:off + 2])
            (ttl,) = struct.unpack(">I", data[off + 4:off + 8])
            (rdlen,) = struct.unpack(">H", data[off + 8:off + 10])
            if rewrite:
                new_ttl = max(0, ttl - int(elapsed))
                struct.pack_into(">I", data, off + 4, new_ttl)
                ttl = new_ttl
            min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
            off += 10 + rdlen
            count += 1
        return min_ttl, count

    # ---------------- 报文构造 ----------------
    @staticmethod
    def _read_name(data, off):
        """读取（可能带压缩指针的）域名。返回 (name, 记录头起始偏移)。"""
        labels = []
        jump_origin = None
        jumps = 0
        while True:
            if off >= len(data):
                raise ValueError("域名越界")
            length = data[off]
            if length == 0:
                off += 1
                break
            if length & 0xC0 == 0xC0:
                if off + 1 >= len(data):
                    raise ValueError("指针越界")
                ptr = ((length & 0x3F) << 8) | data[off + 1]
                if jump_origin is None:
                    jump_origin = off + 2
                off = ptr
                jumps += 1
                if jumps > 32:
                    raise ValueError("压缩指针循环")
                continue
            if length > 63 or off + 1 + length > len(data):
                raise ValueError("标签非法")
            labels.append(data[off + 1:off + 1 + length].decode("ascii", "replace"))
            off += 1 + length
        return ".".join(labels), jump_origin if jump_origin is not None else off

    @staticmethod
    def _parse_question(data):
        """解析问题区。返回 (name, qtype, qclass, 问题区结束偏移)。"""
        name, off = DnsFilter._read_name(data, 12)
        if off + 4 > len(data):
            raise ValueError("问题区不完整")
        qtype, qclass = struct.unpack(">HH", data[off:off + 4])
        return name, qtype, qclass, off + 4

    @staticmethod
    def _patch_id(resp, query_id):
        out = bytearray(resp)
        struct.pack_into(">H", out, 0, query_id)
        return bytes(out)

    def _patch_id_adjust_ttl(self, resp, query_id, elapsed):
        out = bytearray(resp)
        struct.pack_into(">H", out, 0, query_id)
        try:
            self._walk_answers(out, self._question_end(out), rewrite=True, elapsed=elapsed)
        except Exception:
            pass
        return bytes(out)

    @staticmethod
    def _question_end(data):
        _name, off = DnsFilter._read_name(data, 12)
        return off + 4

    @staticmethod
    def _build_header(query_id, rcode=0, ancount=0):
        flags = 0x8180 | rcode  # QR|RD|RA + rcode
        return struct.pack(">HHHHHH", query_id, flags, 1, ancount, 0, 0)

    def _build_blocked(self, query_id, question_bytes, qtype):
        """构造拦截应答：A→0.0.0.0，AAAA→::，其他类型→NXDOMAIN。"""
        if self.block_action == "nxdomain":
            return self._build_header(query_id, rcode=3)
        if qtype == QTYPE_A:
            rdata = b"\x00\x00\x00\x00"
            rr_type = QTYPE_A
        elif qtype == QTYPE_AAAA:
            rdata = b"\x00" * 16
            rr_type = QTYPE_AAAA
        else:
            return self._build_header(query_id, rcode=3)
        answer = (b"\xc0\x0c" + struct.pack(">HHIH", rr_type, 1, 10, len(rdata)) + rdata)
        return self._build_header(query_id, ancount=1) + question_bytes + answer

    def _build_rewrite(self, query_id, question_bytes, qtype, ip_text):
        """按重写目标构造应答；类型不匹配时返回空应答（NODATA）。"""
        parsed = ip_to_rdata(ip_text)
        if not parsed:
            return None
        rr_type, rdata = parsed
        if qtype != rr_type:
            # 有 A 重写但查的是 AAAA（或反之）→ 回空应答，避免回落真实 IP
            return self._build_header(query_id) + question_bytes
        ttl = max(10, min(600, int(self.cache_max_ttl) or 600))
        answer = (b"\xc0\x0c" + struct.pack(">HHIH", rr_type, 1, ttl, len(rdata)) + rdata)
        return self._build_header(query_id, ancount=1) + question_bytes + answer

    @staticmethod
    def _build_servfail(query_id, question_bytes):
        return DnsFilter._build_header(query_id, rcode=2) + question_bytes

    # ---------------- 订阅更新 ----------------
    def update_subscription(self, url="https://anti-ad.net/hosts", timeout=30):
        """下载 hosts 格式订阅并转为黑名单文件，返回（条数, 错误信息）。"""
        try:
            resp = requests.get(url, timeout=timeout,
                                headers={"User-Agent": "SkyGuard-DnsFilter/1.0"})
            resp.raise_for_status()
            domains = set()
            for line in resp.text.splitlines():
                line = line.split("#", 1)[0].strip().lower()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                    domain = parts[1]
                elif len(parts) == 1 and "." in parts[0]:
                    domain = parts[0]
                else:
                    continue
                domain = domain.lstrip("*.").rstrip(".")
                if domain and not domain.replace(".", "").replace("-", "").replace(":", "").isalnum():
                    continue
                if domain:
                    domains.add(domain)
            if not domains:
                return 0, "订阅内容为空"
            os.makedirs(os.path.dirname(self.blocklist_path), exist_ok=True)
            with open(self.blocklist_path, "w", encoding="utf-8") as f:
                f.write(f"# SkyGuard DNS 黑名单（来源: {url}，更新于 {time.strftime('%Y-%m-%d %H:%M')}）\n")
                f.write("\n".join(sorted(domains)) + "\n")
            self.reload_blocklist()
            logger.info(f"DNS 黑名单订阅更新完成：{len(domains)} 条")
            return len(domains), None
        except Exception as e:
            logger.error(f"更新 DNS 黑名单订阅失败: {e}")
            return 0, str(e)

    # ---------------- 配置序列化 ----------------
    def export_config(self):
        with self._state_lock:
            return {
                "port": self.port,
                "block_action": self.block_action,
                "selected": self.selected,
                "strategy": self.upstream_strategy,
                "upstreams": [u.to_dict() for u in self.upstreams],
                "rewrites": dict(self.rewrites),
            }

    def import_config(self, data):
        ups = [Upstream.from_dict(d) for d in data.get("upstreams", [])]
        with self._state_lock:
            self.upstreams = ups
            self.selected = int(data.get("selected", 0))
            self.port = int(data.get("port", self.port))
            self.block_action = data.get("block_action", self.block_action)
            strategy = data.get("strategy", self.upstream_strategy)
            if strategy in (STRATEGY_SEQUENTIAL, STRATEGY_PARALLEL):
                self.upstream_strategy = strategy
        if isinstance(data.get("rewrites"), dict):
            self.set_rewrites(data["rewrites"])
