#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SkyGuard 自检：分别验证 DNS 过滤器与本地代理能否真正工作

设计约束（避免自检本身改变用户环境）：
  · 全部使用高位端口（DNS 15353 / 代理 17890 / 内核 API 19090），不需要管理员权限
  · 不改系统 DNS、不改 hosts、不设系统代理，跑完立即停服务并清理临时目录
  · 每项输出 ok / fail / skip + 说明 + 耗时，命令行与界面共用同一套逻辑
"""

import shutil
import socket
import struct
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from core import clash_kernel
from core.clash_kernel import (
    KernelNotFound, MihomoKernel, is_real_node, provider_name,
)
from core.dns_filter import (
    PROTO_UDP, QTYPE_A, DnsFilter, Upstream, build_query,
)
from core.local_proxy import (
    MODE_GLOBAL, MODE_SMART, RuleEngine, LocalProxy,
)
from core.proxy_connectors import probe_node
from core.proxy_nodes import fetch_subscription_ex, parse_subscription
from utils.logger import logger

OK, FAIL, SKIP = "ok", "fail", "skip"

CHECK_TIMEOUT = 12.0


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


def http_via_proxy(port, url, timeout=CHECK_TIMEOUT):
    """经本地代理访问一个 URL，返回 (状态码, 耗时ms)。失败抛异常。"""
    import requests

    proxy = f"http://127.0.0.1:{int(port)}"
    started = time.perf_counter()
    resp = requests.get(url, proxies={"http": proxy, "https": proxy},
                        timeout=timeout, allow_redirects=False)
    return resp.status_code, _ms(started)


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
def check_dns(port=None, upstream="223.5.5.5:53", timeout=8.0):
    """验证 DNS 过滤器：监听、上游解析、本地应答、拦截、重写、缓存、日志。"""
    items = []
    listen_port = int(port or free_port(15353))
    flt = DnsFilter(listen_hosts=["127.0.0.1"], port=listen_port,
                    block_action="blackhole")
    flt.upstream_timeout = min(4.0, timeout)
    flt.set_upstreams([Upstream("自检上游", PROTO_UDP, upstream)], 0)
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
            up = Upstream("自检上游", PROTO_UDP, upstream)
            raw = up.query(build_query("www.baidu.com", QTYPE_A, 0x1111),
                           timeout=min(4.0, timeout))
            _rcode, _count, ips = parse_a_records(raw)
            if ips:
                items.append(CheckItem("上游 DNS 直连", OK,
                                       f"{upstream} 返回 {', '.join(ips[:2])}", _ms(started)))
            else:
                items.append(CheckItem("上游 DNS 直连", FAIL,
                                       f"{upstream} 无 A 记录应答", _ms(started)))
        except Exception as e:
            items.append(CheckItem("上游 DNS 直连", FAIL,
                                   f"{upstream} 查询失败：{e}", _ms(started)))

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
        if flt.bind_errors:
            items.append(CheckItem("监听告警", SKIP, "；".join(flt.bind_errors)))
    finally:
        flt.stop()
        logger.debug(f"DNS 自检完成，端口 {listen_port} 已释放")

    return items


# ----------------------------------------------------------------------
# 订阅拉取（DNS / 代理自检共用）
# ----------------------------------------------------------------------
def fetch_subscription_nodes(url, timeout=25.0):
    """拉订阅 → 返回 (nodes, skipped, meta)。异常向上抛。"""
    text, meta = fetch_subscription_ex(url, timeout=timeout)
    nodes, skipped = parse_subscription(text, "自检订阅")
    return nodes, skipped, meta


def describe_meta(meta):
    """把订阅元信息格式化成一行。"""
    if not meta:
        return ""
    parts = []
    total = int(meta.get("total") or 0)
    used = int(meta.get("upload") or 0) + int(meta.get("download") or 0)
    if total:
        parts.append(f"流量 {used / 1024 ** 3:.1f}/{total / 1024 ** 3:.1f} GB")
    expire = int(meta.get("expire") or 0)
    if expire:
        parts.append("到期 " + time.strftime("%Y-%m-%d", time.localtime(expire)))
    if meta.get("title"):
        parts.append(str(meta["title"]))
    if meta.get("interval"):
        parts.append(f"每 {meta['interval']} 小时更新")
    return " · ".join(parts)


# ----------------------------------------------------------------------
# 代理自检：内置引擎（ss / trojan / socks5 / http）
# ----------------------------------------------------------------------
def check_proxy_local(nodes=None, subscription_url="", port=None,
                      timeout=20.0, probe_limit=12):
    """用内置引擎验证代理链路：节点测速 → 起本地代理 → 真实访问外网。"""
    items = []
    skipped_proto = {}
    meta = None

    if nodes is None:
        nodes = []
        if subscription_url:
            started = time.perf_counter()
            try:
                nodes, skipped_proto, meta = fetch_subscription_nodes(subscription_url, timeout)
                items.append(CheckItem(
                    "订阅拉取", OK,
                    f"{len(nodes)} 个可解析节点" + (f"，{describe_meta(meta)}" if meta else ""),
                    _ms(started)))
            except Exception as e:
                items.append(CheckItem("订阅拉取", FAIL, f"{type(e).__name__}: {e}",
                                       _ms(started)))
                return items

    items.append(CheckItem(
        "内置引擎支持的节点", OK if nodes else SKIP,
        (f"{len(nodes)} 个（" + "、".join(sorted({n.type for n in nodes})) + "）")
        if nodes else ("订阅里没有内置引擎支持的协议"
                       + (f"（{skipped_proto}）" if skipped_proto else "")
                       + "，请在软件里切换到 mihomo 内核模式"),
    ))
    if not nodes:
        return items

    # 节点测速
    started = time.perf_counter()
    candidates = nodes[:probe_limit]
    latencies = {}
    with ThreadPoolExecutor(max_workers=min(8, len(candidates))) as pool:
        for node, ms in zip(candidates, pool.map(lambda n: probe_node(n, timeout=6.0),
                                                 candidates)):
            if ms is not None:
                latencies[node.uid] = ms
    usable = [n for n in candidates if n.uid in latencies]
    items.append(CheckItem(
        "节点连通性", OK if usable else FAIL,
        (f"{len(usable)}/{len(candidates)} 个节点握手成功，最快 "
         f"{min(latencies.values())}ms") if usable else "全部节点握手失败",
        _ms(started)))
    if not usable:
        return items

    best = min(usable, key=lambda n: latencies[n.uid])

    # 起本地代理，全局模式确保流量一定走节点
    listen_port = int(port or free_port(17890))
    proxy = LocalProxy(host="127.0.0.1", port=listen_port, rules=[], mode=MODE_GLOBAL,
                       node_provider=lambda: best)
    started = time.perf_counter()
    if not proxy.start():
        items.append(CheckItem(f"本地代理监听 127.0.0.1:{listen_port}", FAIL,
                               "；".join(proxy.bind_errors) or "端口占用", _ms(started)))
        return items
    items.append(CheckItem(f"本地代理监听 127.0.0.1:{listen_port}", OK,
                           f"节点 {best.name}（{latencies[best.uid]}ms）", _ms(started)))

    try:
        for label, url, expect in (
            ("经代理访问 generate_204", "http://www.gstatic.com/generate_204", 204),
            ("经代理访问 GitHub", "https://github.com", 200),
        ):
            started = time.perf_counter()
            try:
                code, _ = http_via_proxy(listen_port, url)
                ok = code == expect or (label.endswith("GitHub") and code in (200, 301, 302))
                items.append(CheckItem(label, OK if ok else FAIL,
                                       f"HTTP {code}", _ms(started)))
            except Exception as e:
                items.append(CheckItem(label, FAIL, f"{type(e).__name__}: {e}",
                                       _ms(started)))
    finally:
        proxy.stop()
    return items


# ----------------------------------------------------------------------
# 代理自检：mihomo 内核（hysteria2 / vless / vmess 等全部支持）
# ----------------------------------------------------------------------
def check_proxy_kernel(subscription_url="", kernel_path="", mixed_port=None,
                       api_port=None, timeout=30.0, wait_nodes=25.0):
    """用 mihomo 内核验证订阅：启动内核 → 拉订阅 → 健康检查 → 真实访问。"""
    items = []
    try:
        path = clash_kernel.find_kernel(kernel_path)
    except KernelNotFound as e:
        return [CheckItem("mihomo 内核", SKIP,
                          f"未找到内核（{e}）；可在加速页指定路径或下载内核")]
    items.append(CheckItem("mihomo 内核", OK, path))

    work_dir = tempfile.mkdtemp(prefix="skyguard-selfcheck-")
    mixed = int(mixed_port or free_port(17890))
    api = int(api_port or free_port(19090))
    kernel = MihomoKernel(path, work_dir, mixed_port=mixed, api_port=api)

    try:
        config = clash_kernel.build_config(
            [{"name": "自检订阅", "url": subscription_url, "enabled": True}] if subscription_url else [],
            [], [], mixed_port=mixed, api_port=api, clash_mode="rule")

        started = time.perf_counter()
        try:
            kernel.start(config, timeout=15.0)
        except Exception as e:
            items.append(CheckItem("内核启动", FAIL, str(e), _ms(started)))
            return items
        try:
            ver = (kernel.version() or {}).get("version", "")
            items.append(CheckItem("内核启动", OK,
                                   f"mihomo {ver} · 混合端口 {mixed} · API {api}",
                                   _ms(started)))
        except Exception as e:
            items.append(CheckItem("内核启动", FAIL, f"API 不可用：{e}", _ms(started)))
            return items

        # 等订阅由 provider 拉取完成（provider 的节点不在顶层 /proxies 里）
        started = time.perf_counter()
        group = "🚀 节点选择"
        sub_nodes = []
        deadline = time.time() + wait_nodes
        while time.time() < deadline:
            try:
                sub_nodes = kernel.subscription_nodes()
            except Exception:
                sub_nodes = []
            if sub_nodes:
                break
            time.sleep(0.6)
        if not sub_nodes:
            items.append(CheckItem("订阅节点", FAIL,
                                   f"{wait_nodes:.0f}s 内没有从订阅拉到节点，"
                                   f"检查订阅地址、网络或内核日志", _ms(started)))
            return items
        items.append(CheckItem("订阅节点", OK,
                               f"从订阅拉到 {len(sub_nodes)} 个节点"
                               f"（{len({n['type'] for n in sub_nodes})} 种协议）",
                               _ms(started)))

        # 健康检查，挑最快节点
        started = time.perf_counter()
        provider = provider_name("自检订阅")
        latencies = {}
        try:
            latencies = kernel.provider_delay(provider, timeout_ms=5000)
        except Exception as e:
            logger.debug(f"provider 健康检查失败：{e}")
        alive = {k: int(v or 0) for k, v in latencies.items()
                 if int(v or 0) > 0 and is_real_node(k, {})}

        if not alive:
            # 部分版本拿不到 history，直接实测：逐个选中后访问 generate_204
            for cand in sub_nodes[:6]:
                try:
                    kernel.select_proxy(cand["name"], group)
                    code, ms = http_via_proxy(
                        mixed, "http://www.gstatic.com/generate_204", timeout=10.0)
                    if code == 204:
                        alive[cand["name"]] = ms
                        break
                except Exception:
                    continue
        if not alive:
            items.append(CheckItem("节点延迟测试", FAIL,
                                   "所有节点都不可用（订阅到期、节点失效或本地网络限制）",
                                   _ms(started)))
            return items

        best = min(alive, key=lambda k: alive[k])
        items.append(CheckItem("节点延迟测试", OK,
                               f"{len(alive)}/{len(sub_nodes)} 个可用，最快 {best} "
                               f"{alive[best]}ms", _ms(started)))
        try:
            kernel.select_proxy(best, group)
        except Exception as e:
            items.append(CheckItem("节点切换", SKIP, f"切换失败：{e}"))

        # 真实访问（经内核混合端口）
        for label, url, expect in (
            ("经内核访问 generate_204", "http://www.gstatic.com/generate_204", 204),
            ("经内核访问 GitHub", "https://github.com", 200),
            ("经内核访问 Google", "https://www.google.com/generate_204", 204),
        ):
            started = time.perf_counter()
            try:
                code, _ = http_via_proxy(mixed, url)
                items.append(CheckItem(label, OK if code in (expect, 200) else FAIL,
                                       f"HTTP {code}", _ms(started)))
            except Exception as e:
                items.append(CheckItem(label, FAIL, f"{type(e).__name__}: {e}",
                                       _ms(started)))
    finally:
        try:
            kernel.stop()
        except Exception:
            pass
        shutil.rmtree(work_dir, ignore_errors=True)

    return items


# ----------------------------------------------------------------------
# 一键自检
# ----------------------------------------------------------------------
def check_all(subscription_url="", kernel_path="", dns_port=None,
              proxy_port=None, use_kernel=True):
    """DNS + 代理一起自检，返回 {"dns": [...], "proxy": [...]}。"""
    result = {"dns": check_dns(port=dns_port)}
    if use_kernel:
        result["proxy"] = check_proxy_kernel(
            subscription_url=subscription_url, kernel_path=kernel_path,
            mixed_port=proxy_port)
    else:
        result["proxy"] = check_proxy_local(subscription_url=subscription_url,
                                            port=proxy_port)
    return result
