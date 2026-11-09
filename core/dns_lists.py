#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""DNS 过滤器列表管理（AdGuard Home 的 Filters 面板）。

每个列表 = 一条远程 URL（也支持 file:// 与本地路径），下载后缓存到
`~/.skyguard/dns/lists/`，离线启动也能用上次的缓存。

配置里保存的是列表元信息（name/url/enabled/interval/count/updated），
规则内容不写进主配置，避免配置文件膨胀。

规则一律按 **DNS 层严格模式** 编译（见 core.dns_rules 的 strict）：
作用域修饰符（`$domain=`）与带路径的规则在 DNS 层无法正确表达，直接丢弃。
列表的 count 记录的是「真正生效的条数」，不是原始行数。
"""

import hashlib
import os
import threading
import time

from core.dns_rules import RuleSet, parse_filter_list
from utils.logger import logger

# 默认订阅：天影规则聚合（广告拦截 + 白名单），DNS 层可直接生效
DEFAULT_LISTS = [
    {"name": "天影规则 · 广告拦截", "url": "https://testingcf.jsdelivr.net/gh/xiaolei7172/ADS@master/data/rules/adblock.txt",
     "enabled": True, "interval": 24},
    {"name": "天影规则 · 白名单（误杀放行）", "url": "https://testingcf.jsdelivr.net/gh/xiaolei7172/ADS@master/data/rules/allow.txt",
     "enabled": True, "interval": 24},
]

# 默认列表版本：升级这个数字，老用户下次启动会补上新增的默认列表（已删除的不会被硬塞回来）
DEFAULT_LISTS_VERSION = 2

# 编译结果缓存：{url: (mtime_ns, size, state)}，避免每次重建都重解析几十万行
_STATE_CACHE = {}
_STATE_LOCK = threading.Lock()


def list_cache_dir():
    return os.path.join(os.path.expanduser("~"), ".skyguard", "dns", "lists")


def list_cache_path(url):
    digest = hashlib.sha1((url or "").encode("utf-8")).hexdigest()[:16]
    return os.path.join(list_cache_dir(), f"{digest}.txt")


def normalize_entry(entry):
    """补全列表条目的默认值。"""
    url = str(entry.get("url", "")).strip()
    if not url:
        return None
    return {
        "name": str(entry.get("name", "")).strip() or url,
        "url": url,
        "enabled": bool(entry.get("enabled", True)),
        "interval": max(0, int(entry.get("interval", 24) or 0)),
        "count": max(0, int(entry.get("count", 0) or 0)),
        "updated": max(0, int(entry.get("updated", 0) or 0)),
    }


def read_list_text(url):
    """读取列表内容：本地路径 / file:// / 远程 URL。远程失败抛异常。"""
    url = (url or "").strip()
    if not url:
        raise ValueError("列表地址为空")
    if url.startswith("file://"):
        with open(url[7:], "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    if os.path.exists(url):
        with open(url, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    import requests        # 懒导入：只有真的要从网上拉列表才需要 requests
    resp = requests.get(url, timeout=20,
                        headers={"User-Agent": "SkyGuard-DNS/1.2 (+adguard-compatible)"})
    resp.raise_for_status()
    return resp.text


def compile_filter_lines(lines):
    """把规则行编译成 DNS 层可用的 RuleSet（严格模式）。"""
    ruleset = RuleSet()
    ruleset.extend(lines, strict=True)
    return ruleset


def update_list(entry, timeout=20):
    """下载并缓存一个列表，返回 (条数, 错误)。失败时保留旧缓存。

    成功时会把 count / updated / name 回写到传入的 entry 字典，方便界面直接刷新。
    条数是「DNS 层实际生效」的数量：作用域修饰符与带路径的规则不计入。
    """
    norm = normalize_entry(entry)
    if not norm:
        return 0, "列表地址为空"
    url = norm["url"]
    try:
        text = read_list_text(url)
        rules = parse_filter_list(text)
        if not rules:
            return 0, "列表内容为空"
        compiled = compile_filter_lines(rules)
        if not compiled.count:
            return 0, "列表内没有可直接用于 DNS 的规则"
        os.makedirs(list_cache_dir(), exist_ok=True)
        path = list_cache_path(url)
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# {norm['name']}\n# 来源 {url}\n# 更新于 {time.strftime('%Y-%m-%d %H:%M')}\n")
            f.write("\n".join(rules) + "\n")
        with _STATE_LOCK:
            _STATE_CACHE.pop(url, None)
        norm["count"] = compiled.count
        norm["updated"] = int(time.time())
        if isinstance(entry, dict):
            entry.update({"name": norm["name"], "count": norm["count"],
                          "updated": norm["updated"]})
        logger.info(f"过滤器列表已更新：{norm['name']}（DNS 生效 {compiled.count} 条，"
                    f"跳过 {compiled.skipped} 条作用域/路径规则）")
        return compiled.count, None
    except Exception as e:
        logger.warning(f"更新过滤器列表失败 {url}: {e}")
        return 0, str(e)


def load_cached_rules(entry):
    """读取某个列表的缓存规则行；没有缓存返回空列表。"""
    entry = normalize_entry(entry)
    if not entry:
        return []
    path = list_cache_path(entry["url"])
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return parse_filter_list(f.read())
    except OSError:
        return []


def load_cached_state(entry):
    """读取列表缓存并编译成可复用的 state（按 文件修改时间 + 大小 缓存）。

    返回 RuleSet.state() 的结果；没有缓存或读取失败返回 None。
    """
    entry = normalize_entry(entry)
    if not entry:
        return None
    url = entry["url"]
    path = list_cache_path(url)
    try:
        st = os.stat(path)
    except OSError:
        return None
    sig = (st.st_mtime_ns, st.st_size)
    with _STATE_LOCK:
        hit = _STATE_CACHE.get(url)
        if hit and hit[0] == sig:
            return hit[1]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return None
    compiled = compile_filter_lines(parse_filter_list(text))
    state = compiled.state() if compiled.count else None
    with _STATE_LOCK:
        _STATE_CACHE[url] = (sig, state)
    return state


def merged_states(entries):
    """把启用中的列表编译结果合并起来，供 DnsFilter 直接吸收。

    Returns:
        (states, counts)：states 为 state 列表；counts 为 {url: 生效条数}
    """
    states, counts = [], {}
    for raw in entries or []:
        entry = normalize_entry(raw)
        if not entry or not entry["enabled"]:
            continue
        state = load_cached_state(entry)
        if not state:
            counts[entry["url"]] = 0
            continue
        states.append(state)
        counts[entry["url"]] = int(state.get("lines", 0) or 0)
    return states, counts


def merge_default_lists(entries, version=0):
    """把新增的默认列表补进配置（只补缺失的 URL，不动用户已有条目）。

    返回 (entries, added)：added 是本次新增的条目列表。version 达到
    DEFAULT_LISTS_VERSION 时视为已补齐，不会再补，避免用户删掉后被硬塞回来。
    """
    current = [normalize_entry(e) for e in (entries or [])]
    current = [e for e in current if e]
    if int(version or 0) >= DEFAULT_LISTS_VERSION:
        return current, []
    have = {e["url"] for e in current}
    added = []
    for d in DEFAULT_LISTS:
        if d["url"] in have:
            continue
        entry = normalize_entry(dict(d, count=0, updated=0))
        if entry:
            added.append(entry)
    return current + added, added


def merged_rules(entries, cache=None):
    """把启用中的列表规则合并成一个大列表（供 RuleSet 编译）。

    Args:
        entries: 配置里的列表条目
        cache:   {url: [lines]} 可选，避免重复读盘
    """
    lines = []
    counts = {}
    for raw in entries or []:
        entry = normalize_entry(raw)
        if not entry or not entry["enabled"]:
            continue
        cached = None
        if cache is not None:
            cached = cache.get(entry["url"])
        if cached is None:
            cached = load_cached_rules(entry)
            if cache is not None:
                cache[entry["url"]] = cached
        counts[entry["url"]] = len(cached)
        lines.extend(cached)
    return lines, counts


def is_due(entry, now=None):
    """列表是否到了自动更新时间（interval 单位：小时，0 表示不自动更新）。"""
    entry = normalize_entry(entry)
    if not entry or not entry["enabled"]:
        return False
    if not entry["interval"]:
        return False
    now = time.time() if now is None else now
    if not entry["updated"]:
        return True
    return now - entry["updated"] >= entry["interval"] * 3600


def format_updated(ts):
    if not ts:
        return "从未更新"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(ts)))
