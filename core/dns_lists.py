#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""DNS 过滤器列表管理（AdGuard Home 的 Filters 面板）。

每个列表 = 一条远程 URL（也支持 file:// 与本地路径），下载后缓存到
`~/.skyguard/dns/lists/`，离线启动也能用上次的缓存。

配置里保存的是列表元信息（name/url/enabled/interval/count/updated），
规则内容不写进主配置，避免配置文件膨胀。
"""

import hashlib
import os
import time

import requests

from core.dns_rules import parse_filter_list
from utils.logger import logger

DEFAULT_LISTS = [
    {"name": "AdGuard 中文广告拦截", "url": "https://anti-ad.net/adguard.txt",
     "enabled": True, "interval": 24},
]


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
    resp = requests.get(url, timeout=20,
                        headers={"User-Agent": "SkyGuard-DNS/1.2 (+adguard-compatible)"})
    resp.raise_for_status()
    return resp.text


def update_list(entry, timeout=20):
    """下载并缓存一个列表，返回 (条数, 错误)。失败时保留旧缓存。

    成功时会把 count / updated / name 回写到传入的 entry 字典，方便界面直接刷新。
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
        os.makedirs(list_cache_dir(), exist_ok=True)
        path = list_cache_path(url)
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# {norm['name']}\n# 来源 {url}\n# 更新于 {time.strftime('%Y-%m-%d %H:%M')}\n")
            f.write("\n".join(rules) + "\n")
        norm["count"] = len(rules)
        norm["updated"] = int(time.time())
        if isinstance(entry, dict):
            entry.update({"name": norm["name"], "count": norm["count"],
                          "updated": norm["updated"]})
        logger.info(f"过滤器列表已更新：{norm['name']}（{len(rules)} 条）")
        return len(rules), None
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
