#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
代理节点与订阅解析

支持两种订阅格式：
  1. Clash 配置（proxies: 列表）
  2. 通用订阅（base64 编码的 ss:// / trojan:// / socks5:// / http:// 列表）

当前可直接使用的协议：Shadowsocks(AEAD)、Trojan、HTTP、SOCKS5。
vmess / vless / hysteria / tuic 等需要额外协议栈，会被识别但标记为不支持，
界面上如实提示，不做假连接。
"""

import base64
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

import yaml

from utils.logger import logger

SUPPORTED_TYPES = ("ss", "trojan", "http", "socks5")
# 能识别但内核暂不实现的协议，导入时给出明确提示而不是静默丢弃
KNOWN_UNSUPPORTED = {
    "vmess": "VMess 需要额外协议栈",
    "vless": "VLESS 需要额外协议栈",
    "ssr": "SSR 为旧版协议",
    "hysteria": "Hysteria 基于 QUIC",
    "hysteria2": "Hysteria2 基于 QUIC",
    "tuic": "TUIC 基于 QUIC",
    "wireguard": "WireGuard 为 VPN 协议",
    "snell": "Snell 为私有协议",
    "ssh": "SSH 隧道",
}
SS_CIPHERS = (
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "aes-192-gcm",
)


def _b64decode(data):
    """宽松 base64 解码：自动补 padding，兼容 url-safe。"""
    if isinstance(data, str):
        data = data.strip().encode("utf-8")
    data = data.replace(b"\n", b"").replace(b"\r", b"")
    pad = (-len(data)) % 4
    data += b"=" * pad
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(data)
        except Exception:
            continue
    return b""


def _split_host_port(text):
    """拆分 host:port，兼容 [IPv6]:443。"""
    text = text.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port or 443)
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host, int(port or 443)
    return text, 443


@dataclass
class ProxyNode:
    """一个代理节点。uid 用于配置里稳定选中某一个节点。"""

    name: str = ""
    type: str = "ss"
    server: str = ""
    port: int = 0
    password: str = ""
    cipher: str = ""
    username: str = ""
    sni: str = ""
    skip_cert_verify: bool = False
    subscription: str = ""

    def __post_init__(self):
        self.type = (self.type or "").strip().lower()
        self.server = (self.server or "").strip()
        try:
            self.port = int(self.port or 0)
        except (TypeError, ValueError):
            self.port = 0
        if not self.name:
            self.name = f"{self.server}:{self.port}"

    @property
    def uid(self):
        return f"{self.type}://{self.server}:{self.port}#{self.name}"

    @property
    def supported(self):
        return self.type in SUPPORTED_TYPES and bool(self.server) and self.port > 0

    @property
    def server_label(self):
        return f"{self.server}:{self.port}"

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        if not isinstance(d, dict):
            return None
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in allowed})


# ----------------------------------------------------------------------
# URI 解析
# ----------------------------------------------------------------------
def parse_proxy_uri(uri):
    """解析单条代理 URI，返回 ProxyNode；无法识别返回 None。"""
    uri = (uri or "").strip()
    if not uri or "://" not in uri:
        return None
    scheme = uri.split("://", 1)[0].lower()
    try:
        if scheme == "ss":
            return _parse_ss(uri)
        if scheme == "trojan":
            return _parse_trojan(uri)
        if scheme in ("socks5", "socks", "socks5h"):
            return _parse_socks(uri)
        if scheme in ("http", "https"):
            return _parse_http(uri)
    except Exception as e:
        logger.debug(f"解析代理 URI 失败 {uri[:40]}…: {e}")
    return None


def _split_name(uri):
    """拆出 #备注 部分。"""
    body, _, tag = uri.partition("#")
    return body, unquote(tag).strip()


def _parse_ss(uri):
    body, name = _split_name(uri)
    rest = body[len("ss://"):]
    rest, _, query = rest.partition("?")
    params = parse_qs(query)

    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = _b64decode(userinfo).decode("utf-8", "ignore")
        method, _, password = userinfo.partition(":")
        host, port = _split_host_port(hostport)
    else:
        decoded = _b64decode(rest).decode("utf-8", "ignore")
        if "@" not in decoded:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)
        method, _, password = userinfo.partition(":")
        host, port = _split_host_port(hostport)

    cipher = method.strip().lower()
    if cipher not in SS_CIPHERS:
        return None
    return ProxyNode(name=name or f"{host}:{port}", type="ss", server=host, port=port,
                     password=password, cipher=cipher)


def _parse_trojan(uri):
    body, name = _split_name(uri)
    parts = urlsplit(body)
    password = unquote(parts.username or "")
    if not parts.hostname:
        return None
    params = parse_qs(parts.query)
    sni = (params.get("sni") or params.get("peer") or [""])[0]
    skip = (params.get("allowInsecure") or params.get("allow_insecure") or ["0"])[0]
    return ProxyNode(name=name or f"{parts.hostname}:{parts.port or 443}", type="trojan",
                     server=parts.hostname, port=parts.port or 443, password=password,
                     sni=sni, skip_cert_verify=str(skip).lower() in ("1", "true"))


def _parse_socks(uri):
    body, name = _split_name(uri)
    parts = urlsplit(body)
    if not parts.hostname:
        return None
    return ProxyNode(name=name or f"{parts.hostname}:{parts.port or 1080}", type="socks5",
                     server=parts.hostname, port=parts.port or 1080,
                     username=unquote(parts.username or ""), password=unquote(parts.password or ""))


def _parse_http(uri):
    body, name = _split_name(uri)
    parts = urlsplit(body)
    if not parts.hostname:
        return None
    return ProxyNode(name=name or f"{parts.hostname}:{parts.port or 8080}", type="http",
                     server=parts.hostname, port=parts.port or 8080,
                     username=unquote(parts.username or ""), password=unquote(parts.password or ""))


# ----------------------------------------------------------------------
# Clash 配置解析
# ----------------------------------------------------------------------
def _node_from_clash(entry, subscription=""):
    """把 Clash proxies 里的一条转换成 ProxyNode。"""
    if not isinstance(entry, dict):
        return None
    ptype = str(entry.get("type", "")).strip().lower()
    if ptype not in SUPPORTED_TYPES:
        return None
    node = ProxyNode(
        name=str(entry.get("name") or f"{entry.get('server')}:{entry.get('port')}").strip(),
        type=ptype,
        server=str(entry.get("server", "")).strip(),
        port=entry.get("port") or 0,
        password=str(entry.get("password") or ""),
        cipher=str(entry.get("cipher") or "").lower(),
        username=str(entry.get("username") or ""),
        sni=str(entry.get("sni") or entry.get("servername") or ""),
        skip_cert_verify=bool(entry.get("skip-cert-verify", False)),
        subscription=subscription,
    )
    if ptype == "ss" and node.cipher not in SS_CIPHERS:
        return None
    return node if node.supported else None


def parse_subscription(text, subscription=""):
    """
    解析订阅内容。

    Returns:
        (nodes, skipped)  skipped 为 {协议: 数量}，用于界面提示哪些节点没导入
    """
    nodes = []
    skipped = {}
    text = (text or "").lstrip("\ufeff").strip()
    if not text:
        return nodes, skipped

    # --- Clash YAML ---
    if "proxies:" in text:
        try:
            data = yaml.safe_load(text)
        except Exception as e:
            logger.warning(f"Clash 订阅 YAML 解析失败: {e}")
            data = None
        if isinstance(data, dict):
            entries = data.get("proxies") or []
            if isinstance(entries, list):
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    node = _node_from_clash(entry, subscription)
                    if node:
                        nodes.append(node)
                    else:
                        ptype = str(entry.get("type", "unknown")).lower()
                        skipped[ptype] = skipped.get(ptype, 0) + 1
                if nodes or skipped:
                    _dedupe(nodes)
                    return nodes, skipped

    # --- base64 / 明文 URI 列表 ---
    raw = text
    if "://" not in raw:
        decoded = _b64decode(raw).decode("utf-8", "ignore")
        if "://" in decoded:
            raw = decoded
    for line in re.split(r"[\r\n]+", raw):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        node = parse_proxy_uri(line)
        if node and node.supported:
            node.subscription = subscription
            nodes.append(node)
        elif "://" in line:
            scheme = line.split("://", 1)[0].lower()
            skipped[scheme] = skipped.get(scheme, 0) + 1
    _dedupe(nodes)
    return nodes, skipped


def _dedupe(nodes):
    seen = set()
    unique = []
    for n in nodes:
        key = (n.type, n.server, n.port, n.password, n.name)
        if key in seen:
            continue
        seen.add(key)
        unique.append(n)
    nodes[:] = unique


def fetch_subscription(url, timeout=20):
    """拉取订阅文本；也支持本地文件路径，方便导入已有配置。"""
    text, _meta = fetch_subscription_ex(url, timeout=timeout)
    return text


def parse_subscription_userinfo(value):
    """解析订阅响应头 subscription-userinfo（Clash Verge 同款）。

    形如：upload=123; download=456; total=107374182400; expire=1767225600
    返回 {'upload','download','total','expire'}（缺省为 0）。
    """
    info = {"upload": 0, "download": 0, "total": 0, "expire": 0}
    for part in str(value or "").split(";"):
        key, _, val = part.partition("=")
        key = key.strip().lower()
        if key not in info:
            continue
        try:
            info[key] = int(float(val.strip()))
        except (TypeError, ValueError):
            continue
    return info


def parse_subscription_headers(headers):
    """从订阅响应头提取元信息：流量、到期、建议更新间隔、标题。"""
    norm = {str(k).lower(): v for k, v in dict(headers or {}).items()}
    meta = parse_subscription_userinfo(norm.get("subscription-userinfo", ""))
    meta["info_present"] = bool(norm.get("subscription-userinfo"))
    interval = norm.get("profile-update-interval", "")
    try:
        meta["interval"] = max(0, int(float(interval)))
    except (TypeError, ValueError):
        meta["interval"] = 0
    title = ""
    disposition = norm.get("content-disposition", "")
    if "filename*=" in disposition:
        title = disposition.split("filename*=", 1)[1].split(";")[0].strip()
        if "''" in title:
            title = title.split("''", 1)[1]
        title = unquote(title)
    elif 'filename="' in disposition:
        title = disposition.split('filename="', 1)[1].split('"', 1)[0]
    meta["title"] = title
    return meta


def format_traffic(byte_count):
    """字节数转人类可读（Clash Verge 的流量显示口径）。"""
    try:
        value = float(byte_count or 0)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return "-"


def fetch_subscription_ex(url, timeout=20):
    """拉取订阅并返回 (文本, 元信息)。

    元信息来自响应头：流量用量、到期时间、更新间隔、配置标题。
    本地文件路径或 file:// 时元信息为空。
    """
    url = (url or "").strip()
    if not url:
        raise ValueError("订阅地址为空")
    if url.startswith("file://"):
        path = url[7:]
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(), {"local": True}
    if os.path.exists(url):
        with open(url, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(), {"local": True}

    import requests

    headers = {
        "User-Agent": "clash-verge/v1.6.5",
        "Accept": "*/*",
    }
    resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    resp.raise_for_status()
    meta = parse_subscription_headers(resp.headers)
    meta["status"] = resp.status_code
    return resp.text, meta


# ----------------------------------------------------------------------
# 节点存储（订阅 + 手动添加），与主配置分离避免配置膨胀
# ----------------------------------------------------------------------
def default_store_path():
    return os.path.join(os.path.expanduser("~"), ".skyguard", "proxy_nodes.json")


class NodeStore:
    """节点与订阅的本地存储。"""

    def __init__(self, path=None):
        self.path = path or default_store_path()
        self.subscriptions = []   # [{name, url, updated, nodes: [dict]}]
        self.manual = []          # [dict]
        self._cache = None        # 节点对象列表缓存，改动时失效
        self._index = {}
        self.load()

    # -- 读写 --------------------------------------------------------
    def load(self):
        try:
            if not os.path.exists(self.path):
                return
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            subs = data.get("subscriptions")
            if isinstance(subs, list):
                self.subscriptions = [s for s in subs if isinstance(s, dict)]
            manual = data.get("manual")
            if isinstance(manual, list):
                self.manual = [m for m in manual if isinstance(m, dict)]
        except Exception as e:
            logger.warning(f"读取代理节点文件失败: {e}")
        finally:
            self._invalidate()

    def _invalidate(self):
        self._cache = None
        self._index = {}

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump({"subscriptions": self.subscriptions, "manual": self.manual},
                          f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"保存代理节点失败: {e}")
            return False

    # -- 查询 --------------------------------------------------------
    def all_nodes(self):
        """返回节点对象列表。结果缓存，代理每条连接都会调用，不能每次都重建。"""
        if self._cache is not None:
            return self._cache
        nodes = []
        index = {}
        for m in self.manual:
            node = ProxyNode.from_dict(m)
            if node and node.supported:
                nodes.append(node)
                index.setdefault(node.uid, node)
        for sub in self.subscriptions:
            if not sub.get("enabled", True):
                continue
            name = sub.get("name") or sub.get("url", "")
            for item in sub.get("nodes", []):
                node = ProxyNode.from_dict(item)
                if node and node.supported:
                    if not node.subscription:
                        node.subscription = name
                    nodes.append(node)
                    index.setdefault(node.uid, node)
        self._cache = nodes
        self._index = index
        return nodes

    def find(self, uid):
        if self._cache is None:
            self.all_nodes()
        return self._index.get(uid)

    def subscription_names(self):
        return [s.get("name") or s.get("url", "") for s in self.subscriptions]

    def subscription(self, name_or_url):
        """按名称或地址取订阅条目（含 enabled / interval / meta）。"""
        for sub in self.subscriptions:
            if name_or_url in (sub.get("name"), sub.get("url")):
                return sub
        return None

    def enabled_subscriptions(self):
        return [s for s in self.subscriptions if s.get("enabled", True)]

    def due_subscriptions(self, now=None):
        """到更新时间的订阅列表（interval 单位：分钟，0 表示不自动更新）。"""
        now = time.time() if now is None else now
        due = []
        for sub in self.subscriptions:
            if not sub.get("enabled", True):
                continue
            interval = int(sub.get("interval", 0) or 0)
            if interval <= 0:
                continue
            updated = int(sub.get("updated", 0) or 0)
            if not updated or now - updated >= interval * 60:
                due.append(sub)
        return due

    # -- 修改 --------------------------------------------------------
    def upsert_subscription(self, name, url, nodes, meta=None, error=""):
        entry = {
            "name": name or url,
            "url": url,
            "updated": int(time.time()),
            "nodes": [n.to_dict() for n in nodes],
            "enabled": True,
            "interval": 0,
            "meta": dict(meta or {}),
            "error": error or "",
        }
        for i, sub in enumerate(self.subscriptions):
            if sub.get("url") == url or (name and sub.get("name") == name):
                # 保留用户设置：启用状态与更新间隔
                entry["enabled"] = bool(sub.get("enabled", True))
                entry["interval"] = int(sub.get("interval", 0) or 0)
                if not meta and sub.get("meta"):
                    entry["meta"] = dict(sub.get("meta"))
                entry["error"] = error or ""
                self.subscriptions[i] = entry
                break
        else:
            self.subscriptions.append(entry)
        self._invalidate()
        self.save()
        return len(nodes)

    def update_subscription_meta(self, name_or_url, meta=None, error=""):
        """只更新订阅的元信息/错误提示（不动节点列表）。"""
        sub = self.subscription(name_or_url)
        if sub is None:
            return False
        if meta:
            sub["meta"] = dict(meta)
        sub["error"] = error or ""
        sub["checked"] = int(time.time())
        self.save()
        return True

    def set_subscription_state(self, name_or_url, *, enabled=None, interval=None):
        """切换订阅启用状态或自动更新间隔（分钟）。"""
        sub = self.subscription(name_or_url)
        if sub is None:
            return False
        if enabled is not None:
            sub["enabled"] = bool(enabled)
        if interval is not None:
            sub["interval"] = max(0, int(interval))
        self._invalidate()
        self.save()
        return True

    def mark_updated(self, name_or_url, nodes=None, meta=None, error=""):
        """记录一次成功/失败的更新结果。"""
        sub = self.subscription(name_or_url)
        if sub is None:
            return False
        sub["updated"] = int(time.time())
        sub["error"] = error or ""
        if meta:
            sub["meta"] = dict(meta)
        if nodes is not None:
            sub["nodes"] = [n.to_dict() for n in nodes]
            self._invalidate()
        self.save()
        return True

    def add_subscription(self, name, url):
        """只登记订阅不解析节点（mihomo 内核自己拉取）。"""
        return self.upsert_subscription(name, url, [])

    def remove_subscription(self, name_or_url):
        before = len(self.subscriptions)
        self.subscriptions = [
            s for s in self.subscriptions
            if s.get("url") != name_or_url and s.get("name") != name_or_url
        ]
        if len(self.subscriptions) != before:
            self._invalidate()
            self.save()
            return True
        return False

    def add_manual(self, node):
        if not node or not node.supported:
            return False
        if any(n.uid == node.uid for n in self.all_nodes()):
            return False
        node.subscription = "手动添加"
        self.manual.append(node.to_dict())
        self._invalidate()
        self.save()
        return True

    def remove_node(self, uid):
        """手动节点直接删除；订阅节点记录到隐藏列表，避免下次更新又回来。"""
        before = len(self.manual)
        kept = []
        for item in self.manual:
            node = ProxyNode.from_dict(item)
            if node is not None and node.uid == uid:
                continue
            kept.append(item)
        self.manual = kept
        if len(self.manual) != before:
            self._invalidate()
            self.save()
            return True
        return False

    def node_count(self):
        return len(self.all_nodes())
