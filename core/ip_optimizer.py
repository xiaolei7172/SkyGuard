#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GitHub / Steam 加速：优选 IP 抓取与 hosts 管理

思路：
  1. 用多个公共 DoH（阿里、腾讯、Cloudflare、Google）解析同一批域名，
     不同出口会拿到不同的 CDN 边缘节点，取并集作为候选池；
  2. 对候选 IP 做 443 端口 TCP 握手测速，按延迟排序取最快的几个；
  3. 结果写入本地缓存，代理里的「加速」规则直接复用最优 IP，
     也可以一键写入 hosts（需要管理员权限），用完可还原。

只做 DNS 优选 + 直连转发，不解密也不改动任何业务数据。
"""

import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from utils import atomic_io
from utils.logger import logger

# ----------------------------------------------------------------------
# 域名清单
# ----------------------------------------------------------------------
GITHUB_DOMAINS = [
    "github.com",
    "api.github.com",
    "gist.github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "objects.githubusercontent.com",
    "user-images.githubusercontent.com",
    "avatars.githubusercontent.com",
    "camo.githubusercontent.com",
    "private-user-images.githubusercontent.com",
    "github.githubassets.com",
    "assets-cdn.github.com",
    "collector.github.com",
    "uploads.github.com",
    "github.global.ssl.fastly.net",
    "github.map.fastly.net",
    "ghcr.io",
    "npm.pkg.github.com",
    "maven.pkg.github.com",
]

STEAM_DOMAINS = [
    "store.steampowered.com",
    "api.steampowered.com",
    "login.steampowered.com",
    "checkout.steampowered.com",
    "help.steampowered.com",
    "steamcommunity.com",
    "www.steamcommunity.com",
    "media.steampowered.com",
    "cdn.akamai.steamstatic.com",
    "cdn.cloudflare.steamstatic.com",
    "cdn.fastly.steamstatic.com",
    "community.cloudflare.steamstatic.com",
    "shared.cloudflare.steamstatic.com",
    "shared.fastly.steamstatic.com",
    "client-update.akamai.steamstatic.com",
    "steamcdn-a.akamaihd.net",
]

DOMAIN_GROUPS = {
    "github": ("GitHub", GITHUB_DOMAINS),
    "steam": ("Steam", STEAM_DOMAINS),
}

# 多个 DoH 出口，出口不同拿到的边缘节点也不同
DOH_PROVIDERS = [
    ("阿里", "https://dns.alidns.com/resolve", {}),
    ("腾讯", "https://doh.pub/dns-query", {"accept": "application/dns-json"}),
    ("Cloudflare", "https://cloudflare-dns.com/dns-query", {"accept": "application/dns-json"}),
    ("Google", "https://dns.google/resolve", {}),
]

# 社区维护的 GitHub hosts 池，作为 DoH 之外的补充来源
COMMUNITY_HOSTS_URL = "https://raw.hellogithub.com/hosts"

HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          "System32", "drivers", "etc", "hosts")
HOSTS_BEGIN = "# >>> SkyGuard 加速开始（删除本段即可还原）>>>"
HOSTS_END = "# <<< SkyGuard 加速结束 <<<"


def cache_path():
    return os.path.join(os.path.expanduser("~"), ".skyguard", "ip_cache.json")


# ----------------------------------------------------------------------
# DNS 查询
# ----------------------------------------------------------------------
def _doh_query(name, url, headers, timeout=6.0, session=None):
    """查询单个 DoH 提供方，返回 A 记录列表。"""
    getter = session.get if session is not None else requests.get
    try:
        resp = getter(url, params={"name": name, "type": "A"},
                      headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except Exception as e:
        logger.debug(f"DoH 查询失败 {url} {name}: {e}")
        return []

    ips = []
    for answer in data.get("Answer") or []:
        if int(answer.get("type", 0)) != 1:
            continue
        value = str(answer.get("data", "")).strip()
        if _valid_ipv4(value):
            ips.append(value)
    return ips


def _valid_ipv4(text):
    try:
        ip = ipaddress.ip_address(text)
        return ip.version == 4 and not ip.is_private and not ip.is_loopback
    except ValueError:
        return False


def resolve_candidates(domain, timeout=6.0):
    """从全部 DoH 出口汇总候选 IP，返回 [(ip, 来源)]，已去重。"""
    found = {}
    session = requests.Session()
    try:
        for provider, url, headers in DOH_PROVIDERS:
            for ip in _doh_query(domain, url, headers, timeout=timeout, session=session):
                found.setdefault(ip, provider)
    finally:
        session.close()
    return [(ip, source) for ip, source in found.items()]


def fetch_community_hosts(timeout=10.0):
    """拉取社区 hosts 池，返回 {domain: [ip,...]}；失败返回空字典。"""
    result = {}
    try:
        resp = requests.get(COMMUNITY_HOSTS_URL, timeout=timeout)
        if resp.status_code != 200:
            return result
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip, domain = parts[0], parts[1].lower()
            if _valid_ipv4(ip):
                result.setdefault(domain, []).append(ip)
    except Exception as e:
        logger.debug(f"社区 hosts 拉取失败: {e}")
    return result


# ----------------------------------------------------------------------
# 测速
# ----------------------------------------------------------------------
def tcp_latency(ip, port=443, timeout=1.5):
    """TCP 握手耗时（毫秒），失败返回 None。"""
    started = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        return int((time.perf_counter() - started) * 1000)
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def optimize_domain(domain, port=443, top_n=3, timeout=1.5, extra_ips=None):
    """
    单个域名优选：多出口解析 → 测速 → 取最快的 top_n 个。

    Returns:
        {"domain":..., "ips":[{"ip":..,"ms":..,"source":..}], "ts": int}
    """
    candidates = list(resolve_candidates(domain))
    if extra_ips:
        for ip in extra_ips:
            if ip not in {c[0] for c in candidates}:
                candidates.append((ip, "社区"))
    if not candidates:
        return {"domain": domain, "ips": [], "ts": int(time.time())}

    ips = [c[0] for c in candidates]
    with ThreadPoolExecutor(max_workers=min(16, len(ips))) as pool:
        latencies = list(pool.map(lambda ip: tcp_latency(ip, port, timeout), ips))

    scored = []
    for (ip, source), ms in zip(candidates, latencies):
        if ms is not None:
            scored.append({"ip": ip, "ms": ms, "source": source})
    scored.sort(key=lambda x: x["ms"])
    return {"domain": domain, "ips": scored[:top_n], "ts": int(time.time())}


def optimize_domains(domains, port=443, top_n=3, max_workers=8, progress=None):
    """
    批量优选。progress(done, total, domain) 用于界面进度提示。
    """
    total = len(domains)
    results = []
    if total == 0:
        return results

    community = {}
    counter = {"done": 0}
    lock = threading.Lock()

    # 社区 hosts 源可能被墙，放到后台拉，拉不到就不等它，避免整个测速卡住
    def load_community():
        try:
            community.update(fetch_community_hosts(timeout=5))
        except Exception:
            pass

    threading.Thread(target=load_community, daemon=True).start()

    def work(domain):
        extra = community.get(domain)
        data = optimize_domain(domain, port=port, top_n=top_n, extra_ips=extra)
        with lock:
            counter["done"] += 1
            done = counter["done"]
        if progress:
            try:
                progress(done, total, domain)
            except Exception:
                pass
        return data

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for data in pool.map(work, domains):
            results.append(data)
    return results


# ----------------------------------------------------------------------
# 缓存（代理的加速规则直接读这里）
# ----------------------------------------------------------------------
class IpCache:
    """优选 IP 缓存，线程安全，供代理规则实时查询。"""

    def __init__(self, path=None, max_age=6 * 3600):
        self.path = path or cache_path()
        self.max_age = max_age
        self.data = {}          # domain -> {"ips": [...], "ts": int}
        self._lock = threading.RLock()
        self.load()

    def load(self, merge=True):
        """从磁盘加载。

        merge=True 时按 ts 取新（磁盘上更新的记录覆盖内存里的旧值），
        这样可以反复调用而不会把别处（定时任务）刚写入的新结果冲掉。
        """
        try:
            if not os.path.exists(self.path):
                return
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                with self._lock:
                    for domain, item in raw.items():
                        if not (isinstance(item, dict) and isinstance(item.get("ips"), list)):
                            continue
                        if merge:
                            cur = self.data.get(domain)
                            if cur and cur.get("ts", 0) > item.get("ts", 0):
                                continue
                        self.data[domain] = item
        except Exception as e:
            logger.warning(f"读取优选 IP 缓存失败: {e}")

    def save(self):
        try:
            with self._lock:
                snapshot = json.loads(json.dumps(self.data))
            # 原子写：缓存被 UI 与定时任务双写，截断重写一旦中断会整片丢失
            return atomic_io.write_json(self.path, snapshot, indent=2)
        except Exception as e:
            logger.error(f"保存优选 IP 缓存失败: {e}")
            return False

    def update(self, results):
        """接收 optimize_domains 的结果列表。

        写盘前先合并磁盘上的最新内容：本实例可能是启动时加载的旧快照，
        直接整文件覆盖会把定时任务刚写入的其他域名结果回滚掉。
        """
        now = int(time.time())
        with self._lock:
            self.load(merge=True)   # RLock 可重入
            for item in results:
                if item.get("ips"):
                    self.data[item["domain"]] = {"ips": item["ips"], "ts": item.get("ts", now)}
            self.save()

    def best_ip(self, domain):
        """返回最优 IP，没有可用记录返回 None。"""
        domain = (domain or "").lower().strip(".")
        with self._lock:
            item = self.data.get(domain)
            if not item:
                return None
            if time.time() - item.get("ts", 0) > self.max_age:
                return None
            for entry in item.get("ips") or []:
                if _valid_ipv4(str(entry.get("ip", ""))):
                    return entry["ip"]
        return None

    def best_for_suffix(self, domain):
        """按域名逐级向上匹配，命中任意父域的最优 IP。"""
        if not domain:
            return None
        domain = domain.lower().strip(".")
        if best := self.best_ip(domain):
            return best
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if best := self.best_ip(parent):
                return best
        return None

    def set_from_pairs(self, pairs):
        """pairs: [(domain, ip)] 手动导入。"""
        now = int(time.time())
        with self._lock:
            for domain, ip in pairs:
                if _valid_ipv4(ip):
                    self.data[domain] = {"ips": [{"ip": ip, "ms": 0, "source": "手动"}], "ts": now}
        self.save()

    def as_hosts_pairs(self):
        """取每个域名当前最优 IP，用于写 hosts。"""
        pairs = []
        with self._lock:
            for domain, item in self.data.items():
                ips = item.get("ips") or []
                if ips:
                    pairs.append((domain, ips[0]["ip"]))
        pairs.sort()
        return pairs


# ----------------------------------------------------------------------
# hosts 管理
# ----------------------------------------------------------------------
def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def read_hosts():
    with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def strip_our_block(text):
    """去掉之前写入的 SkyGuard 段，返回 (剩余内容, 是否找到)。"""
    if HOSTS_BEGIN not in text:
        return text, False
    out = []
    inside = False
    for line in text.splitlines():
        if line.strip() == HOSTS_BEGIN:
            inside = True
            continue
        if line.strip() == HOSTS_END:
            inside = False
            continue
        if not inside:
            out.append(line)
    return "\n".join(out) + "\n", True


def backup_hosts():
    """首次修改前备份一份原始 hosts。"""
    backup = os.path.join(os.path.expanduser("~"), ".skyguard", "hosts-before-skyguard.txt")
    if os.path.exists(backup):
        return backup
    try:
        os.makedirs(os.path.dirname(backup), exist_ok=True)
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as src:
            content = src.read()
        with open(backup, "w", encoding="utf-8") as dst:
            dst.write(content)
        return backup
    except Exception as e:
        logger.warning(f"备份 hosts 失败: {e}")
        return None


def write_hosts(pairs, only_domains=None):
    """
    把优选 IP 写入 hosts。

    Args:
        pairs: [(domain, ip)]
        only_domains: 只写这些域名（None 表示全部）

    Returns:
        (ok, message, count)
    """
    selected = [(d, ip) for d, ip in pairs if not only_domains or d in only_domains]
    if not selected:
        return False, "没有可写入的优选记录，请先测速", 0
    if not is_admin():
        return False, "写入 hosts 需要管理员权限，请以管理员身份运行 SkyGuard", 0

    try:
        backup = backup_hosts()
        original = read_hosts()
        rest, _ = strip_our_block(original)
        block = [HOSTS_BEGIN]
        for domain, ip in selected:
            block.append(f"{ip:<16} {domain}")
        block.append(HOSTS_END)
        new_text = rest.rstrip("\n") + "\n\n" + "\n".join(block) + "\n"
        with open(HOSTS_PATH, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_text)
        flush_dns()
        tip = f"已写入 {len(selected)} 条记录并刷新 DNS 缓存"
        if backup:
            tip += f"\n原文件已备份到：{backup}"
        return True, tip, len(selected)
    except PermissionError:
        return False, "没有权限修改 hosts，请用管理员身份运行", 0
    except Exception as e:
        return False, f"写入 hosts 失败：{e}", 0


def restore_hosts():
    """删除 SkyGuard 写入的段。"""
    if not is_admin():
        return False, "还原 hosts 需要管理员权限，请以管理员身份运行"
    try:
        original = read_hosts()
        rest, found = strip_our_block(original)
        if not found:
            return True, "hosts 中没有 SkyGuard 写入的记录"
        with open(HOSTS_PATH, "w", encoding="utf-8", newline="\n") as f:
            f.write(rest)
        flush_dns()
        return True, "已从 hosts 移除 SkyGuard 记录并刷新 DNS 缓存"
    except Exception as e:
        return False, f"还原 hosts 失败：{e}"


def has_hosts_block():
    try:
        return HOSTS_BEGIN in read_hosts()
    except Exception:
        return False


def flush_dns():
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=15)
        return True
    except Exception as e:
        logger.debug(f"刷新 DNS 缓存失败: {e}")
        return False
