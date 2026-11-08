# -*- coding: utf-8 -*-
"""Clash (mihomo) 内核集成。

作用：
- 复用与 Clash 相同的 mihomo 内核跑代理，原生支持 hysteria2 / vless 等
  全部主流协议（内置引擎只支持 ss / trojan / http / socks5）；
- 订阅直接交给内核的 proxy-providers 拉取与更新，不再需要 SkyGuard 自己解析；
- 通过 RESTful API 控制内核：切换节点 / 测延迟 / 切模式 / 读流量与连接。

查找内核的顺序：
1. 用户配置的路径（config proxy.kernel_path）
2. %USERPROFILE%\\.skyguard\\core\\mihomo.exe（一键下载的目标位置）
3. 程序目录 tools/mihomo/mihomo.exe（绿色包内置）
4. 常见 Clash Verge / Clash Nyanpasu / mihomo 安装位置
5. PATH
"""
import json
import os
import random
import shutil
import string
import subprocess
import threading
import time
import zipfile
from http.client import HTTPConnection

import yaml

from utils.logger import logger

KERNEL_FILENAME = "mihomo.exe" if os.name == "nt" else "mihomo"

# 常见 GUI 自带内核的位置（按常见度排序）
KNOWN_KERNEL_DIRS = [
    r"D:\vpn\Clash Verge",
    r"C:\Program Files\Clash Verge",
    r"D:\Program Files\Clash Verge",
    r"C:\Program Files\Clash Nyanpasu",
    r"D:\Clash Verge",
    r"D:\Clash",
]

GITHUB_LATEST = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"


class KernelNotFound(Exception):
    pass


# ----------------------------------------------------------------------
# 内核查找 / 下载
# ----------------------------------------------------------------------
def user_kernel_dir():
    return os.path.join(os.path.expanduser("~"), ".skyguard", "core")


def find_kernel(configured_path=""):
    """返回可用的 mihomo 内核路径，找不到返回 None。"""
    candidates = []
    if configured_path:
        candidates.append(configured_path)
    candidates.append(os.path.join(user_kernel_dir(), KERNEL_FILENAME))
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(root, "tools", "mihomo", KERNEL_FILENAME))
    for d in KNOWN_KERNEL_DIRS:
        candidates.append(os.path.join(d, KERNEL_FILENAME))
        # Clash Verge 的内核叫 verge-mihomo.exe
        candidates.append(os.path.join(d, "verge-mihomo.exe"))
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return shutil.which("mihomo") or shutil.which("verge-mihomo")


def download_kernel(dest_dir=None, progress=None):
    """从 GitHub 下载官方 mihomo 内核到 dest_dir，返回内核路径。"""
    import urllib.request

    dest_dir = dest_dir or user_kernel_dir()
    os.makedirs(dest_dir, exist_ok=True)

    token = ""
    token_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              os.pardir, ".gh_token")
    proxies = urllib.request.getproxies() or None
    if proxies:
        handler = urllib.request.ProxyHandler(
            {k: v for k, v in proxies.items()})
        opener = urllib.request.build_opener(handler)
    else:
        opener = urllib.request.build_opener()

    req = urllib.request.Request(GITHUB_LATEST)
    req.add_header("Accept", "application/vnd.github+json")
    if token and os.path.isfile(os.path.abspath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)), os.pardir, ".gh_token"))):
        with open(token_file, encoding="utf-8") as f:
            token = f.read().strip()
        req.add_header("Authorization", f"token {token}")

    def fetch(request, timeout=60):
        return opener.open(request, timeout=timeout).read()

    data = json.loads(fetch(req))
    release_tag = data.get("tag_name", "")
    asset = None
    suffix = "windows-amd64-v1" if os.name == "nt" else "linux-amd64-v1"
    for a in data.get("assets", []):
        name = a.get("name", "")
        if suffix in name and name.endswith(".zip"):
            asset = a
            break
    if asset is None:
        for a in data.get("assets", []):
            name = a.get("name", "")
            if "windows-amd64" in name and name.endswith(".zip") and "go1" not in name:
                asset = a
                break
    if asset is None:
        raise KernelNotFound(f"发布 {release_tag} 里没有找到 Windows amd64 内核压缩包")

    url = asset["browser_download_url"]
    if progress:
        progress(f"下载 {asset['name']} …")
    zip_path = os.path.join(dest_dir, "mihomo_download.zip")
    last = [0]

    def report(count, block, total):
        done = count * block
        if total > 0 and progress and done - last[0] > total // 20:
            last[0] = done
            progress(f"下载 {asset['name']} … {min(100, done * 100 // total)}%")

    urllib.request.urlretrieve(url, zip_path, reporthook=report)

    if progress:
        progress("解压内核 …")
    exe_name = None
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            if info.filename.lower().endswith(".exe") or info.filename == "mihomo":
                exe_name = info.filename
                break
        if exe_name is None:
            raise KernelNotFound("压缩包里没有找到内核可执行文件")
        z.extract(exe_name, dest_dir)
    os.remove(zip_path)

    exe_path = os.path.join(dest_dir, os.path.basename(exe_name))
    target = os.path.join(dest_dir, KERNEL_FILENAME)
    if os.path.abspath(exe_path) != os.path.abspath(target):
        if os.path.isfile(target):
            os.remove(target)
        os.rename(exe_path, target)
    if progress:
        progress(f"内核已就绪：{target}")
    logger.info(f"mihomo 内核下载完成 {release_tag}: {target}")
    return target


# ----------------------------------------------------------------------
# 配置生成
# ----------------------------------------------------------------------
def build_config(subscriptions, manual_nodes, rules, *, mixed_port=7890,
                 api_port=19090, api_secret=None, allow_lan=False,
                 clash_mode="rule", local_dns=False, accel_domains=()):
    """生成 mihomo 配置 dict（可 yaml.safe_dump）。

    Args:
        subscriptions: [{name, url, ...}] 订阅列表，交给内核 proxy-providers
        manual_nodes:  [ProxyNode] 手动节点
        rules:         SkyGuard 规则列表，映射为内核规则
        clash_mode:    rule / global / direct
        local_dns:     True 时内核 DNS 走本机 127.0.0.1:53（DNS 过滤器）
        accel_domains: 优选加速域名集合（映射为 DIRECT，域名不变）
    """
    api_secret = api_secret or "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(16))

    providers = {}
    for i, sub in enumerate(subscriptions or []):
        url = (sub.get("url") or "").strip()
        if not url:
            continue
        if not sub.get("enabled", True):
            continue
        name = provider_name(sub.get("name") or f"s{i}")
        # 订阅自己的更新间隔（分钟），未设置时按天
        interval = max(60, int(sub.get("interval", 1440) or 1440) * 60)
        providers[name] = {
            "type": "http",
            "url": url,
            "path": f"./providers/{name}.yaml",
            "interval": interval,
            "health-check": {
                "enable": True,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 600,
            },
        }

    proxies = []
    for node in manual_nodes or []:
        d = node_to_clash(node)
        if d:
            proxies.append(d)

    group_name = "🚀 节点选择"
    group = {"name": group_name, "type": "select", "proxies": []}
    if providers:
        group["use"] = sorted(providers)
    group["proxies"].append("DIRECT")
    for p in proxies:
        group["proxies"].append(p["name"])

    # 规则映射：动作 direct/accel → DIRECT，reject → REJECT，proxy → 节点组
    policy = {"DIRECT": "DIRECT", "ACCEL": "DIRECT", "REJECT": "REJECT",
              "PROXY": group_name}
    rules_out = []
    for r in rules or []:
        rtype = r.get("type")
        value = r.get("value", "")
        act = policy.get(r.get("action", "").upper())
        if not value or not act:
            continue
        if rtype == "final":
            rules_out.append(f"MATCH,{act}")
        elif rtype == "domain-suffix":
            rules_out.append(f"DOMAIN-SUFFIX,{value},{act}")
        elif rtype == "domain":
            rules_out.append(f"DOMAIN,{value},{act}")
        elif rtype == "domain-keyword":
            rules_out.append(f"DOMAIN-KEYWORD,{value},{act}")
        elif rtype == "domain-regex":
            rules_out.append(f"DOMAIN-REGEX,{value},{act}")
        elif rtype == "ip-cidr":
            rules_out.append(f"IP-CIDR,{value},{act},no-resolve")
        elif rtype == "ip-cidr6":
            rules_out.append(f"IP-CIDR6,{value},{act},no-resolve")
        else:
            # 未知类型按关键词兜底，保证安全侧
            rules_out.append(f"DOMAIN-KEYWORD,{value},{act}")

    # 优选加速域名（GitHub/Steam 等）→ DIRECT（配合 SkyGuard 的优选 IP / hosts）
    for d in sorted(set(accel_domains or [])):
        d = d.strip().lstrip(".")
        if d:
            rules_out.append(f"DOMAIN-SUFFIX,{d},DIRECT")

    # 兜底：智能/规则模式下国内 IP 直连，其余走节点；global/direct 由 mode 决定
    if clash_mode == "rule":
        rules_out.append("GEOIP,PRIVATE,DIRECT,no-resolve")
        rules_out.append("GEOIP,CN,DIRECT")
        if not any(r.startswith("MATCH,") for r in rules_out):
            rules_out.append(f"MATCH,{group_name}")
    elif clash_mode == "global":
        rules_out = [f"MATCH,{group_name}"]
    else:  # direct
        rules_out = ["MATCH,DIRECT"]

    dns = {
        "enable": True,
        "listen": "127.0.0.1:0",   # 只做内核内部解析，不对外监听
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "nameserver": ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"],
    }
    if local_dns:
        dns["nameserver"] = ["127.0.0.1"]
        dns["default-nameserver"] = ["127.0.0.1"]

    return {
        "mixed-port": int(mixed_port),
        "allow-lan": bool(allow_lan),
        "bind-address": "*" if allow_lan else "127.0.0.1",
        "mode": clash_mode,
        "log-level": "warning",
        "ipv6": True,
        "external-controller": f"127.0.0.1:{int(api_port)}",
        "secret": api_secret,
        "unified-delay": True,
        "tcp-concurrent": True,
        "profile": {"store-selected": True},
        "dns": dns,
        "proxy-providers": providers,
        "proxies": proxies,
        "proxy-groups": [group],
        "rules": rules_out,
    }


def provider_name(sub_name):
    """订阅名 → proxy-provider 名（与 build_config 保持一致）。"""
    return "sub_" + "".join(
        c if c.isalnum() else "_" for c in (sub_name or "s"))[:24]


def node_to_clash(node):
    """把 SkyGuard 的 ProxyNode 转成 mihomo proxies 条目；不支持的协议返回 None。"""
    t = (node.type or "").lower()
    name = node.name or f"{node.server}:{node.port}"
    common = {"name": name, "server": node.server, "port": int(node.port)}
    if t == "ss":
        return {**common, "type": "ss",
                "cipher": node.cipher or "aes-256-gcm",
                "password": node.password or "",
                "udp": True}
    if t == "trojan":
        return {**common, "type": "trojan", "password": node.password or "",
                "sni": node.sni or node.server, "udp": True,
                "skip-cert-verify": bool(node.skip_cert_verify)}
    if t == "http":
        out = {**common, "type": "http"}
        if node.username:
            out["username"] = node.username
        if node.password:
            out["password"] = node.password
        return out
    if t == "socks5":
        out = {**common, "type": "socks5", "udp": True}
        if node.username:
            out["username"] = node.username
        if node.password:
            out["password"] = node.password
        return out
    return None


# ----------------------------------------------------------------------
# 内核进程与 RESTful API
# ----------------------------------------------------------------------
class MihomoKernel:
    """管理一个 mihomo 子进程：生成配置、启动、停止、API 调用。"""

    def __init__(self, kernel_path, work_dir, *, mixed_port=7890,
                 api_port=19090, allow_lan=False):
        if not kernel_path or not os.path.isfile(kernel_path):
            raise KernelNotFound(f"内核不存在: {kernel_path}")
        self.kernel_path = kernel_path
        self.work_dir = work_dir
        self.mixed_port = int(mixed_port)
        self.api_port = int(api_port)
        self.allow_lan = bool(allow_lan)
        self.secret = "".join(random.choice(string.ascii_letters + string.digits)
                              for _ in range(16))
        self.config = {}
        self._proc = None
        self._stopped = threading.Event()

    # -- 生命周期 ----------------------------------------------------
    @property
    def running(self):
        return self._proc is not None and self._proc.poll() is None

    def start(self, config_dict, timeout=15.0):
        """写配置 → 启动内核 → 等 API 就绪。失败抛 RuntimeError。"""
        if self.running:
            return True
        os.makedirs(self.work_dir, exist_ok=True)
        os.makedirs(os.path.join(self.work_dir, "providers"), exist_ok=True)
        # 以进程对象为准，强制对齐 API 端口与 secret，避免配置侧另生成导致 401
        config_dict["secret"] = self.secret
        config_dict["external-controller"] = f"127.0.0.1:{self.api_port}"
        config_dict["mixed-port"] = self.mixed_port
        self.config = config_dict
        config_path = os.path.join(self.work_dir, "config.yaml")
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config_dict, f, allow_unicode=True, sort_keys=False)

        self._stopped.clear()
        creationflags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
        try:
            self._proc = subprocess.Popen(
                [self.kernel_path, "-d", self.work_dir, "-f", config_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=creationflags)
        except OSError as e:
            self._proc = None
            raise RuntimeError(f"内核启动失败: {e}") from e

        deadline = time.time() + timeout
        err = ""
        while time.time() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"内核进程退出（码 {self._proc.returncode}），"
                                   f"常见原因：端口被占用或配置不合法")
            try:
                self.version()
                logger.info(f"mihomo 内核已启动，混合端口 {self.mixed_port}，"
                            f"API {self.api_port}")
                return True
            except OSError as e:
                err = str(e)
                time.sleep(0.25)
        self.stop()
        raise RuntimeError(f"内核 API 未在 {timeout:.0f}s 内就绪（{err}），"
                           f"请检查端口 {self.api_port} 是否被占用")

    def stop(self):
        self._stopped.set()
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
        logger.info("mihomo 内核已停止")

    # -- RESTful API -------------------------------------------------
    def _request(self, method, path, body=None, timeout=6):
        conn = HTTPConnection("127.0.0.1", self.api_port, timeout=timeout)
        headers = {"Authorization": f"Bearer {self.secret}"}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            if resp.status >= 300:
                raise OSError(f"API {path} → HTTP {resp.status}: {data[:120]!r}")
            return json.loads(data.decode("utf-8", "ignore")) if data else {}
        finally:
            conn.close()

    def version(self):
        return self._request("GET", "/version")

    def proxies(self):
        """全部代理节点与分组。"""
        return self._request("GET", "/proxies").get("proxies", {})

    def group_nodes(self, group="🚀 节点选择"):
        info = self.proxies().get(group) or {}
        return list(info.get("all") or [])

    def select_proxy(self, name, group="🚀 节点选择"):
        return self._request("PUT", f"/proxies/{_quote(group)}", {"name": name})

    def test_delay(self, name, timeout_ms=5000,
                   url="http://www.gstatic.com/generate_204"):
        data = self._request(
            "GET", f"/proxies/{_quote(name)}/delay?timeout={timeout_ms}&url={_quote(url)}",
            timeout=timeout_ms / 1000 + 3)
        return int(data.get("delay", 0))

    def provider_delay(self, provider, timeout_ms=5000):
        """对整个订阅源做健康检查，返回 {节点名: 延迟ms}。"""
        data = self._request(
            "GET",
            f"/providers/proxies/{_quote(provider)}/healthcheck?timeout={timeout_ms}",
            timeout=timeout_ms / 1000 + 5)
        return {k: int(v.get("delay", 0)) for k, v in (data or {}).items()
                if isinstance(v, dict)}

    def update_provider(self, provider):
        """立即更新一个订阅源（mihomo 会重新拉取该 provider）。"""
        return self._request("PUT", f"/providers/proxies/{_quote(provider)}", timeout=30)

    def set_mode(self, mode):
        return self._request("PATCH", "/configs", {"mode": mode})

    def traffic(self):
        """累计上下行字节数（内核重启后从零开始）。"""
        data = self._request("GET", "/connections")
        meta = data.get("downloadTotal", 0), data.get("uploadTotal", 0)
        return {"down": int(meta[0]), "up": int(meta[1]),
                "active": len(data.get("connections") or [])}

    def recent_connections(self, limit=200):
        data = self._request("GET", "/connections")
        rows = []
        for c in (data.get("connections") or [])[-limit:]:
            meta = c.get("metadata", {})
            chains = c.get("chains") or []
            rows.append({
                "id": c.get("id", ""),
                "host": meta.get("host") or meta.get("destinationIP", ""),
                "port": int(meta.get("destinationPort", 0) or 0),
                "node": chains[0] if chains else "",
                "rule": c.get("rule", ""),
                "up": int(c.get("upload", 0) or 0),
                "down": int(c.get("download", 0) or 0),
                "start": c.get("start", ""),
            })
        return rows

    def close_connection(self, conn_id):
        """断开一条活动连接。"""
        return self._request("DELETE", f"/connections/{_quote(conn_id)}")

    def close_all_connections(self):
        self._request("DELETE", "/connections")


def _quote(text):
    from urllib.parse import quote
    return quote(str(text), safe="")
