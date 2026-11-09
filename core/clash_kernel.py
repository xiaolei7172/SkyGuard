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
import hashlib
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


# GeoIP / GeoSite 数据文件：mihomo 首次启动若找不到会联网下载，被墙时会卡住几十秒
GEO_SEED_FILES = ("geoip.metadb", "Country.mmdb", "geoip.dat", "geosite.dat")


def geo_seed_dirs(kernel_path=""):
    """可能已有 GeoIP/GeoSite 数据的目录（Clash Verge、mihomo 目录、用户数据目录）。"""
    dirs = []
    if kernel_path:
        base = os.path.dirname(os.path.abspath(kernel_path))
        dirs.extend([base, os.path.join(base, "resources"), os.path.join(base, "data")])
    appdata = os.environ.get("APPDATA") or ""
    localappdata = os.environ.get("LOCALAPPDATA") or ""
    for root in (appdata, localappdata):
        if not root:
            continue
        for name in ("io.github.clash-verge-rev.clash-verge-rev",
                     "io.github.clash-verge-rev",
                     "clash-verge-rev",
                     "com.core.beyondsky",
                     "mihomo"):
            dirs.append(os.path.join(root, name, "clash"))
            dirs.append(os.path.join(root, name))
    home = os.path.expanduser("~")
    dirs.extend([os.path.join(home, ".config", "clash"),
                 os.path.join(home, ".config", "mihomo"),
                 os.path.join(home, ".skyguard", "core")])
    return [d for d in dirs if d and os.path.isdir(d)]


def ensure_geo_files(work_dir, kernel_path=""):
    """把本机已有的 GeoIP/GeoSite 数据复制进内核工作目录。

    内核启动时若缺这些文件会尝试联网下载（GitHub 常被墙），表现为
    「内核 API 一直不就绪」。复制本机数据可让启动稳定在 1~2 秒。
    """
    os.makedirs(work_dir, exist_ok=True)
    copied = []
    dirs = geo_seed_dirs(kernel_path)
    for fname in GEO_SEED_FILES:
        dest = os.path.join(work_dir, fname)
        if os.path.exists(dest) and os.path.getsize(dest) > 0:
            continue
        for d in dirs:
            src = os.path.join(d, fname)
            try:
                if os.path.isfile(src) and os.path.getsize(src) > 100 * 1024:
                    shutil.copy2(src, dest)
                    copied.append(fname)
                    logger.debug(f"GeoIP 数据已就位：{src} → {dest}")
                    break
            except Exception as e:
                logger.debug(f"复制 GeoIP 数据失败 {src}: {e}")
    if copied:
        logger.info(f"GeoIP/GeoSite 数据已准备好：{'、'.join(copied)}")
    return copied


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

    # 可选私有 token（GitHub API 限流 60 次/小时，够用；有 token 就带上）
    token_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              os.pardir, ".gh_token")
    token = ""
    if os.path.isfile(token_file):
        try:
            with open(token_file, encoding="utf-8") as f:
                token = f.read().strip()
        except OSError:
            token = ""

    proxies = urllib.request.getproxies() or None
    if proxies:
        handler = urllib.request.ProxyHandler(
            {k: v for k, v in proxies.items()})
        opener = urllib.request.build_opener(handler)
    else:
        opener = urllib.request.build_opener()

    req = urllib.request.Request(GITHUB_LATEST)
    req.add_header("Accept", "application/vnd.github+json")
    if token:
        req.add_header("Authorization", f"token {token}")

    def fetch(request, timeout=60):
        # 必须关闭响应，否则每次请求都留一个未释放的连接
        with opener.open(request, timeout=timeout) as resp:
            return resp.read()

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

    # urlretrieve 没有超时参数，网络卡住会永久挂起；改用 urlopen 分块下载
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "SkyGuard")
    total = int(asset.get("size", 0) or 0)
    with opener.open(req, timeout=60) as resp, open(zip_path, "wb") as fh:
        fetched = 0
        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            fh.write(chunk)
            fetched += len(chunk)
            if progress and total > 0 and fetched // (total // 20) != \
                    (fetched - len(chunk)) // (total // 20):
                progress(f"下载 {asset['name']} … {min(100, fetched * 100 // total)}%")
    if total and fetched != total:
        try:
            os.remove(zip_path)
        except OSError:
            pass
        raise KernelNotFound(f"内核下载不完整（{fetched}/{total} 字节），已放弃安装")

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
        # 防路径穿越：解压目标必须在 dest_dir 内（zip-slip 防护）
        if os.path.basename(exe_name) != exe_name and not exe_name.endswith("/"):
            safe_rel = os.path.normpath(exe_name).lstrip("/\\")
            if safe_rel.startswith("..") or ".." in safe_rel.split(os.sep):
                raise KernelNotFound(f"压缩包内路径异常（{exe_name}），已拒绝解压")
        z.extract(exe_name, dest_dir)
    os.remove(zip_path)

    exe_path = os.path.join(dest_dir, os.path.basename(exe_name))
    target = os.path.join(dest_dir, KERNEL_FILENAME)

    # 完整性校验：只接受 PE 格式且体积合理的内核，防止投毒/损坏文件被当内核执行
    with open(exe_path, "rb") as fh:
        head = fh.read(2)
        size = fh.seek(0, 2)
    if head != b"MZ":
        try:
            os.remove(exe_path)
        except OSError:
            pass
        raise KernelNotFound("下载的内核文件不是有效的 Windows 可执行文件（缺少 PE 头），已拒绝安装")
    if size < 1024 * 1024 or size > 512 * 1024 * 1024:
        try:
            os.remove(exe_path)
        except OSError:
            pass
        raise KernelNotFound(f"内核文件体积异常（{size} 字节），已拒绝安装")

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
                 clash_mode="rule", local_dns=False, local_dns_port=None,
                 block_ads=False, ads_payload=None, accel_domains=()):
    """生成 mihomo 配置 dict（可 yaml.safe_dump）。

    Args:
        subscriptions: [{name, url, ...}] 订阅列表，交给内核 proxy-providers
        manual_nodes:  [ProxyNode] 手动节点
        rules:         SkyGuard 规则列表，映射为内核规则
        clash_mode:    rule / global / direct
        local_dns:     True 时内核 DNS 走本机 DNS 过滤器（与 SkyGuard 的 DNS 页联动）
        local_dns_port: 过滤器实际监听端口（默认 53）。端口可配，不能写死，
                        否则用户把 DNS 改到 5353 后内核解析会全部失败
        block_ads:     True 时在内核规则最前面拦广告（GEOSITE category-ads-all）。
                       必须走内核规则：fake-ip 模式下内核会忽略上游返回的 0.0.0.0
                       并回退到公网 DNS，光靠 DNS 上游拦不住代理流量里的广告
        ads_payload:   DNS 页过滤列表导出的域名（'+.example.com' 形式），
                       会和 GEOSITE 一起生效，覆盖 geosite 分类里没有的国内域名
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
    rule_providers = {}
    if ads_payload:
        # 用 rule-provider 承载 DNS 页的过滤域名：几万条也不占内存、
        # 不拖慢匹配，且能覆盖 geosite 分类里没有的国内统计/广告域名。
        name = "skyguard-ads"
        rule_providers[name] = {
            "type": "file",
            "behavior": "domain",
            "path": f"./rules/{name}.yaml",
        }
        rules_out.append(f"RULE-SET,{name},REJECT")
    if block_ads:
        # 广告/追踪域名最先拒绝：必须走内核规则，因为 fake-ip 模式下内核会
        # 忽略 DNS 上游返回的 0.0.0.0（回退公网 DNS），光靠上游拦不住代理流量。
        rules_out.append("GEOSITE,category-ads-all,REJECT")
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
        # 带上真实端口：DNS 页把端口改成 5353 时，内核仍要能找到过滤器
        port = int(local_dns_port or 53)
        # 第一顺位走本机过滤器（广告过滤对代理流量也生效）；
        # 后面留公网 DoH 兜底：过滤器被停掉/崩溃时代理还能解析域名，
        # 不会因为「DNS 页停服务」把整个代理拖死。
        dns["nameserver"] = [f"127.0.0.1:{port}",
                             "https://223.5.5.5/dns-query",
                             "https://doh.pub/dns-query"]
        # default-nameserver 只能用纯 IP（mihomo 用它解析其它 DNS 的域名），
        # 写 IP:端口会被忽略 → 内核 DNS 全挂、订阅拉不到节点。
        # 这里也故意留公网 IP：不能让它依赖本地过滤器，否则过滤器没起来时
        # 内核连"解析"都做不到（自己解析自己，死循环）。
        dns["default-nameserver"] = ["223.5.5.5", "119.29.29.29"]

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
        "rule-providers": rule_providers,
        "proxies": proxies,
        "proxy-groups": [group],
        "rules": rules_out,
        # 内部传递用，start() 会写成 rules/skyguard-ads.yaml 并从配置里摘掉
        "_ads_payload": list(ads_payload or []),
    }


def provider_name(sub_name):
    """订阅名 → proxy-provider 名（与 build_config 保持一致）。

    只能用 ASCII 字母数字：provider 名会出现在内核 API 的 URL 路径里，
    中文会让 http.client 以 ascii 编码时抛 UnicodeEncodeError。
    纯中文名退化为短哈希，保证不同订阅不撞名。
    """
    raw = str(sub_name or "s")
    safe = "".join(c if (c.isascii() and c.isalnum()) else "_" for c in raw)[:24]
    if not safe.strip("_"):
        safe = hashlib.md5(raw.encode("utf-8")).hexdigest()[:8]
    return "sub_" + safe


# 机场常把「剩余流量 / 套餐到期」做成假节点塞进订阅，测速必然失败，需要排除
INFO_NODE_KEYWORDS = ("剩余流量", "套餐到期", "距离下次", "下次重置", "重置剩余",
                      "官网", "订阅", "到期时间", "流量重置", "群组", "客服",
                      "过期时间", "有效期")
_GROUP_TYPES = {"selector", "urltest", "fallback", "loadbalance", "relay",
                "direct", "reject", "rejectdrop", "compatible", "pass", "dns", "url-test"}
_BUILTIN_NODE_NAMES = {"direct", "reject", "reject-drop", "rejectdrop", "compatible",
                       "pass", "pass-rule", "global", "dns", "dns-out",
                       "节点选择", "proxy", "自动选择", "global "}


def is_real_node(name, meta):
    """判断内核返回的条目是不是真实可测速的节点（排除分组与信息占位节点）。"""
    if not isinstance(meta, dict):
        return False
    if str(meta.get("type", "")).lower() in _GROUP_TYPES:
        return False
    if str(name or "").strip().lower() in _BUILTIN_NODE_NAMES:
        return False
    if any(k in str(name or "") for k in INFO_NODE_KEYWORDS):
        return False
    return True


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
        # 先把本机已有的 GeoIP 数据放到工作目录，避免内核卡在联网下载
        ensure_geo_files(self.work_dir, self.kernel_path)
        # 广告域名列表落到工作目录，供 rule-provider（type: file）读取
        payload = config_dict.pop("_ads_payload", None)
        if payload:
            rules_dir = os.path.join(self.work_dir, "rules")
            os.makedirs(rules_dir, exist_ok=True)
            ads_path = os.path.join(rules_dir, "skyguard-ads.yaml")
            try:
                with open(ads_path, "w", encoding="utf-8") as f:
                    yaml.safe_dump({"payload": payload}, f,
                                   allow_unicode=True, sort_keys=False)
                logger.info(f"内核广告规则已写入：{len(payload)} 条 → {ads_path}")
            except OSError as e:
                logger.warning(f"写入内核广告规则失败，改为只按规则拦截：{e}")
                config_dict["rules"] = [r for r in (config_dict.get("rules") or [])
                                        if not r.startswith("RULE-SET,skyguard-ads")]
        # 没有 geosite 数据时 GEOSITE 规则会让配置校验失败，先摘掉（退回纯 DNS 过滤）
        if not os.path.exists(os.path.join(self.work_dir, "geosite.dat")):
            rules = config_dict.get("rules") or []
            dropped = [r for r in rules if str(r).startswith("GEOSITE,")]
            if dropped:
                config_dict["rules"] = [r for r in rules
                                        if not str(r).startswith("GEOSITE,")]
                logger.warning(f"缺少 geosite.dat，已跳过 {len(dropped)} 条 GEOSITE 规则")
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

    def provider_proxies(self, name):
        """读取一个订阅源（provider）下的节点，含延迟与存活状态。

        注意：mihomo 把 provider 的节点挂在 /providers/proxies/{name} 里，
        顶层 /proxies 只有分组和手动节点，所以「读取订阅节点」必须走这里，
        否则按节点名调 /proxies/{name}/delay 会 404（Resource not found）。
        """
        data = self._request("GET", f"/providers/proxies/{_quote(name)}")
        rows = []
        for p in data.get("proxies") or []:
            hist = p.get("history") or []
            delay = int((hist[-1] or {}).get("delay", 0) or 0) if hist else 0
            rows.append({
                "name": p.get("name", ""),
                "type": str(p.get("type", "")),
                "alive": bool(p.get("alive", False)),
                "delay": delay,
                "provider": p.get("provider-name") or name,
            })
        return rows

    def subscription_providers(self):
        """所有订阅类型（vehicleType=http）的 provider 名。"""
        try:
            data = self._request("GET", "/providers/proxies")
        except OSError as e:
            logger.debug(f"读取 provider 列表失败: {e}")
            return []
        names = []
        for name, meta in (data.get("providers") or {}).items():
            if str((meta or {}).get("vehicleType", "")).lower() == "http":
                names.append(name)
        return names

    def subscription_nodes(self):
        """所有订阅里的真实节点（已排除信息占位节点与分组）。"""
        rows = []
        for pname in self.subscription_providers():
            try:
                items = self.provider_proxies(pname)
            except OSError as e:
                logger.debug(f"读取 provider {pname} 节点失败: {e}")
                continue
            for node in items:
                if is_real_node(node["name"], {"type": node["type"]}):
                    rows.append(node)
        return rows

    def provider_delay(self, provider, timeout_ms=5000):
        """触发订阅源健康检查，返回 {节点名: 延迟ms}（0 表示不可用）。

        不同 mihomo 版本 healthcheck 的返回体不一致（有的直接空 {}），
        所以统一以 provider 详情里的 history 为准。
        """
        try:
            self._request(
                "GET",
                f"/providers/proxies/{_quote(provider)}/healthcheck?timeout={timeout_ms}",
                timeout=timeout_ms / 1000 + 8)
        except OSError as e:
            logger.debug(f"provider 健康检查接口异常（改用已有历史）：{e}")
        return {p["name"]: p["delay"] for p in self.provider_proxies(provider)}

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
