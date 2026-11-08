#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
国内 / 国外智能分流

判断顺序（越靠前越快，绝大多数请求不会走到 DNS 查询）：
  1. 本机与内网地址            → 直连
  2. 内置国内域名后缀表        → 直连（几百条，内存里直接比对）
  3. 目标是 IP 字面量          → 查国内 IP 段
  4. 域名解析结果落在国内 IP 段 → 直连
  5. 解析失败或超时            → 走代理（被墙域名本地 DNS 往往直接失败，
                                 交给节点的出口解析反而更容易通）

国内 IPv4 段来自 APNIC 委派数据，随仓库带一份快照（约 65KB / 4000 条），
也可以在界面上「更新 IP 库」重新下载到用户目录，不依赖运行时联网。
"""

import bisect
import ipaddress
import os
import socket
import struct
import threading
import time

from utils.logger import logger

APNIC_URL = "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"

# 常见国内站点与 CDN 后缀（含 .cn 全后缀，覆盖绝大多数国内访问）
CN_DOMAIN_SUFFIXES = (
    # 通用顶级后缀
    "cn", "中国", "公司", "网络",
    # 门户 / 搜索 / 社交
    "baidu.com", "bdstatic.com", "bdimg.com", "baidupcs.com", "baidubce.com",
    "qq.com", "gtimg.com", "qpic.cn", "qlogo.cn", "tencent.com", "tencentcloudapi.com",
    "myqcloud.com", "qcloud.com", "weixin.com", "wechat.com", "weixinbridge.com",
    "sogou.com", "soso.com", "so.com", "360.cn", "qhimg.com", "qhres.com", "360.com",
    "sina.com.cn", "sina.cn", "sinaimg.cn", "weibo.com", "weibo.cn", "t.cn",
    "163.com", "126.net", "127.net", "netease.com", "yeah.net",
    "zhihu.com", "zhimg.com", "douban.com", "doubanio.com", "jianshu.com", "jianshu.io",
    "toutiao.com", "bytedance.com", "bytecdn.cn", "pstatp.com", "snssdk.com", "byteimg.com",
    "douyin.com", "douyincdn.com", "ixigua.com", "feishu.cn", "larksuite.com",
    "kuaishou.com", "kwai.com", "gifshow.com", "xiaohongshu.com", "xhscdn.com",
    "bilibili.com", "hdslb.com", "biliapi.net", "bilivideo.com", "acgvideo.com",
    "youku.com", "iqiyi.com", "qiyi.com", "mgtv.com", "pptv.com", "le.com", "letv.com",
    "douyu.com", "huya.com", "yy.com", "douyucdn.cn",
    # 电商 / 生活 / 支付
    "taobao.com", "tmall.com", "tbcdn.cn", "taobaocdn.com", "alicdn.com", "alibaba.com",
    "alipay.com", "alipayobjects.com", "aliyun.com", "aliyuncs.com", "alikunlun.com",
    "jd.com", "jd.hk", "360buyimg.com", "pinduoduo.com", "yangkeduo.com", "pddpic.com",
    "meituan.com", "meituan.net", "dianping.com", "ele.me", "ctrip.com", "trip.com",
    "qunar.com", "ly.com", "alitrip.com", "fliggy.com", "didi-global.com",
    "xiaojukeji.com", "didichuxing.com", "hellobike.com", "lianjia.com", "ke.com",
    "sf-express.com", "sfreight.com", "kuaidi100.com", "cainiao.com",
    # 硬件 / 运营商 / 云
    "huawei.com", "hicloud.com", "huaweicloud.com", "xiaomi.com", "mi.com", "miui.com",
    "xiaomi.net", "oppo.com", "vivo.com", "meizu.com", "lenovo.com.cn", "lenovo.com",
    "zte.com.cn", "honor.com", "realme.com", "oneplus.com", "cmcc.com", "10086.cn",
    "chinaunicom.com", "189.cn", "chinatelecom.com.cn", "unicom.com.cn",
    "ksyun.com", "ucloud.cn", "qingcloud.com", "volces.com", "volcengine.com",
    "qiniu.com", "qiniucdn.com", "qnssl.com", "upyun.com", "chinanetcenter.com",
    "wangsu.com", "cdntip.com", "lxdns.com", "baishancloud.com",
    # 开发者 / 工具
    "csdn.net", "cnblogs.com", "gitee.com", "oschina.net", "juejin.cn", "segmentfault.com",
    "51cto.com", "iteye.com", "runoob.com", "w3school.com.cn", "chinaunix.net",
    "openai-proxy.cn", "deepseek.com", "moonshot.cn", "bigmodel.cn", "aliyunpan.com",
    # 政务 / 金融 / 教育 / 医疗
    "gov.cn", "12306.cn", "chinatax.gov.cn", "mohrss.gov.cn", "12377.cn",
    "icbc.com.cn", "ccb.com", "abchina.com", "boc.cn", "cmbchina.com", "bankcomm.com",
    "psbc.com", "spdb.com.cn", "cib.com.cn", "cebbank.com", "pingan.com", "95559.com.cn",
    "edu.cn", "chaoxing.com", "zhihuishu.com", "xuetangx.com", "icourse163.org",
    "dingtalk.com", "dingtalk.net", "alipay.cn", "wps.cn", "wps.com", "kdocs.cn",
    "kingsoft.com", "youdao.com", "iciba.com", "amap.com", "autonavi.com", "gaode.com",
)


class GeoClassifier:
    """国内 / 国外判定器，带 DNS 结果缓存，避免每条连接都去解析。"""

    # 长跑时唯一域名可能上万，缓存必须有上限，否则内存只涨不落
    CACHE_MAX = 4096

    def __init__(self, data_path=None, user_path=None, dns_ttl=600, verdict_ttl=600,
                 resolve_timeout=1.0, workers=6, cache_max=None):
        self.user_path = user_path or os.path.join(
            os.path.expanduser("~"), ".skyguard", "china_ipv4.txt")
        self.bundled_path = data_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "china_ipv4.txt")
        self.dns_ttl = dns_ttl
        self.verdict_ttl = verdict_ttl
        self.resolve_timeout = resolve_timeout
        self.cache_max = int(cache_max or self.CACHE_MAX)

        self._starts = []
        self._ends = []
        self._suffixes = tuple(sorted(CN_DOMAIN_SUFFIXES, key=len, reverse=True))
        self._verdict = {}
        self._dns = {}
        self._lock = threading.RLock()
        # 用守护线程做解析：超时后线程自己烂在后台即可，不阻塞程序退出
        self._slots = threading.Semaphore(workers)
        self.source = "未加载"
        self.load()

    # -- IP 库 --------------------------------------------------------
    def load(self):
        """优先用用户目录里的新版库，没有就用随包的快照。"""
        for path, label in ((self.user_path, "用户库"), (self.bundled_path, "内置快照")):
            if not os.path.exists(path):
                continue
            try:
                starts, ends = [], []
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        addr, _, plen = line.partition("/")
                        try:
                            # 直接算整数区间，比 ipaddress.ip_network 快一个数量级
                            start = struct.unpack(">I", socket.inet_aton(addr))[0]
                            bits = 32 - int(plen)
                        except (OSError, ValueError):
                            continue
                        starts.append(start)
                        ends.append(start | ((1 << bits) - 1))
                if not starts:
                    continue
                pairs = sorted(zip(starts, ends))
                with self._lock:
                    self._starts = [p[0] for p in pairs]
                    self._ends = [p[1] for p in pairs]
                    self._verdict.clear()
                self.source = f"{label}（{len(pairs)} 段 · {os.path.basename(path)}）"
                logger.info(f"国内 IP 库已加载: {self.source}")
                return True
            except Exception as e:
                logger.warning(f"读取国内 IP 库失败 {path}: {e}")
        self.source = "缺失（仅用域名表判断）"
        logger.warning("没有可用的国内 IP 库，智能分流将只依赖域名表")
        return False

    @property
    def range_count(self):
        return len(self._starts)

    def is_china_ip(self, ip_text):
        if not self._starts:
            return False
        try:
            value = int(ipaddress.IPv4Address(ip_text))
        except (ipaddress.AddressValueError, ValueError):
            return False
        idx = bisect.bisect_right(self._starts, value) - 1
        return idx >= 0 and value <= self._ends[idx]

    def is_china_domain(self, host):
        host = (host or "").lower().strip(".")
        if not host:
            return False
        for suffix in self._suffixes:
            if host == suffix or host.endswith("." + suffix):
                return True
        return False

    # -- DNS 解析（带缓存 + 超时） ------------------------------------
    def _resolve(self, host, timeout=None):
        timeout = self.resolve_timeout if timeout is None else timeout
        box = {}
        done = threading.Event()

        def work():
            try:
                box["ips"] = self._getaddrinfo(host)
            except Exception:
                box["ips"] = []
            finally:
                self._slots.release()
                done.set()

        if not self._slots.acquire(timeout=timeout):
            return None
        threading.Thread(target=work, daemon=True, name="geo-dns").start()
        if not done.wait(timeout):
            logger.debug(f"解析超时，按国外处理: {host}")
            return None
        return box.get("ips")

    @staticmethod
    def _getaddrinfo(host):
        try:
            return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
        except OSError:
            return []

    def _remember(self, cache, key, value, ttl):
        """写入缓存并做容量控制：先清过期，仍超限就按插入顺序淘汰最老的四分之一。"""
        if len(cache) >= self.cache_max and key not in cache:
            now = time.time()
            for k in [k for k, v in cache.items() if now - v[0] >= ttl]:
                cache.pop(k, None)
            if len(cache) >= self.cache_max:
                for k in list(cache)[: max(1, self.cache_max // 4)]:
                    cache.pop(k, None)
        cache[key] = value

    def resolve(self, host, timeout=None):
        """返回 IP 列表；超时返回 None，解析失败返回 []。"""
        now = time.time()
        with self._lock:
            cached = self._dns.get(host)
        if cached and now - cached[0] < self.dns_ttl:
            return cached[1]

        ips = self._resolve(host, timeout)

        if ips is not None:
            with self._lock:
                self._remember(self._dns, host, (now, ips), self.dns_ttl)
        return ips

    # -- 对外结论 -----------------------------------------------------
    def should_direct(self, host, timeout=None):
        """True 表示国内直连，False 表示走代理。"""
        host = (host or "").lower().strip(".")
        if not host:
            return True
        if self.is_china_domain(host):
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            return self.is_china_ip(str(ip)) if ip.version == 4 else False

        with self._lock:
            cached = self._verdict.get(host)
        now = time.time()
        if cached and now - cached[0] < self.verdict_ttl:
            return cached[1]

        ips = self.resolve(host, timeout)
        if ips is None:
            # 解析超时：先按国外走代理，30 秒后再试
            with self._lock:
                self._remember(self._verdict, host,
                               (now - self.verdict_ttl + 30, False), self.verdict_ttl)
            return False
        china = any(self.is_china_ip(ip) for ip in ips)
        with self._lock:
            self._remember(self._verdict, host, (now, china), self.verdict_ttl)
        return china

    def clear_cache(self):
        with self._lock:
            self._verdict.clear()
            self._dns.clear()

    # -- 更新 IP 库 ---------------------------------------------------
    def update_from_network(self, timeout=90):
        """下载 APNIC 委派数据，重建用户目录里的国内 IPv4 段。"""
        import requests

        resp = requests.get(APNIC_URL, timeout=timeout, stream=True)
        resp.raise_for_status()
        ranges = []
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw or not raw.startswith("apnic|CN|ipv4|"):
                continue
            parts = raw.split("|")
            if len(parts) < 5:
                continue
            try:
                start = int(ipaddress.IPv4Address(parts[3]))
                count = int(parts[4])
            except (ValueError, ipaddress.AddressValueError):
                continue
            ranges.append((start, start + count - 1))
        if not ranges:
            raise ValueError("APNIC 数据里没有解析到中国大陆记录")

        ranges.sort()
        merged = []
        for start, end in ranges:
            if merged and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])

        lines = [f"# 中国大陆 IPv4 段（APNIC 更新于 {time.strftime('%Y-%m-%d')}）"]
        for start, end in merged:
            for net in ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)):
                lines.append(str(net))

        os.makedirs(os.path.dirname(self.user_path), exist_ok=True)
        tmp = self.user_path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, self.user_path)
        self.load()
        self.clear_cache()
        return len(merged), len(lines) - 1

    def shutdown(self):
        self.clear_cache()


_shared = None
_shared_lock = threading.Lock()


def get_classifier():
    """进程内共享一个实例，避免每处都加载 IP 库。"""
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = GeoClassifier()
        return _shared
