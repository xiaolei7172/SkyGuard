#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
本地混合代理（类似 Clash 的 mixed port）

同一个端口同时说两种话：
  * HTTP 代理：CONNECT 隧道 + 普通 http:// 请求转发
  * SOCKS5：无认证，CONNECT 命令，支持域名 / IPv4 / IPv6
浏览器或系统代理填 127.0.0.1:7890 即可直接使用。

规则动作：
  DIRECT  直连
  ACCEL   直连，但把域名换成优选 IP（GitHub / Steam 加速）
  PROXY   走当前选中节点
  REJECT  拒绝

三种模式：rule（按规则）/ global（全走节点）/ direct（全直连）。
内网与本机地址在任何模式下都强制直连，避免把本地服务代理坏。
"""

import ipaddress
import re
import socket
import struct
import threading
import time
from collections import deque
from urllib.parse import urlsplit

from core.proxy_connectors import ConnectorError, open_tunnel
from utils.logger import logger

ACTION_DIRECT = "DIRECT"
ACTION_PROXY = "PROXY"
ACTION_REJECT = "REJECT"
ACTION_ACCEL = "ACCEL"

MODE_RULE = "rule"
MODE_GLOBAL = "global"
MODE_DIRECT = "direct"
MODE_SMART = "smart"
MODES = (MODE_SMART, MODE_RULE, MODE_GLOBAL, MODE_DIRECT)

RULE_TYPES = ("domain-suffix", "domain", "domain-keyword", "domain-regex", "ip-cidr", "final")

# GitHub / Steam 的加速规则：命中后走优选 IP 直连
_ACCEL_SUFFIXES = [
    "github.com", "githubusercontent.com", "githubassets.com", "github.io",
    "github.dev", "ghcr.io", "githubapp.com", "githubstatus.com",
    "steampowered.com", "steamstatic.com", "steamcommunity.com",
    "steamcontent.com", "steamserver.net", "steamgames.com", "akamaihd.net",
]

_REJECT_SUFFIXES = [
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "adservice.google.com", "scorecardresearch.com", "adnxs.com",
    "criteo.com", "taboola.com", "outbrain.com", "adcolony.com",
]

DEFAULT_RULES = (
    [{"type": "domain-suffix", "value": "localhost", "action": ACTION_DIRECT},
     {"type": "domain-suffix", "value": "local", "action": ACTION_DIRECT},
     {"type": "domain-suffix", "value": "lan", "action": ACTION_DIRECT},
     {"type": "domain-suffix", "value": "msftconnecttest.com", "action": ACTION_DIRECT}]
    + [{"type": "domain-suffix", "value": d, "action": ACTION_REJECT} for d in _REJECT_SUFFIXES]
    + [{"type": "domain-suffix", "value": d, "action": ACTION_ACCEL} for d in _ACCEL_SUFFIXES]
    + [{"type": "final", "value": "", "action": ACTION_DIRECT}]
)

_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
)]


def is_local_address(host):
    """本机 / 内网 / 保留地址，永远直连。"""
    if not host:
        return True
    host = host.strip("[]").lower()
    if host in ("localhost", "localhost.localdomain") or host.endswith(".local"):
        return True
    if host.endswith(".lan") or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETS)


class RuleEngine:
    """规则匹配，先匹配先返回。智能模式下 final 交给国内外判定。"""

    def __init__(self, rules=None, mode=MODE_RULE, geo=None):
        self._lock = threading.RLock()
        self.rules = ()
        self.mode = mode if mode in MODES else MODE_RULE
        self.geo = geo
        self.set_rules(rules if rules is not None else DEFAULT_RULES)

    def set_rules(self, rules):
        cleaned = []
        for rule in rules or []:
            if not isinstance(rule, dict):
                continue
            rtype = str(rule.get("type", "")).strip().lower()
            action = str(rule.get("action", "")).strip().upper()
            value = str(rule.get("value", "")).strip().lower()
            if rtype not in RULE_TYPES or action not in (
                    ACTION_DIRECT, ACTION_PROXY, ACTION_REJECT, ACTION_ACCEL):
                continue
            if rtype != "final" and not value:
                continue
            entry = {"type": rtype, "value": value, "action": action}
            if rtype == "ip-cidr":
                try:
                    entry["network"] = ipaddress.ip_network(value, strict=False)
                except ValueError:
                    continue
            if rtype == "domain-regex":
                try:
                    entry["regex"] = re.compile(value)
                except re.error:
                    continue
            cleaned.append(entry)
        with self._lock:
            self.rules = tuple(cleaned)
        return len(cleaned)

    def set_mode(self, mode):
        with self._lock:
            self.mode = mode if mode in MODES else MODE_RULE

    def set_geo(self, geo):
        self.geo = geo

    def match(self, host, port=0):
        """
        Returns:
            (action, 规则描述)
        """
        if is_local_address(host):
            return ACTION_DIRECT, "本机/内网"

        mode = self.mode
        rules = self.rules

        if mode == MODE_GLOBAL:
            return ACTION_PROXY, "全局模式"
        if mode == MODE_DIRECT:
            return ACTION_DIRECT, "直连模式"

        host_l = (host or "").lower().strip(".")
        try:
            ip = ipaddress.ip_address(host_l)
        except ValueError:
            ip = None

        for rule in rules:
            rtype = rule["type"]
            if rtype == "final":
                break
            if ip is not None:
                if rtype == "ip-cidr" and ip in rule["network"]:
                    return rule["action"], f"IP {rule['value']}"
                continue
            value = rule["value"]
            if rtype == "domain-suffix":
                if host_l == value or host_l.endswith("." + value):
                    return rule["action"], rule["value"]
            elif rtype == "domain":
                if host_l == value:
                    return rule["action"], rule["value"]
            elif rtype == "domain-keyword":
                if value in host_l:
                    return rule["action"], rule["value"]
            elif rtype == "domain-regex":
                if rule["regex"].search(host_l):
                    return rule["action"], rule["value"]

        # 智能模式：显式规则都没命中，按国内外归属决定
        if mode == MODE_SMART and self.geo is not None:
            if self.geo.should_direct(host_l):
                return ACTION_DIRECT, "国内直连"
            return ACTION_PROXY, "国外走代理"

        return ACTION_DIRECT, "默认直连"


class ProxyStats:
    """线程安全的统计与最近连接记录。"""

    def __init__(self, log_limit=200):
        self._lock = threading.Lock()
        self.total = 0
        self.active = 0
        self.rejected = 0
        self.proxied = 0
        self.direct = 0
        self.accel = 0
        self.up_bytes = 0
        self.down_bytes = 0
        self.failed = 0
        self.recent = deque(maxlen=log_limit)

    def begin(self, host, port, action, rule, node_name=""):
        entry = {
            "time": time.strftime("%H:%M:%S"),
            "host": host,
            "port": port,
            "action": action,
            "rule": rule,
            "node": node_name,
            "up": 0,
            "down": 0,
            "result": "连接中",
        }
        with self._lock:
            self.total += 1
            self.active += 1
            self.recent.appendleft(entry)
        return entry

    def finish(self, entry, up=0, down=0, error=None):
        with self._lock:
            self.active = max(0, self.active - 1)
            self.up_bytes += up
            self.down_bytes += down
            entry["up"] = up
            entry["down"] = down
            if error:
                self.failed += 1
                entry["result"] = error
            else:
                entry["result"] = "完成"
            action = entry.get("action")
            if action == ACTION_REJECT:
                self.rejected += 1
            elif action == ACTION_PROXY:
                self.proxied += 1
            elif action == ACTION_ACCEL:
                self.accel += 1
            else:
                self.direct += 1

    def add_traffic(self, up=0, down=0):
        with self._lock:
            self.up_bytes += up
            self.down_bytes += down

    def snapshot(self):
        with self._lock:
            return {
                "total": self.total,
                "active": self.active,
                "rejected": self.rejected,
                "proxied": self.proxied,
                "direct": self.direct,
                "accel": self.accel,
                "up": self.up_bytes,
                "down": self.down_bytes,
                "failed": self.failed,
                "recent": list(self.recent)[:50],
            }

    def reset(self):
        with self._lock:
            self.total = self.active = self.rejected = self.proxied = 0
            self.direct = self.accel = self.up_bytes = self.down_bytes = self.failed = 0
            self.recent.clear()


class LocalProxy:
    """混合端口代理服务。"""

    def __init__(self, host="127.0.0.1", port=7890, rules=None, mode=MODE_RULE,
                 node_provider=None, accel_ip_provider=None, geo=None):
        self.host = host
        self.port = int(port)
        self.engine = RuleEngine(rules, mode, geo=geo)
        self.stats = ProxyStats()
        self.node_provider = node_provider          # () -> ProxyNode | None
        self.accel_ip_provider = accel_ip_provider  # (host) -> ip | None
        self.connect_timeout = 8.0

        self._server = None
        self._thread = None
        self._running = False
        self._stop_event = threading.Event()
        self._conns = set()
        self._conns_lock = threading.Lock()
        self.bind_errors = []

    # -- 生命周期 ----------------------------------------------------
    @property
    def running(self):
        return self._running

    def start(self):
        if self._running:
            return True
        self.bind_errors = []
        self._stop_event.clear()
        host = self.host
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        try:
            server = socket.socket(family, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, self.port))
            server.listen(128)
            server.settimeout(1.0)
        except OSError as e:
            self.bind_errors.append(f"{host}:{self.port} → {e.strerror or e}")
            logger.error(f"代理端口绑定失败 {host}:{self.port}: {e}")
            return False

        self._server = server
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, name="proxy-accept", daemon=True)
        self._thread.start()
        logger.info(f"本地代理已启动 {host}:{self.port}（模式 {self.engine.mode}）")
        return True

    def stop(self):
        self._running = False
        self._stop_event.set()
        if self._server is not None:
            try:
                self._server.close()
            except Exception:
                pass
            self._server = None
        # 主动断开在途连接，避免停止后线程还挂在 recv 上
        with self._conns_lock:
            conns = list(self._conns)
            self._conns.clear()
        for sock in conns:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("本地代理已停止")

    def set_mode(self, mode):
        self.engine.set_mode(mode)

    def set_geo(self, geo):
        self.engine.set_geo(geo)

    def set_rules(self, rules):
        return self.engine.set_rules(rules)

    def set_node_provider(self, provider):
        self.node_provider = provider

    def set_accel_ip_provider(self, provider):
        self.accel_ip_provider = provider

    # -- 接受连接 ----------------------------------------------------
    def _accept_loop(self):
        while self._running:
            try:
                client, _addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._conns_lock:
                self._conns.add(client)
            threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()

    def _handle_client(self, client):
        try:
            client.settimeout(30)
            first = client.recv(1, socket.MSG_PEEK)
            if not first:
                return
            if first == b"\x05":
                self._handle_socks5(client)
            else:
                self._handle_http(client)
        except Exception as e:
            logger.debug(f"代理连接异常: {e}")
        finally:
            with self._conns_lock:
                self._conns.discard(client)
            try:
                client.close()
            except Exception:
                pass

    # -- 出站 --------------------------------------------------------
    def _open_upstream(self, host, port, action):
        """
        Returns:
            (socket, reader, writer, node_name)
        """
        fallback_name = ""
        if action == ACTION_PROXY:
            node = self.node_provider() if self.node_provider else None
            if node is not None:
                sock, reader, writer = open_tunnel(node, host, port, timeout=self.connect_timeout)
                return sock, reader, writer, node.name
            if self.engine.mode not in (MODE_SMART, MODE_RULE):
                raise ConnectorError("未选择代理节点")
            # 智能 / 规则模式下没有节点时直连兜底，别把用户的网直接掐了
            logger.debug(f"没有可用节点，{host} 回退直连")
            fallback_name = "无节点→直连"

        target = host
        if action == ACTION_ACCEL and self.accel_ip_provider:
            ip = self.accel_ip_provider(host)
            if ip:
                target = ip
        sock = socket.create_connection((target, port), timeout=self.connect_timeout)
        sock.settimeout(None)
        if fallback_name:
            return sock, None, None, fallback_name
        return sock, None, None, "优选IP" if action == ACTION_ACCEL else ""

    def _relay(self, client, remote, reader, writer, entry):
        """双向转发，返回 (上行字节, 下行字节)。"""
        counter = {"up": 0, "down": 0}
        done = threading.Event()

        def client_to_remote():
            try:
                while not self._stop_event.is_set():
                    data = client.recv(65536)
                    if not data:
                        break
                    if writer is not None:
                        writer.send(data)
                    else:
                        remote.sendall(data)
                    counter["up"] += len(data)
                    self.stats.add_traffic(up=len(data))
            except Exception as e:
                # 节点密码/加密方式不对会抛 InvalidTag 之类的非 OSError，别让它炸线程
                logger.debug(f"转发上行结束 {entry['host']}:{entry['port']}: {e}")
            finally:
                done.set()
                # 半关闭：让上游知道请求已发完，同时自己仍能继续收响应
                _shutdown(remote, socket.SHUT_WR)

        def remote_to_client():
            try:
                while not self._stop_event.is_set():
                    data = reader.recv(65536) if reader is not None else remote.recv(65536)
                    if not data:
                        break
                    client.sendall(data)
                    counter["down"] += len(data)
                    self.stats.add_traffic(down=len(data))
            except Exception as e:
                logger.debug(f"转发下行结束 {entry['host']}:{entry['port']}: {e}")
            finally:
                done.set()
                _shutdown(client, socket.SHUT_WR)

        up_thread = threading.Thread(target=client_to_remote, daemon=True)
        down_thread = threading.Thread(target=remote_to_client, daemon=True)
        up_thread.start()
        down_thread.start()
        up_thread.join()
        down_thread.join()
        return counter["up"], counter["down"]

    def _serve(self, client, host, port, is_connect, prelude=b""):
        """匹配规则、建立上游、回写响应并转发。"""
        action, rule = self.engine.match(host, port)
        entry = self.stats.begin(host, port, action, rule)

        if action == ACTION_REJECT:
            self.stats.finish(entry, error="已拒绝")
            if is_connect:
                _send(client, b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            else:
                body = "<h1>403 已被 SkyGuard 拦截</h1>".encode("utf-8")
                _send(client, b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\n"
                             + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
            return

        remote = None
        try:
            remote, reader, writer, node_name = self._open_upstream(host, port, action)
            entry["node"] = node_name
        except Exception as e:
            self.stats.finish(entry, error=f"连接失败：{e}")
            if is_connect:
                _send(client, b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            logger.debug(f"上游连接失败 {host}:{port} ({action}) - {e}")
            return

        try:
            if is_connect:
                _send(client, b"HTTP/1.1 200 Connection Established\r\n"
                             b"Proxy-Agent: SkyGuard\r\n\r\n")
            elif prelude:
                # 普通 HTTP 请求改写后会先发一段首部；节点隧道必须走加密 writer，
                # 直接写裸 socket 会把明文灌进 SS/Trojan 流，对端解帧直接失败。
                if writer is not None:
                    writer.send(prelude)
                else:
                    _send(remote, prelude)
            client.settimeout(None)
            remote.settimeout(None)
            up, down = self._relay(client, remote, reader, writer, entry)
            self.stats.finish(entry, up, down)
        except Exception as e:
            self.stats.finish(entry, error=f"转发中断：{e}")
        finally:
            try:
                remote.close()
            except Exception:
                pass

    # -- HTTP 代理 ---------------------------------------------------
    def _handle_http(self, client):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = client.recv(8192)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 131072:
                _send(client, b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                return

        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        try:
            method, target, version = lines[0].decode("latin-1").split(" ", 2)
        except ValueError:
            _send(client, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return

        if method.upper() == "CONNECT":
            host, port = _split_target(target, 443)
            if not host:
                _send(client, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return
            self._serve(client, host, port, True)
            return

        # 普通 HTTP：把绝对 URL 改写成路径后转发
        if not target.lower().startswith("http://"):
            _send(client, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        parts = urlsplit(target)
        host = parts.hostname or ""
        port = parts.port or 80
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines[0] = f"{method} {path} {version}".encode("latin-1")
        prelude = b"\r\n".join(lines) + b"\r\n\r\n" + rest
        self._serve(client, host, port, False, prelude)

    # -- SOCKS5 ------------------------------------------------------
    def _handle_socks5(self, client):
        try:
            head = _recv_exact(client, 2)
            if head[0] != 5:
                return
            methods = _recv_exact(client, head[1])
            if 0 not in methods:
                _send(client, b"\x05\xff")
                return
            _send(client, b"\x05\x00")

            request = _recv_exact(client, 4)
            if request[0] != 5:
                return
            cmd, atyp = request[1], request[3]

            # 先把地址读完，避免提前关闭连接时残留数据触发 RST
            if atyp == 1:
                host = socket.inet_ntoa(_recv_exact(client, 4))
            elif atyp == 3:
                length = _recv_exact(client, 1)[0]
                host = _recv_exact(client, length).decode("utf-8", "ignore")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
            else:
                _send(client, b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            port = struct.unpack(">H", _recv_exact(client, 2))[0]

            if cmd != 0x01:  # 只支持 CONNECT
                _send(client, b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
        except OSError:
            return

        if not host:
            _send(client, b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        action, rule = self.engine.match(host, port)
        entry = self.stats.begin(host, port, action, rule)
        if action == ACTION_REJECT:
            self.stats.finish(entry, error="已拒绝")
            _send(client, b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        remote = None
        try:
            remote, reader, writer, node_name = self._open_upstream(host, port, action)
            entry["node"] = node_name
        except Exception as e:
            self.stats.finish(entry, error=f"连接失败：{e}")
            _send(client, b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        try:
            _send(client, b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            client.settimeout(None)
            remote.settimeout(None)
            up, down = self._relay(client, remote, reader, writer, entry)
            self.stats.finish(entry, up, down)
        except Exception as e:
            self.stats.finish(entry, error=f"转发中断：{e}")
        finally:
            try:
                remote.close()
            except Exception:
                pass


# ----------------------------------------------------------------------
# 小工具
# ----------------------------------------------------------------------
def _send(sock, data):
    try:
        sock.sendall(data)
    except OSError:
        pass


def _recv_exact(sock, n):
    parts = []
    while n > 0:
        chunk = sock.recv(n)
        if not chunk:
            raise ConnectionError("连接已关闭")
        parts.append(chunk)
        n -= len(chunk)
    return b"".join(parts)


def _shutdown(sock, how):
    try:
        sock.shutdown(how)
    except OSError:
        pass


def _split_target(target, default_port):
    """拆分 host:port，兼容 [IPv6]:443 与无端口写法。"""
    target = target.strip()
    if target.startswith("["):
        host, _, rest = target[1].partition("]")
        port_text = rest.lstrip(":")
        return host, int(port_text) if port_text.isdigit() else default_port
    if target.count(":") == 1:
        host, _, port_text = target.partition(":")
        return host, int(port_text) if port_text.isdigit() else default_port
    if target.count(":") > 1:  # 裸 IPv6
        return target, default_port
    return target, default_port


def format_bytes(num):
    num = float(num or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} GB"
