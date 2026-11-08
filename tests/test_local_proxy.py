#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
本地混合代理单测

全部在本机回环完成，不依赖外网：起一个 echo 服务和一个 HTTP 服务作为目标，
再让代理去连它们，验证 CONNECT / SOCKS5 / 普通 HTTP / 拦截 / 优选 IP 替换。
"""

import http.server
import socket
import threading
import time
import unittest
from unittest import mock

import core.local_proxy as lp
from core.local_proxy import (
    ACTION_ACCEL, ACTION_DIRECT, ACTION_PROXY, ACTION_REJECT,
    MODE_DIRECT, MODE_GLOBAL, MODE_RULE, LocalProxy, RuleEngine,
)
from core.proxy_nodes import ProxyNode


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def recv_until(sock, marker, limit=65536):
    data = b""
    while marker not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


class EchoServer(threading.Thread):
    """连上先发 HELLO，之后原样回显。"""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        try:
            client.sendall(b"HELLO")
            while True:
                data = client.recv(4096)
                if not data:
                    break
                client.sendall(data)
        except OSError:
            pass
        finally:
            client.close()

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok-body"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class TestRuleEngine(unittest.TestCase):
    def test_suffix_matches_subdomain_not_partial(self):
        engine = RuleEngine([{"type": "domain-suffix", "value": "github.com",
                              "action": ACTION_ACCEL},
                             {"type": "final", "value": "", "action": ACTION_DIRECT}])
        self.assertEqual(engine.match("github.com")[0], ACTION_ACCEL)
        self.assertEqual(engine.match("api.github.com")[0], ACTION_ACCEL)
        self.assertEqual(engine.match("notgithub.com")[0], ACTION_DIRECT)

    def test_keyword_and_regex(self):
        engine = RuleEngine([
            {"type": "domain-keyword", "value": "doubleclick", "action": ACTION_REJECT},
            {"type": "domain-regex", "value": r"^ad\d+\.", "action": ACTION_REJECT},
            {"type": "final", "value": "", "action": ACTION_DIRECT},
        ])
        self.assertEqual(engine.match("ads.doubleclick.net")[0], ACTION_REJECT)
        self.assertEqual(engine.match("ad12.example.com")[0], ACTION_REJECT)
        self.assertEqual(engine.match("www.example.com")[0], ACTION_DIRECT)

    def test_ip_cidr(self):
        engine = RuleEngine([
            {"type": "ip-cidr", "value": "8.8.8.0/24", "action": ACTION_PROXY},
            {"type": "final", "value": "", "action": ACTION_DIRECT},
        ])
        self.assertEqual(engine.match("8.8.8.8")[0], ACTION_PROXY)
        self.assertEqual(engine.match("1.1.1.1")[0], ACTION_DIRECT)

    def test_local_always_direct(self):
        engine = RuleEngine([{"type": "final", "value": "", "action": ACTION_PROXY}],
                            mode=MODE_GLOBAL)
        self.assertEqual(engine.match("127.0.0.1")[0], ACTION_DIRECT)
        self.assertEqual(engine.match("localhost")[0], ACTION_DIRECT)
        self.assertEqual(engine.match("192.168.1.2")[0], ACTION_DIRECT)

    def test_global_and_direct_mode(self):
        engine = RuleEngine([{"type": "final", "value": "", "action": ACTION_DIRECT}])
        engine.set_mode(MODE_GLOBAL)
        self.assertEqual(engine.match("example.com")[0], ACTION_PROXY)
        engine.set_mode(MODE_DIRECT)
        self.assertEqual(engine.match("example.com")[0], ACTION_DIRECT)

    def test_final_fallback(self):
        engine = RuleEngine([])
        self.assertEqual(engine.match("whatever.com"), (ACTION_DIRECT, "默认直连"))

    def test_invalid_rules_skipped(self):
        engine = RuleEngine([
            {"type": "bogus", "value": "x", "action": ACTION_PROXY},
            {"type": "ip-cidr", "value": "not-a-cidr", "action": ACTION_PROXY},
            {"type": "domain", "value": "ok.com", "action": ACTION_DIRECT},
        ])
        self.assertEqual(len(engine.rules), 1)


class ProxyTestBase(unittest.TestCase):
    rules = [{"type": "final", "value": "", "action": ACTION_DIRECT}]

    def setUp(self):
        self.echo = EchoServer()
        self.echo.start()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.http_port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

        self.port = free_port()
        self.proxy = LocalProxy(host="127.0.0.1", port=self.port, rules=self.rules)
        self.assertTrue(self.proxy.start(), self.proxy.bind_errors)
        time.sleep(0.1)

    def tearDown(self):
        self.proxy.stop()
        self.echo.close()
        self.httpd.shutdown()
        self.httpd.server_close()

    def connect(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        sock.settimeout(5)
        return sock

    def http_connect(self, host, port):
        sock = self.connect()
        sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        head = recv_until(sock, b"\r\n\r\n")
        return sock, head


class TestConnectTunnel(ProxyTestBase):
    def test_connect_then_echo(self):
        sock, head = self.http_connect("127.0.0.1", self.echo.port)
        self.assertIn(b"200", head.split(b"\r\n")[0])
        self.assertEqual(recv_until(sock, b"HELLO"), b"HELLO")
        sock.sendall(b"ping")
        self.assertEqual(recv_until(sock, b"ping"), b"ping")
        sock.close()

    def test_plain_http_forward(self):
        sock = self.connect()
        sock.sendall(f"GET http://127.0.0.1:{self.http_port}/x HTTP/1.1\r\n"
                     f"Host: 127.0.0.1:{self.http_port}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        self.assertIn(b"200", data.split(b"\r\n")[0])
        self.assertIn(b"ok-body", data)
        sock.close()

    def test_reject_domain(self):
        self.proxy.set_rules([{"type": "domain-suffix", "value": "blocked.test",
                               "action": ACTION_REJECT},
                              {"type": "final", "value": "", "action": ACTION_DIRECT}])
        sock, head = self.http_connect("blocked.test", 80)
        self.assertIn(b"403", head.split(b"\r\n")[0])
        sock.close()
        self.assertGreaterEqual(self.proxy.stats.snapshot()["rejected"], 1)

    def test_proxy_mode_without_node_returns_502(self):
        self.proxy.set_mode(MODE_GLOBAL)
        sock, head = self.http_connect("example.com", 80)
        self.assertIn(b"502", head.split(b"\r\n")[0])
        sock.close()

    def test_stats_counted(self):
        sock, _ = self.http_connect("127.0.0.1", self.echo.port)
        recv_until(sock, b"HELLO")
        sock.close()
        time.sleep(0.2)
        snap = self.proxy.stats.snapshot()
        self.assertGreaterEqual(snap["total"], 1)
        self.assertGreaterEqual(snap["direct"], 1)


class TestAccelSubstitution(ProxyTestBase):
    rules = [{"type": "domain-suffix", "value": "accel.test", "action": ACTION_ACCEL},
             {"type": "final", "value": "", "action": ACTION_DIRECT}]

    def test_accel_uses_preferred_ip(self):
        self.proxy.set_accel_ip_provider(
            lambda host: "127.0.0.1" if host == "accel.test" else None)
        sock, head = self.http_connect("accel.test", self.echo.port)
        self.assertIn(b"200", head.split(b"\r\n")[0])
        self.assertEqual(recv_until(sock, b"HELLO"), b"HELLO")
        sock.close()
        time.sleep(0.2)
        self.assertGreaterEqual(self.proxy.stats.snapshot()["accel"], 1)

    def test_accel_falls_back_to_direct(self):
        self.proxy.set_accel_ip_provider(lambda host: None)
        sock, head = self.http_connect("accel.test", self.echo.port)
        # 没有优选 IP 时按普通直连处理，域名本身不可解析 → 502
        self.assertIn(b"502", head.split(b"\r\n")[0])
        sock.close()


class TestSocks5(ProxyTestBase):
    def test_socks5_connect(self):
        sock = self.connect()
        sock.sendall(b"\x05\x01\x00")
        self.assertEqual(sock.recv(2), b"\x05\x00")

        req = b"\x05\x01\x00\x03" + bytes([len("127.0.0.1")]) + b"127.0.0.1" \
              + self.echo.port.to_bytes(2, "big")
        sock.sendall(req)
        reply = sock.recv(10)
        self.assertEqual(reply[0], 5)
        self.assertEqual(reply[1], 0)
        self.assertEqual(recv_until(sock, b"HELLO"), b"HELLO")
        sock.close()

    def test_socks5_unsupported_command(self):
        sock = self.connect()
        sock.sendall(b"\x05\x01\x00")
        sock.recv(2)
        sock.sendall(b"\x05\x03\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x50")
        reply = sock.recv(10)
        self.assertEqual(reply[1], 0x07)
        sock.close()


class _RecordingWriter:
    """记录写入内容的假 writer（模拟 Shadowsocks 加密通道）。"""

    def __init__(self):
        self.chunks = []

    def send(self, data):
        self.chunks.append(bytes(data))
        return len(data)

    @property
    def raw(self):
        return b"".join(self.chunks)


class _EmptyReader:
    """立刻返回 EOF 的假 reader。"""

    def recv(self, _n):
        return b""


class TestTunnelPlainHttp(unittest.TestCase):
    """普通 HTTP（非 CONNECT）经节点隧道时，改写后的首部必须走加密 writer。

    回归：之前实现直接 _send(remote, prelude) 把明文写进 SS/Trojan 加密流，
    对端解帧 InvalidTag，导致所有 http:// 站点经节点访问全部失败。
    """

    def setUp(self):
        self.port = free_port()
        self.node = ProxyNode(name="tunnel-test", type="ss", server="127.0.0.1", port=1,
                              password="p", cipher="aes-256-gcm")
        self.writer = _RecordingWriter()
        self.remote, self.peer = socket.socketpair()
        self.proxy = LocalProxy(host="127.0.0.1", port=self.port, mode=MODE_GLOBAL,
                                node_provider=lambda: self.node)
        self.assertTrue(self.proxy.start(), self.proxy.bind_errors)
        time.sleep(0.1)

    def tearDown(self):
        self.proxy.stop()
        for sock in (self.remote, self.peer):
            try:
                sock.close()
            except OSError:
                pass

    def test_prelude_goes_through_encrypted_writer(self):
        with mock.patch.object(lp, "open_tunnel",
                               return_value=(self.remote, _EmptyReader(), self.writer)):
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            sock.settimeout(5)
            sock.sendall(b"GET http://plain.test/x HTTP/1.1\r\n"
                         b"Host: plain.test\r\nConnection: close\r\n\r\n")
            time.sleep(0.4)
            sock.close()

        self.assertTrue(self.writer.raw.startswith(b"GET /x HTTP/1.1"),
                        f"首部没有走 writer: {self.writer.raw[:80]!r}")
        self.assertIn(b"Host: plain.test", self.writer.raw)

        # 裸 socket 上不允许出现任何明文请求（否则就是泄进了加密流）
        self.peer.settimeout(0.5)
        try:
            leaked = self.peer.recv(4096)
        except socket.timeout:
            leaked = b""
        self.assertEqual(leaked, b"", f"明文泄漏到裸连接: {leaked[:80]!r}")


if __name__ == "__main__":
    unittest.main()
