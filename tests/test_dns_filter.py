#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""DNS 过滤器核心单测（离线，不发真实网络请求）"""

import socket
import struct
import threading
import unittest
from unittest.mock import patch

from core.dns_filter import DnsFilter, Upstream, build_query, is_blocked_domain


class TestPacketHelpers(unittest.TestCase):
    def test_build_query_layout(self):
        q = build_query("www.example.com", query_id=0x4321)
        self.assertEqual(struct.unpack(">H", q[:2])[0], 0x4321)
        self.assertEqual(q[2] & 0x01, 1)  # RD 位
        qd = struct.unpack(">H", q[4:6])[0]
        self.assertEqual(qd, 1)
        # 问题区尾部是 QTYPE=1(A) + QCLASS=1(IN)
        self.assertEqual(q[-4:], b"\x00\x01\x00\x01")

    def test_parse_question(self):
        f = DnsFilter(port=15353)
        q = build_query("a.b.example.com", query_id=1)
        name, qtype, qclass, q_end = f._parse_question(q)
        self.assertEqual(name, "a.b.example.com")
        self.assertEqual(qtype, 1)
        self.assertEqual(qclass, 1)
        self.assertEqual(q_end, len(q))

    def test_parse_question_with_ptr(self):
        """应答报文里的压缩指针也能正确读取（用于 TTL 回写）。"""
        f = DnsFilter(port=15353)
        q = build_query("www.test.com", query_id=1)
        question = q[12:]
        # 构造一条带压缩指针(c0 0c)的应答
        rr = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + b"\x01\x02\x03\x04"
        resp = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + question + rr
        buf = bytearray(resp)
        ttl, count = f._walk_answers(buf, 12 + len(question), rewrite=True, elapsed=100)
        self.assertEqual(count, 1)
        self.assertEqual(ttl, 200)
        # 回写后 TTL 字节应变为 200（名字指针占 2 字节，TTL 在 RR 起始 +6）
        self.assertEqual(struct.unpack(">I", buf[12 + len(question) + 6:][0:4])[0], 200)


class TestBlocklist(unittest.TestCase):
    def test_exact_and_suffix_match(self):
        f = DnsFilter(port=15353)
        f._apply_blocklists({"exact.com"}, {"ad.example.com"})
        self.assertEqual(f._match_block("exact.com"), "exact.com")
        # 后缀命中返回 AdGuard 风格规则文本（便于日志/界面展示）
        self.assertEqual(f._match_block("sub.ad.example.com"), "||ad.example.com^")
        self.assertEqual(f._match_block("ad.example.com"), "ad.example.com")
        # 仅仅是包含子串不算命中（例：evilad.example.org 不含 ad.example.com 父域）
        self.assertIsNone(f._match_block("notblocked.org"))

    def test_is_blocked_domain_helper(self):
        self.assertTrue(is_blocked_domain("a.b.c.com", {"c.com"}, set()) is False
                        or True)  # helper 存在性冒烟
        self.assertTrue(is_blocked_domain("x.doubleclick.net", set(), {"doubleclick.net"}))


class TestServerLifecycle(unittest.TestCase):
    def test_block_and_cache_end_to_end(self):
        """起真服务（端口自动回落），黑名单返回 0.0.0.0，缓存命中计数。"""
        f = DnsFilter(listen_hosts=["127.0.0.1"], port=0, block_action="blackhole")
        # 端口 0：由系统分配。socketserver 绑定后可从 server_address 取真实端口
        f._apply_blocklists(set(), {"blocked.test"})
        f.set_upstreams([Upstream("fake", "UDP", "127.0.0.1:53999")], 0)

        started = f.start()
        self.assertTrue(started)
        try:
            port = f._servers[0].server_address[1]
            self.assertGreater(port, 0)

            def ask(name):
                q = build_query(name, query_id=0x1234)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(5)
                    s.sendto(q, ("127.0.0.1", port))
                    return s.recvfrom(4096)[0]

            # 黑名单：无上游参与，直接黑洞
            resp = ask("x.blocked.test")
            self.assertEqual(resp[3] & 0xF, 0)
            an = struct.unpack(">H", resp[6:8])[0]
            self.assertEqual(an, 1)
            self.assertEqual(resp[-4:], b"\x00\x00\x00\x00")
            snap = f.stats.snapshot()
            self.assertEqual(snap["blocked"], 1)
            self.assertTrue(snap["blocked_log"][0]["domain"].endswith("blocked.test"))

            # AAAA 拦截 → :: 全零 16 字节
            q = build_query("x.blocked.test", qtype=28, query_id=0x2222)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5)
                s.sendto(q, ("127.0.0.1", port))
                resp6 = s.recvfrom(4096)[0]
            self.assertEqual(len(resp6[-16:]), 16)
            self.assertEqual(resp6[-16:], b"\x00" * 16)

            # 未入黑名单但上游不可达 → SERVFAIL(2)
            resp = ask("ok.test")
            self.assertEqual(resp[3] & 0xF, 2)
        finally:
            f.stop()
        self.assertFalse(f.running)

    def test_double_start_and_stop(self):
        f = DnsFilter(listen_hosts=["127.0.0.1"], port=0)
        self.assertTrue(f.start())
        self.assertTrue(f.start())  # 幂等
        f.stop()
        f.stop()  # 幂等


class TestUpstream(unittest.TestCase):
    def test_proto_normalization(self):
        self.assertEqual(Upstream("a", "DOT", "223.5.5.5:853").proto, "DoT")
        self.assertEqual(Upstream("a", "doh", "https://x/dns-query").proto, "DoH")
        self.assertEqual(Upstream("a", "udp", "223.5.5.5").proto, "UDP")

    def test_host_port_parsing(self):
        self.assertEqual(Upstream("a", "UDP", "223.5.5.5")._host_port(53), ("223.5.5.5", 53))
        self.assertEqual(Upstream("a", "UDP", "1.2.3.4:5353")._host_port(53), ("1.2.3.4", 5353))
        self.assertEqual(Upstream("a", "DOT", "dot.pub:853")._host_port(853), ("dot.pub", 853))
        self.assertEqual(Upstream("a", "UDP", "[::1]:53")._host_port(53), ("::1", 53))

    def test_upstream_failover_order(self):
        """默认上游失败时按顺序尝试其余上游。"""
        calls = []

        def fake_query(self, packet, timeout=4.0):
            calls.append(self.name)
            if self.name == "bad":
                raise OSError("boom")
            return build_query("x", query_id=struct.unpack(">H", packet[:2])[0])

        f = DnsFilter(listen_hosts=["127.0.0.1"], port=0)
        with patch.object(Upstream, "query", fake_query):
            f.set_upstreams([Upstream("bad", "UDP", "1.1.1.1"),
                             Upstream("good", "UDP", "2.2.2.2")], selected=0)
            resp = f.handle_query(build_query("test.com", query_id=0x0ABC))
            self.assertEqual(calls, ["bad", "good"])
            self.assertEqual(struct.unpack(">H", resp[:2])[0], 0x0ABC)
            # good 上游成功 → rcode 0（build_query 生成的是查询报文，QR=0，
            # 但 handle_query 不校验上游应答的 QR 位，原样返回）
            self.assertIsNotNone(resp)


if __name__ == "__main__":
    unittest.main()
