#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""优选 IP / hosts 管理单测（除本机回环外不发真实网络请求）"""

import json
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from core import ip_optimizer
from core.ip_optimizer import (
    HOSTS_BEGIN, HOSTS_END, IpCache, optimize_domain, strip_our_block, tcp_latency,
)


class TestHostsBlock(unittest.TestCase):
    def test_strip_existing_block(self):
        text = ("127.0.0.1 localhost\n"
                f"{HOSTS_BEGIN}\n1.2.3.4 github.com\n{HOSTS_END}\n"
                "10.0.0.1 intranet\n")
        rest, found = strip_our_block(text)
        self.assertTrue(found)
        self.assertIn("localhost", rest)
        self.assertIn("intranet", rest)
        self.assertNotIn("github.com", rest)
        self.assertNotIn(HOSTS_BEGIN, rest)

    def test_strip_no_block(self):
        text = "127.0.0.1 localhost\n"
        rest, found = strip_our_block(text)
        self.assertFalse(found)
        self.assertEqual(rest, text)

    def test_write_hosts_requires_admin(self):
        with patch.object(ip_optimizer, "is_admin", return_value=False):
            ok, msg, count = ip_optimizer.write_hosts([("github.com", "1.2.3.4")])
        self.assertFalse(ok)
        self.assertIn("管理员", msg)
        self.assertEqual(count, 0)

    def test_write_hosts_empty_pairs(self):
        ok, msg, _ = ip_optimizer.write_hosts([])
        self.assertFalse(ok)
        self.assertIn("测速", msg)


class TestIpCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "cache.json")
        self.cache = IpCache(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_update_and_best(self):
        self.cache.update([{"domain": "github.com",
                            "ips": [{"ip": "1.1.1.1", "ms": 20, "source": "阿里"}],
                            "ts": int(time.time())}])
        self.assertEqual(self.cache.best_ip("github.com"), "1.1.1.1")
        self.assertEqual(self.cache.best_for_suffix("api.github.com"), "1.1.1.1")
        self.assertIsNone(self.cache.best_ip("unknown.com"))
        self.assertTrue(os.path.exists(self.path))

    def test_reload_from_disk(self):
        self.cache.update([{"domain": "a.com",
                            "ips": [{"ip": "9.9.9.9", "ms": 5, "source": "腾讯"}],
                            "ts": int(time.time())}])
        other = IpCache(self.path)
        self.assertEqual(other.best_ip("a.com"), "9.9.9.9")

    def test_stale_entry_ignored(self):
        self.cache.update([{"domain": "old.com",
                            "ips": [{"ip": "2.2.2.2", "ms": 30, "source": "x"}],
                            "ts": int(time.time()) - 7 * 3600}])
        self.assertIsNone(self.cache.best_ip("old.com"))

    def test_as_hosts_pairs(self):
        self.cache.set_from_pairs([("github.com", "3.3.3.3"), ("bad", "not-ip")])
        pairs = dict(self.cache.as_hosts_pairs())
        self.assertEqual(pairs, {"github.com": "3.3.3.3"})


class TestOptimize(unittest.TestCase):
    def test_optimize_domain_sorts_and_truncates(self):
        candidates = [("1.1.1.1", "阿里"), ("2.2.2.2", "腾讯"), ("3.3.3.3", "Google")]
        latency = {"1.1.1.1": 120, "2.2.2.2": 30, "3.3.3.3": 80}
        with patch.object(ip_optimizer, "resolve_candidates", return_value=candidates), \
                patch.object(ip_optimizer, "tcp_latency", side_effect=lambda ip, port, t: latency[ip]):
            result = optimize_domain("github.com", top_n=2)
        self.assertEqual([x["ip"] for x in result["ips"]], ["2.2.2.2", "3.3.3.3"])
        self.assertEqual(result["domain"], "github.com")

    def test_optimize_domain_no_candidates(self):
        with patch.object(ip_optimizer, "resolve_candidates", return_value=[]):
            result = optimize_domain("none.example")
        self.assertEqual(result["ips"], [])

    def test_optimize_domain_skips_unreachable(self):
        candidates = [("1.1.1.1", "阿里"), ("2.2.2.2", "腾讯")]
        latency = {"1.1.1.1": None, "2.2.2.2": 40}
        with patch.object(ip_optimizer, "resolve_candidates", return_value=candidates), \
                patch.object(ip_optimizer, "tcp_latency", side_effect=lambda ip, port, t: latency[ip]):
            result = optimize_domain("github.com", top_n=3)
        self.assertEqual(len(result["ips"]), 1)
        self.assertEqual(result["ips"][0]["ip"], "2.2.2.2")


class TestTcpLatency(unittest.TestCase):
    def test_local_listener(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        port = server.getsockname()[1]
        threading.Thread(target=lambda: server.accept(), daemon=True).start()
        ms = tcp_latency("127.0.0.1", port, timeout=2)
        server.close()
        self.assertIsNotNone(ms)
        self.assertGreaterEqual(ms, 0)

    def test_closed_port(self):
        port = 1  # 基本可以确定没有服务
        self.assertIsNone(tcp_latency("127.0.0.1", port, timeout=0.3))


if __name__ == "__main__":
    unittest.main()
