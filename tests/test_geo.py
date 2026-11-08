#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""国内外智能分流单测（不依赖外网，DNS 用桩替换）"""

import os
import tempfile
import time
import unittest
from unittest.mock import patch

from core.geo import GeoClassifier
from core.local_proxy import (
    ACTION_ACCEL, ACTION_DIRECT, ACTION_PROXY, DEFAULT_RULES,
    MODE_RULE, MODE_SMART, RuleEngine,
)


class FakeGeo:
    """按预设表回答，避免真实 DNS。"""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def should_direct(self, host, timeout=None):
        self.calls.append(host)
        if host in self.table:
            return self.table[host]
        for suffix, value in self.table.items():
            if host.endswith("." + suffix):
                return value
        return False


class TestGeoClassifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.geo = GeoClassifier()

    def test_ip_lookup(self):
        self.assertTrue(self.geo.is_china_ip("1.0.1.1"))       # 阿里 / 国内段
        self.assertFalse(self.geo.is_china_ip("8.8.8.8"))      # Google
        self.assertFalse(self.geo.is_china_ip("not-an-ip"))

    def test_domain_suffix(self):
        self.assertTrue(self.geo.is_china_domain("baidu.com"))
        self.assertTrue(self.geo.is_china_domain("www.baidu.com"))
        self.assertTrue(self.geo.is_china_domain("foo.cn"))
        self.assertTrue(self.geo.is_china_domain("github.com.cn"))
        self.assertFalse(self.geo.is_china_domain("github.com"))
        self.assertFalse(self.geo.is_china_domain("notbaidu.com"))

    def test_should_direct_by_domain(self):
        self.assertTrue(self.geo.should_direct("www.qq.com"))

    def test_should_direct_by_resolved_ip(self):
        with patch.object(self.geo, "_getaddrinfo", return_value=["1.0.1.1"]):
            self.assertTrue(self.geo.should_direct("unknown-cn-site.test"))
        with patch.object(self.geo, "_getaddrinfo", return_value=["8.8.8.8"]):
            self.assertFalse(self.geo.should_direct("unknown-foreign-site.test"))

    def test_resolve_failure_goes_proxy(self):
        with patch.object(self.geo, "_getaddrinfo", return_value=[]):
            self.assertFalse(self.geo.should_direct("blocked-domain.test"))

    def test_resolve_timeout_goes_proxy(self):
        geo = GeoClassifier(resolve_timeout=0.05)
        with patch.object(geo, "_getaddrinfo", side_effect=lambda h: time.sleep(0.3) or []):
            started = time.time()
            self.assertFalse(geo.should_direct("slow-domain.test"))
            self.assertLess(time.time() - started, 0.5)

    def test_verdict_cached(self):
        geo = GeoClassifier()
        with patch.object(geo, "_getaddrinfo", return_value=["8.8.8.8"]) as mocked:
            geo.should_direct("cache-me.test")
            geo.should_direct("cache-me.test")
            self.assertEqual(mocked.call_count, 1)

    def test_missing_database_still_works(self):
        geo = GeoClassifier(data_path="/nonexistent/x.txt", user_path="/nonexistent/y.txt")
        self.assertEqual(geo.range_count, 0)
        self.assertIn("缺失", geo.source)
        self.assertTrue(geo.should_direct("baidu.com"))       # 域名表仍然生效
        self.assertFalse(geo.should_direct("example.com"))    # 没有 IP 库时只能按国外

    def test_lookup_speed(self):
        """单次判定要足够快，不能拖慢每条连接。"""
        self.assertGreater(self.geo.range_count, 1000)
        started = time.perf_counter()
        for _ in range(5000):
            self.geo.should_direct("www.baidu.com")
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 0.5, f"5000 次域名判定耗时 {elapsed:.3f}s")


class TestSmartMode(unittest.TestCase):
    def test_rules_first_then_geo(self):
        geo = FakeGeo({"baidu.com": True, "google.com": False})
        engine = RuleEngine(DEFAULT_RULES, mode=MODE_SMART, geo=geo)
        self.assertEqual(engine.match("github.com")[0], ACTION_ACCEL)   # 显式规则优先
        self.assertEqual(engine.match("www.baidu.com"), (ACTION_DIRECT, "国内直连"))
        self.assertEqual(engine.match("www.google.com"), (ACTION_PROXY, "国外走代理"))
        self.assertEqual(engine.match("127.0.0.1")[0], ACTION_DIRECT)   # 本机不查库
        self.assertNotIn("127.0.0.1", geo.calls)

    def test_smart_without_geo_falls_back(self):
        engine = RuleEngine(DEFAULT_RULES, mode=MODE_SMART)
        self.assertEqual(engine.match("some-unknown-site.com")[0], ACTION_DIRECT)

    def test_rule_mode_ignores_geo(self):
        geo = FakeGeo({"baidu.com": True})
        engine = RuleEngine(DEFAULT_RULES, mode=MODE_RULE, geo=geo)
        self.assertEqual(engine.match("some-unknown-site.com")[0], ACTION_DIRECT)
        self.assertEqual(geo.calls, [])

    def test_global_mode_ignores_geo(self):
        geo = FakeGeo({"baidu.com": True})
        engine = RuleEngine(DEFAULT_RULES, mode="global", geo=geo)
        self.assertEqual(engine.match("www.baidu.com")[0], ACTION_PROXY)
        self.assertEqual(geo.calls, [])


if __name__ == "__main__":
    unittest.main()
