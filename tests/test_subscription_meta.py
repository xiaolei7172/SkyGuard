# -*- coding: utf-8 -*-
"""订阅元信息与状态管理测试（借鉴 Clash Verge 的订阅面板语义）。"""

import json
import os
import tempfile
import time
import unittest

from core.proxy_nodes import (
    NodeStore,
    ProxyNode,
    format_traffic,
    parse_subscription_headers,
    parse_subscription_userinfo,
)


class TestUserInfoParse(unittest.TestCase):
    def test_full(self):
        info = parse_subscription_userinfo(
            "upload=1024; download=2048; total=107374182400; expire=1767225600")
        self.assertEqual(info["upload"], 1024)
        self.assertEqual(info["download"], 2048)
        self.assertEqual(info["total"], 107374182400)
        self.assertEqual(info["expire"], 1767225600)

    def test_partial_and_broken(self):
        info = parse_subscription_userinfo("download=100; total=abc; unknown=1")
        self.assertEqual(info["download"], 100)
        self.assertEqual(info["total"], 0)
        self.assertEqual(parse_subscription_userinfo("")["total"], 0)

    def test_float_strings(self):
        self.assertEqual(parse_subscription_userinfo("total=1.5e3")["total"], 1500)


class TestHeaders(unittest.TestCase):
    def test_headers(self):
        meta = parse_subscription_headers({
            "Subscription-Userinfo": "upload=1; download=2; total=3; expire=1767225600",
            "Profile-Update-Interval": "12",
            "Content-Disposition": "attachment; filename*=UTF-8''%E6%9C%BA%E5%9C%BA.yaml",
        })
        self.assertTrue(meta["info_present"])
        self.assertEqual(meta["total"], 3)
        self.assertEqual(meta["interval"], 12)
        self.assertEqual(meta["title"], "机场.yaml")

    def test_plain_filename(self):
        meta = parse_subscription_headers(
            {"content-disposition": 'attachment; filename="sub.yaml"'})
        self.assertEqual(meta["title"], "sub.yaml")

    def test_missing(self):
        meta = parse_subscription_headers({})
        self.assertFalse(meta["info_present"])
        self.assertEqual(meta["interval"], 0)
        self.assertEqual(meta["title"], "")


class TestFormatTraffic(unittest.TestCase):
    def test_units(self):
        self.assertEqual(format_traffic(0), "0 B")
        self.assertEqual(format_traffic(1536), "1.5 KB")
        self.assertEqual(format_traffic(1048576), "1.0 MB")
        self.assertEqual(format_traffic(107374182400), "100.0 GB")


class TestStoreState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "nodes.json")
        self.store = NodeStore(self.path)

    def tearDown(self):
        try:
            os.remove(self.path)
        except OSError:
            pass
        os.rmdir(self.tmp)

    def _node(self, name="n1"):
        return ProxyNode(name=name, type="ss", server="1.2.3.4", port=8388,
                         password="p", cipher="aes-256-gcm")

    def test_upsert_keeps_state(self):
        self.store.upsert_subscription("机场A", "http://a/sub", [self._node()])
        self.store.set_subscription_state("机场A", enabled=False, interval=60)
        # 再次更新订阅内容，启用状态与间隔要保留
        self.store.upsert_subscription("机场A", "http://a/sub", [self._node("n2")])
        sub = self.store.subscription("机场A")
        self.assertFalse(sub["enabled"])
        self.assertEqual(sub["interval"], 60)
        self.assertEqual(len(sub["nodes"]), 1)
        self.assertEqual(sub["nodes"][0]["name"], "n2")

    def test_disabled_subscription_nodes_excluded(self):
        self.store.upsert_subscription("A", "http://a", [self._node("a1")])
        self.store.upsert_subscription("B", "http://b", [self._node("b1")])
        self.assertEqual(len(self.store.all_nodes()), 2)
        self.store.set_subscription_state("A", enabled=False)
        self.assertEqual([n.name for n in self.store.all_nodes()], ["b1"])

    def test_due_subscriptions(self):
        self.store.upsert_subscription("A", "http://a", [])
        self.store.set_subscription_state("A", interval=30)
        now = time.time()
        self.assertEqual(self.store.due_subscriptions(now), [])  # 刚更新过
        self.assertEqual(len(self.store.due_subscriptions(now + 31 * 60)), 1)
        # interval=0 不参与自动更新
        self.store.set_subscription_state("A", interval=0)
        self.assertEqual(self.store.due_subscriptions(now + 99999), [])

    def test_mark_updated_records_error(self):
        self.store.upsert_subscription("A", "http://a", [self._node()])
        self.store.mark_updated("A", error="404")
        self.assertEqual(self.store.subscription("A")["error"], "404")
        self.store.mark_updated("A", nodes=[], meta={"total": 100}, error="")
        sub = self.store.subscription("A")
        self.assertEqual(sub["error"], "")
        self.assertEqual(sub["meta"]["total"], 100)
        self.assertEqual(sub["nodes"], [])

    def test_persistence(self):
        self.store.upsert_subscription("A", "http://a", [self._node()],
                                       meta={"total": 5, "expire": 1767225600})
        self.store.set_subscription_state("A", interval=120)
        reloaded = NodeStore(self.path)
        sub = reloaded.subscription("A")
        self.assertEqual(sub["interval"], 120)
        self.assertEqual(sub["meta"]["expire"], 1767225600)
        with open(self.path, encoding="utf-8") as f:
            self.assertIn("subscriptions", json.load(f))


if __name__ == "__main__":
    unittest.main()
