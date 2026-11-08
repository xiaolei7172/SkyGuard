#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""节点与订阅解析单测（离线）"""

import base64
import json
import os
import tempfile
import unittest

from core.proxy_nodes import (
    NodeStore, ProxyNode, parse_proxy_uri, parse_subscription,
)


def b64(text):
    return base64.b64encode(text.encode()).decode()


class TestUriParsing(unittest.TestCase):
    def test_ss_legacy_base64(self):
        payload = b64("aes-256-gcm:pass123@1.2.3.4:8388")
        node = parse_proxy_uri(f"ss://{payload}#香港 01")
        self.assertIsNotNone(node)
        self.assertEqual(node.type, "ss")
        self.assertEqual(node.server, "1.2.3.4")
        self.assertEqual(node.port, 8388)
        self.assertEqual(node.cipher, "aes-256-gcm")
        self.assertEqual(node.password, "pass123")
        self.assertEqual(node.name, "香港 01")

    def test_ss_sip002_userinfo(self):
        node = parse_proxy_uri("ss://chacha20-ietf-poly1305:pw@example.com:443#Dummy")
        self.assertEqual(node.cipher, "chacha20-ietf-poly1305")
        self.assertEqual(node.port, 443)
        self.assertEqual(node.server, "example.com")

    def test_ss_unsupported_cipher_rejected(self):
        payload = b64("rc4-md5:pw@1.2.3.4:8388")
        self.assertIsNone(parse_proxy_uri(f"ss://{payload}"))

    def test_trojan_with_sni_and_insecure(self):
        node = parse_proxy_uri(
            "trojan://secret@example.com:443?sni=cdn.example.com&allowInsecure=1#US")
        self.assertEqual(node.type, "trojan")
        self.assertEqual(node.password, "secret")
        self.assertEqual(node.sni, "cdn.example.com")
        self.assertTrue(node.skip_cert_verify)

    def test_socks5_with_auth(self):
        node = parse_proxy_uri("socks5://user:pass@10.0.0.1:1080#内网")
        self.assertEqual(node.type, "socks5")
        self.assertEqual(node.username, "user")
        self.assertEqual(node.password, "pass")

    def test_ipv6_host(self):
        payload = b64("aes-128-gcm:pw@[2001:db8::1]:8388")
        node = parse_proxy_uri(f"ss://{payload}")
        self.assertEqual(node.server, "2001:db8::1")
        self.assertEqual(node.port, 8388)

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_proxy_uri("http://"))
        self.assertIsNone(parse_proxy_uri("not a uri"))


class TestSubscription(unittest.TestCase):
    def test_base64_subscription(self):
        lines = [
            "ss://" + b64("aes-256-gcm:pw@1.1.1.1:8388") + "#A",
            "trojan://pw@2.2.2.2:443#B",
            "vmess://eyJhZGQiOiIzLjMuMy4zIn0=",
        ]
        text = base64.b64encode("\n".join(lines).encode()).decode()
        nodes, skipped = parse_subscription(text, "测试订阅")
        self.assertEqual(len(nodes), 2)
        self.assertEqual(skipped.get("vmess"), 1)
        self.assertTrue(all(n.subscription == "测试订阅" for n in nodes))

    def test_clash_yaml(self):
        text = """
proxies:
  - name: 香港 01
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pass
  - name: 日本 01
    type: trojan
    server: jp.example.com
    port: 443
    password: pw
    sni: jp.example.com
    skip-cert-verify: true
  - name: vless 节点
    type: vless
    server: x.example.com
    port: 443
    uuid: abc
"""
        nodes, skipped = parse_subscription(text, "clash")
        self.assertEqual(len(nodes), 2)
        self.assertEqual(nodes[0].name, "香港 01")
        self.assertEqual(nodes[1].type, "trojan")
        self.assertTrue(nodes[1].skip_cert_verify)
        self.assertEqual(skipped.get("vless"), 1)

    def test_duplicate_nodes_deduped(self):
        line = "trojan://pw@2.2.2.2:443#B"
        nodes, _ = parse_subscription(line + "\n" + line)
        self.assertEqual(len(nodes), 1)

    def test_empty(self):
        self.assertEqual(parse_subscription(""), ([], {}))


class TestNodeStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "nodes.json")
        self.store = NodeStore(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_manual_add_and_find(self):
        node = ProxyNode(name="n1", type="trojan", server="a.com", port=443, password="p")
        self.assertTrue(self.store.add_manual(node))
        self.assertFalse(self.store.add_manual(node))  # 重复
        found = self.store.find(node.uid)
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "n1")
        self.assertEqual(self.store.node_count(), 1)

    def test_remove_manual(self):
        node = ProxyNode(name="n1", type="ss", server="a.com", port=1,
                         password="p", cipher="aes-128-gcm")
        self.store.add_manual(node)
        self.assertTrue(self.store.remove_node(node.uid))
        self.assertEqual(self.store.node_count(), 0)

    def test_subscription_persisted(self):
        nodes = [ProxyNode(name="s1", type="http", server="b.com", port=8080)]
        self.store.upsert_subscription("sub", "https://x/sub", nodes)
        reloaded = NodeStore(self.path)
        self.assertEqual(reloaded.node_count(), 1)
        self.assertEqual(reloaded.subscriptions[0]["name"], "sub")
        data = json.load(open(self.path, encoding="utf-8"))
        self.assertIn("subscriptions", data)

    def test_update_existing_subscription(self):
        self.store.upsert_subscription("sub", "https://x/sub",
                                       [ProxyNode(name="s1", type="http", server="b.com", port=1)])
        self.store.upsert_subscription("sub", "https://x/sub",
                                       [ProxyNode(name="s2", type="http", server="c.com", port=2)])
        self.assertEqual(len(self.store.subscriptions), 1)
        self.assertEqual(self.store.subscriptions[0]["nodes"][0]["name"], "s2")


if __name__ == "__main__":
    unittest.main()
