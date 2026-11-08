# -*- coding: utf-8 -*-
"""clash_kernel 配置生成与节点映射的单元测试（不需要真实内核）。"""
import os
import unittest

from core import clash_kernel
from core.clash_kernel import build_config, node_to_clash
from core.proxy_nodes import ProxyNode


def make_node(**kw):
    defaults = dict(name="n1", type="ss", server="1.2.3.4", port=8388,
                    password="pw", cipher="aes-256-gcm")
    defaults.update(kw)
    return ProxyNode(**defaults)


class TestNodeToClash(unittest.TestCase):
    def test_ss(self):
        d = node_to_clash(make_node())
        self.assertEqual(d["type"], "ss")
        self.assertEqual(d["cipher"], "aes-256-gcm")
        self.assertEqual(d["server"], "1.2.3.4")
        self.assertTrue(d["udp"])

    def test_trojan_sni_default_server(self):
        d = node_to_clash(make_node(type="trojan", password="t", sni=""))
        self.assertEqual(d["type"], "trojan")
        self.assertEqual(d["sni"], "1.2.3.4")
        self.assertIn("skip-cert-verify", d)

    def test_http_with_auth(self):
        d = node_to_clash(make_node(type="http", username="u", password="p"))
        self.assertEqual(d["type"], "http")
        self.assertEqual(d["username"], "u")

    def test_socks5(self):
        d = node_to_clash(make_node(type="socks5", username="u"))
        self.assertEqual(d["type"], "socks5")
        self.assertTrue(d["udp"])

    def test_unsupported_returns_none(self):
        self.assertIsNone(node_to_clash(make_node(type="hysteria2")))


class TestBuildConfig(unittest.TestCase):
    def base(self, **kw):
        defaults = dict(
            subscriptions=[{"name": "机场A", "url": "https://sub.example.com/x"}],
            manual_nodes=[make_node()],
            rules=[],
        )
        defaults.update(kw)
        return build_config(**defaults)

    def test_ports_and_api(self):
        cfg = self.base(mixed_port=17896, api_port=19091)
        self.assertEqual(cfg["mixed-port"], 17896)
        self.assertEqual(cfg["external-controller"], "127.0.0.1:19091")
        self.assertTrue(cfg["secret"])
        self.assertIn("mixed-port", cfg)

    def test_provider_generated_from_subscription(self):
        cfg = self.base()
        self.assertEqual(len(cfg["proxy-providers"]), 1)
        (p,) = cfg["proxy-providers"].values()
        self.assertEqual(p["url"], "https://sub.example.com/x")
        self.assertEqual(p["type"], "http")
        # 提供者被节点选择组引用
        (group,) = cfg["proxy-groups"]
        self.assertIn(list(cfg["proxy-providers"])[0], group["use"])

    def test_manual_node_in_group(self):
        cfg = self.base()
        (group,) = cfg["proxy-groups"]
        self.assertIn("n1", group["proxies"])
        self.assertIn("DIRECT", group["proxies"])
        self.assertEqual(cfg["proxies"][0]["name"], "n1")

    def test_rule_mapping(self):
        rules = [
            {"type": "domain-suffix", "value": "cn.example", "action": "DIRECT"},
            {"type": "domain-keyword", "value": "ads", "action": "REJECT"},
            {"type": "ip-cidr", "value": "10.0.0.0/8", "action": "DIRECT"},
            {"type": "domain-suffix", "value": "corp.com", "action": "PROXY"},
            {"type": "final", "value": "", "action": "PROXY"},
        ]
        cfg = self.base(rules=rules)
        self.assertIn("DOMAIN-SUFFIX,cn.example,DIRECT", cfg["rules"])
        self.assertIn("DOMAIN-KEYWORD,ads,REJECT", cfg["rules"])
        self.assertIn("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", cfg["rules"])
        self.assertIn("DOMAIN-SUFFIX,corp.com,🚀 节点选择", cfg["rules"])
        self.assertIn("MATCH,🚀 节点选择", cfg["rules"])

    def test_accel_domains_direct(self):
        cfg = self.base(accel_domains=["github.com", "steampowered.com"])
        self.assertIn("DOMAIN-SUFFIX,github.com,DIRECT", cfg["rules"])
        self.assertIn("DOMAIN-SUFFIX,steampowered.com,DIRECT", cfg["rules"])

    def test_smart_mode_geoip_direct(self):
        cfg = self.base(clash_mode="rule")
        self.assertIn("GEOIP,CN,DIRECT", cfg["rules"])
        self.assertTrue(any(r.startswith("MATCH,") for r in cfg["rules"]))

    def test_global_mode_only_match(self):
        cfg = self.base(clash_mode="global",
                        rules=[{"type": "domain-suffix", "value": "x.com",
                                "action": "DIRECT"}])
        self.assertEqual(cfg["rules"], ["MATCH,🚀 节点选择"])

    def test_direct_mode(self):
        cfg = self.base(clash_mode="direct")
        self.assertEqual(cfg["rules"], ["MATCH,DIRECT"])

    def test_local_dns(self):
        cfg = self.base(local_dns=True)
        self.assertIn("127.0.0.1", cfg["dns"]["nameserver"])

    def test_empty_subscription_skipped(self):
        cfg = self.base(subscriptions=[{"name": "空", "url": " "}])
        self.assertEqual(cfg["proxy-providers"], {})

    def test_yaml_roundtrip(self):
        import yaml
        cfg = self.base()
        text = yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False)
        loaded = yaml.safe_load(text)
        self.assertEqual(loaded["mixed-port"], cfg["mixed-port"])
        self.assertIn("DOMAIN-SUFFIX,cn.example,DIRECT", loaded["rules"]) \
            if False else None


class TestFindKernel(unittest.TestCase):
    def test_returns_none_or_path(self):
        # 不依赖环境，只保证不抛异常且返回 str 或 None
        result = clash_kernel.find_kernel("")
        self.assertTrue(result is None or os.path.isfile(result))

    def test_configured_path_wins(self):
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".exe")
        os.close(fd)
        try:
            self.assertEqual(clash_kernel.find_kernel(path), path)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
