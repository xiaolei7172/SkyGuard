#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""自检模块单测：报文解析、结果汇总、端口选择、provider 命名与节点过滤。"""

import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import clash_kernel
from core.clash_kernel import is_real_node, provider_name
from core.selfcheck import (CheckItem, FAIL, OK, SKIP, format_report, free_port,
                           parse_a_records, summarize)


def _fake_answer(ips, rcode=0, qname=b"\x07example\x03com\x00", qtype=1):
    """构造一个最小 DNS 应答，用于验证解析逻辑。"""
    header = struct.pack(">HHHHHH", 0x1234, 0x8180 | rcode, 1, len(ips), 0, 0)
    question = qname + struct.pack(">HH", qtype, 1)
    answers = b""
    for ip in ips:
        answers += (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
                    + socket.inet_aton(ip))
    return header + question + answers


class TestParseAnswers(unittest.TestCase):
    def test_parse_a_records(self):
        rcode, count, ips = parse_a_records(_fake_answer(["1.2.3.4", "5.6.7.8"]))
        self.assertEqual(rcode, 0)
        self.assertEqual(count, 2)
        self.assertEqual(ips, ["1.2.3.4", "5.6.7.8"])

    def test_parse_nxdomain(self):
        rcode, count, ips = parse_a_records(_fake_answer([], rcode=3))
        self.assertEqual(rcode, 3)
        self.assertEqual(count, 0)
        self.assertEqual(ips, [])

    def test_parse_short_packet(self):
        self.assertEqual(parse_a_records(b"\x00\x01")[0], -1)
        self.assertEqual(parse_a_records(b"")[2], [])


class TestSummarize(unittest.TestCase):
    def test_counts(self):
        items = [CheckItem("a", OK), CheckItem("b", OK),
                 CheckItem("c", FAIL, "挂了"), CheckItem("d", SKIP)]
        stat = summarize(items)
        self.assertEqual((stat["total"], stat["passed"], stat["failed"],
                          stat["skipped"]), (4, 2, 1, 1))
        self.assertFalse(stat["ok"])

    def test_all_pass(self):
        stat = summarize([CheckItem("a", OK)])
        self.assertTrue(stat["ok"])

    def test_empty_is_not_ok(self):
        self.assertFalse(summarize([])["ok"])

    def test_format_report(self):
        text = format_report([CheckItem("监听", OK, "已就绪", 12),
                              CheckItem("解析", FAIL, "超时")], title="DNS 自检")
        self.assertIn("== DNS 自检 ==", text)
        self.assertIn("[通过] 监听（12ms）：已就绪", text)
        self.assertIn("[失败] 解析：超时", text)
        self.assertIn("合计 2 项", text)


class TestFreePort(unittest.TestCase):
    def test_returns_bindable_port(self):
        port = free_port(15353)
        self.assertGreaterEqual(port, 15353)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
        finally:
            s.close()

    def test_skips_occupied_port(self):
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            holder.bind(("127.0.0.1", 15360))
            holder.listen(1)
            self.assertNotEqual(free_port(15360), 15360)
        finally:
            holder.close()


class TestProviderName(unittest.TestCase):
    def test_ascii_name_kept(self):
        self.assertEqual(provider_name("abc"), "sub_abc")

    def test_chinese_name_is_hashed(self):
        """中文名不能进 URL 路径，否则 http.client 用 ascii 编码报错。"""
        name = provider_name("自检订阅")
        self.assertTrue(name.isascii(), name)
        self.assertTrue(name.startswith("sub_"))
        self.assertNotEqual(provider_name("订阅甲"), provider_name("订阅乙"))

    def test_illegal_chars_replaced(self):
        name = provider_name("my sub/1")
        self.assertTrue(name.isascii())
        self.assertNotIn(" ", name)
        self.assertNotIn("/", name)


class TestIsRealNode(unittest.TestCase):
    def test_group_types_excluded(self):
        for t in ("selector", "urltest", "direct", "reject", "URLTest"):
            self.assertFalse(is_real_node("节点选择", {"type": t}), t)
        self.assertFalse(is_real_node("DIRECT", {}))

    def test_info_placeholder_excluded(self):
        for name in ("剩余流量：1005.44 GB", "套餐到期：长期有效", "官网：example.com",
                     "距离下次重置剩余 12 天"):
            self.assertFalse(is_real_node(name, {"type": "vless"}), name)

    def test_real_nodes_kept(self):
        self.assertTrue(is_real_node("🇯🇵日本东京01 | 移动联通推荐", {"type": "vless"}))
        self.assertTrue(is_real_node("美国圣何塞-hy2", {"type": "hysteria2"}))


class TestGeoSeedDirs(unittest.TestCase):
    def test_returns_existing_dirs_only(self):
        for path in clash_kernel.geo_seed_dirs(""):
            self.assertTrue(os.path.isdir(path), path)

    def test_kernel_dir_included(self):
        kernel = os.path.join(os.environ.get("TEMP", "."), "mihomo.exe")
        dirs = clash_kernel.geo_seed_dirs(kernel)
        base = os.path.dirname(os.path.abspath(kernel))
        self.assertIn(base, dirs) if os.path.isdir(base) else None


if __name__ == "__main__":
    unittest.main()
