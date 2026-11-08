# -*- coding: utf-8 -*-
"""上游黑洞拦截（去广告 DNS）识别能力测试。

背景：AdGuard DNS / 去广告机场 DoH 这类上游不返回 NXDOMAIN，而是回 0.0.0.0。
若软件把它当「放行」，用户在日志里完全看不出过滤有没有生效。
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.dns_filter import (
    RESULT_ALLOW, RESULT_UPSTREAM_BLOCKED, DnsFilter, QTYPE_A, Upstream, build_query,
)
from core.selfcheck import AD_PROBE_DOMAINS, make_upstream, probe_ad_block


class _FakeUpstream(Upstream):
    """按域名返回预设 IP 的假上游。"""

    def __init__(self, ip_map, name="fake"):
        super().__init__(name, "UDP", "127.0.0.1:1")
        self.ip_map = ip_map
        self.calls = 0

    def query(self, wire_query, timeout=4.0):
        self.calls += 1
        qid = struct.unpack(">H", wire_query[:2])[0]
        # 从问题段取出域名（测试里域名都不带压缩指针）
        off = 12
        labels = []
        while wire_query[off]:
            ln = wire_query[off]
            labels.append(wire_query[off + 1:off + 1 + ln].decode())
            off += ln + 1
        domain = ".".join(labels)
        question = wire_query[12:off + 5]
        ip = self.ip_map.get(domain)
        if ip is None:
            return struct.pack(">HHHHHH", qid, 0x8180, 1, 0, 0, 0) + question
        rdata = bytes(int(x) for x in ip.split("."))
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + rdata
        return struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + answer


class TestBlackholeDetect(unittest.TestCase):
    def test_blackhole_recognized_as_upstream_blocked(self):
        f = DnsFilter(port=15353)
        up = _FakeUpstream({"ads.test": "0.0.0.0", "ok.test": "1.2.3.4"})
        f.set_upstreams([up], 0)

        f.handle_query(build_query("ads.test", query_id=1), client="-")
        f.handle_query(build_query("ok.test", query_id=2), client="-")

        rows = {e["domain"]: e for e in f.stats.query_log.snapshot()}
        self.assertEqual(rows["ads.test"]["result"], RESULT_UPSTREAM_BLOCKED)
        self.assertEqual(rows["ads.test"]["result_label"], "上游拦截")
        self.assertIn("黑洞", rows["ads.test"]["rule"])
        self.assertEqual(rows["ok.test"]["result"], RESULT_ALLOW)

        snap = f.stats.snapshot()
        self.assertEqual(snap["blocked"], 1)     # 上游拦的也计入拦截数
        self.assertEqual(snap["total"], 2)

    def test_blackhole_counted_in_top_blocked(self):
        f = DnsFilter(port=15353)
        up = _FakeUpstream({"ads.test": "0.0.0.0"})
        f.set_upstreams([up], 0)
        for i in range(3):
            f.handle_query(build_query("ads.test", query_id=i + 1), client="-")
        agg = f.stats.query_log.aggregates()
        self.assertEqual(agg["top_blocked"][0], ("ads.test", 3))

    def test_cached_blackhole_keeps_classification(self):
        f = DnsFilter(port=15353)
        up = _FakeUpstream({"ads.test": "0.0.0.0"})
        f.set_upstreams([up], 0)
        f.handle_query(build_query("ads.test", query_id=1), client="-")
        f.handle_query(build_query("ads.test", query_id=2), client="-")  # 走缓存
        self.assertEqual(up.calls, 1)
        rows = f.stats.query_log.snapshot()
        # 两条都应标成「上游拦截」，缓存的不能退回「缓存命中」
        self.assertTrue(all(r["result"] == RESULT_UPSTREAM_BLOCKED for r in rows))
        self.assertEqual(f.stats.snapshot()["cache_hits"], 1)

    def test_normal_answer_not_mistaken(self):
        f = DnsFilter(port=15353)
        up = _FakeUpstream({"www.test": "110.242.68.66"})
        f.set_upstreams([up], 0)
        f.handle_query(build_query("www.test", query_id=1), client="-")
        self.assertEqual(f.stats.snapshot()["blocked"], 0)

    def test_empty_answer_not_blackhole(self):
        """无 A 记录（如只回 CNAME / 空应答）不能误判成拦截。"""
        f = DnsFilter(port=15353)
        up = _FakeUpstream({})     # 什么都不返回
        f.set_upstreams([up], 0)
        f.handle_query(build_query("empty.test", query_id=1), client="-")
        self.assertEqual(f.stats.snapshot()["blocked"], 0)


class TestAdProbe(unittest.TestCase):
    def test_probe_counts_blocked_and_allowed(self):
        up = _FakeUpstream({"doubleclick.net": "0.0.0.0", "umeng.com": "1.2.3.4"})
        blocked, allowed, failed = probe_ad_block(
            up, domains=["doubleclick.net", "umeng.com"])
        self.assertEqual(blocked, ["doubleclick.net"])
        self.assertEqual(allowed, ["umeng.com"])
        self.assertEqual(failed, [])

    def test_probe_records_failures(self):
        class Boom(Upstream):
            def __init__(self):
                super().__init__("boom", "UDP", "127.0.0.1:1")

            def query(self, wire_query, timeout=4.0):
                raise OSError("no route")

        blocked, allowed, failed = probe_ad_block(Boom(), domains=["a.test"])
        self.assertEqual((blocked, allowed), ([], []))
        self.assertEqual(len(failed), 1)

    def test_make_upstream_guesses_protocol(self):
        self.assertEqual(
            make_upstream("https://dns.example/dns-query").proto, "DoH")
        self.assertEqual(make_upstream("223.5.5.5:53").proto, "UDP")
        self.assertEqual(
            make_upstream({"name": "x", "proto": "DoT", "address": "1.1.1.1:853"}).proto, "DoT")
        self.assertEqual(make_upstream(None).address, "223.5.5.5:53")

    def test_probe_domains_cover_common_ad_hosts(self):
        # 样本里应同时有国内外常见广告域名，否则无法判断「去广告 DNS」
        joined = " ".join(AD_PROBE_DOMAINS)
        self.assertIn("doubleclick.net", joined)
        self.assertIn("pos.baidu.com", joined)
        self.assertGreaterEqual(len(AD_PROBE_DOMAINS), 5)


if __name__ == "__main__":
    unittest.main()
