# -*- coding: utf-8 -*-
"""DNS 新增能力测试：查询日志、Top 统计、重写、并行上游、TTL 上下限。"""

import struct
import threading
import time
import unittest

from core.dns_filter import (
    RESULT_BLOCKED,
    RESULT_CACHED,
    RESULT_REWRITE,
    STRATEGY_PARALLEL,
    DnsFilter,
    QueryLog,
    Upstream,
    build_query,
)


def _answer_ips(resp):
    """从应答里取出全部 A 记录 IP（只处理应答含 1 条 answer 的简单情形）。"""
    an = struct.unpack(">H", resp[6:8])[0]
    if an == 0:
        return []
    # 解析问题区长度
    off = 12
    while resp[off] != 0:
        off += 1 + resp[off]
    off += 5
    # 跳过名字（可能是指针）
    off += 2
    rdlen = struct.unpack(">H", resp[off + 8:off + 10])[0]
    return [resp[off + 10:off + 10 + rdlen]]


class TestQueryLog(unittest.TestCase):
    def test_add_and_snapshot(self):
        log = QueryLog(size=10)
        log.add("10.0.0.2", "a.com", 1, RESULT_BLOCKED, rule="||a.com^")
        log.add("10.0.0.3", "b.com", 28, "allow", upstream="阿里 UDP", ms=12.5)
        rows = log.snapshot()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["domain"], "b.com")  # 新的在前
        self.assertEqual(rows[1]["qtype"], "A")
        self.assertEqual(rows[1]["result_label"], "已拦截")
        self.assertEqual(rows[0]["ms"], 12.5)

    def test_filter_by_result_and_search(self):
        log = QueryLog()
        log.add("10.0.0.2", "ads.com", 1, RESULT_BLOCKED)
        log.add("10.0.0.2", "ok.com", 1, "allow")
        log.add("10.0.0.9", "ads.net", 1, RESULT_BLOCKED)
        self.assertEqual(len(log.snapshot(result=RESULT_BLOCKED)), 2)
        self.assertEqual(len(log.snapshot(search="ads")), 2)
        self.assertEqual(len(log.snapshot(search="10.0.0.9")), 1)
        self.assertEqual(len(log.snapshot(limit=1)), 1)

    def test_maxlen_and_clear(self):
        log = QueryLog(size=50)
        for i in range(60):
            log.add("-", f"d{i}.com", 1, "allow")
        self.assertEqual(log.size, 50)
        log.clear()
        self.assertEqual(log.size, 0)

    def test_paused(self):
        log = QueryLog()
        log.paused = True
        log.add("-", "a.com", 1, "allow")
        self.assertEqual(log.size, 0)
        self.assertEqual(log.dropped, 1)


class TestAggregates(unittest.TestCase):
    def test_top_lists(self):
        f = DnsFilter(port=15353)
        f._apply_blocklists(set(), {"ads.test"})
        f.handle_query(build_query("x.ads.test", query_id=1), client="10.0.0.2")
        f.handle_query(build_query("x.ads.test", query_id=2), client="10.0.0.2")
        f.handle_query(build_query("y.ads.test", query_id=3), client="10.0.0.3")
        agg = f.stats.query_log.aggregates(top_n=3)
        self.assertEqual(agg["top_clients"][0], ("10.0.0.2", 2))
        self.assertEqual(agg["top_blocked"][0], ("x.ads.test", 2))
        self.assertEqual(agg["by_type"][0][0], "A")
        self.assertEqual(len(agg["hourly"]), 24)

    def test_snapshot_counts(self):
        f = DnsFilter(port=15353)
        f._apply_blocklists(set(), {"ads.test"})
        f.handle_query(build_query("a.ads.test", query_id=1), client="1.1.1.1")
        snap = f.stats.snapshot()
        self.assertEqual(snap["total"], 1)
        self.assertEqual(snap["blocked"], 1)
        self.assertEqual(snap["log_size"], 1)
        self.assertEqual(len(snap["blocked_log"]), 1)


class TestRewrite(unittest.TestCase):
    def test_a_record_rewrite(self):
        f = DnsFilter(port=15353)
        f.set_rewrites({"nas.home": "192.168.1.10"})
        resp = f.handle_query(build_query("nas.home", query_id=0x1111), client="127.0.0.1")
        self.assertIsNotNone(resp)
        self.assertEqual(struct.unpack(">H", resp[6:8])[0], 1)  # an=1
        self.assertEqual(resp[-4:], bytes([192, 168, 1, 10]))
        snap = f.stats.snapshot()
        self.assertEqual(snap["rewrites"], 1)
        self.assertEqual(f.stats.query_log.snapshot()[0]["result"], RESULT_REWRITE)

    def test_wildcard_rewrite(self):
        f = DnsFilter(port=15353)
        f.set_rewrites({"*.lan": "10.0.0.5"})
        resp = f.handle_query(build_query("printer.lan", query_id=2), client="-")
        self.assertEqual(resp[-4:], bytes([10, 0, 0, 5]))

    def test_invalid_rewrite_ignored(self):
        f = DnsFilter(port=15353)
        self.assertEqual(f.set_rewrites({"bad.home": "not-an-ip"}), 0)

    def test_type_mismatch_returns_empty_answer(self):
        f = DnsFilter(port=15353)
        f.set_rewrites({"nas.home": "192.168.1.10"})
        resp = f.handle_query(build_query("nas.home", qtype=28, query_id=3), client="-")
        self.assertEqual(struct.unpack(">H", resp[6:8])[0], 0)  # 空应答，避免回落真实 AAAA


class _FakeUpstream(Upstream):
    """可控上游：延时指定秒数后返回一条 A 记录应答。"""

    def __init__(self, name, delay=0.0, fail=False, ip="1.2.3.4"):
        super().__init__(name, "UDP", "127.0.0.1:1")
        self.delay = delay
        self.fail = fail
        self.ip = ip
        self.calls = 0

    def query(self, wire_query, timeout=4.0):
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise OSError("fake fail")
        qid = struct.unpack(">H", wire_query[:2])[0]
        question = wire_query[12:]
        rdata = bytes(int(x) for x in self.ip.split("."))
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + rdata
        return (struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + answer)


class TestUpstreamStrategy(unittest.TestCase):
    def test_sequential_failover(self):
        f = DnsFilter(port=15353)
        bad = _FakeUpstream("bad", fail=True)
        good = _FakeUpstream("good")
        f.set_upstreams([bad, good], 0)
        self.assertEqual(f.upstream_strategy, "sequential")
        resp = f.handle_query(build_query("a.test", query_id=1), client="-")
        self.assertEqual(resp[-4:], bytes([1, 2, 3, 4]))
        self.assertEqual(bad.calls, 1)
        snap = f.stats.snapshot()
        self.assertEqual(snap["upstreams"]["bad"]["fail"], 1)
        self.assertEqual(snap["upstreams"]["good"]["ok"], 1)

    def test_parallel_takes_fastest(self):
        f = DnsFilter(port=15353)
        slow = _FakeUpstream("slow", delay=0.6, ip="9.9.9.9")
        fast = _FakeUpstream("fast", delay=0.05, ip="5.5.5.5")
        f.set_upstreams([slow, fast], 0)
        f.upstream_strategy = STRATEGY_PARALLEL
        start = time.monotonic()
        resp = f.handle_query(build_query("a.test", query_id=2), client="-")
        cost = time.monotonic() - start
        self.assertEqual(resp[-4:], bytes([5, 5, 5, 5]))
        self.assertLess(cost, 0.5)  # 没等慢的那个
        self.assertEqual(slow.calls, 1)
        self.assertEqual(fast.calls, 1)

    def test_no_upstream_servfail(self):
        f = DnsFilter(port=15353)
        f.set_upstreams([], 0)
        resp = f.handle_query(build_query("a.test", query_id=3), client="-")
        self.assertEqual(resp[3] & 0xF, 2)
        self.assertEqual(f.stats.query_log.snapshot()[0]["result"], "fail")


class TestCacheTtlBounds(unittest.TestCase):
    def test_cache_hit_recorded(self):
        f = DnsFilter(port=15353)
        up = _FakeUpstream("u")
        f.set_upstreams([up], 0)
        q = build_query("cache.test", query_id=1)
        f.handle_query(q, client="-")
        f.handle_query(build_query("cache.test", query_id=2), client="-")
        self.assertEqual(up.calls, 1)
        self.assertEqual(f.stats.snapshot()["cache_hits"], 1)
        results = [r["result"] for r in f.stats.query_log.snapshot()]
        self.assertIn(RESULT_CACHED, results)

    def test_min_ttl_clamped(self):
        f = DnsFilter(port=15353)
        f.cache_min_ttl = 120
        up = _FakeUpstream("u")     # 应答 TTL=30
        f.set_upstreams([up], 0)
        f.handle_query(build_query("clamp.test", query_id=1), client="-")
        with f._cache_lock:
            _expires, _resp, min_ttl, _up = next(iter(f._cache.values()))
        self.assertEqual(min_ttl, 120)


if __name__ == "__main__":
    unittest.main()
