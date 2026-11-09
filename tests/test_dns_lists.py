# -*- coding: utf-8 -*-
"""过滤器列表管理测试（本地文件，不联网）。"""

import os
import tempfile
import time
import unittest

from core import dns_lists


class TestListEntry(unittest.TestCase):
    def test_normalize(self):
        e = dns_lists.normalize_entry({"url": " http://a/list.txt ", "name": ""})
        self.assertEqual(e["url"], "http://a/list.txt")
        self.assertEqual(e["name"], "http://a/list.txt")
        self.assertTrue(e["enabled"])
        self.assertEqual(e["interval"], 24)
        self.assertIsNone(dns_lists.normalize_entry({"name": "no-url"}))


class TestUpdateAndMerge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.listfile = os.path.join(self.tmp, "list.txt")
        with open(self.listfile, "w", encoding="utf-8") as f:
            f.write("# 测试列表\n0.0.0.0 ads.test\n||track.test^\n@@||ok.track.test^\n")
        self._old_dir = dns_lists.list_cache_dir
        dns_lists.list_cache_dir = lambda: os.path.join(self.tmp, "cache")

    def tearDown(self):
        dns_lists.list_cache_dir = self._old_dir
        for name in os.listdir(os.path.join(self.tmp, "cache")) if os.path.isdir(
                os.path.join(self.tmp, "cache")) else []:
            os.remove(os.path.join(self.tmp, "cache", name))
        os.remove(self.listfile)
        if os.path.isdir(os.path.join(self.tmp, "cache")):
            os.rmdir(os.path.join(self.tmp, "cache"))
        os.rmdir(self.tmp)

    def test_update_list_from_file(self):
        entry = {"name": "本地列表", "url": self.listfile, "enabled": True}
        count, err = dns_lists.update_list(entry)
        self.assertIsNone(err)
        self.assertEqual(count, 3)
        self.assertEqual(entry["count"], 3)
        self.assertGreater(entry["updated"], 0)

    def test_merged_rules_skips_disabled(self):
        e1 = {"url": self.listfile, "enabled": True}
        dns_lists.update_list(e1)
        e2 = {"url": self.listfile + ".missing", "enabled": False}
        lines, counts = dns_lists.merged_rules([e1, e2])
        self.assertEqual(len(lines), 3)
        self.assertEqual(counts[self.listfile], 3)

    def test_missing_cache_is_empty(self):
        self.assertEqual(dns_lists.load_cached_rules({"url": "http://none/x.txt"}), [])

    def test_is_due(self):
        entry = {"url": "http://a", "enabled": True, "interval": 12,
                 "updated": int(time.time()) - 13 * 3600}
        self.assertTrue(dns_lists.is_due(entry))
        self.assertFalse(dns_lists.is_due(dict(entry, updated=int(time.time()))))
        self.assertFalse(dns_lists.is_due(dict(entry, interval=0)))

    def test_update_failure_keeps_error(self):
        count, err = dns_lists.update_list({"url": os.path.join(self.tmp, "nope.txt")})
        self.assertEqual(count, 0)
        self.assertTrue(err)


if __name__ == "__main__":
    unittest.main()


class TestDefaultListsMerge(unittest.TestCase):
    """内置订阅补齐：老用户升级后应补上天影两条列表，删掉的不再回填。"""

    def test_merge_into_empty(self):
        entries, added = dns_lists.merge_default_lists([], 0)
        self.assertEqual(len(added), 2)
        self.assertEqual(len(entries), 2)
        urls = {e["url"] for e in entries}
        self.assertTrue(any("adblock.txt" in u for u in urls))
        self.assertTrue(any("allow.txt" in u for u in urls))

    def test_merge_keeps_existing(self):
        old = {"name": "老列表", "url": "https://anti-ad.net/adguard.txt", "enabled": False}
        entries, added = dns_lists.merge_default_lists([old], 0)
        self.assertEqual(len(entries), 3)
        self.assertEqual(len(added), 2)
        self.assertFalse([e for e in entries if e["url"] == old["url"]][0]["enabled"])

    def test_merge_is_idempotent_after_version(self):
        entries, added = dns_lists.merge_default_lists([], 0)
        again, added2 = dns_lists.merge_default_lists(entries, dns_lists.DEFAULT_LISTS_VERSION)
        self.assertEqual(added2, [])
        self.assertEqual(len(again), 2)

    def test_deleted_default_not_readded(self):
        entries, _ = dns_lists.merge_default_lists([], 0)
        kept = entries[:1]
        again, added = dns_lists.merge_default_lists(kept, dns_lists.DEFAULT_LISTS_VERSION)
        self.assertEqual(added, [])
        self.assertEqual(len(again), 1)


class TestCompiledStateCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.listfile = os.path.join(self.tmp, "list.txt")
        with open(self.listfile, "w", encoding="utf-8") as f:
            f.write("||ads.test^\n@@||ok.ads.test^\n"
                    "@@||cdn.big.com/x$domain=site.com\n||p.test/a/b^\n")
        self._old_dir = dns_lists.list_cache_dir
        dns_lists.list_cache_dir = lambda: os.path.join(self.tmp, "cache")
        dns_lists._STATE_CACHE.clear()

    def tearDown(self):
        dns_lists.list_cache_dir = self._old_dir
        dns_lists._STATE_CACHE.clear()
        cache = os.path.join(self.tmp, "cache")
        for name in os.listdir(cache) if os.path.isdir(cache) else []:
            os.remove(os.path.join(cache, name))
        if os.path.isdir(cache):
            os.rmdir(cache)
        os.remove(self.listfile)
        os.rmdir(self.tmp)

    def test_state_only_counts_dns_rules(self):
        entry = {"name": "本地", "url": self.listfile, "enabled": True}
        count, err = dns_lists.update_list(entry)
        self.assertIsNone(err)
        # 4 行里 2 行是作用域/路径规则，DNS 层只认 2 条
        self.assertEqual(count, 2)
        state = dns_lists.load_cached_state(entry)
        self.assertIsNotNone(state)
        self.assertEqual(state["lines"], 2)

    def test_state_cache_invalidated_on_change(self):
        entry = {"name": "本地", "url": self.listfile, "enabled": True}
        dns_lists.update_list(entry)
        first = dns_lists.load_cached_state(entry)
        self.assertIs(first, dns_lists.load_cached_state(entry))
        with open(self.listfile, "a", encoding="utf-8") as f:
            f.write("||extra.test^\n")
        dns_lists.update_list(entry)
        second = dns_lists.load_cached_state(entry)
        self.assertIsNot(first, second)
        self.assertEqual(second["lines"], 3)

    def test_merged_states_skips_disabled(self):
        e1 = {"url": self.listfile, "enabled": True}
        dns_lists.update_list(e1)
        states, counts = dns_lists.merged_states(
            [e1, {"url": self.listfile + ".x", "enabled": False}])
        self.assertEqual(len(states), 1)
        self.assertEqual(counts[self.listfile], 2)
