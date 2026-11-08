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
