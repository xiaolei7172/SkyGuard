#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""全盘空间分析引擎测试（只读逻辑，不触碰真实磁盘以外内容）"""

import os
import sys
import time
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import disk_analyzer as da  # noqa: E402


class TestDirSize(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        os.makedirs(os.path.join(root, "sub", "deep"))
        with open(os.path.join(root, "a.bin"), "wb") as f:
            f.write(b"x" * 1000)
        with open(os.path.join(root, "sub", "b.bin"), "wb") as f:
            f.write(b"y" * 2000)
        with open(os.path.join(root, "sub", "deep", "c.bin"), "wb") as f:
            f.write(b"z" * 3000)

    def tearDown(self):
        self.tmp.cleanup()

    def test_dir_size_recursive(self):
        size, count = da.dir_size(self.tmp.name)
        self.assertEqual(size, 6000)
        self.assertEqual(count, 3)

    def test_dir_size_single_file(self):
        size, count = da.dir_size(os.path.join(self.tmp.name, "a.bin"))
        self.assertEqual((size, count), (1000, 1))

    def test_dir_size_missing(self):
        self.assertEqual(da.dir_size(os.path.join(self.tmp.name, "nope")), (0, 0))


class TestBigFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        for name, size in (("big1.bin", 300), ("big2.bin", 500), ("small.bin", 10),
                          ("pagefile.sys", 999), ("swapfile.sys", 999)):
            with open(os.path.join(root, name), "wb") as f:
                f.write(b"0" * size)

    def tearDown(self):
        self.tmp.cleanup()

    def test_big_files_excludes_system(self):
        analyzer = da.DiskAnalyzer()
        with patch.object(da, "BIG_FILE_MIN", 100):
            files = analyzer._scan_big_files([self.tmp.name], None, lambda m, p: None)
        names = [os.path.basename(f["path"]) for f in files]
        self.assertIn("big1.bin", names)
        self.assertIn("big2.bin", names)
        self.assertNotIn("pagefile.sys", names)
        self.assertNotIn("swapfile.sys", names)
        self.assertNotIn("small.bin", names)
        self.assertEqual(files[0]["size"], 500)      # 降序


class TestDuplicates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.content = b"dup" * 1000
        for i in range(2):
            with open(os.path.join(self.tmp.name, f"copy{i}.bin"), "wb") as f:
                f.write(self.content)
        with open(os.path.join(self.tmp.name, "unique.bin"), "wb") as f:
            f.write(b"uniq" * 1000)

    def tearDown(self):
        self.tmp.cleanup()

    def test_find_duplicates(self):
        analyzer = da.DiskAnalyzer()
        size = len(self.content)
        big = [{"size": size, "path": os.path.join(self.tmp.name, "copy0.bin"), "mtime": 0},
               {"size": size, "path": os.path.join(self.tmp.name, "copy1.bin"), "mtime": 0},
               {"size": size, "path": os.path.join(self.tmp.name, "unique.bin"), "mtime": 0}]
        with patch.object(da, "DUP_FILE_MIN", 1):
            groups = analyzer._find_duplicates(big, None, lambda m, p: None)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]["paths"]), 2)
        self.assertEqual(groups[0]["wasted"], size)


class TestOldFiles(unittest.TestCase):
    def test_filter_old(self):
        now = time.time()
        files = [{"path": "new", "size": 1, "mtime": now},
                 {"path": "old", "size": 1, "mtime": now - da.OLD_FILE_DAYS * 86400 - 10}]
        old = da.DiskAnalyzer._filter_old(files)
        self.assertEqual([f["path"] for f in old], ["old"])


class TestOverview(unittest.TestCase):
    def test_overview_has_system_drive(self):
        ov = da.DiskAnalyzer.overview()
        self.assertTrue(ov)
        self.assertTrue(any(d["total"] > 0 for d in ov))
        for d in ov:
            self.assertIn("percent", d)
            self.assertGreaterEqual(d["percent"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
