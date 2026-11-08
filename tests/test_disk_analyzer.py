#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""全盘空间分析引擎测试（只读逻辑，不触碰真实磁盘以外内容）"""

import os
import sys
import time
import tempfile
import unittest
import unittest.mock
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


class TestRemoteAndRemovable(unittest.TestCase):
    """网络盘/U 盘必须排除，否则遍历会卡死或扫到拔出的盘"""

    class _Part:
        def __init__(self, dev, mnt, fs, opts):
            self.device, self.mountpoint, self.fstype, self.opts = dev, mnt, fs, opts

    def _run(self, include_removable=False):
        from unittest.mock import patch
        fake = [self._Part("C://", "C://", "NTFS", "rw,fixed"),
                self._Part("Z://", "Z://", "NTFS", "rw,remote"),
                self._Part("Y://", "Y://", "cifs", "rw"),
                self._Part("F://", "F://", "FAT32", "rw,removable")]
        with patch("psutil.disk_partitions", return_value=fake), \
                patch("psutil.disk_usage") as du:
            du.return_value.total = 100
            du.return_value.used = 40
            du.return_value.free = 60
            du.return_value.percent = 40
            return [d["mount"] for d in da.DiskAnalyzer.overview(include_removable)]

    def test_skip_remote(self):
        mounts = self._run()
        self.assertIn("C://", mounts)
        self.assertNotIn("Z://", mounts)
        self.assertNotIn("Y://", mounts)

    def test_removable_optional(self):
        self.assertNotIn("F://", self._run())
        self.assertIn("F://", self._run(include_removable=True))


class TestPatternPath(unittest.TestCase):
    """开发缓存里的通配路径（如 WSL 的 Packages\\*\\LocalState\\ext4.vhdx）要能展开"""

    def test_expand_file_in_wildcard_dir(self):
        with tempfile.TemporaryDirectory() as base:
            pkg = os.path.join(base, "Packages")
            target = os.path.join(pkg, "Ubuntu_abc", "LocalState")
            os.makedirs(target)
            vhdx = os.path.join(target, "ext4.vhdx")
            with open(vhdx, "wb") as f:
                f.write(b"0")
            got = da._expand_pattern_path(os.path.join(pkg, "*", "LocalState", "ext4.vhdx"))
            self.assertEqual(got, [vhdx])

    def test_expand_missing_returns_empty(self):
        with tempfile.TemporaryDirectory() as base:
            self.assertEqual(da._expand_pattern_path(os.path.join(base, "nope", "*.bin")), [])


class TestRecycleNotAutoCleaned(unittest.TestCase):
    """回收站不可恢复，必须标记为需单独确认，不能混进一键清理"""

    def test_recycle_marked_manual(self):
        with tempfile.TemporaryDirectory() as base:
            rb = os.path.join(base, "$Recycle.Bin")
            os.makedirs(rb)
            with open(os.path.join(rb, "a.bin"), "wb") as f:
                f.write(b"x" * 10)
            analyzer = da.DiskAnalyzer()
            with unittest.mock.patch.object(da.DiskAnalyzer, "_fixed_drives", return_value=[base]):
                items = analyzer._scan_system(None)
        rb_items = [i for i in items if i["key"] == "recycle_bin"]
        self.assertTrue(rb_items)
        self.assertIn("规则清理", rb_items[0]["action_text"])   # 不参与一键清理
        self.assertIn("不可恢复", rb_items[0]["detail"])        # 风险如实告知
