#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
system_metrics 纯函数单测

只测不依赖系统状态的纯函数（速率格式化、差分基线逻辑）。
温度走 WMI，各机器表现不同，不进自动化断言——验收标准是
"能读到就给数，读不到就 None"，由冒烟测试人工确认。
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.system_metrics import SystemMetrics, format_bytes, format_rate


class TestFormatRate(unittest.TestCase):
    """速率格式化：悬浮窗上每一格数字都经过它。"""

    def test_zero(self):
        self.assertEqual(format_rate(0), "0 B/s")

    def test_negative_clamped(self):
        # 计数器回绕会出现负差分，上游已归零，这里验证兜底
        self.assertEqual(format_rate(-5), "0 B/s")

    def test_bytes(self):
        self.assertEqual(format_rate(500), "500 B/s")

    def test_kilobytes_one_decimal(self):
        self.assertEqual(format_rate(2048), "2.0 KB/s")

    def test_megabytes_no_decimal_when_large(self):
        self.assertEqual(format_rate(15 * 1024 * 1024), "15 MB/s")

    def test_gigabytes(self):
        self.assertEqual(format_rate(2.5 * 1024 ** 3), "2.5 GB/s")

    def test_invalid(self):
        self.assertEqual(format_rate(None), "—")
        self.assertEqual(format_rate("abc"), "—")


class TestFormatBytes(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(format_bytes(500), "500 B")

    def test_megabytes(self):
        self.assertEqual(format_bytes(5 * 1024 * 1024), "5.0 MB")

    def test_gigabytes(self):
        self.assertEqual(format_bytes(31.5 * 1024 ** 3), "31.5 GB")


class TestNetworkDiff(unittest.TestCase):
    """网速差分：首帧只建基线，第二帧才算速率，计数器回绕要重建基线。"""

    def _make_counters(self, sent, recv):
        counters = patch.dict("os.environ")
        # psutil 的 namedtuple 只要 bytes_sent / bytes_recv 两个字段
        from collections import namedtuple

        NetIO = namedtuple(
            "NetIO",
            "bytes_sent bytes_recv packets_sent packets_recv errin errout dropin dropout",
        )
        return NetIO(sent, recv, 0, 0, 0, 0, 0, 0)

    def _metrics_with(self, counters):
        metrics = SystemMetrics()
        fake_psutil = type("P", (), {"net_io_counters": staticmethod(lambda: counters)})()
        return metrics, fake_psutil

    def test_first_sample_no_speed(self):
        metrics, fake = self._metrics_with(self._make_counters(1000, 2000))
        with patch("core.system_metrics.psutil", fake):
            data = metrics.sample()
        self.assertEqual(data["download_bps"], 0.0)
        self.assertEqual(data["upload_bps"], 0.0)

    def test_second_sample_computes_rate(self):
        metrics, fake = self._metrics_with(self._make_counters(1000, 2000))
        # 两次采样共享同一个 monotonic 序列：0.0 建基线，10.0 算速率
        with patch("core.system_metrics.psutil", fake), \
             patch("core.system_metrics.time.monotonic", side_effect=[0.0, 10.0]):
            metrics.sample()
            fake.net_io_counters = staticmethod(lambda: self._make_counters(11_000, 42_000))
            data = metrics.sample()
        self.assertAlmostEqual(data["download_bps"], 4000.0, delta=1)
        self.assertAlmostEqual(data["upload_bps"], 1000.0, delta=1)

    def test_counter_reset_rebuilds_baseline(self):
        metrics, fake = self._metrics_with(self._make_counters(1_000_000, 2_000_000))
        with patch("core.system_metrics.psutil", fake), \
             patch("core.system_metrics.time.monotonic", side_effect=[0.0, 10.0]):
            metrics.sample()
            # 网卡重置后计数器清零：差分为负，应重建基线而不是输出负速率
            fake.net_io_counters = staticmethod(lambda: self._make_counters(50, 100))
            data = metrics.sample()
        self.assertEqual(data["download_bps"], 0.0)
        self.assertEqual(data["upload_bps"], 0.0)


if __name__ == "__main__":
    unittest.main()
