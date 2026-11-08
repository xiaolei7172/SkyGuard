#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
系统指标采集：网络速率 / CPU / 内存 / 温度

设计要点
--------
1. **网速用差分算**：`net_io_counters()` 给的是开机以来的累计字节，必须
   两次采样相减再除以间隔。首次采样只建基线、返回 0，否则第一帧会出现
   "本次开机以来总共下载了 60 GB，速度 60 GB/s" 这种荒唐数字。
2. **温度是尽力而为**：Windows 没有统一的 CPU 温度接口，
   `psutil.sensors_temperatures()` 在 Windows 上根本不存在。这里按可靠性
   依次尝试 LibreHardwareMonitor → OpenHardwareMonitor → ACPI 热区，
   全拿不到就返回 None，由 UI 显示 "—"，绝不编造数值。
3. **温度查询要缓存 + 退避**：WMI 单次查询 100~500 ms，每秒一次会拖垮 UI，
   所以成功缓存 5 秒；失败后指数退避（最长 120 秒再试），避免在传感器
   不可用的机器上每秒打一次异常、把日志刷满。
4. **不做 Qt 依赖**：本模块可脱离界面单独测试（`python system_metrics.py`）。
"""

import time


try:
    import psutil
except ImportError:  # pragma: no cover - 打包环境一定带 psutil
    psutil = None


# 温度查询退避参数（秒）
_TEMP_CACHE_TTL = 5.0
_TEMP_BACKOFF_START = 15.0
_TEMP_BACKOFF_MAX = 120.0


def format_rate(bytes_per_sec):
    """把字节/秒格式化成人类可读的速率。"""
    try:
        value = float(bytes_per_sec)
    except (TypeError, ValueError):
        return "—"
    if value < 0:
        value = 0.0
    units = (("GB/s", 1024 ** 3), ("MB/s", 1024 ** 2), ("KB/s", 1024), ("B/s", 1))
    for suffix, scale in units:
        if value >= scale:
            num = value / scale
            # 10 以上不留小数，省宽度；10 以下保留一位，读数才有意义
            return f"{num:.0f} {suffix}" if num >= 10 else f"{num:.1f} {suffix}"
    return "0 B/s"


def format_bytes(num_bytes):
    """把字节数格式化成人类可读的容量。"""
    try:
        value = float(num_bytes)
    except (TypeError, ValueError):
        return "—"
    for suffix, scale in (("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024)):
        if value >= scale:
            return f"{value / scale:.1f} {suffix}"
    return f"{value:.0f} B"


class SystemMetrics:
    """系统指标采样器（有状态：网速靠两次采样差分，温度有缓存）。"""

    def __init__(self):
        self._prev_net = None
        self._prev_time = None
        self._temp_cache = {}          # {"cpu": float|None, "gpu": float|None, "source": str}
        self._temp_expire = 0.0        # 缓存到期时间
        self._temp_retry_at = 0.0      # 退避：这个时刻之前不再尝试
        self._temp_backoff = _TEMP_BACKOFF_START
        self._net_warned = False

        # 首次调用 cpu_percent 传 interval=None 会返回 0.0，
        # 这里先"预热"一次，让下一次拿到有意义的区间值
        if psutil:
            try:
                psutil.cpu_percent(interval=None)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 采样
    # ------------------------------------------------------------------
    def sample(self):
        """采集一次全部指标，返回扁平字典（UI 直接消费）。"""
        now = time.monotonic()
        data = {
            "upload_bps": 0.0,
            "download_bps": 0.0,
            "cpu_percent": None,
            "mem_percent": None,
            "mem_used": None,
            "mem_total": None,
            "cpu_temp": None,
            "gpu_temp": None,
            "temp_source": "",
            "timestamp": now,
        }

        if psutil is None:
            return data

        self._sample_network(data, now)
        self._sample_cpu_mem(data)
        temps = self._temperatures(now)
        if temps:
            data["cpu_temp"] = temps.get("cpu")
            data["gpu_temp"] = temps.get("gpu")
            data["temp_source"] = temps.get("source", "")
        return data

    def _sample_network(self, data, now):
        try:
            counters = psutil.net_io_counters()
        except Exception:
            return

        if self._prev_net is None:
            # 只建基线，不产出速度
            self._prev_net = counters
            self._prev_time = now
            return

        elapsed = now - self._prev_time
        if elapsed <= 0:
            return
        # 计数器被重置（网卡禁用/驱动重载）时会出现负数，直接归零重建基线
        sent = counters.bytes_sent - self._prev_net.bytes_sent
        recv = counters.bytes_recv - self._prev_net.bytes_recv
        if sent < 0 or recv < 0:
            self._prev_net, self._prev_time = counters, now
            return
        data["upload_bps"] = sent / elapsed
        data["download_bps"] = recv / elapsed
        self._prev_net = counters
        self._prev_time = now

    def _sample_cpu_mem(self, data):
        try:
            data["cpu_percent"] = psutil.cpu_percent(interval=None)
        except Exception:
            pass
        try:
            mem = psutil.virtual_memory()
            data["mem_percent"] = mem.percent
            data["mem_used"] = mem.used
            data["mem_total"] = mem.total
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 温度
    # ------------------------------------------------------------------
    def _temperatures(self, now):
        if now < self._temp_retry_at:
            return self._temp_cache or None
        if self._temp_cache and now < self._temp_expire:
            return self._temp_cache

        result = self._query_temperatures()
        if result:
            self._temp_cache = result
            self._temp_expire = now + _TEMP_CACHE_TTL
            self._temp_backoff = _TEMP_BACKOFF_START
            self._temp_retry_at = 0.0
            return result

        # 一个都读不到：指数退避，别每秒撞一次 WMI
        self._temp_cache = {}
        self._temp_retry_at = now + self._temp_backoff
        self._temp_backoff = min(self._temp_backoff * 2, _TEMP_BACKOFF_MAX)
        return None

    def _query_temperatures(self):
        """依次尝试三种数据源，返回 dict 或 None。"""
        if not _WMI_AVAILABLE():
            return None

        for reader in (self._read_lhm, self._read_acpi):
            try:
                value = reader()
            except Exception:
                continue
            if value:
                return value
        return None

    @staticmethod
    def _read_lhm():
        """LibreHardwareMonitor / OpenHardwareMonitor 的 WMI 传感器。

        这两个是 Windows 上唯一能拿到真实 CPU/GPU 温度的通用途径，
        但需要用户本机装有对应软件且处于运行状态。
        """
        import win32com.client

        cpu = gpu = None
        source = ""
        for namespace in ("root\\LibreHardwareMonitor", "root\\OpenHardwareMonitor"):
            try:
                wmi = win32com.client.GetObject(
                    "winmgmts:{impersonationLevel=impersonate}!\\\\.\\" + namespace
                )
                sensors = wmi.InstancesOf("Sensor")
            except Exception:
                continue

            for sensor in sensors:
                try:
                    if str(sensor.SensorType) != "Temperature":
                        continue
                    name = str(sensor.Name or "")
                    value = float(sensor.Value)
                except Exception:
                    continue
                if not (0 < value < 130):
                    continue
                lower = name.lower()
                if cpu is None and "cpu" in lower:
                    cpu = value
                elif gpu is None and "gpu" in lower:
                    gpu = value

            if cpu is not None or gpu is not None:
                source = namespace.split("\\")[-1]
                break

        if cpu is None and gpu is None:
            return None
        return {"cpu": cpu, "gpu": gpu, "source": source}

    @staticmethod
    def _read_acpi():
        """ACPI 热区温度（root\\WMI）。

        这是系统自带数据源，不需要装软件，但多数台式机主板不上报，
        只有部分笔记本可用。数值单位是 0.1 开尔文。
        """
        import win32com.client

        wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\WMI")
        zones = wmi.InstancesOf("MSAcpi_ThermalZoneTemperature")

        readings = []
        for zone in zones:
            try:
                celsius = float(zone.CurrentTemperature) / 10.0 - 273.15
            except Exception:
                continue
            # 过滤明显的假值：0 表示未实现，负值或 120+ 是换算错
            if 5 < celsius < 120:
                readings.append(celsius)

        if not readings:
            return None
        # 多个热区时取最高温：最接近 "热点" 语义，比取平均更实用
        return {"cpu": max(readings), "gpu": None, "source": "ACPI"}


def _WMI_AVAILABLE():
    """win32com 是否可用（非 Windows 环境或未装 pywin32 时返回 False）。"""
    try:
        import win32com.client  # noqa: F401
    except Exception:
        return False
    return True


if __name__ == "__main__":  # pragma: no cover - 手工自查用
    metrics = SystemMetrics()
    print("首次采样（只建网速基线）:", metrics.sample())
    time.sleep(1.2)
    snapshot = metrics.sample()
    print(f"下载 {format_rate(snapshot['download_bps'])} / "
          f"上传 {format_rate(snapshot['upload_bps'])} | "
          f"CPU {snapshot['cpu_percent']}% | "
          f"内存 {snapshot['mem_percent']}%")
    for label, key in (("CPU", "cpu_temp"), ("GPU", "gpu_temp")):
        value = snapshot[key]
        print(f"{label} 温度: {'—' if value is None else f'{value:.0f}°C'}"
              f"（来源 {snapshot['temp_source'] or '不可用'}）")
