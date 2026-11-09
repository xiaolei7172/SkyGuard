#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""历史统计中心数据层。

- 清理历史：直接聚合 clean_engine 落盘的 reports/clean_*.json（数据已有，零新增写入）。
- DNS / 代理用量：内存里的累计计数器按天增量落盘到 stats_daily.json，
  由主窗口的采样定时器周期调用 record_delta()（服务重启计数清零时自动按 0 处理）。
"""

import glob
import json
import os
import threading
import time

from utils import atomic_io

SKYGUARD_DIR = os.path.join(os.path.expanduser("~"), ".skyguard")
DAILY_FILE = os.path.join(SKYGUARD_DIR, "stats_daily.json")
REPORT_DIR = os.path.join(SKYGUARD_DIR, "reports")
TOTALS_FILE = os.path.join(SKYGUARD_DIR, "clean_totals.json")

# 每日累计字段
FIELDS = ("dns_queries", "dns_blocked", "proxy_total", "proxy_up", "proxy_down")

# 落盘保留天数：load_daily 只看 30 天，留 180 天足够回溯，也避免文件无限增长
KEEP_DAYS = 180

# record_delta 是「读-改-写」，目前只有 UI 采样定时器在调；
# 加锁是为了将来把采样搬到后台线程时不会静默丢计数。
_daily_lock = threading.Lock()
_totals_lock = threading.Lock()


def _today():
    return time.strftime("%Y-%m-%d")


def _load_daily():
    return atomic_io.read_json(DAILY_FILE, default={}, expect=dict)


def _save_daily(data):
    return atomic_io.write_json(DAILY_FILE, data)


def _prune(data, today):
    """只保留最近 KEEP_DAYS 天，返回是否有裁剪。"""
    if len(data) <= KEEP_DAYS + 10:
        return False
    try:
        cutoff = time.strftime(
            "%Y-%m-%d", time.localtime(time.time() - KEEP_DAYS * 86400))
    except (OSError, ValueError, OverflowError):
        return False
    stale = [d for d in data if d < cutoff]
    for d in stale:
        data.pop(d, None)
    return bool(stale)


def record_delta(**deltas):
    """把一段时间内的增量累加到当天记录。全 0 时跳过写盘。"""
    clean = {k: int(v) for k, v in deltas.items()
             if k in FIELDS and int(v) > 0}
    if not clean:
        return
    with _daily_lock:
        data = _load_daily()
        today = _today()
        rec = data.setdefault(today, {k: 0 for k in FIELDS})
        for k, v in clean.items():
            rec[k] = int(rec.get(k, 0)) + v
        _prune(data, today)
        _save_daily(data)


def load_daily(days=30):
    """最近 N 天的每日用量，按日期升序返回 [{date, ...FIELDS}]。"""
    data = _load_daily()
    result = []
    for i in range(days - 1, -1, -1):
        day = time.strftime("%Y-%m-%d", time.localtime(time.time() - i * 86400))
        rec = data.get(day, {})
        row = {"date": day}
        for k in FIELDS:
            row[k] = int(rec.get(k, 0) or 0)
        result.append(row)
    return result


def load_clean_reports(limit=200):
    """解析清理报告（新→旧）。字段缺失/损坏的文件跳过并记录日志。"""
    reports = []
    try:
        files = sorted(glob.glob(os.path.join(REPORT_DIR, "clean_*.json")),
                       reverse=True)
    except OSError:
        return reports
    for path in files[:limit]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                r = json.load(f)
            reports.append({
                "time": str(r.get("time", "")),
                "to_recycle": bool(r.get("to_recycle", True)),
                "total_size": int(r.get("total_size", 0) or 0),
                "total_files": int(r.get("total_files", 0) or 0),
                "total_dirs": int(r.get("total_dirs", 0) or 0),
                "failures": int(r.get("failures", 0) or 0),
                "rule_count": len(r.get("rules", []) or []),
            })
        except (OSError, ValueError):
            # 损坏的报告不阻塞整页刷新（warning 由调用方按签名去重）
            continue
    return reports


def reports_signature():
    """报告目录的轻量签名（文件名+修改时间+大小），用于跳过无变化的重建。"""
    try:
        files = sorted(glob.glob(os.path.join(REPORT_DIR, "clean_*.json")))
    except OSError:
        return ()
    sig = []
    for path in files:
        try:
            st = os.stat(path)
            sig.append((os.path.basename(path), int(st.st_mtime), st.st_size))
        except OSError:
            continue
    return tuple(sig)


def ensure_totals_seeded():
    """首次使用累加账时，用现存报告播种（只做一次）。

    老版本升级上来时 reports/ 里已有历史报告；如果直接等 record_clean 累加，
    那些历史就永远漏统计了。空目录也写一份 0 值，标记"已播种"避免反复扫描。
    """
    with _totals_lock:
        if atomic_io.read_json(TOTALS_FILE, default=None, expect=dict) is not None:
            return False
        reports = load_clean_reports(limit=10 ** 6)
        totals = {
            "count": len(reports),
            "total_size": sum(r["total_size"] for r in reports),
            "last_time": reports[0]["time"] if reports else "",
            "seeded_at": _today(),
        }
        atomic_io.write_json(TOTALS_FILE, totals)
        return True


def record_clean(report):
    """一次清理完成后累加到总量。

    必须单独记账：报告文件只保留最近 200 份，若"累计释放空间"靠扫描报告求和，
    轮转一次数字就会倒退。
    """
    ensure_totals_seeded()      # 历史先入账，避免首次清理时把老报告漏掉
    # 累加账用 _totals_lock：和 ensure_totals_seeded 抢同一把锁，
    # 原来这里用 _daily_lock 保护 TOTALS_FILE，播种与累加可能交错丢计数
    with _totals_lock:
        totals = atomic_io.read_json(TOTALS_FILE, default=None, expect=dict) or {}
        totals["count"] = int(totals.get("count", 0)) + 1
        totals["total_size"] = (int(totals.get("total_size", 0))
                                + int(report.get("total_size", 0) or 0))
        totals["last_time"] = str(report.get("time", "") or "")
        atomic_io.write_json(TOTALS_FILE, totals)


def clean_totals(reports=None):
    """累计清理次数与释放字节（读累加账，轮转删报告也不受影响）。"""
    ensure_totals_seeded()
    totals = atomic_io.read_json(TOTALS_FILE, default={}, expect=dict) or {}
    return {"count": int(totals.get("count", 0) or 0),
            "total_size": int(totals.get("total_size", 0) or 0)}
