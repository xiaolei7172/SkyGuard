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
import time

from utils.logger import logger

SKYGUARD_DIR = os.path.join(os.path.expanduser("~"), ".skyguard")
DAILY_FILE = os.path.join(SKYGUARD_DIR, "stats_daily.json")
REPORT_DIR = os.path.join(SKYGUARD_DIR, "reports")

# 每日累计字段
FIELDS = ("dns_queries", "dns_blocked", "proxy_total", "proxy_up", "proxy_down")


def _today():
    return time.strftime("%Y-%m-%d")


def _load_daily():
    try:
        if os.path.exists(DAILY_FILE):
            with open(DAILY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
    except (OSError, ValueError) as e:
        logger.debug(f"读取每日统计失败: {e}")
    return {}


def _save_daily(data):
    try:
        os.makedirs(SKYGUARD_DIR, exist_ok=True)
        with open(DAILY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        return True
    except OSError as e:
        logger.debug(f"写入每日统计失败: {e}")
        return False


def record_delta(**deltas):
    """把一段时间内的增量累加到当天记录。全 0 时跳过写盘。"""
    clean = {k: int(v) for k, v in deltas.items()
             if k in FIELDS and int(v) > 0}
    if not clean:
        return
    data = _load_daily()
    today = _today()
    rec = data.setdefault(today, {k: 0 for k in FIELDS})
    for k, v in clean.items():
        rec[k] = int(rec.get(k, 0)) + v
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
        except (OSError, ValueError) as e:
            logger.debug(f"清理报告解析失败 {path}: {e}")
    return reports


def clean_totals(reports=None):
    """汇总清理历史：累计释放字节、次数。"""
    if reports is None:
        reports = load_clean_reports()
    total_size = sum(r["total_size"] for r in reports)
    return {"count": len(reports), "total_size": total_size}
