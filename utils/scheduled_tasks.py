#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""定时自动化任务：复用内存清理的定时线程模型。

- 自动清理：每 N 天自动跑一次垃圾清理（仅缓存类规则，强制走回收站）。
- 自动优选：每天指定小时自动重测 GitHub/Steam 优选 IP 并刷新缓存；
  若 hosts 里已存在 SkyGuard 加速块，则顺带用新结果重写。

运行状态记录在 ~/.skyguard/schedule_state.json，避免同一天重复触发
（例如程序一天内多次启动）。
"""

import json
import os
import threading
import time

from utils.clean_rules import get_rules
from utils.logger import logger

STATE_FILE = os.path.join(os.path.expanduser("~"), ".skyguard", "schedule_state.json")

# 自动清理只碰"纯缓存类"规则：无系统组件、无回收站，删错也能重来
AUTO_CLEAN_KEYS = (
    "temp_user", "temp_system", "inet_cache", "thumb_cache", "prefetch",
    "wer_reports", "chrome_cache", "edge_cache", "firefox_cache",
    "wechat_cache", "qq_cache", "app_common_cache",
)


def _today():
    return time.strftime("%Y-%m-%d")


def _load_state():
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
    except (OSError, ValueError) as e:
        logger.debug(f"读取定时任务状态失败: {e}")
    return {}


def _save_state(state):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
    except OSError as e:
        logger.debug(f"写入定时任务状态失败: {e}")


class ScheduledTaskManager:
    """后台分钟级巡检：到点就干，干完记账。"""

    def __init__(self, config_manager, notify=None):
        self.config_manager = config_manager
        self.notify = notify or (lambda msg: None)  # 完成提示（通知/日志）
        self.running = False
        self._thread = None
        self._stop_event = threading.Event()
        self._work_lock = threading.Lock()  # 同一时间只跑一个任务

    # ------------------------------------------------------------------
    def start(self):
        if self.running:
            return
        self.running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="ScheduledTaskManager")
        self._thread.start()
        logger.debug("定时自动化任务线程已启动")

    def stop(self):
        self.running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(2.0)

    # ------------------------------------------------------------------
    def _loop(self):
        # 分段睡眠：每分钟醒一次看有没有到点的任务，随时可停
        while self.running:
            try:
                self._tick()
            except Exception as e:
                logger.error(f"定时任务巡检出错: {e}")
            for _ in range(60):
                if not self.running:
                    return
                time.sleep(1)

    def _tick(self):
        cfg = self.config_manager
        state = _load_state()
        today = _today()

        # 每日自动优选 IP：指定小时触发
        if cfg.schedule_auto_ip_enabled and state.get("last_ip_date") != today:
            if time.localtime().tm_hour == cfg.schedule_auto_ip_hour:
                if self._run_ip_refresh():
                    state["last_ip_date"] = today
                    _save_state(state)

        # 每 N 天自动清理
        if cfg.schedule_auto_clean_enabled:
            last = state.get("last_clean_date")
            due = last is None or self._days_between(last, today) >= cfg.schedule_auto_clean_days
            if due and state.get("last_clean_date") != today:
                # 每天最多尝试一次（失败也等明天，避免反复打扰）
                if self._run_auto_clean():
                    state["last_clean_date"] = today
                    _save_state(state)

    @staticmethod
    def _days_between(earlier, later):
        try:
            t1 = time.mktime(time.strptime(earlier, "%Y-%m-%d"))
            t2 = time.mktime(time.strptime(later, "%Y-%m-%d"))
            return max(0, int((t2 - t1) // 86400))
        except ValueError:
            return 999  # 状态损坏视为已到期

    # ------------------------------------------------------------------
    def _run_auto_clean(self):
        """自动清理缓存类规则（强制回收站）。返回是否执行完成。"""
        if not self._work_lock.acquire(blocking=False):
            return False  # 有任务在跑，这轮放弃
        try:
            from utils.clean_engine import get_clean_engine

            engine = get_clean_engine()
            valid = {r["key"] for r in get_rules()}
            keys = [k for k in AUTO_CLEAN_KEYS if k in valid]
            report = engine.clean(keys, to_recycle=True)
            size_mb = report.get("total_size", 0) / 1024 / 1024
            msg = f"自动清理完成：释放 {size_mb:.1f} MB（已放入回收站）"
            logger.info(msg)
            self.notify(msg)
            return True
        except Exception as e:
            logger.error(f"自动清理失败: {e}")
            return False
        finally:
            self._work_lock.release()

    def _run_ip_refresh(self):
        """自动重测优选 IP；hosts 已有加速块时顺带重写。返回是否成功。"""
        if not self._work_lock.acquire(blocking=False):
            return False
        try:
            from core import ip_optimizer
            from core.ip_optimizer import DOMAIN_GROUPS

            domains = []
            cfg = self.config_manager
            for key, (_, group) in DOMAIN_GROUPS.items():
                if cfg.proxy_accel_groups.get(key, key == "github"):
                    domains.extend(group)
            extra = [d.strip() for d in (cfg.proxy_extra_domains or []) if d.strip()]
            domains.extend(extra)
            if not domains:
                logger.debug("自动优选跳过：未勾选任何目标域名")
                return True  # 视为完成，明天再说

            results = ip_optimizer.optimize_domains(
                domains, top_n=cfg.proxy_top_n)
            usable = sum(1 for r in results if r["ips"])

            # 更新缓存（accel_page 的 IpCache 是全局同一份文件）
            try:
                from core.ip_optimizer import IpCache
                cache = IpCache()
                cache.load()
                cache.update(results)
                cache.save()
            except Exception as e:
                logger.debug(f"自动优选写入缓存失败: {e}")

            msg = f"自动优选完成：{usable}/{len(results)} 个域名拿到可用 IP"
            logger.info(msg)
            self.notify(msg)
            return True
        except Exception as e:
            logger.error(f"自动优选失败: {e}")
            return False
        finally:
            self._work_lock.release()
