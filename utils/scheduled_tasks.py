#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""定时自动化任务：复用内存清理的定时线程模型。

- 自动清理：每 N 天自动跑一次垃圾清理（仅缓存类规则，强制走回收站）。
- 自动优选：每天指定小时自动重测 GitHub/Steam 优选 IP 并刷新缓存。
  只更新缓存（供代理按域名选 IP），**不改写系统 hosts** —— 无人值守时
  改写系统文件风险过高，hosts 仍由用户在加速页手动触发。

状态记录在 ~/.skyguard/schedule_state.json：成功、失败、被占用都记账，
保证「每天最多尝试一次」，不会因为失败而每分钟重刷。
"""

import os
import threading
import time

from utils import atomic_io
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
    return atomic_io.read_json(STATE_FILE, default={}, expect=dict)


def _save_state(state):
    atomic_io.write_json(STATE_FILE, state)


class ScheduledTaskManager:
    """后台分钟级巡检：到点就干，干完记账。"""

    def __init__(self, config_manager, notify=None, on_ip_refreshed=None):
        self.config_manager = config_manager
        self.notify = notify or (lambda msg: None)  # 完成提示（通知/日志）
        # 优选写完盘后回调，让 UI 重新加载缓存并刷新（实现方负责切回主线程）
        self.on_ip_refreshed = on_ip_refreshed
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
        self._thread = None

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
        # 两个开关都关时直接返回：默认配置就是全关，
        # 不该每分钟都去读一次状态文件
        if not (cfg.schedule_auto_ip_enabled or cfg.schedule_auto_clean_enabled):
            return
        state = _load_state()
        today = _today()

        # 每日自动优选 IP：当天只尝试一次（成败都记账），
        # 否则失败后会在整点那一小时里每分钟重跑一次全量测速
        if cfg.schedule_auto_ip_enabled and state.get("ip_tried_date") != today:
            if time.localtime().tm_hour == cfg.schedule_auto_ip_hour:
                status = self._run_ip_refresh()
                if status == "busy":
                    return      # 另一个任务在跑，下一分钟再看
                state["ip_tried_date"] = today
                state["last_ip_result"] = status
                if status == "ok":
                    state["last_ip_date"] = today
                _save_state(state)
                return          # 一分钟只干一件事

        # 每 N 天自动清理：成功后按间隔再算；失败/被占用当天只试一次
        if cfg.schedule_auto_clean_enabled:
            last = state.get("last_clean_date")
            due = last is None or self._days_between(last, today) >= cfg.schedule_auto_clean_days
            if due and state.get("clean_tried_date") != today:
                status = self._run_auto_clean()
                if status == "busy":
                    return
                state["clean_tried_date"] = today
                state["last_clean_result"] = status
                if status == "ok":
                    state["last_clean_date"] = today
                _save_state(state)

    @staticmethod
    def _days_between(earlier, later):
        try:
            t1 = time.mktime(time.strptime(earlier, "%Y-%m-%d"))
            t2 = time.mktime(time.strptime(later, "%Y-%m-%d"))
        except (ValueError, OverflowError):
            return 999  # 状态损坏视为已到期
        diff = int((t2 - t1) // 86400)
        if diff < 0:
            # 状态里是"未来日期"（系统时间被回拨过）：视为到期跑一次，
            # 跑完会覆盖成今天，不会长期卡死
            return 999
        return diff

    # ------------------------------------------------------------------
    def _run_auto_clean(self):
        """自动清理缓存类规则（强制回收站）。返回 ok / fail / busy。"""
        if not self._work_lock.acquire(blocking=False):
            return "busy"
        try:
            from utils.clean_engine import get_clean_engine

            engine = get_clean_engine()
            valid = {r["key"] for r in get_rules()}
            keys = [k for k in AUTO_CLEAN_KEYS if k in valid]
            # blocking=False：UI 正在清理时立刻跳过，绝不排队堵在锁上
            report = engine.clean(keys, to_recycle=True, blocking=False)
            if report.get("busy"):
                logger.debug("自动清理跳过：已有清理任务在运行")
                return "busy"
            size_mb = report.get("total_size", 0) / 1024 / 1024
            msg = f"自动清理完成：释放 {size_mb:.1f} MB（已放入回收站）"
            logger.info(msg)
            self.notify(msg)
            return "ok"
        except Exception as e:
            logger.error(f"自动清理失败: {e}")
            return "fail"
        finally:
            self._work_lock.release()

    def _run_ip_refresh(self):
        """自动重测优选 IP 并刷新缓存。返回 ok / fail / busy。"""
        if not self._work_lock.acquire(blocking=False):
            return "busy"
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
                return "ok"  # 视为完成，明天再说

            results = ip_optimizer.optimize_domains(
                domains, top_n=cfg.proxy_top_n)
            usable = sum(1 for r in results if r["ips"])

            # 更新缓存：update() 内部会先合并磁盘上的最新内容再原子落盘，
            # 不会覆盖掉 UI 侧刚测出的结果
            try:
                from core.ip_optimizer import IpCache
                cache = IpCache()
                cache.update(results)
            except Exception as e:
                logger.debug(f"自动优选写入缓存失败: {e}")

            msg = f"自动优选完成：{usable}/{len(results)} 个域名拿到可用 IP"
            logger.info(msg)
            self.notify(msg)
            # 通知 UI 重新加载缓存并刷新表格，否则运行中的代理要到重启才用上新 IP
            if self.on_ip_refreshed:
                try:
                    self.on_ip_refreshed()
                except Exception as e:
                    logger.debug(f"优选结果通知 UI 失败: {e}")
            return "ok"
        except Exception as e:
            logger.error(f"自动优选失败: {e}")
            return "fail"
        finally:
            self._work_lock.release()
