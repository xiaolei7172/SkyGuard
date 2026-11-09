#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""JSON 数据文件的原子读写。

程序里的「用户数据」（每日统计、定时任务状态、优选 IP 缓存）都是小 JSON，
但原来的写法是 ``open(path, "w")`` 直接截断重写：一旦写入过程中断电、
崩溃或磁盘写满，文件就变成空文件或半截 JSON，读取侧只能当空数据处理，
历史数据等于被静默清库。

这里统一改成「写临时文件 → fsync → os.replace 原子替换」，
保证任何时刻磁盘上的文件要么是旧的完整版本，要么是新的完整版本。
读取失败时把坏文件改名保留为 ``.corrupt``，便于事后找回，也不再被下一次
写入当空覆盖。
"""

import json
import os
import tempfile
import time

from utils.logger import logger


def write_json(path, data, indent=None):
    """原子写入 JSON。失败返回 False（不会破坏原文件）。"""
    directory = os.path.dirname(os.path.abspath(path))
    tmp_path = None
    try:
        os.makedirs(directory, exist_ok=True)
        # 临时文件放在同目录，保证 os.replace 是同卷操作（跨卷不是原子的）
        fd, tmp_path = tempfile.mkstemp(
            prefix=os.path.basename(path) + ".", suffix=".tmp", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=indent)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        tmp_path = None
        return True
    except (OSError, TypeError, ValueError) as e:
        logger.warning(f"写入 {os.path.basename(path)} 失败: {e}")
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def read_json(path, default=None, expect=dict):
    """读取 JSON。文件不存在返回 default；内容损坏则改名 .corrupt 后返回 default。"""
    try:
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if expect is not None and not isinstance(data, expect):
            raise ValueError(f"顶层类型不是 {expect.__name__}")
        return data
    except (OSError, ValueError) as e:
        logger.warning(f"读取 {os.path.basename(path)} 失败（已保留为 .corrupt）: {e}")
        _quarantine(path)
        return default


def _quarantine(path):
    """把损坏文件改名保留，避免下一次写入把它当空文件覆盖掉。"""
    try:
        if not os.path.exists(path):
            return
        target = f"{path}.corrupt.{time.strftime('%Y%m%d_%H%M%S')}"
        os.replace(path, target)
        logger.warning(f"损坏的数据文件已保留为 {os.path.basename(target)}")
    except OSError as e:
        logger.debug(f"保留损坏文件失败: {e}")
