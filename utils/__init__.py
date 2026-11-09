#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""工具类模块"""

from utils.logger import setup_logger, logger
# 通知模块懒加载：utils.notification 顶层不再携带 winrt/windows_toasts，
# 且本 __init__ 也不顶层 re-export，首次访问时才导入（PEP 562 __getattr__）
from utils.version_checker import (
    check_for_update,
    get_app_version,
    format_version_info,
    create_update_message,
    get_version_checker,
)
from utils.system_utils import (
    run_as_admin,
    is_admin,
    relaunch_as_admin,
    check_auto_start,
    enable_auto_start,
    disable_auto_start,
    check_single_instance,
)
from utils.privilege import (
    ADMIN_ONLY_FEATURES,
    ensure_admin,
    prompt_elevate_on_startup,
    show_admin_help,
)
from utils.memory_cleaner import get_memory_cleaner
from utils.process_io_priority import get_io_priority_manager, get_io_priority_service, IO_PRIORITY_HINT
from utils.clean_engine import get_clean_engine, format_size
from utils.startup_manager import get_startup_manager
from utils.clean_rules import get_rules as get_clean_rules


def __getattr__(name):
    """PEP 562：通知相关符号在首次访问时才导入，缩短启动导入链。"""
    if name in ("send_notification", "notification_thread",
                "find_icon_path", "create_notification_thread"):
        from utils import notification as _notification
        return getattr(_notification, name)
    raise AttributeError(f"module 'utils' has no attribute {name!r}")


__all__ = [
    "send_notification",
    "notification_thread",
    "find_icon_path",
    "create_notification_thread",
    "get_memory_cleaner",
    "setup_logger",
    "logger",
    "check_for_update",
    "get_app_version",
    "format_version_info",
    "create_update_message",
    "get_version_checker",
    "run_as_admin",
    "is_admin",
    "relaunch_as_admin",
    "ADMIN_ONLY_FEATURES",
    "ensure_admin",
    "prompt_elevate_on_startup",
    "show_admin_help",
    "check_auto_start",
    "enable_auto_start",
    "disable_auto_start",
    "check_single_instance",
    "get_io_priority_manager",
    "get_io_priority_service",
    "IO_PRIORITY_HINT",
    "get_clean_engine",
    "format_size",
    "get_startup_manager",
    "get_clean_rules",
]
