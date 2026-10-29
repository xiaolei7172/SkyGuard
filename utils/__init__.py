#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""工具类模块"""

from utils.logger import setup_logger, logger
from utils.notification import send_notification, notification_thread
from utils.version_checker import (
    check_for_update,
    get_app_version,
    format_version_info,
    create_update_message,
    get_version_checker,
)
from utils.system_utils import (
    run_as_admin,
    check_auto_start,
    enable_auto_start,
    disable_auto_start,
    check_single_instance,
)
from utils.memory_cleaner import get_memory_cleaner
from utils.process_io_priority import get_io_priority_manager, get_io_priority_service, IO_PRIORITY_HINT
from utils.clean_engine import get_clean_engine, format_size
from utils.startup_manager import get_startup_manager
from utils.clean_rules import get_rules as get_clean_rules

from utils.notification import find_icon_path, create_notification_thread


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
