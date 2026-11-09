#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SkyGuard主程序入口
"""

import sys

from config import ConfigManager, APP_INFO, SYSTEM_CONFIG
from core.process_monitor import GameProcessMonitor
from ui.main_window import create_gui
from utils import (
    logger,
    setup_logger,
    find_icon_path,
    create_notification_thread,
    is_admin,
    check_single_instance,
    get_io_priority_service,
    check_for_update,
)


def main(custom_app_info=None, custom_default_config=None, custom_system_config=None):
    """
    主程序入口函数

    Args:
        custom_app_info (dict, optional): 自定义应用信息，用于覆盖默认值
        custom_default_config (dict, optional): 自定义默认配置，用于覆盖默认值
        custom_system_config (dict, optional): 自定义系统配置，用于覆盖默认值
    """
    # 检查是否以最小化模式启动（通过命令行参数）
    start_minimized = "--minimized" in sys.argv

    # 合并应用信息
    final_app_info = APP_INFO.copy()
    if custom_app_info:
        final_app_info.update(custom_app_info)

    # 合并系统配置
    final_system_config = SYSTEM_CONFIG.copy()
    if custom_system_config:
        final_system_config.update(custom_system_config)

    # 管理员权限：程序不再主动申请，默认受限模式运行。
    # 需要提权的功能（接管网卡 DNS / 53 端口服务）由用户在标题栏
    # 「受限模式 · 点此提权」自行决定，也可以命令行传 --elevate 直接提权。
    restricted_mode = False
    if not is_admin():
        if "--elevate" in sys.argv:
            from utils.system_utils import relaunch_as_admin
            try:
                relaunch_as_admin()
                return    # 控制权已交给新的管理员进程
            except Exception:
                pass      # 提权失败（用户取消 UAC）则继续受限模式
        restricted_mode = True
        logger.info("受限模式启动：未获得管理员权限，"
                    "接管系统 DNS / 53 端口服务不可用；"
                    "需要时点击标题栏「受限模式」提权")

    # 检查单实例运行
    mutex_name = f"Global\\{final_app_info['name'].replace(' ', '_')}_MUTEX"
    if not check_single_instance(mutex_name):
        return

    # 创建配置管理器
    config_manager = ConfigManager(
        custom_app_info=final_app_info,
        custom_default_config=custom_default_config,
        custom_system_config=final_system_config,
    )

    # 配置日志系统
    setup_logger(
        config_manager.log_dir,
        config_manager.log_retention_days,
        config_manager.log_rotation,
        config_manager.debug_mode,
    )

    # 创建进程监控器
    monitor = GameProcessMonitor(config_manager)

    # 创建并启动I/O优先级服务
    io_priority_service = get_io_priority_service(config_manager)
    if io_priority_service:
        io_priority_service.start_service()

    # 现在日志系统已初始化，可以记录启动信息
    logger.debug(f"🟩 {final_app_info['name']} 程序已启动！")

    # 查找图标文件
    icon_path = find_icon_path()

    # 创建通知线程
    notification_thread_obj, stop_event = create_notification_thread(monitor.message_queue, icon_path)

    # 创建并运行PySide6图形界面
    app, window = create_gui(config_manager, monitor, icon_path, start_minimized)

    if config_manager.check_update_on_start:
        logger.debug("启动时检查更新已开启，执行静默检查更新...")
        check_for_update(config_manager, silent_mode=True)

    try:
        # 运行应用（这会阻塞主线程直到应用程序退出）
        sys.exit(app.exec())
    except KeyboardInterrupt:
        # 处理键盘中断
        pass
    finally:
        # 确保停止所有线程，唯一调用stop_monitors的地方
        if monitor.running:
            monitor.running = False
            # 停止所有游戏监控
            monitor.stop_monitors()

        # 停止I/O优先级服务
        if io_priority_service and io_priority_service.running:
            io_priority_service.stop_service()

        # 设置通知线程停止事件
        stop_event.set()

        # 等待通知线程结束
        notification_thread_obj.join(timeout=0.5)

        logger.debug(f"🔴 {final_app_info['name']} 程序已终止！")


if __name__ == "__main__":
    main()
