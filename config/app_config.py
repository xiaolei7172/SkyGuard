#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
配置模块
"""

# 应用程序基本信息
APP_INFO = {
    "name": "SkyGuard",                        # 应用名称（同时决定构建产物名 SkyGuard.exe）
    "author": "xiaolei7172",                   # 维护者（原作者 CassianVale，见 README 致谢）
    "version": "1.1.0",                       # 版本号（会被GitHub Actions构建时替换）
    "description": "天幕进程优化工具 · 游戏反作弊进程管理",      # 应用描述
    "github_repo": "xiaolei7172/SkyGuard",         # GitHub仓库
    "github_api_url": "https://api.github.com/repos/xiaolei7172/SkyGuard/releases/latest",  # GitHub API URL
    "github_releases_url": "https://github.com/xiaolei7172/SkyGuard/releases",              # GitHub发布页面URL
}

# 用户默认配置
DEFAULT_CONFIG = {
    "notifications": {
        "enabled": True                       # 通知默认开启
    },
    "logging": {
        "retention_days": 7,                  # 日志保留天数
        "rotation": "1 day",                  # 日志轮转周期
        "debug_mode": False                   # 调试模式默认关闭
    },
    "application": {
        "auto_start": False,                  # 开机自启动默认关闭
        "close_to_tray": True,                # 关闭窗口时默认最小化到托盘
        "theme": "light",                     # 默认浅色主题
        "check_update_on_start": True         # 启动时检查更新默认开启
    },
    "monitor": {
        "enabled": True                       # ACE弹窗监控开关默认开启
    },
    "memory_cleaner": {
        "enabled": False,                     # 内存清理开关默认关闭
        "brute_mode": True,                   # 内存清理暴力模式默认开启
        "switches": [True, True, False, False, False, False],  # 内存清理选项默认值
        "interval": 300,                      # 内存清理间隔默认值(秒)
        "threshold": 80.0,                    # 内存占用触发阈值默认值(百分比)
        "cooldown": 60                        # 内存清理冷却时间默认值(秒)
    },
    "io_priority": {
        "processes": [                        # 需要自动设置I/O优先级的进程名列表
            {"name": "SGuard64.exe", "priority": 0},
            {"name": "ACE-Tray.exe", "priority": 0}
        ]
    }
}

# 系统配置
SYSTEM_CONFIG = {
    "config_dir_name": ".skyguard",           # 配置目录名称（改名后与旧版 ACE-KILLER 配置互不影响）
    "log_dir_name": "logs",                   # 日志目录名称
    "config_file_name": "config.yaml",        # 配置文件名称
    "network_timeout": 10,                    # 网络请求超时时间（秒）
}
