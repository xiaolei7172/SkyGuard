#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
配置模块
"""

# 应用程序基本信息
APP_INFO = {
    "name": "SkyGuard",                        # 应用名称（同时决定构建产物名 SkyGuard.exe）
    "author": "xiaolei7172",                   # 维护者（原作者 CassianVale，见 README 致谢）
    "version": "1.5.0",                       # 版本号（会被GitHub Actions构建时替换）
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
    "schedule": {
        "auto_clean_enabled": False,          # 定时自动清理默认关闭
        "auto_clean_days": 7,                 # 自动清理间隔（天）
        "auto_ip_enabled": False,             # 每日自动重测优选 IP 默认关闭
        "auto_ip_hour": 3                     # 自动优选触发小时（24 小时制）
    },
    "io_priority": {
        "processes": [                        # 需要自动设置I/O优先级的进程名列表
            {"name": "SGuard64.exe", "priority": 0},
            {"name": "ACE-Tray.exe", "priority": 0}
        ]
    },
    "floating_window": {
        "enabled": False,                     # 悬浮窗默认关闭（首次启动不打扰）
        "opacity": 0.9,                       # 卡片不透明度 0.6~1.0
        "locked": False,                      # 锁定后不可拖动，防误碰
        "interval": 1.0,                      # 刷新间隔（秒）
        "x": None,                            # 位置，None 表示默认贴右下角
        "y": None,
        "items": {                            # 各显示项开关
            "download": True,
            "upload": True,
            "cpu": True,
            "memory": True,
            "temp": True
        }
    },
    "proxy": {
        "enabled": False,                     # 本地代理服务默认不随程序启动
        "mode": "smart",                      # smart=国内直连国外代理 / rule=按规则 / global=全走节点 / direct=全直连
        "host": "127.0.0.1",
        "port": 7890,                         # 与 Clash 默认 mixed 端口一致，便于习惯迁移
        "allow_lan": False,                   # True 时监听 0.0.0.0，局域网可用
        "set_system_proxy": True,             # 启动代理时顺带接管系统代理
        "selected_node": "",                  # 选中节点的 uid（空表示没有节点）
        "engine": "builtin",                  # builtin=内置引擎 / clash=mihomo 内核（支持 hysteria2/vless 等全部协议）
        "kernel_path": "",                    # mihomo 内核路径，空表示自动查找/下载
        "clash_api_port": 19090,              # mihomo RESTful API 端口
        "rules": [],                          # 空列表表示使用内置默认规则
        "accel_groups": {                     # 优选 IP 覆盖范围
            "github": True,
            "steam": True
        },
        "extra_domains": [],                  # 额外需要优选的域名
        "top_n": 3                            # 每个域名保留几个优选 IP
    },
    "dns_filter": {
        "enabled": False,                     # DNS 过滤服务默认不随程序启动
        "port": 53,
        "listen_lan": False,                  # True 时同时监听 0.0.0.0（局域网设备可访问）
        "block_action": "blackhole",          # blackhole=返回0.0.0.0 / nxdomain=返回不存在
        "selected_upstream": 0,
        # sequential=按顺序优先；parallel=并发问前几个，谁快用谁（AdGuard 风格）
        "strategy": "sequential",
        "cache_min_ttl": 0,
        "cache_max_ttl": 86400,
        "log_enabled": True,                  # 记录查询日志（可暂停，不落盘）
        "lists": [],                          # 过滤器列表 [{name,url,enabled,interval,count,updated}]
        "custom_rules": [],                   # 自定义规则（AdGuard 语法，一行一条）
        "rewrites": {},                       # DNS 重写 {域名: IP}
        "upstreams": [
            {"name": "阿里 UDP", "proto": "UDP", "address": "223.5.5.5:53"},
            {"name": "阿里 DoT", "proto": "DoT", "address": "223.5.5.5:853"},
            {"name": "阿里 DoH", "proto": "DoH", "address": "https://dns.alidns.com/dns-query"},
            {"name": "腾讯 DoH", "proto": "DoH", "address": "https://doh.pub/dns-query"}
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
