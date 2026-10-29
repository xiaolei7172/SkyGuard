#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
内置清理规则库

设计原则：
  1. 声明式——只描述"清哪里、清什么"，扫描/删除逻辑全在 clean_engine.py；
  2. 保守优先——只清理业界公认的缓存与临时文件，绝不触碰用户文档；
  3. 分级授权——risk 0 默认勾选、1 需用户手动勾选、2 收在"显示高级项"里。

规则字段：
  key          唯一标识
  name         显示名称
  group        分组（UI 树的一级节点）
  desc         说明
  risk         0=安全 1=谨慎 2=高级（有副作用）
  targets      清理目标列表：
                 path       支持 %ENV% 变量与 * 通配（通配在任意层级）
                 pattern    文件名匹配（* 表示全部）
                 mode       files=删匹配文件 / contents=清空目录内容
                            dirs=删匹配子目录（含内容）
                 recursive  是否递归子目录
  special      特殊目标：recycle_bin=清空回收站 / dism=组件清理
  skip_if_running  进程运行时跳过（避免删到正在写入的缓存）
"""

# 常用浏览器缓存子目录（Chrome / Edge 同构）
_CHROMIUM_CACHE_DIRS = [
    "Cache",
    "Code Cache",
    "GPUCache",
    "ShaderCache",
    "GrShaderCache",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "Service Worker/CacheStorage",
    "Service Worker/ScriptCache",
]

BUILTIN_RULES = [
    # ==========================================
    # 系统临时文件
    # ==========================================
    {
        "key": "temp_user",
        "name": "用户临时文件",
        "group": "系统临时",
        "desc": "%TEMP% 目录下的临时文件",
        "risk": 0,
        "targets": [{"path": "%TEMP%", "pattern": "*", "mode": "contents", "recursive": True}],
    },
    {
        "key": "temp_system",
        "name": "系统临时文件",
        "group": "系统临时",
        "desc": "%SystemRoot%\\Temp（需管理员权限）",
        "risk": 0,
        "targets": [{"path": "%SystemRoot%\\Temp", "pattern": "*", "mode": "contents", "recursive": True}],
    },
    {
        "key": "inet_cache",
        "name": "IE / 系统网络缓存",
        "group": "系统临时",
        "desc": "WinINet 缓存、Cookie 临时文件",
        "risk": 0,
        "targets": [
            {"path": "%LocalAppData%\\Microsoft\\Windows\\INetCache", "pattern": "*", "mode": "contents", "recursive": True},
            {"path": "%LocalAppData%\\Microsoft\\Windows\\WebCache", "pattern": "*", "mode": "contents", "recursive": True},
        ],
    },
    {
        "key": "thumb_cache",
        "name": "缩略图 / 图标缓存",
        "group": "系统临时",
        "desc": "Explorer 缩略图数据库（系统会自动重建）",
        "risk": 0,
        "targets": [
            {"path": "%LocalAppData%\\Microsoft\\Windows\\Explorer", "pattern": "thumbcache_*.db", "mode": "files", "recursive": False},
            {"path": "%LocalAppData%\\Microsoft\\Windows\\Explorer", "pattern": "iconcache_*.db", "mode": "files", "recursive": False},
        ],
    },
    {
        "key": "prefetch",
        "name": "预读取文件（Prefetch）",
        "group": "系统临时",
        "desc": "清理后首次启动程序会略慢，系统会重新生成",
        "risk": 1,
        "targets": [{"path": "%SystemRoot%\\Prefetch", "pattern": "*.pf", "mode": "files", "recursive": False}],
    },
    {
        "key": "wer_reports",
        "name": "错误报告与转储",
        "group": "系统临时",
        "desc": "Windows 错误报告（WER）与崩溃转储文件",
        "risk": 1,
        "targets": [
            {"path": "%LocalAppData%\\Microsoft\\Windows\\WER", "pattern": "*", "mode": "contents", "recursive": True},
            {"path": "%ProgramData%\\Microsoft\\Windows\\WER", "pattern": "*", "mode": "contents", "recursive": True},
            {"path": "%LocalAppData%\\CrashDumps", "pattern": "*.dmp", "mode": "files", "recursive": False},
        ],
    },

    # ==========================================
    # 回收站
    # ==========================================
    {
        "key": "recycle_bin",
        "name": "回收站",
        "group": "回收站",
        "desc": "清空回收站（不可恢复，请先确认）",
        "risk": 1,
        "targets": [],
        "special": "recycle_bin",
    },

    # ==========================================
    # 浏览器缓存
    # ==========================================
    {
        "key": "chrome_cache",
        "name": "Chrome 缓存",
        "group": "浏览器缓存",
        "desc": "各用户配置的页面缓存（不含 Cookie / 密码 / 书签）",
        "risk": 0,
        "skip_if_running": ["chrome.exe"],
        "targets": [
            {"path": "%LocalAppData%\\Google\\Chrome\\User Data\\*\\" + d, "pattern": "*", "mode": "contents", "recursive": True}
            for d in _CHROMIUM_CACHE_DIRS
        ],
    },
    {
        "key": "edge_cache",
        "name": "Edge 缓存",
        "group": "浏览器缓存",
        "desc": "各用户配置的页面缓存（不含 Cookie / 密码 / 书签）",
        "risk": 0,
        "skip_if_running": ["msedge.exe"],
        "targets": [
            {"path": "%LocalAppData%\\Microsoft\\Edge\\User Data\\*\\" + d, "pattern": "*", "mode": "contents", "recursive": True}
            for d in _CHROMIUM_CACHE_DIRS
        ],
    },
    {
        "key": "firefox_cache",
        "name": "Firefox 缓存",
        "group": "浏览器缓存",
        "desc": "cache2 目录（不含 Cookie / 历史记录）",
        "risk": 0,
        "skip_if_running": ["firefox.exe"],
        "targets": [
            {"path": "%LocalAppData%\\Mozilla\\Firefox\\Profiles\\*\\cache2", "pattern": "*", "mode": "contents", "recursive": True},
        ],
    },

    # ==========================================
    # 应用缓存（国内常用）
    # ==========================================
    {
        "key": "wechat_cache",
        "name": "微信缓存",
        "group": "应用缓存",
        "desc": "聊天缓存 / 图片视频缩略缓存（不含聊天记录数据库）",
        "risk": 1,
        "skip_if_running": ["WeChat.exe", "Weixin.exe"],
        "targets": [
            # 微信 3.x
            {"path": "%USERPROFILE%\\Documents\\WeChat Files\\*\\FileStorage\\Cache", "pattern": "*", "mode": "contents", "recursive": True},
            {"path": "%USERPROFILE%\\Documents\\WeChat Files\\*\\FileStorage\\Video", "pattern": "*", "mode": "contents", "recursive": True},
            {"path": "%USERPROFILE%\\Documents\\WeChat Files\\*\\FileStorage\\MsgAttach", "pattern": "*", "mode": "contents", "recursive": True},
            # 微信 4.x
            {"path": "%USERPROFILE%\\Documents\\xwechat_files\\*\\msg\\attach", "pattern": "*", "mode": "contents", "recursive": True},
            {"path": "%USERPROFILE%\\Documents\\xwechat_files\\*\\msg\\video", "pattern": "*", "mode": "contents", "recursive": True},
        ],
    },
    {
        "key": "qq_cache",
        "name": "QQ 缓存",
        "group": "应用缓存",
        "desc": "QQ 聊天缓存与图片缓存",
        "risk": 1,
        "skip_if_running": ["QQ.exe", "QQNT.exe"],
        "targets": [
            {"path": "%USERPROFILE%\\Documents\\Tencent Files\\*\\FileRecv\\..\\Cache", "pattern": "*", "mode": "contents", "recursive": True},
            {"path": "%USERPROFILE%\\Documents\\Tencent Files\\*\\Image", "pattern": "*", "mode": "contents", "recursive": True},
        ],
    },
    {
        "key": "app_common_cache",
        "name": "常见软件缓存",
        "group": "应用缓存",
        "desc": "网易云音乐 / 钉钉 / 企业微信等缓存目录",
        "risk": 0,
        "skip_if_running": ["CloudMusic.exe", "DingTalk.exe", "WXWork.exe"],
        "targets": [
            {"path": "%LocalAppData%\\Netease\\CloudMusic\\Cache", "pattern": "*", "mode": "contents", "recursive": True},
            {"path": "%LocalAppData%\\DingTalk\\media_cache", "pattern": "*", "mode": "contents", "recursive": True},
            {"path": "%USERPROFILE%\\Documents\\WXWork\\*\\Cache", "pattern": "*", "mode": "contents", "recursive": True},
        ],
    },

    # ==========================================
    # 系统组件（高级）
    # ==========================================
    {
        "key": "windows_update_cache",
        "name": "Windows 更新缓存",
        "group": "系统组件（高级）",
        "desc": "已安装更新的下载残留，可释放数 GB；正在更新时请勿清理",
        "risk": 2,
        "targets": [
            {"path": "%SystemRoot%\\SoftwareDistribution\\Download", "pattern": "*", "mode": "contents", "recursive": True},
        ],
    },
    {
        "key": "delivery_optimization",
        "name": "传递优化缓存",
        "group": "系统组件（高级）",
        "desc": "Windows 更新 P2P 分发缓存",
        "risk": 2,
        "targets": [
            {"path": "%SystemRoot%\\SoftwareDistribution\\DeliveryOptimization", "pattern": "*", "mode": "contents", "recursive": True},
            {"path": "%SystemRoot%\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization", "pattern": "*", "mode": "contents", "recursive": True},
        ],
    },
    {
        "key": "cbs_logs",
        "name": "系统组件日志",
        "group": "系统组件（高级）",
        "desc": "CBS / DISM 日志（排查系统问题时会用到，一般可删）",
        "risk": 2,
        "targets": [
            {"path": "%SystemRoot%\\Logs\\CBS", "pattern": "*.log", "mode": "files", "recursive": False},
            {"path": "%SystemRoot%\\Logs\\CBS", "pattern": "*.cab", "mode": "files", "recursive": False},
            {"path": "%SystemRoot%\\Logs\\DISM", "pattern": "*.log", "mode": "files", "recursive": False},
        ],
    },
    {
        "key": "dism_component",
        "name": "WinSxS 组件清理",
        "group": "系统组件（高级）",
        "desc": "调用系统 DISM 清理被取代的组件，耗时较长（5-30 分钟），清理后无法卸载已安装更新",
        "risk": 2,
        "targets": [],
        "special": "dism",
    },
]


def get_rules():
    """返回规则列表副本，避免调用方误改模块常量"""
    return [dict(r) for r in BUILTIN_RULES]


def get_rule(key):
    for r in BUILTIN_RULES:
        if r["key"] == key:
            return dict(r)
    return None
