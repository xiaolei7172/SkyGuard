#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Windows 系统代理设置（WinINet）

只改当前用户的 Internet Settings，不需要管理员权限。
设置前会把原始值备份，取消时优先还原备份，避免把用户原来的代理弄丢。
"""

import json
import os

from utils.logger import logger

SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
BACKUP_PATH = os.path.join(os.path.expanduser("~"), ".skyguard", "system_proxy_backup.json")

DEFAULT_BYPASS = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;" \
                 "172.30.*;172.31.*;192.168.*;<local>"


def _winreg():
    try:
        import winreg
        return winreg
    except ImportError:
        return None


def is_supported():
    return os.name == "nt" and _winreg() is not None


def _read_values():
    winreg = _winreg()
    if not winreg:
        return {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, SETTINGS_KEY) as key:
            result = {}
            for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
                try:
                    result[name] = winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    result[name] = None
            return result
    except OSError as e:
        logger.debug(f"读取系统代理设置失败: {e}")
        return {}


def current():
    """返回 {'enabled': bool, 'server': str, 'bypass': str}。"""
    values = _read_values()
    return {
        "enabled": bool(values.get("ProxyEnable", 0)),
        "server": values.get("ProxyServer") or "",
        "bypass": values.get("ProxyOverride") or "",
    }


def _backup_once():
    if os.path.exists(BACKUP_PATH):
        return
    try:
        os.makedirs(os.path.dirname(BACKUP_PATH), exist_ok=True)
        with open(BACKUP_PATH, "w", encoding="utf-8") as f:
            json.dump(_read_values(), f, ensure_ascii=False)
    except Exception as e:
        logger.warning(f"备份系统代理设置失败: {e}")


def _notify_change():
    """通知系统代理设置已变化，浏览器才会立即生效。"""
    try:
        import ctypes
        internet_set_option = ctypes.windll.wininet.InternetSetOptionW
        internet_set_option(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        internet_set_option(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception as e:
        logger.debug(f"刷新系统代理设置失败: {e}")


def set_proxy(server="127.0.0.1:7890", bypass=DEFAULT_BYPASS):
    """把系统代理指向本地端口。"""
    winreg = _winreg()
    if not winreg:
        return False, "当前系统不支持自动设置代理，请手动填写 127.0.0.1:端口"
    try:
        _backup_once()
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, SETTINGS_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, bypass)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        _notify_change()
        return True, f"系统代理已指向 {server}"
    except Exception as e:
        logger.error(f"设置系统代理失败: {e}")
        return False, f"设置系统代理失败：{e}"


def _restore_from_backup():
    winreg = _winreg()
    if not winreg or not os.path.exists(BACKUP_PATH):
        return False
    try:
        with open(BACKUP_PATH, "r", encoding="utf-8") as f:
            saved = json.load(f)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, SETTINGS_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as key:
            enable = int(saved.get("ProxyEnable") or 0)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, enable)
            if saved.get("ProxyServer"):
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, saved["ProxyServer"])
            else:
                try:
                    winreg.DeleteValue(key, "ProxyServer")
                except FileNotFoundError:
                    pass
            if saved.get("ProxyOverride") is not None:
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ,
                                  saved["ProxyOverride"] or "")
        _notify_change()
        os.remove(BACKUP_PATH)
        return True
    except Exception as e:
        logger.warning(f"还原系统代理失败: {e}")
        return False


def clear_proxy():
    """关闭系统代理（优先还原设置前的原值）。"""
    winreg = _winreg()
    if not winreg:
        return False, "当前系统不支持自动设置代理"
    if _restore_from_backup():
        return True, "已还原设置前的系统代理"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, SETTINGS_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        _notify_change()
        return True, "系统代理已关闭"
    except Exception as e:
        return False, f"关闭系统代理失败：{e}"


def is_pointing_to(port, host="127.0.0.1"):
    info = current()
    if not info["enabled"]:
        return False
    server = info["server"].replace("http=", "").replace("https=", "").strip()
    return server in (f"{host}:{port}", f"http://{host}:{port}")
