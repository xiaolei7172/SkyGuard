#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
管理员权限提示模块

SkyGuard 的以下功能需要管理员权限：
  - 接管 / 恢复系统 DNS（netsh 修改网卡 DNS）
  - 监听 53 端口的本地 DNS 服务（1024 以下端口需要管理员）

本模块提供两种提示：
  1. prompt_elevate_on_startup()  启动前的原生弹窗（此时还没有 QApplication）
  2. ensure_admin() / show_admin_help()  运行中的界面提示
"""

import ctypes

from utils.logger import logger
from utils.system_utils import is_admin, relaunch_as_admin

# 需要管理员权限的具体功能，用于提示文案
ADMIN_ONLY_FEATURES = (
    "接管与恢复系统 DNS",
    "在 53 端口启动本地 DNS 服务",
)

MB_YESNO = 0x00000004
MB_ICONWARNING = 0x00000030
MB_ICONINFORMATION = 0x00000040
MB_SETFOREGROUND = 0x00010000
MB_TOPMOST = 0x00040000
IDYES = 6
IDNO = 7


def features_text(indent="    "):
    return "\n".join(f"{indent}· {item}" for item in ADMIN_ONLY_FEATURES)


def prompt_elevate_on_startup(app_name="SkyGuard"):
    """
    启动时（QApplication 之前）询问是否以管理员身份运行。

    Returns:
        str: "elevated" 已提权 / "limited" 用户选择受限模式运行 / "abort" 用户取消启动
    """
    if is_admin():
        return "elevated"

    text = (
        f"{app_name} 当前没有管理员权限。\n\n"
        f"以下功能需要管理员权限，受限模式下将无法使用：\n"
        f"{features_text()}\n\n"
        f"是否以管理员身份重新启动？\n"
        f"  是 —— 弹出 UAC 确认后以管理员运行（推荐）\n"
        f"  否 —— 以受限模式继续运行（代理 / DNS 查询等基础功能仍可用）\n"
    )
    try:
        ret = ctypes.windll.user32.MessageBoxW(
            None, text, f"{app_name} · 权限提示",
            MB_YESNO | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST)
    except Exception as e:
        logger.warning(f"显示权限提示失败: {e}")
        return "limited"

    if ret == IDYES:
        if relaunch_as_admin():
            logger.info("已请求以管理员身份重启")
            return "elevated"
        # 用户拒绝了 UAC
        try:
            ctypes.windll.user32.MessageBoxW(
                None,
                "提权被取消，将以受限模式继续运行。\n"
                "之后可在标题栏点击「受限模式」随时重新提权。",
                f"{app_name} · 受限模式",
                MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST)
        except Exception:
            pass
        return "limited"

    logger.info("用户选择以受限模式运行")
    return "limited"


def ensure_admin(parent=None, action="该操作"):
    """
    运行中检查管理员权限；不足时询问是否提权重启。

    Returns:
        bool: 当前是否具备管理员权限（False 时调用方应直接返回）
    """
    if is_admin():
        return True

    from PySide6.QtWidgets import QApplication, QMessageBox

    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.Warning)
    msg.setWindowTitle("需要管理员权限")
    msg.setText(f"「{action}」需要管理员权限。")
    msg.setInformativeText(
        "需要管理员权限的功能：\n" + features_text() +
        "\n\n是否以管理员身份重新启动？当前窗口会关闭，重启后设置保持不变。")
    restart_btn = msg.addButton("以管理员身份重启", QMessageBox.ButtonRole.AcceptRole)
    msg.addButton("取消", QMessageBox.ButtonRole.RejectRole)
    msg.exec()

    if msg.clickedButton() is restart_btn:
        if relaunch_as_admin():
            app = QApplication.instance()
            if app is not None:
                app.quit()
        else:
            QMessageBox.information(parent, "提权已取消", "未能获取管理员权限，操作未执行。")
    return False


def show_admin_help(parent=None):
    """说明当前权限状态，并提供一键提权入口。"""
    from PySide6.QtWidgets import QApplication, QMessageBox

    if is_admin():
        QMessageBox.information(
            parent, "权限状态",
            "当前以管理员身份运行。\n\n"
            "写 hosts、接管系统 DNS、53 端口 DNS 服务等全部功能可用。")
        return

    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.Warning)
    msg.setWindowTitle("权限状态")
    msg.setText("当前为受限模式（非管理员）。")
    msg.setInformativeText(
        "以下功能暂不可用：\n" + features_text() +
        "\n\n代理转发、节点测速、DNS 查询与过滤等功能仍可正常使用。")
    restart_btn = msg.addButton("以管理员身份重启", QMessageBox.ButtonRole.AcceptRole)
    msg.addButton("知道了", QMessageBox.ButtonRole.RejectRole)
    msg.exec()

    if msg.clickedButton() is restart_btn:
        if relaunch_as_admin():
            app = QApplication.instance()
            if app is not None:
                app.quit()
        else:
            QMessageBox.information(parent, "提权已取消", "未能获取管理员权限。")
