#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""自检结果对话框：DNS 与代理页面共用。"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QPushButton, QTextBrowser, QVBoxLayout,
)

from core.selfcheck import FAIL, OK, SKIP, summarize


def _summary_html(items):
    stat = summarize(items)
    if stat["failed"]:
        color, text = "#cf1322", f"发现 {stat['failed']} 项异常"
    elif stat["passed"]:
        color, text = "#389e0d", "全部检查通过"
    else:
        color, text = "#d46b08", "无法完成检查"
    return (f'<span style="color:{color};font-weight:600;font-size:14px;">{text}</span>'
            f'<span style="color:#8c8c8c;"> · 共 {stat["total"]} 项'
            f'（通过 {stat["passed"]} / 失败 {stat["failed"]} / 跳过 {stat["skipped"]}）</span>')


def _detail_html(items):
    rows = []
    styles = {
        OK: ("#389e0d", "通过", "✓"),
        FAIL: ("#cf1322", "失败", "✗"),
        SKIP: ("#d46b08", "跳过", "–"),
    }
    for item in items:
        color, label, mark = styles.get(item.status, ("#595959", item.status, "·"))
        ms = f'<span style="color:#8c8c8c;"> {item.ms}ms</span>' if item.ms else ""
        detail = (f'<br><span style="color:#8c8c8c;">{item.detail}</span>'
                  if item.detail else "")
        rows.append(
            f'<p style="margin:2px 0;">'
            f'<span style="color:{color};font-weight:600;">{mark} {label}</span>'
            f'&nbsp;&nbsp;{item.name}{ms}{detail}</p>')
    return "".join(rows)


def show_results(parent, items, title="自检结果"):
    """弹出结果对话框；返回对话框对象（便于测试）。"""
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.resize(660, 420)

    layout = QVBoxLayout(dlg)
    layout.setSpacing(10)

    summary = QLabel(_summary_html(items))
    summary.setTextFormat(Qt.TextFormat.RichText)
    summary.setWordWrap(True)
    layout.addWidget(summary)

    browser = QTextBrowser()
    browser.setHtml(_detail_html(items))
    browser.setOpenExternalLinks(False)
    layout.addWidget(browser, 1)

    row = QHBoxLayout()
    row.addStretch()
    copy_btn = QPushButton("复制结果")
    close_btn = QPushButton("关闭")
    close_btn.setDefault(True)
    row.addWidget(copy_btn)
    row.addWidget(close_btn)
    layout.addLayout(row)

    def copy_text():
        lines = []
        for item in items:
            label = {OK: "通过", FAIL: "失败", SKIP: "跳过"}.get(item.status, item.status)
            extra = f"（{item.ms}ms）" if item.ms else ""
            lines.append(f"[{label}] {item.name}{extra}"
                         + (f"：{item.detail}" if item.detail else ""))
        stat = summarize(items)
        lines.append(f"合计 {stat['total']} 项 · 通过 {stat['passed']} · "
                     f"失败 {stat['failed']} · 跳过 {stat['skipped']}")
        QGuiApplication.clipboard().setText("\n".join(lines))
        copy_btn.setText("已复制")

    copy_btn.clicked.connect(copy_text)
    close_btn.clicked.connect(dlg.accept)

    dlg.exec()
    return dlg
