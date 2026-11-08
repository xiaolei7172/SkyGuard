#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
开机优化页面

四个来源：注册表 Run/RunOnce、启动文件夹、计划任务、系统服务（只读）。
启停走 StartupApproved（与任务管理器同机制），不删除任何启动项本体，可逆；
操作前自动导出 .reg 备份，支持一键还原。

新增「建议」能力：
  · 每个启动项给出 建议关闭 / 建议保留 / 可选 三档结论，附理由与关闭影响；
  · 支持只看建议关闭项，以及一键关闭全部建议项（先备份、可还原）。
"""

import threading
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QLineEdit,
    QGroupBox, QAbstractItemView,
)

from utils.logger import logger
from utils.startup_manager import get_startup_manager, BACKUP_DIR
from utils.startup_advisor import VERDICT_DISABLE, VERDICT_KEEP, VERDICT_OPTIONAL, advise, summarize
from ui.styles import StyleHelper

# 建议 → (排序权重, 显示文本, 前景色)
_VERDICT_VIEW = {
    VERDICT_DISABLE: (0, "🟠 建议关闭", "#e08b3a"),
    VERDICT_OPTIONAL: (1, "⚪ 可选", "#8a94a6"),
    VERDICT_KEEP: (2, "🟢 建议保留", "#37b26c"),
}


class StartupPage(QWidget):
    """开机启动项管理"""

    load_done = Signal(list)
    op_done = Signal(str, str)   # (结果说明, 级别 success/error)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.manager = get_startup_manager()
        self.items = []
        self.advices = {}
        self.summary = {}
        self._busy = False
        self.setup_ui()

        self.load_done.connect(self._on_load_done)
        self.op_done.connect(self._on_op_done)

    # --------------------------------------
    # 界面
    # --------------------------------------
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        tip = QLabel(
            "🚀 启动项越多，开机越慢。禁用只是「关掉」，不会删除任何文件或注册表项，随时可以再打开。\n"
            "💡 「建议关闭」标的是冗余自启（更新器、游戏平台、影音客户端等）；安全软件与输入法标为「建议保留」。"
        )
        tip.setWordWrap(True)
        StyleHelper.set_label_type(tip, "success")
        layout.addWidget(tip)

        # 工具栏
        bar = QHBoxLayout()
        self.refresh_btn = QPushButton("🔄 刷新")
        self.refresh_btn.clicked.connect(self.refresh)
        bar.addWidget(self.refresh_btn)

        self.enable_btn = QPushButton("✅ 启用选中")
        self.enable_btn.clicked.connect(lambda: self.toggle_selected(True))
        bar.addWidget(self.enable_btn)

        self.disable_btn = QPushButton("⛔ 禁用选中")
        self.disable_btn.clicked.connect(lambda: self.toggle_selected(False))
        bar.addWidget(self.disable_btn)

        self.advice_btn = QPushButton("⚡ 一键关闭建议项")
        self.advice_btn.setToolTip("关闭所有「建议关闭」且当前启用的项目，操作前自动备份")
        self.advice_btn.clicked.connect(self.disable_recommended)
        self.advice_btn.setEnabled(False)
        bar.addWidget(self.advice_btn)

        self.backup_btn = QPushButton("💾 备份与还原")
        self.backup_btn.clicked.connect(self.show_backup_menu)
        bar.addWidget(self.backup_btn)

        StyleHelper.set_button_type(self.refresh_btn, "primary")
        StyleHelper.set_button_type(self.enable_btn, "success")
        StyleHelper.set_button_type(self.disable_btn, "warning")
        StyleHelper.set_button_type(self.advice_btn, "danger")
        StyleHelper.set_button_type(self.backup_btn, "default")
        bar.addStretch()
        layout.addLayout(bar)

        # 第二行：搜索与过滤（拆行是为了在 780px 最小宽度下不横向溢出）
        bar2 = QHBoxLayout()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("搜索名称 / 命令…")
        self.filter_edit.setMaximumWidth(220)
        self.filter_edit.textChanged.connect(self.apply_filter)
        bar2.addWidget(self.filter_edit)

        self.only_advice_check = QCheckBox("只看建议关闭")
        self.only_advice_check.setToolTip("只显示被判为「建议关闭」的启动项")
        self.only_advice_check.stateChanged.connect(self.apply_filter)
        bar2.addWidget(self.only_advice_check)

        self.show_system_check = QCheckBox("显示系统服务")
        self.show_system_check.setChecked(False)
        self.show_system_check.setToolTip("系统自带服务建议保持默认，误关可能导致系统功能异常")
        self.show_system_check.stateChanged.connect(self.apply_filter)
        bar2.addWidget(self.show_system_check)
        bar2.addStretch()
        layout.addLayout(bar2)

        # 建议概要
        self.advice_label = QLabel("读取启动项后给出优化建议")
        self.advice_label.setWordWrap(True)
        StyleHelper.set_label_type(self.advice_label, "info")
        layout.addWidget(self.advice_label)

        # 表格
        group = QGroupBox("启动项列表（双击查看建议详情）")
        group_layout = QVBoxLayout()
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["状态", "名称", "建议", "位置", "命令 / 路径", "备注"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.itemDoubleClicked.connect(self._show_item_advice)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        group_layout.addWidget(self.table)
        group.setLayout(group_layout)
        layout.addWidget(group)

        self.status_label = QLabel("点击「刷新」读取启动项")
        self.status_label.setWordWrap(True)
        StyleHelper.set_label_type(self.status_label, "info")
        layout.addWidget(self.status_label)

    # --------------------------------------
    # 载入
    # --------------------------------------
    def refresh(self):
        if self._busy:
            return
        self._busy = True
        self.refresh_btn.setEnabled(False)
        self.status_label.setText("正在读取启动项…")
        threading.Thread(target=self._load_worker, daemon=True).start()

    def _load_worker(self):
        try:
            items = self.manager.enum_all(include_services=True)
            self.load_done.emit(items)
        except Exception as e:
            logger.exception("启动项读取失败")
            self.load_done.emit([])
            self.op_done.emit(f"读取失败：{e}", "error")

    def _on_load_done(self, items):
        self.items = items
        self._busy = False
        self.refresh_btn.setEnabled(True)
        self.advices = {i.key: advise(i) for i in items}
        self.summary = summarize(items, self.advices)
        self.fill_table()
        self._update_summary_labels()

    def _update_summary_labels(self):
        s = self.summary
        n = s.get("suggest_disable", 0)
        saving = s.get("est_saving_ms", 0) / 1000.0
        if n:
            self.advice_label.setText(
                f"💡 已启用 {s.get('enabled', 0)} 项自启，其中 {n} 项建议关闭，"
                f"预计可缩短开机约 {saving:.1f} 秒。点「一键关闭建议项」即可批量处理（可还原）。"
            )
            StyleHelper.set_label_type(self.advice_label, "warning")
        else:
            self.advice_label.setText(
                f"✅ 已启用 {s.get('enabled', 0)} 项自启，没有发现明显的冗余项，暂不需要优化。"
            )
            StyleHelper.set_label_type(self.advice_label, "success")

        self.advice_btn.setText(f"⚡ 一键关闭建议项（{n}）")
        self.advice_btn.setEnabled(n > 0 and not self._busy)
        self.status_label.setText(
            f"共 {s.get('total', 0)} 项（已启用 {s.get('enabled', 0)} 项，"
            f"已禁用 {s.get('total', 0) - s.get('enabled', 0)} 项）"
        )
        StyleHelper.set_label_type(self.status_label, "info")

    def _sorted_items(self):
        """建议关闭的排最前，其次可选，最后保留；同档内启用优先"""
        def key(item):
            a = self.advices.get(item.key)
            rank = _VERDICT_VIEW.get(a.verdict if a else VERDICT_OPTIONAL, (1,))[0]
            return (rank, 0 if item.enabled else 1, item.name.lower())
        return sorted(self.items, key=key)

    def fill_table(self):
        self.table.setRowCount(0)
        for item in self._sorted_items():
            a = self.advices.get(item.key)
            view = _VERDICT_VIEW.get(a.verdict if a else VERDICT_OPTIONAL, (1, "⚪ 可选", "#8a94a6"))
            advice_text = view[1] + (f"（{a.category}）" if a and a.category not in ("未知", "系统托盘") else "")
            row = self.table.rowCount()
            self.table.insertRow(row)
            state = "🟢 启用" if item.enabled else "⚪ 禁用"
            cells = [state, item.name, advice_text, item.location, item.command, item.detail]
            for col, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                cell.setToolTip(text)
                if col == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, item.key)
                if col == 2:
                    cell.setForeground(QBrush(QColor(view[2])))
                    if a:
                        cell.setToolTip(f"{a.reason}\n关闭影响：{a.impact}")
                self.table.setItem(row, col, cell)
        self.apply_filter()

    def apply_filter(self):
        """按关键词、「只看建议关闭」「显示系统服务」过滤行"""
        kw = self.filter_edit.text().strip().lower()
        show_system = self.show_system_check.isChecked()
        only_advice = self.only_advice_check.isChecked()
        for row in range(self.table.rowCount()):
            name = self.table.item(row, 1).text().lower()
            advice_text = self.table.item(row, 2).text()
            cmd = self.table.item(row, 4).text().lower()
            loc = self.table.item(row, 3).text()
            note = self.table.item(row, 5).text()
            visible = True
            if kw and kw not in name and kw not in cmd:
                visible = False
            if only_advice and "建议关闭" not in advice_text:
                visible = False
            if not show_system and loc == "系统服务" and note == "系统组件":
                visible = False
            self.table.setRowHidden(row, not visible)

    # --------------------------------------
    # 建议详情
    # --------------------------------------
    def _show_item_advice(self, cell_item):
        row = cell_item.row()
        key = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        item = next((i for i in self.items if i.key == key), None)
        if not item:
            return
        a = self.advices.get(item.key)
        if not a:
            return
        box = QMessageBox(self)
        box.setWindowTitle("启动项建议")
        box.setText(f"<b>{item.name}</b><br>建议：{a.label}（{a.category}）")
        box.setInformativeText(
            f"理由：{a.reason}\n"
            f"关闭影响：{a.impact}\n"
            f"启动耗时估算：约 {a.est_ms} ms\n"
            f"位置：{item.location}\n"
            f"命令：{item.command}"
        )
        box.setIcon(QMessageBox.Icon.Information)
        box.exec()

    # --------------------------------------
    # 启停
    # --------------------------------------
    def _selected_items(self):
        rows = sorted({idx.row() for idx in self.table.selectedIndexes()})
        result = []
        for r in rows:
            key_item = self.table.item(r, 0)
            if not key_item:
                continue
            key = key_item.data(Qt.ItemDataRole.UserRole)
            for item in self.items:
                if item.key == key:
                    result.append(item)
                    break
        return result

    def _apply_toggle(self, items, enable):
        """执行批量启停，返回 (成功数, 失败数, 提示列表)"""
        if not enable:
            try:
                self.manager.backup(tag="before_disable")
            except Exception as e:
                logger.warning(f"备份失败（继续执行）：{e}")
        ok, fail, messages = 0, 0, []
        for item in items:
            success, msg = self.manager.set_enabled(item, enable)
            if success:
                item.enabled = enable
                ok += 1
            else:
                fail += 1
                messages.append(f"{item.name}: {msg}")
        if ok:
            self.advices = {i.key: advise(i) for i in self.items}
            self.summary = summarize(self.items, self.advices)
        self.fill_table()
        self._update_summary_labels()
        return ok, fail, messages

    def toggle_selected(self, enable):
        items = self._selected_items()
        if not items:
            QMessageBox.information(self, "提示", "请先在列表中选择要操作的启动项（可多选）")
            return

        editable = [i for i in items if i.editable]
        readonly = [i for i in items if not i.editable]
        if not editable:
            QMessageBox.warning(self, "不支持", "系统服务项仅支持查看，请勿在此禁用（可能导致系统异常）")
            return

        action = "启用" if enable else "禁用"
        names = "\n".join(f"• {i.name}" for i in editable[:8])
        more = f"\n…等 {len(editable)} 项" if len(editable) > 8 else ""
        reply = QMessageBox.question(
            self, f"确认{action}",
            f"将要{action}以下启动项：\n{names}{more}\n\n"
            f"{'操作前会自动备份注册表，可随时还原。' if not enable else ''}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        ok, fail, messages = self._apply_toggle(editable, enable)
        text = f"已{action} {ok} 项" + (f"，失败 {fail} 项" if fail else "")
        if messages:
            text += "\n" + "\n".join(messages[:3])
        if readonly:
            text += f"\n（{len(readonly)} 项系统服务已跳过）"
        self.op_done.emit(text, "success" if fail == 0 else "error")

    def disable_recommended(self):
        """一键关闭所有「建议关闭」且当前启用的项"""
        targets = [i for i in self.items
                   if i.enabled and i.editable
                   and self.advices.get(i.key)
                   and self.advices[i.key].verdict == VERDICT_DISABLE]
        if not targets:
            QMessageBox.information(self, "提示", "当前没有需要关闭的建议项")
            return

        saving = sum(self.advices[i.key].est_ms for i in targets) / 1000.0
        names = "\n".join(
            f"• {i.name}（{self.advices[i.key].category}）" for i in targets[:12]
        )
        more = f"\n…等 {len(targets)} 项" if len(targets) > 12 else ""
        reply = QMessageBox.question(
            self, "确认关闭建议项",
            f"将关闭 {len(targets)} 个冗余自启项，预计缩短开机约 {saving:.1f} 秒：\n\n"
            f"{names}{more}\n\n"
            "只关闭自启，不删除任何文件；操作前自动备份注册表，可一键还原。\n是否继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        ok, fail, messages = self._apply_toggle(targets, False)
        text = f"已关闭 {ok} 个建议项" + (f"，失败 {fail} 项" if fail else "")
        if ok:
            text += f"，预计缩短开机约 {saving:.1f} 秒"
        if messages:
            text += "\n" + "\n".join(messages[:3])
        self.op_done.emit(text, "success" if fail == 0 else "error")

    # --------------------------------------
    # 备份与还原
    # --------------------------------------
    def show_backup_menu(self):
        backups = self.manager.list_backups()
        latest = backups[0][0] if backups else "（暂无备份）"
        box = QMessageBox(self)
        box.setWindowTitle("备份与还原")
        box.setText(
            f"备份目录：{BACKUP_DIR}\n最近备份：{latest}\n\n"
            "备份内容：注册表 Run 键 + StartupApproved 状态 + 启动项清单 JSON。"
        )
        do_backup = box.addButton("立即备份", QMessageBox.ButtonRole.ActionRole)
        do_restore = box.addButton("还原最近备份", QMessageBox.ButtonRole.DestructiveRole)
        open_dir = box.addButton("打开备份目录", QMessageBox.ButtonRole.ActionRole)
        box.addButton("关闭", QMessageBox.ButtonRole.RejectRole)
        box.exec()

        clicked = box.clickedButton()
        if clicked is do_backup:
            self._do_backup()
        elif clicked is do_restore:
            self._do_restore(latest if backups else None)
        elif clicked is open_dir:
            try:
                os.makedirs(BACKUP_DIR, exist_ok=True)
                os.startfile(BACKUP_DIR)
            except OSError as e:
                self.op_done.emit(f"打开目录失败：{e}", "error")

    def _do_backup(self):
        try:
            out_dir, exported = self.manager.backup(tag="manual")
            self.op_done.emit(f"备份完成（{exported} 个注册表位置）\n{out_dir}", "success")
        except Exception as e:
            logger.exception("备份失败")
            self.op_done.emit(f"备份失败：{e}", "error")

    def _do_restore(self, backup_name):
        if not backup_name:
            QMessageBox.information(self, "提示", "还没有备份，请先点「立即备份」")
            return
        reply = QMessageBox.question(
            self, "确认还原",
            f"将从备份「{backup_name}」还原注册表启动项状态。\n"
            "还原后当前的自定义启停设置会被覆盖，是否继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        path = os.path.join(BACKUP_DIR, backup_name)
        ok, msg = self.manager.restore(path)
        self.op_done.emit(msg, "success" if ok else "error")
        self.refresh()

    # --------------------------------------
    def _on_op_done(self, msg, level):
        self.status_label.setText(msg)
        StyleHelper.set_label_type(self.status_label, "success" if level == "success" else "error")
        if level == "error":
            QMessageBox.warning(self, "操作结果", msg)
