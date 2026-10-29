#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
开机优化页面

四个来源：注册表 Run/RunOnce、启动文件夹、计划任务、系统服务（只读）。
启停走 StartupApproved（与任务管理器同机制），不删除任何启动项本体，可逆；
操作前自动导出 .reg 备份，支持一键还原。
"""

import threading
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QLineEdit,
    QGroupBox, QAbstractItemView,
)

from utils.logger import logger
from utils.startup_manager import get_startup_manager, BACKUP_DIR
from ui.styles import StyleHelper


class StartupPage(QWidget):
    """开机启动项管理"""

    load_done = Signal(list)
    op_done = Signal(str, str)   # (结果说明, 级别 success/error)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.manager = get_startup_manager()
        self.items = []
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
            "🛡️ 每次修改前都会自动备份注册表，可在「备份与还原」里一键恢复。"
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

        self.backup_btn = QPushButton("💾 备份与还原")
        self.backup_btn.clicked.connect(self.show_backup_menu)
        bar.addWidget(self.backup_btn)

        StyleHelper.set_button_type(self.refresh_btn, "primary")
        StyleHelper.set_button_type(self.enable_btn, "success")
        StyleHelper.set_button_type(self.disable_btn, "warning")
        StyleHelper.set_button_type(self.backup_btn, "default")

        bar.addStretch()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("搜索名称 / 命令…")
        self.filter_edit.setMaximumWidth(220)
        self.filter_edit.textChanged.connect(self.apply_filter)
        bar.addWidget(self.filter_edit)

        self.show_system_check = QCheckBox("显示系统服务")
        self.show_system_check.setChecked(False)
        self.show_system_check.setToolTip("系统自带服务建议保持默认，误关可能导致系统功能异常")
        self.show_system_check.stateChanged.connect(self.apply_filter)
        bar.addWidget(self.show_system_check)
        layout.addLayout(bar)

        # 表格
        group = QGroupBox("启动项列表")
        group_layout = QVBoxLayout()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["状态", "名称", "位置", "命令 / 路径", "备注"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
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
        self.fill_table()
        enabled = sum(1 for i in items if i.enabled)
        self.status_label.setText(
            f"共 {len(items)} 项（已启用 {enabled} 项，已禁用 {len(items) - enabled} 项）"
        )
        StyleHelper.set_label_type(self.status_label, "info")

    def fill_table(self):
        self.table.setRowCount(0)
        for item in self.items:
            row = self.table.rowCount()
            self.table.insertRow(row)
            state = "🟢 启用" if item.enabled else "⚪ 禁用"
            cells = [state, item.name, item.location, item.command, item.detail]
            for col, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                cell.setToolTip(text)
                if col == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, item.key)
                self.table.setItem(row, col, cell)
        self.apply_filter()

    def apply_filter(self):
        """按关键词与「显示系统服务」过滤行"""
        kw = self.filter_edit.text().strip().lower()
        show_system = self.show_system_check.isChecked()
        for row in range(self.table.rowCount()):
            name = self.table.item(row, 1).text().lower()
            cmd = self.table.item(row, 3).text().lower()
            loc = self.table.item(row, 2).text()
            note = self.table.item(row, 4).text()
            visible = True
            if kw and kw not in name and kw not in cmd:
                visible = False
            if not show_system and loc == "系统服务" and note == "系统组件":
                visible = False
            self.table.setRowHidden(row, not visible)

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

        # 禁用前先备份（启用不需要，防止用户误以为是危险操作）
        if not enable:
            try:
                self.manager.backup(tag="before_disable")
            except Exception as e:
                logger.warning(f"备份失败（继续执行）：{e}")

        ok, fail = 0, 0
        messages = []
        for item in editable:
            success, msg = self.manager.set_enabled(item, enable)
            if success:
                item.enabled = enable
                ok += 1
            else:
                fail += 1
                messages.append(f"{item.name}: {msg}")

        self.fill_table()
        text = f"已{action} {ok} 项" + (f"，失败 {fail} 项" if fail else "")
        if messages:
            text += "\n" + "\n".join(messages[:3])
        if readonly:
            text += f"\n（{len(readonly)} 项系统服务已跳过）"
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
