#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
垃圾清理页面

交互流程：扫描（预览） → 勾选 → 清理（默认送回收站）。
所有耗时操作在线程中执行，通过信号回主线程更新界面，避免卡死。
"""

import threading

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QCheckBox,
    QTreeWidget, QTreeWidgetItem, QProgressBar, QMessageBox, QGroupBox,
    QHeaderView,
)

from utils.logger import logger
from utils.clean_engine import get_clean_engine, format_size
from ui.styles import StyleHelper


class DiskCleanPage(QWidget):
    """垃圾清理"""

    scan_progress = Signal(str, int)
    scan_done = Signal(dict)
    clean_progress = Signal(str, int)
    clean_done = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = get_clean_engine()
        self.scan_result = {}
        self._busy = False
        self.setup_ui()
        self.build_tree()

        self.scan_progress.connect(self._on_progress)
        self.clean_progress.connect(self._on_progress)
        self.scan_done.connect(self._on_scan_done)
        self.clean_done.connect(self._on_clean_done)

    # --------------------------------------
    # 界面
    # --------------------------------------
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        tip = QLabel(
            "🧹 只清理缓存与临时文件，不会删除你的文档、照片或聊天记录。\n"
            "🛡️ 默认删除到回收站，误删可还原；每次清理都会生成 JSON 报告。"
        )
        tip.setWordWrap(True)
        StyleHelper.set_label_type(tip, "success")
        layout.addWidget(tip)

        # 工具栏
        bar = QHBoxLayout()
        self.scan_btn = QPushButton("🔍 扫描")
        self.scan_btn.setToolTip("先扫描，看清每一项能释放多少空间")
        self.scan_btn.clicked.connect(self.start_scan)
        bar.addWidget(self.scan_btn)

        self.clean_btn = QPushButton("🧹 清理选中项")
        self.clean_btn.setToolTip("清理勾选的分类，默认送入回收站")
        self.clean_btn.clicked.connect(self.start_clean)
        self.clean_btn.setEnabled(False)
        bar.addWidget(self.clean_btn)

        StyleHelper.set_button_type(self.scan_btn, "primary")
        StyleHelper.set_button_type(self.clean_btn, "success")

        bar.addStretch()

        self.recycle_check = QCheckBox("删除到回收站")
        self.recycle_check.setChecked(True)
        self.recycle_check.setToolTip("取消勾选将永久删除，不可恢复")
        bar.addWidget(self.recycle_check)

        self.advanced_check = QCheckBox("显示高级项")
        self.advanced_check.setToolTip("包含 Windows 更新缓存、WinSxS 组件清理等有副作用的项目")
        self.advanced_check.stateChanged.connect(self._toggle_advanced)
        bar.addWidget(self.advanced_check)
        layout.addLayout(bar)

        # 列表
        group = QGroupBox("清理项目")
        group_layout = QVBoxLayout()
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["项目", "说明", "可释放", "文件数"])
        self.tree.setRootIsDecorated(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.itemChanged.connect(self._on_item_changed)
        group_layout.addWidget(self.tree)
        group.setLayout(group_layout)
        layout.addWidget(group)

        # 进度与状态
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        StyleHelper.set_progress_type(self.progress, "memory-low")
        layout.addWidget(self.progress)

        self.status_label = QLabel("尚未扫描")
        self.status_label.setWordWrap(True)
        StyleHelper.set_label_type(self.status_label, "info")
        layout.addWidget(self.status_label)

    def build_tree(self):
        """按规则生成分类树；risk 2 默认隐藏"""
        self.tree.blockSignals(True)
        self.tree.clear()
        groups = {}
        for rule in self.engine.rules:
            gname = rule["group"]
            if gname not in groups:
                top = QTreeWidgetItem(self.tree, [gname, "", "", ""])
                top.setFirstColumnSpanned(True)
                top.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
                top.setCheckState(0, Qt.CheckState.Checked)
                font = top.font(0)
                font.setBold(True)
                top.setFont(0, font)
                groups[gname] = top
            parent = groups[gname]
            child = QTreeWidgetItem(parent, [rule["name"], rule["desc"], "—", "—"])
            child.setData(0, Qt.ItemDataRole.UserRole, rule["key"])
            child.setData(0, Qt.ItemDataRole.UserRole + 1, rule["risk"])
            child.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
            child.setCheckState(0, Qt.CheckState.Checked if rule["risk"] == 0 else Qt.CheckState.Unchecked)
            child.setToolTip(1, rule["desc"])
        self.tree.blockSignals(False)
        self._refresh_group_state()
        self._toggle_advanced()

    def _refresh_group_state(self):
        """按子项勾选情况回算分组三态（避免分组显示勾选但子项未全选）"""
        self.tree.blockSignals(True)
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            states = [top.child(j).checkState(0) for j in range(top.childCount())]
            if not states:
                continue
            if all(s == Qt.CheckState.Checked for s in states):
                top.setCheckState(0, Qt.CheckState.Checked)
            elif all(s == Qt.CheckState.Unchecked for s in states):
                top.setCheckState(0, Qt.CheckState.Unchecked)
            else:
                top.setCheckState(0, Qt.CheckState.PartiallyChecked)
        self.tree.blockSignals(False)

    def _toggle_advanced(self):
        """高级项显隐"""
        show = self.advanced_check.isChecked()
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            if "高级" in top.text(0):
                top.setHidden(not show)

    # --------------------------------------
    # 勾选联动
    # --------------------------------------
    def _on_item_changed(self, item, column):
        if column != 0:
            return
        self.tree.blockSignals(True)
        if item.parent() is None:
            # 分组节点：统一下发到子项
            state = item.checkState(0)
            for i in range(item.childCount()):
                item.child(i).setCheckState(0, state)
        else:
            # 子项变化：回算分组三态
            parent = item.parent()
            states = [parent.child(i).checkState(0) for i in range(parent.childCount())]
            if all(s == Qt.CheckState.Checked for s in states):
                parent.setCheckState(0, Qt.CheckState.Checked)
            elif all(s == Qt.CheckState.Unchecked for s in states):
                parent.setCheckState(0, Qt.CheckState.Unchecked)
            else:
                parent.setCheckState(0, Qt.CheckState.PartiallyChecked)
        self.tree.blockSignals(False)
        self.clean_btn.setEnabled(bool(self.checked_keys()) and not self._busy)

    def checked_keys(self):
        keys = []
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            for j in range(top.childCount()):
                child = top.child(j)
                if child.checkState(0) == Qt.CheckState.Checked:
                    keys.append(child.data(0, Qt.ItemDataRole.UserRole))
        return keys

    def _item_by_key(self, key):
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            for j in range(top.childCount()):
                child = top.child(j)
                if child.data(0, Qt.ItemDataRole.UserRole) == key:
                    return child
        return None

    # --------------------------------------
    # 扫描
    # --------------------------------------
    def start_scan(self):
        if self._busy:
            return
        keys = self.checked_keys()
        if not keys:
            QMessageBox.information(self, "提示", "请先勾选要扫描的分类")
            return
        self._set_busy(True, "正在扫描…")
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        threading.Thread(target=self._scan_worker, args=(keys,), daemon=True).start()

    def _scan_worker(self, keys):
        try:
            summary = self.engine.scan(keys, progress=lambda msg, pct: self.scan_progress.emit(msg, pct))
            self.scan_done.emit(summary)
        except Exception as e:
            logger.exception("扫描失败")
            self.scan_done.emit({"error": str(e)})

    def _on_progress(self, msg, pct):
        self.status_label.setText(msg)
        self.progress.setValue(max(0, min(100, pct)))

    def _on_scan_done(self, summary):
        self._set_busy(False)
        if summary.get("error"):
            self.status_label.setText(f"❌ 扫描失败：{summary['error']}")
            StyleHelper.set_label_type(self.status_label, "error")
            return
        self.scan_result = summary
        for key, res in summary.get("rules", {}).items():
            item = self._item_by_key(key)
            if not item:
                continue
            if res.get("skipped"):
                item.setText(2, "—")
                item.setText(3, res["skipped"])
            else:
                item.setText(2, format_size(res["size"]))
                item.setText(3, str(res["files"]))
        total = format_size(summary.get("total_size", 0))
        self.status_label.setText(
            f"✅ 扫描完成：可释放约 {total}，共 {summary.get('total_files', 0)} 个文件"
        )
        StyleHelper.set_label_type(self.status_label, "success")
        self.clean_btn.setEnabled(bool(self.checked_keys()))
        self.progress.setValue(100)

    # --------------------------------------
    # 清理
    # --------------------------------------
    def start_clean(self):
        if self._busy:
            return
        keys = self.checked_keys()
        if not keys:
            QMessageBox.information(self, "提示", "请先勾选要清理的分类")
            return
        to_recycle = self.recycle_check.isChecked()
        est = ""
        if self.scan_result.get("total_size"):
            est = f"\n预计释放：{format_size(self.scan_result['total_size'])}"
        mode = "送回收站（可还原）" if to_recycle else "永久删除（不可恢复）"
        reply = QMessageBox.question(
            self, "确认清理",
            f"将清理 {len(keys)} 个分类。{est}\n删除方式：{mode}\n\n是否继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._set_busy(True, "正在清理…")
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        threading.Thread(target=self._clean_worker, args=(keys, to_recycle), daemon=True).start()

    def _clean_worker(self, keys, to_recycle):
        try:
            report = self.engine.clean(keys, to_recycle=to_recycle,
                                       progress=lambda msg, pct: self.clean_progress.emit(msg, pct))
            self.clean_done.emit(report)
        except Exception as e:
            logger.exception("清理失败")
            self.clean_done.emit({"error": str(e)})

    def _on_clean_done(self, report):
        self._set_busy(False)
        if report.get("error"):
            self.status_label.setText(f"❌ 清理失败：{report['error']}")
            StyleHelper.set_label_type(self.status_label, "error")
            return
        lines = [f"• {r['name']}：{r['files']} 个文件" + (f"（{r['note']}）" if r["note"] else "")
                 for r in report.get("rules", []) if r["files"] or r["note"]]
        freed = format_size(report.get("total_size", 0))
        detail = "\n".join(lines[:10]) if lines else "无可清理内容"
        QMessageBox.information(
            self, "清理完成",
            f"释放空间约 {freed}\n清理文件 {report.get('total_files', 0)} 个"
            + (f"，跳过 {report.get('failures', 0)} 项（占用/无权限）" if report.get("failures") else "")
            + f"\n\n{detail}"
        )
        self.status_label.setText(f"✅ 清理完成：释放约 {freed}")
        StyleHelper.set_label_type(self.status_label, "success")
        self.progress.setValue(100)
        self.scan_result = {}
        self.start_scan()

    # --------------------------------------
    def _set_busy(self, busy, msg=""):
        self._busy = busy
        self.scan_btn.setEnabled(not busy)
        self.clean_btn.setEnabled(not busy and bool(self.checked_keys()))
        if msg:
            self.status_label.setText(msg)
