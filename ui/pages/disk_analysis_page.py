#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
全盘空间分析页面

只读扫描整机可优化空间：系统残留、应用缓存、开发工具缓存、安装包、
大文件、重复文件、长期未动的大文件；能落到清理规则的项可一键送回收站。

耗时的遍历全部在后台线程执行，可随时停止。
"""

import os
import subprocess
import threading

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QCheckBox,
    QComboBox, QTreeWidget, QTreeWidgetItem, QProgressBar, QMessageBox,
    QGroupBox, QHeaderView, QAbstractItemView,
)

from utils.logger import logger
from utils.disk_analyzer import get_disk_analyzer
from utils.clean_engine import get_clean_engine, format_size
from ui.styles import StyleHelper

_RISK_COLORS = {0: "#37b26c", 1: "#e08b3a", 2: "#8a94a6"}
_RISK_TEXT = {0: "可安全释放", 1: "谨慎清理", 2: "仅提示"}


class DiskAnalysisPage(QWidget):
    """全盘空间分析"""

    progress = Signal(str, int)
    scan_done = Signal(dict)
    clean_done = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.analyzer = get_disk_analyzer()
        self.engine = get_clean_engine()
        self.cancel_event = None
        self.result = {}
        self._busy = False
        self._disk_mounts = []
        self._disk_rows = {}
        self.setup_ui()

        self.progress.connect(self._on_progress)
        self.scan_done.connect(self._on_scan_done)
        self.clean_done.connect(self._on_clean_done)
        self.refresh_overview()

    # --------------------------------------
    # 界面
    # --------------------------------------
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        tip = QLabel(
            "🔍 扫描整机可优化空间：系统残留、应用缓存、开发工具缓存、安装包、大文件与重复文件。\n"
            "🛡️ 本页只读不删；只有能对应到清理规则的项目才可一键清理，且默认送回收站、可还原。"
        )
        tip.setWordWrap(True)
        StyleHelper.set_label_type(tip, "success")
        layout.addWidget(tip)

        # 工具栏
        bar = QHBoxLayout()
        self.scan_btn = QPushButton("🔍 开始分析")
        self.scan_btn.clicked.connect(self.start_scan)
        StyleHelper.set_button_type(self.scan_btn, "primary")
        bar.addWidget(self.scan_btn)

        self.stop_btn = QPushButton("⏹ 停止")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        StyleHelper.set_button_type(self.stop_btn, "warning")
        bar.addWidget(self.stop_btn)

        bar.addStretch()

        self.open_btn = QPushButton("📂 打开位置")
        self.open_btn.setEnabled(False)
        self.open_btn.clicked.connect(self.open_selected)
        bar.addWidget(self.open_btn)

        self.clean_btn = QPushButton("🧹 清理可释放项")
        self.clean_btn.setEnabled(False)
        self.clean_btn.setToolTip("把能对应到清理规则的项目送回收站（可还原）")
        self.clean_btn.clicked.connect(self.clean_safe_items)
        StyleHelper.set_button_type(self.clean_btn, "success")
        bar.addWidget(self.clean_btn)
        layout.addLayout(bar)

        # 第二行：扫描范围与深度选项（拆行避免窄窗口横向溢出）
        bar2 = QHBoxLayout()
        bar2.addWidget(QLabel("范围："))
        self.range_combo = QComboBox()
        self.range_combo.addItems(["全部固定磁盘", "仅系统盘"])
        self.range_combo.setMinimumWidth(120)
        self.range_combo.setMaximumWidth(150)
        bar2.addWidget(self.range_combo)

        self.deep_check = QCheckBox("深度扫描（大文件 / 重复文件）")
        self.deep_check.setToolTip("深度模式会遍历整个磁盘，耗时较长（几分钟），但能发现重复的大文件")
        bar2.addWidget(self.deep_check)
        bar2.addStretch()
        layout.addLayout(bar2)

        # 磁盘占用
        disk_group = QGroupBox("磁盘占用")
        self.disk_layout = QVBoxLayout()
        self.disk_layout.setSpacing(4)
        disk_group.setLayout(self.disk_layout)
        layout.addWidget(disk_group)

        # 结果树
        group = QGroupBox("可优化空间")
        group_layout = QVBoxLayout()
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["项目", "说明", "占用", "建议"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.itemSelectionChanged.connect(self._on_select)
        group_layout.addWidget(self.tree)
        group.setLayout(group_layout)
        layout.addWidget(group)

        # 进度与状态
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        StyleHelper.set_progress_type(self.progress_bar, "memory-low")
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("尚未分析")
        self.status_label.setWordWrap(True)
        StyleHelper.set_label_type(self.status_label, "info")
        layout.addWidget(self.status_label)

    def refresh_overview(self):
        """先显示磁盘占用（毫秒级），让用户有即时反馈"""
        data = self.analyzer.overview()
        self._fill_disks(data)

    def _fill_disks(self, overview):
        """磁盘行只创建一次，刷新时只更新数值。

        早期版本每次刷新都重建整行，子布局里的控件不随 takeAt 销毁，
        反复扫描会持续残留 QLabel/QProgressBar（实测 10 次刷新涨到 69 个控件）。
        """
        mounts = [d["mount"] for d in overview]
        if mounts != self._disk_mounts:
            self._clear_disks()
            self._disk_mounts = mounts
            if not overview:
                self.disk_layout.addWidget(QLabel("未读取到磁盘信息"))
            for d in overview:
                row = QHBoxLayout()
                label = QLabel(d["mount"])
                label.setMinimumWidth(52)
                row.addWidget(label)

                bar = QProgressBar()
                bar.setRange(0, 1000)
                bar.setTextVisible(True)
                bar.setFixedHeight(18)
                row.addWidget(bar, 1)

                free = QLabel()
                free.setMinimumWidth(110)
                row.addWidget(free)

                self.disk_layout.addLayout(row)
                self._disk_rows[d["mount"]] = (bar, free)

        for d in overview:
            bar, free = self._disk_rows[d["mount"]]
            bar.setValue(int(d["percent"] * 10))
            bar.setFormat(
                f"{format_size(d['used'])} / {format_size(d['total'])}（{d['percent']:.0f}%）"
            )
            free.setText(f"剩余 {format_size(d['free'])}")
            style = ("memory-high" if d["percent"] >= 90
                     else "memory-medium" if d["percent"] >= 75 else "memory-low")
            if bar.property("progressType") != style:
                StyleHelper.set_progress_type(bar, style)

    def _clear_disks(self):
        """销毁磁盘行（含子布局里的控件，避免遗留）"""
        while self.disk_layout.count():
            item = self.disk_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()
                continue
            sub = item.layout()
            if sub is not None:
                while sub.count():
                    child = sub.takeAt(0)
                    cw = child.widget()
                    if cw is not None:
                        cw.setParent(None)
                        cw.deleteLater()
                sub.deleteLater()
        self._disk_rows = {}

    # --------------------------------------
    # 扫描
    # --------------------------------------
    def start_scan(self):
        if self._busy:
            return
        self._busy = True
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.clean_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.tree.clear()
        self.cancel_event = threading.Event()
        self.status_label.setText("正在启动分析…")
        StyleHelper.set_label_type(self.status_label, "info")

        deep = self.deep_check.isChecked()
        all_drives = self.range_combo.currentIndex() == 0
        threading.Thread(target=self._scan_worker, args=(deep, all_drives), daemon=True).start()

    def stop_scan(self):
        if self.cancel_event:
            self.cancel_event.set()
            self.status_label.setText("正在停止…（等待当前目录扫描结束）")

    def _scan_worker(self, deep, all_drives):
        try:
            result = self.analyzer.scan(
                deep=deep, all_drives=all_drives,
                progress=lambda msg, pct: self.progress.emit(msg, pct),
                cancel=self.cancel_event,
            )
            self.scan_done.emit(result)
        except Exception as e:
            logger.exception("全盘分析失败")
            self.scan_done.emit({"error": str(e)})

    def _on_progress(self, msg, pct):
        self.status_label.setText(msg)
        if pct >= 0:
            self.progress_bar.setValue(min(100, pct))

    def _on_scan_done(self, result):
        self._busy = False
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        if result.get("error"):
            self.status_label.setText(f"❌ 分析失败：{result['error']}")
            StyleHelper.set_label_type(self.status_label, "error")
            return

        self.result = result
        if result.get("overview"):
            self._fill_disks(result["overview"])
        self._fill_tree(result.get("findings", []))

        reclaim = format_size(result.get("total_reclaimable", 0))
        manual = format_size(result.get("total_manual", 0))
        notice = format_size(result.get("total_notice", 0))
        flag = "（已停止，结果为部分数据）" if result.get("cancelled") else ""
        has_recycle = any("recycle_bin" in f.get("rule_keys", [])
                          for f in result.get("findings", []))
        tail = "；回收站需到「规则清理」页单独清空" if has_recycle else ""
        self.status_label.setText(
            f"✅ 分析完成{flag}：可一键释放约 {reclaim}；另有 {manual} 需手动清理、"
            f"{notice} 属提示项（需自行判断）{tail}；耗时 {result.get('elapsed', 0):.1f} 秒"
        )
        StyleHelper.set_label_type(self.status_label, "success")
        self.progress_bar.setValue(100)
        self.clean_btn.setEnabled(bool(self._cleanable_keys()))

    def _fill_tree(self, findings):
        self.tree.clear()
        groups = {}
        order = ["系统可清理", "应用缓存", "开发工具缓存", "安装包残留", "大文件",
                 "重复文件", "长期未动", "磁盘占用"]
        for group_name in order:
            items = [f for f in findings if f["group"] == group_name]
            if not items:
                continue
            items.sort(key=lambda f: (f["risk"], -f["size"]))
            total = sum(f["size"] for f in items if f["risk"] <= 1) or sum(f["size"] for f in items)
            top = QTreeWidgetItem(self.tree, [group_name, f"{len(items)} 项", format_size(total), ""])
            font = top.font(0)
            font.setBold(True)
            top.setFont(0, font)
            groups[group_name] = top
            for f in items:
                child = QTreeWidgetItem(top, [
                    f["name"], f["detail"], format_size(f["size"]),
                    _RISK_TEXT.get(f["risk"], "") + (f"（{f['action_text']}）" if f["action_text"] else ""),
                ])
                child.setData(0, Qt.ItemDataRole.UserRole, f)
                child.setToolTip(1, f["path"] or f["detail"])
                child.setForeground(3, QBrush(QColor(_RISK_COLORS.get(f["risk"], "#8a94a6"))))
        self.tree.expandAll()

    # --------------------------------------
    # 选中项操作
    # --------------------------------------
    def _selected_finding(self):
        item = self.tree.currentItem()
        if not item or item.parent() is None:
            return None
        return item.data(0, Qt.ItemDataRole.UserRole)

    def _on_select(self):
        f = self._selected_finding()
        self.open_btn.setEnabled(bool(f and f.get("path")))

    def open_selected(self):
        f = self._selected_finding()
        if not f or not f.get("path"):
            return
        path = f["path"]
        try:
            if os.path.isdir(path):
                os.startfile(path)
            elif os.path.isfile(path):
                # 不用 os.system 拼接；路径含引号/换行会引起 explorer 参数歧义，
                # 这种情况退化为打开所在目录，避免任何命令解析风险。
                if any(c in path for c in ('"', "\r", "\n")):
                    parent = os.path.dirname(path)
                    if parent and os.path.isdir(parent):
                        os.startfile(parent)
                else:
                    subprocess.Popen(["explorer.exe", f'/select,"{path}"'])
            else:
                parent = os.path.dirname(path)
                if parent and os.path.isdir(parent):
                    os.startfile(parent)
        except OSError as e:
            QMessageBox.warning(self, "打开失败", f"无法打开：{path}\n{e}")

    # --------------------------------------
    # 清理
    # --------------------------------------
    def _cleanable_findings(self):
        """可交给清理引擎的项目。

        刻意排除回收站：清空回收站不可恢复，与「送回收站可还原」的承诺冲突，
        必须让用户到「规则清理」页单独确认。
        """
        return [f for f in self.result.get("findings", [])
                if f.get("risk", 2) <= 1 and f.get("rule_keys")
                and "recycle_bin" not in f["rule_keys"]]

    def _cleanable_keys(self):
        keys = []
        for f in self._cleanable_findings():
            for k in f["rule_keys"]:
                if k not in keys:
                    keys.append(k)
        return keys

    def clean_safe_items(self):
        if self._busy:
            return
        findings = self._cleanable_findings()
        keys = self._cleanable_keys()
        if not keys:
            QMessageBox.information(self, "提示", "没有可直接清理的项目（提示项需要你自行处理）")
            return

        total = sum(f["size"] for f in findings)
        lines = "\n".join(f"• {f['name']}：{format_size(f['size'])}" for f in findings[:12])
        more = f"\n…等 {len(findings)} 项" if len(findings) > 12 else ""
        reply = QMessageBox.question(
            self, "确认清理",
            f"将清理 {len(findings)} 类可释放项，约 {format_size(total)}：\n\n{lines}{more}\n\n"
            "删除方式：送回收站（可还原）。\n"
            "回收站本身不会被清空——需要清空请到「规则清理」页单独确认。\n\n是否继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._busy = True
        self.clean_btn.setEnabled(False)
        self.scan_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("正在清理…")
        threading.Thread(target=self._clean_worker, args=(keys,), daemon=True).start()

    def _clean_worker(self, keys):
        try:
            report = self.engine.clean(
                keys, to_recycle=True,
                progress=lambda msg, pct: self.progress.emit(msg, pct),
            )
            self.clean_done.emit(report)
        except Exception as e:
            logger.exception("清理失败")
            self.clean_done.emit({"error": str(e)})

    def _on_clean_done(self, report):
        self._busy = False
        self.scan_btn.setEnabled(True)
        if report.get("error"):
            self.status_label.setText(f"❌ 清理失败：{report['error']}")
            StyleHelper.set_label_type(self.status_label, "error")
            return
        freed = format_size(report.get("total_size", 0))
        files = report.get("total_files", 0)
        self.status_label.setText(f"✅ 清理完成：释放约 {freed}，清理文件 {files} 个")
        StyleHelper.set_label_type(self.status_label, "success")
        QMessageBox.information(
            self, "清理完成",
            f"释放空间约 {freed}\n清理文件 {files} 个"
            + (f"，跳过 {report.get('failures', 0)} 项（占用/无权限）" if report.get("failures") else "")
            + "\n\n已删除的文件可在回收站还原。",
        )
        self.start_scan()
