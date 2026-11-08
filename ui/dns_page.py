#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
DNS 过滤器页面

本地 DNS 服务器管理：上游服务器（UDP/DoH/DoT）、黑名单拦截、
系统 DNS 接管与恢复、查询统计。

所有耗时操作（查询测试、延迟探测、订阅更新、接管恢复）都放线程，
通过信号回主线程更新界面。
"""

import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton,
    QScrollArea, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    QFrame,
)

from core.dns_filter import DnsFilter, SUPPORTED_PROTOCOLS, Upstream, build_query, QTYPE_A
from ui.styles import StyleHelper
from utils import dns_takeover
from utils.logger import logger

BLOCKLIST_SUBSCRIBE_URL = "https://anti-ad.net/hosts"


def _blocklist_path():
    return os.path.join(os.path.expanduser("~"), ".skyguard", "dns-blocklist.txt")


class DnsPage(QWidget):
    """DNS 过滤器标签页"""

    status_changed = Signal(bool)
    # 后台线程 -> 主线程的回调投递
    ui_call = Signal(object)

    def __init__(self, config_manager, parent=None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.blocklist_path = _blocklist_path()
        self._ensure_blocklist_file()

        self.filter = DnsFilter(
            listen_hosts=self._listen_hosts(),
            port=config_manager.dns_port,
            blocklist_path=self.blocklist_path,
            block_action=config_manager.dns_block_action,
        )
        self.filter.set_upstreams(
            [Upstream.from_dict(u) for u in config_manager.dns_upstreams],
            selected=config_manager.dns_selected_upstream,
        )

        self._adapters = []
        self._probing = False
        self.ui_call.connect(lambda f: f())
        self.setup_ui()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_stats)
        self.refresh_timer.start(2000)

    def _ui(self, func):
        """线程安全地把界面更新投递回主线程。"""
        self.ui_call.emit(func)

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------
    def setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(10)
        scroll.setWidget(content)
        outer.addWidget(scroll)

        # --- 顶部状态条 ---
        top_group = QGroupBox("服务控制")
        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        self.status_pill = QLabel("● 未运行")
        self.status_pill.setObjectName("dnsStatusPill")
        self._style_pill(False)
        top_row.addWidget(self.status_pill)

        self.listen_label = QLabel(
            f"监听 {'、'.join(self._listen_hosts())} :: 端口 {self.config_manager.dns_port}")
        self.listen_label.setStyleSheet("color: #8c8c8c;")
        top_row.addWidget(self.listen_label)
        top_row.addStretch()

        self.restore_btn = QPushButton("恢复系统 DNS")
        self.restore_btn.clicked.connect(self.on_restore_dns)
        StyleHelper.set_button_type(self.restore_btn, "default")
        top_row.addWidget(self.restore_btn)

        self.takeover_btn = QPushButton("接管系统 DNS")
        self.takeover_btn.clicked.connect(self.on_takeover)
        StyleHelper.set_button_type(self.takeover_btn, "default")
        top_row.addWidget(self.takeover_btn)

        self.start_takeover_btn = QPushButton("启动并接管 DNS")
        self.start_takeover_btn.clicked.connect(self.on_start_and_takeover)
        top_row.addWidget(self.start_takeover_btn)

        self.stop_btn = QPushButton("停止服务")
        self.stop_btn.setToolTip("停止本地 DNS 服务，并自动恢复系统 DNS")
        self.stop_btn.clicked.connect(self.on_stop)
        StyleHelper.set_button_type(self.stop_btn, "danger")
        top_row.addWidget(self.stop_btn)

        top_group.setLayout(top_row)
        layout.addWidget(top_group)

        # --- 统计卡片行 ---
        stats_row = QHBoxLayout()
        stats_row.setSpacing(10)
        self.stat_cards = {}
        for key, title in (("total", "累计查询"), ("blocked", "已拦截"),
                           ("cache", "缓存命中率"), ("latency", "当前上游延迟")):
            card = QGroupBox(title)
            card_layout = QVBoxLayout()
            value = QLabel("0")
            value.setStyleSheet("font-size: 22px; font-weight: 600;")
            card_layout.addWidget(value)
            self.stat_cards[key] = value
            card.setLayout(card_layout)
            stats_row.addWidget(card, 1)
        layout.addLayout(stats_row)

        # --- 主体两列 ---
        body = QHBoxLayout()
        body.setSpacing(10)
        layout.addLayout(body)

        left_col = QVBoxLayout()
        left_col.setSpacing(10)
        right_col = QVBoxLayout()
        right_col.setSpacing(10)
        body.addLayout(left_col, 3)
        body.addLayout(right_col, 2)

        # 左列：当前状态
        state_group = QGroupBox("当前状态")
        state_layout = QVBoxLayout()
        self.state_label = QLabel("服务：未运行")
        self.state_label.setWordWrap(True)
        self.state_label.setTextFormat(Qt.TextFormat.RichText)
        state_layout.addWidget(self.state_label)
        state_group.setLayout(state_layout)
        left_col.addWidget(state_group)

        # 左列：上游服务器
        upstream_group = QGroupBox("上游服务器")
        upstream_layout = QVBoxLayout()

        self.upstream_table = QTableWidget(0, 5)
        self.upstream_table.setHorizontalHeaderLabels(["名称", "协议", "地址", "状态", "延迟"])
        self.upstream_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.upstream_table.verticalHeader().setVisible(False)
        self.upstream_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.upstream_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.upstream_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.upstream_table.setMinimumHeight(180)
        self.upstream_table.itemSelectionChanged.connect(self.on_upstream_selected)
        upstream_layout.addWidget(self.upstream_table)

        add_row = QHBoxLayout()
        self.new_name = QLineEdit()
        self.new_name.setPlaceholderText("名称（可留空自动生成）")
        self.new_proto = QComboBox()
        self.new_proto.addItems(list(SUPPORTED_PROTOCOLS))
        self.new_addr = QLineEdit()
        self.new_addr.setPlaceholderText("地址：223.5.5.5:53 / https://dns.alidns.com/dns-query / dot.pub:853")
        add_btn = QPushButton("添加")
        add_btn.clicked.connect(self.on_add_upstream)
        add_row.addWidget(self.new_name, 1)
        add_row.addWidget(self.new_proto)
        add_row.addWidget(self.new_addr, 3)
        add_row.addWidget(add_btn)
        upstream_layout.addLayout(add_row)

        op_row = QHBoxLayout()
        probe_btn = QPushButton("测延迟（全部）")
        probe_btn.clicked.connect(self.on_probe_upstreams)
        del_btn = QPushButton("删除选中")
        del_btn.clicked.connect(self.on_del_upstream)
        default_btn = QPushButton("设为默认")
        default_btn.setToolTip("选中的上游将优先生效；失败时自动按列表顺序尝试其余上游")
        default_btn.clicked.connect(self.on_set_default_upstream)
        op_row.addWidget(probe_btn)
        op_row.addWidget(del_btn)
        op_row.addWidget(default_btn)
        op_row.addStretch()
        upstream_layout.addLayout(op_row)

        self.upstream_hint = QLabel("")
        self.upstream_hint.setStyleSheet("color: #8c8c8c;")
        upstream_layout.addWidget(self.upstream_hint)

        upstream_group.setLayout(upstream_layout)
        left_col.addWidget(upstream_group, 1)

        # 左列：最近被拦截
        blocked_group = QGroupBox("最近被拦截的域名")
        blocked_layout = QVBoxLayout()
        self.blocked_table = QTableWidget(0, 2)
        self.blocked_table.setHorizontalHeaderLabels(["域名", "命中规则"])
        self.blocked_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.blocked_table.verticalHeader().setVisible(False)
        self.blocked_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.blocked_table.setMinimumHeight(150)
        blocked_layout.addWidget(self.blocked_table)
        blocked_group.setLayout(blocked_layout)
        left_col.addWidget(blocked_group, 1)

        # 右列：系统 DNS 接管
        takeover_group = QGroupBox("系统 DNS 接管")
        takeover_layout = QVBoxLayout()
        tip = QLabel("勾选需要接管的网卡，程序会把它们的 DNS 指向本机。"
                     "退出或停止服务时会用备份自动恢复原 DNS。")
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #8c8c8c;")
        takeover_layout.addWidget(tip)

        self.adapter_list = QVBoxLayout()
        self.adapter_list.setSpacing(4)
        takeover_layout.addLayout(self.adapter_list)

        refresh_nic_btn = QPushButton("刷新网卡")
        refresh_nic_btn.clicked.connect(self.refresh_adapters)
        takeover_layout.addWidget(refresh_nic_btn)
        takeover_group.setLayout(takeover_layout)
        right_col.addWidget(takeover_group)

        # 右列：维护
        maint_group = QGroupBox("维护")
        maint_layout = QVBoxLayout()
        for text, slot in (
            ("清空 DNS 缓存", self.on_clear_cache),
            ("重新加载黑名单", self.on_reload_blocklist),
            ("更新订阅列表", self.on_subscribe),
            ("打开黑名单文件", self.on_open_blocklist),
            ("导出配置", self.on_export),
            ("导入配置", self.on_import),
        ):
            btn = QPushButton(text)
            btn.clicked.connect(slot)
            StyleHelper.set_button_type(btn, "default")
            maint_layout.addWidget(btn)
        maint_group.setLayout(maint_layout)
        right_col.addWidget(maint_group)

        right_col.addStretch()
        left_col.addStretch()

        self.refresh_adapters()
        self.reload_upstream_table()
        self.refresh_stats()

    # ------------------------------------------------------------------
    # 服务控制
    # ------------------------------------------------------------------
    def _listen_hosts(self):
        hosts = ["127.0.0.1", "::1"]
        if getattr(self, "config_manager", None) and self.config_manager.dns_listen_lan:
            hosts.append("0.0.0.0")
        return hosts

    def _ensure_blocklist_file(self):
        """首次使用时把出厂兜底黑名单写到用户配置目录，方便直接编辑。"""
        if os.path.exists(self.blocklist_path):
            return
        try:
            os.makedirs(os.path.dirname(self.blocklist_path), exist_ok=True)
            from core.dns_filter import DEFAULT_BLOCKLIST
            with open(self.blocklist_path, "w", encoding="utf-8") as f:
                f.write("# SkyGuard DNS 黑名单（每行一个域名，拦截该域及其全部子域）\n")
                f.write("# 支持 hosts 格式（0.0.0.0 domain）；# 开头为注释\n")
                f.write("\n".join(sorted({d.strip().rstrip('.') for d in DEFAULT_BLOCKLIST if '*' not in d and '/' not in d})) + "\n")
        except Exception as e:
            logger.warning(f"初始化 DNS 黑名单文件失败: {e}")

    def _sync_upstreams_to_filter(self):
        self.filter.set_upstreams(
            [Upstream.from_dict(u) for u in self.config_manager.dns_upstreams],
            selected=self.config_manager.dns_selected_upstream,
        )

    def _start_service(self):
        self._sync_upstreams_to_filter()
        self.filter.port = self.config_manager.dns_port
        self.filter.block_action = self.config_manager.dns_block_action
        ok = self.filter.start()
        self._update_state()
        return ok, list(self.filter.bind_errors)

    def on_start_and_takeover(self):
        ok, errors = self._start_service()
        if not ok:
            QMessageBox.critical(self, "DNS 服务", "服务启动失败：\n" + "\n".join(errors))
            return
        self.on_takeover(start_if_needed=False)

    def on_takeover(self, start_if_needed=True):
        if start_if_needed and not self.filter.running:
            ok, errors = self._start_service()
            if not ok:
                QMessageBox.critical(self, "DNS 服务", "服务启动失败：\n" + "\n".join(errors))
                return
        checked = self._checked_adapters()
        if not checked:
            QMessageBox.information(self, "系统 DNS 接管", "请先在右侧勾选要接管的网卡。")
            return
        done = []
        for idx, name in checked:
            ok, err = dns_takeover.take_over(idx)
            if ok:
                done.append(name)
        if done:
            QMessageBox.information(self, "系统 DNS 接管", "已把以下网卡的 DNS 指向本机：\n" + "、".join(done))
        else:
            QMessageBox.warning(self, "系统 DNS 接管", "没有网卡接管成功，请检查权限。")
        self._update_state()

    def on_restore_dns(self):
        def work():
            restored, err = dns_takeover.restore_all()
            self._ui(lambda: self._after_restore(restored, err))
        threading_run(work)

    def _after_restore(self, restored, err):
        if restored:
            QMessageBox.information(self, "恢复系统 DNS", "已恢复：" + "、".join(restored))
        else:
            QMessageBox.warning(self, "恢复系统 DNS", err or "没有可恢复的备份")
        self._update_state()

    def on_stop(self):
        # 先恢复 DNS 再停服务，避免系统 DNS 指向已停止的本机端口
        if dns_takeover._load_backup():
            restored, _err = dns_takeover.restore_all()
            if restored:
                logger.info(f"停止 DNS 服务前已恢复系统 DNS: {restored}")
        self.filter.stop()
        self._update_state()

    # ------------------------------------------------------------------
    # 上游管理
    # ------------------------------------------------------------------
    def reload_upstream_table(self):
        ups = self.config_manager.dns_upstreams
        self.upstream_table.setRowCount(len(ups))
        for row, u in enumerate(ups):
            norm = Upstream.from_dict(u)
            self.upstream_table.setItem(row, 0, QTableWidgetItem(u["name"]))
            self.upstream_table.setItem(row, 1, QTableWidgetItem(norm.proto))
            self.upstream_table.setItem(row, 2, QTableWidgetItem(u["address"]))
            self.upstream_table.setItem(row, 3, QTableWidgetItem("未测试"))
            self.upstream_table.setItem(row, 4, QTableWidgetItem("—"))
            if row == self.config_manager.dns_selected_upstream:
                for col in range(5):
                    self.upstream_table.item(row, col).setBackground(Qt.GlobalColor.transparent)
                    font = self.upstream_table.item(row, col).font()
                    font.setBold(True)
                    self.upstream_table.item(row, col).setFont(font)
        self._update_selected_hint()

    def on_upstream_selected(self):
        pass  # 选中状态在「设为默认」时使用

    def _update_selected_hint(self):
        ups = self.config_manager.dns_upstreams
        sel = self.config_manager.dns_selected_upstream
        if 0 <= sel < len(ups):
            self.upstream_hint.setText(f"当前选优：{ups[sel]['name']}（{ups[sel]['proto']}）")

    def on_add_upstream(self):
        name = self.new_name.text().strip()
        proto = self.new_proto.currentText()
        addr = self.new_addr.text().strip()
        if not addr:
            QMessageBox.information(self, "添加上游", "请填写地址。")
            return
        if proto == "DoH" and not addr.lower().startswith(("http://", "https://")):
            QMessageBox.information(self, "添加上游", "DoH 地址必须是完整 URL，例如 https://dns.alidns.com/dns-query")
            return
        ups = self.config_manager.dns_upstreams
        ups.append({"name": name or f"{proto}-{addr}", "proto": proto, "address": addr})
        self.config_manager.set_dns_config(upstreams=ups)
        self.new_name.clear()
        self.new_addr.clear()
        self.reload_upstream_table()

    def on_del_upstream(self):
        row = self.upstream_table.currentRow()
        ups = self.config_manager.dns_upstreams
        if row < 0 or row >= len(ups):
            return
        if len(ups) <= 1:
            QMessageBox.information(self, "删除上游", "至少保留一个上游服务器。")
            return
        ups.pop(row)
        sel = self.config_manager.dns_selected_upstream
        self.config_manager.set_dns_config(
            upstreams=ups, selected_upstream=min(sel, len(ups) - 1))
        self.reload_upstream_table()

    def on_set_default_upstream(self):
        row = self.upstream_table.currentRow()
        ups = self.config_manager.dns_upstreams
        if row < 0 or row >= len(ups):
            QMessageBox.information(self, "设为默认", "请先在表格中选中一个上游。")
            return
        self.config_manager.set_dns_config(selected_upstream=row)
        self.reload_upstream_table()
        if self.filter.running:
            self._sync_upstreams_to_filter()

    def on_probe_upstreams(self):
        if self._probing:
            return
        self._probing = True
        self.upstream_hint.setText("正在测延迟…")

        def work():
            results = {}
            ups = self.config_manager.dns_upstreams
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = {u["name"]: pool.submit(
                    Upstream(u["name"], u["proto"], u["address"]).probe) for u in ups}
                for name, fut in futures.items():
                    results[name] = fut.result()
            self._ui(lambda: self._after_probe(results))
        threading_run(work)

    def _after_probe(self, results):
        self._probing = False
        for row, u in enumerate(self.config_manager.dns_upstreams):
            ms = results.get(u["name"])
            self.upstream_table.setItem(row, 3, QTableWidgetItem("正常" if ms is not None else "失败"))
            self.upstream_table.setItem(row, 4, QTableWidgetItem(f"{ms:.0f} ms" if ms is not None else "—"))
            self.filter.stats.count_upstream(u["name"], ms is not None, ms)
        self.upstream_hint.setText("延迟测试完成")

    # ------------------------------------------------------------------
    # 网卡
    # ------------------------------------------------------------------
    def refresh_adapters(self):
        def work():
            adapters = dns_takeover.list_adapters()
            self._ui(lambda: self._fill_adapters(adapters))
        threading_run(work)

    def _fill_adapters(self, adapters):
        self._adapters = adapters
        while self.adapter_list.count():
            item = self.adapter_list.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for a in adapters:
            cb = QCheckBox(f"{a['name']}（{a['status']}）")
            cb.setToolTip(f"接口索引 {a['index']}")
            if a["status"] == "Up":
                cb.setChecked(True)
            self.adapter_list.addWidget(cb)
        if not adapters:
            self.adapter_list.addWidget(QLabel("未枚举到网卡"))

    def _checked_adapters(self):
        result = []
        for i in range(self.adapter_list.count()):
            w = self.adapter_list.itemAt(i).widget()
            if isinstance(w, QCheckBox) and w.isChecked():
                idx = int(w.toolTip().split()[-1])
                name = w.text().split("（")[0]
                result.append((idx, name))
        return result

    # ------------------------------------------------------------------
    # 维护
    # ------------------------------------------------------------------
    def on_clear_cache(self):
        with self.filter._cache_lock:
            self.filter._cache.clear()
        self.filter.stats.reset()
        QMessageBox.information(self, "维护", "DNS 缓存与统计已清空。")

    def on_reload_blocklist(self):
        self.filter.reload_blocklist()
        count = len(self.filter._suffix) + len(self.filter._exact)
        QMessageBox.information(self, "维护", f"黑名单已重新加载：{count} 条规则。")

    def on_subscribe(self):
        self.upstream_hint.setText("正在更新订阅列表…")

        def work():
            count, err = self.filter.update_subscription(BLOCKLIST_SUBSCRIBE_URL)
            self._ui(lambda: self._after_subscribe(count, err))
        threading_run(work)

    def _after_subscribe(self, count, err):
        if err:
            QMessageBox.warning(self, "更新订阅", f"更新失败：{err}")
        else:
            QMessageBox.information(self, "更新订阅", f"订阅更新完成，共 {count} 条规则。")
        self.upstream_hint.setText("")

    def on_open_blocklist(self):
        try:
            subprocess.Popen(["notepad.exe", self.blocklist_path])
        except Exception as e:
            QMessageBox.warning(self, "黑名单", f"打开失败：{e}")

    def on_export(self):
        path, _ = QFileDialog.getSaveFileName(self, "导出 DNS 配置", "dns-config.json", "JSON (*.json)")
        if not path:
            return
        import json
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.filter.export_config(), f, ensure_ascii=False, indent=2)
            QMessageBox.information(self, "导出配置", "导出完成。")
        except Exception as e:
            QMessageBox.warning(self, "导出配置", f"导出失败：{e}")

    def on_import(self):
        path, _ = QFileDialog.getOpenFileName(self, "导入 DNS 配置", "", "JSON (*.json)")
        if not path:
            return
        import json
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ups = [Upstream.from_dict(d).to_dict() for d in data.get("upstreams", [])]
            if not ups:
                raise ValueError("配置中没有上游服务器")
            self.config_manager.set_dns_config(
                upstreams=ups,
                selected_upstream=int(data.get("selected", 0)),
                port=int(data.get("port", self.config_manager.dns_port)),
                block_action=data.get("block_action", self.config_manager.dns_block_action),
            )
            self.reload_upstream_table()
            self.listen_label.setText(
                f"监听 {'、'.join(self._listen_hosts())} :: 端口 {self.config_manager.dns_port}")
            if self.filter.running:
                self.filter.port = self.config_manager.dns_port
                self.filter.block_action = self.config_manager.dns_block_action
                self._sync_upstreams_to_filter()
            QMessageBox.information(self, "导入配置", "导入完成，重启服务后端口变更生效。")
        except Exception as e:
            QMessageBox.warning(self, "导入配置", f"导入失败：{e}")

    # ------------------------------------------------------------------
    # 状态刷新
    # ------------------------------------------------------------------
    def refresh_stats(self):
        if not self.isVisible():
            return
        snap = self.filter.stats.snapshot()
        self.stat_cards["total"].setText(str(snap["total"]))
        self.stat_cards["blocked"].setText(str(snap["blocked"]))
        queries = snap["total"]
        ratio = f"{snap['cache_hits'] * 100 / queries:.0f}%" if queries else "0%"
        self.stat_cards["cache"].setText(ratio)
        sel = self.filter.get_selected_upstream()
        latency = "—"
        if sel:
            slot = self.filter.stats.upstreams.get(sel.name)
            if slot and slot["latency_ms"] is not None:
                latency = f"{slot['latency_ms']:.0f} ms"
        self.stat_cards["latency"].setText(latency)

        # 最近被拦截
        rows = snap["blocked_log"][:50]
        self.blocked_table.setRowCount(len(rows))
        for r, entry in enumerate(rows):
            self.blocked_table.setItem(r, 0, QTableWidgetItem(entry["domain"]))
            self.blocked_table.setItem(r, 1, QTableWidgetItem(f"{entry['rule']}（{entry['action']}）"))

        self._update_state()

    def _update_state(self):
        running = self.filter.running
        if running:
            self.status_pill.setText(f"● 运行中 · 端口 {self.filter.port}")
        else:
            self.status_pill.setText("● 未运行")
        self._style_pill(running)

        sel = self.filter.get_selected_upstream()
        dns_state = "未接管"
        if sel:
            backup = dns_takeover._load_backup()
            if backup:
                dns_state = "已接管 · 本机 DNS 指向 127.0.0.1 / ::1"
        lines = [
            f"<b>服务：</b>{'运行中' if running else '未运行'} · 端口 {self.filter.port}"
            + (f"（监听失败：{'; '.join(self.filter.bind_errors)}）" if running and self.filter.bind_errors else ""),
            f"<b>线路：</b>{sel.name + '（' + sel.proto + '）' if sel else '未配置上游'}",
            f"<b>系统 DNS：</b>{dns_state}",
        ]
        self.state_label.setText("<br>".join(lines))

    def _style_pill(self, running):
        color = "#52c41a" if running else "#8c8c8c"
        bg = "#f6ffed" if running else "#f5f5f5"
        self.status_pill.setStyleSheet(
            f"color: {color}; background-color: {bg}; border-radius: 4px; padding: 2px 8px; font-weight: 600;")

    def shutdown(self):
        """主窗口退出时调用：恢复系统 DNS 并停止服务。"""
        try:
            if dns_takeover._load_backup():
                dns_takeover.restore_all()
        except Exception as e:
            logger.warning(f"退出时恢复系统 DNS 失败: {e}")
        self.filter.stop()


def threading_run(func):
    """简单线程包装：所有耗时操作丢后台。"""
    import threading
    threading.Thread(target=func, daemon=True).start()
