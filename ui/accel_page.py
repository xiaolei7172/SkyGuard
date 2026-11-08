#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
网络加速页面

三件事：
  1. GitHub / Steam 优选 IP：多出口 DoH 抓取候选 IP → 实测延迟 → 写 hosts 或供代理直连使用
  2. 机场订阅 / 手动节点：解析 Clash YAML 与通用 base64 订阅
  3. 本地混合代理：HTTP + SOCKS5 同端口，按规则直连 / 加速 / 走节点 / 拦截

所有网络操作都在后台线程，通过 ui_call 信号回主线程刷新界面。
"""

import os
import threading
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton,
    QScrollArea, QSpinBox, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget, QFrame,
)

from core import ip_optimizer
from core.ip_optimizer import DOMAIN_GROUPS, IpCache
from core.local_proxy import (
    ACTION_ACCEL, ACTION_DIRECT, ACTION_PROXY, ACTION_REJECT,
    DEFAULT_RULES, MODE_DIRECT, MODE_GLOBAL, MODE_RULE, RULE_TYPES,
    LocalProxy, format_bytes,
)
from core.proxy_connectors import probe_node
from core.proxy_nodes import (
    KNOWN_UNSUPPORTED, NodeStore, fetch_subscription,
    parse_proxy_uri, parse_subscription,
)
from ui.styles import StyleHelper
from utils import system_proxy
from utils.logger import logger

MODE_LABELS = (
    ("规则模式（推荐）", MODE_RULE),
    ("全局代理", MODE_GLOBAL),
    ("全部直连", MODE_DIRECT),
)
ACTION_LABELS = (
    ("加速直连", ACTION_ACCEL),
    ("直接连接", ACTION_DIRECT),
    ("走代理节点", ACTION_PROXY),
    ("拒绝", ACTION_REJECT),
)


class AccelPage(QWidget):
    """网络加速标签页"""

    status_changed = Signal(bool)
    ui_call = Signal(object)

    def __init__(self, config_manager, parent=None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.node_store = NodeStore()
        self.ip_cache = IpCache()
        self.selected_uid = config_manager.proxy_selected_node
        self._optimizing = False
        self._testing_nodes = False
        self._last_proxy_error = ""

        self.proxy = LocalProxy(
            host=config_manager.proxy_host,
            port=config_manager.proxy_port,
            rules=self._rules_for_engine(),
            mode=config_manager.proxy_mode,
            node_provider=self._current_node,
            accel_ip_provider=self.ip_cache.best_for_suffix,
        )
        self.proxy.stats.reset()

        self.ui_call.connect(lambda f: f())
        self.setup_ui()

        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self.refresh_stats)
        self.stats_timer.start(1500)

        if config_manager.proxy_enabled:
            QTimer.singleShot(1800, self.on_start_proxy)

    # ------------------------------------------------------------------
    # 公共工具
    # ------------------------------------------------------------------
    def _ui(self, func):
        self.ui_call.emit(func)

    def _run(self, func, on_done=None, on_error=None):
        """后台执行，结果回主线程。"""
        def worker():
            try:
                result = func()
            except Exception as e:  # 网络异常不弹堆栈，交给界面提示
                logger.warning(f"加速页后台任务失败: {e}")
                if on_error:
                    self._ui(lambda: on_error(e))
                return
            if on_done:
                self._ui(lambda: on_done(result))

        threading.Thread(target=worker, daemon=True).start()

    def _rules_for_engine(self):
        rules = self.config_manager.proxy_rules
        return rules if rules else DEFAULT_RULES

    def _current_node(self):
        if not self.selected_uid:
            return None
        node = self.node_store.find(self.selected_uid)
        if node is None or not node.supported:
            return None
        return node

    # ------------------------------------------------------------------
    # UI
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

        layout.addWidget(self._build_control_group())
        layout.addLayout(self._build_stats_row())
        layout.addLayout(self._build_body())
        layout.addStretch()

        self.refresh_node_table()
        self.refresh_rule_table()
        self.refresh_ip_table()
        self.refresh_stats()
        self.refresh_status()

    # -- 服务控制 ----------------------------------------------------
    def _build_control_group(self):
        group = QGroupBox("代理服务")
        box = QVBoxLayout()

        row = QHBoxLayout()
        row.setSpacing(8)
        self.status_pill = QLabel("● 未运行")
        self.status_pill.setObjectName("dnsStatusPill")
        self._style_pill(False)
        row.addWidget(self.status_pill)

        self.listen_host = QComboBox()
        self.listen_host.addItems(["127.0.0.1", "0.0.0.0"])
        self.listen_host.setCurrentText(self.config_manager.proxy_host)
        self.listen_host.setToolTip("0.0.0.0 表示允许局域网其他设备使用本机代理")
        row.addWidget(self.listen_host)

        self.listen_port = QSpinBox()
        self.listen_port.setRange(1, 65535)
        self.listen_port.setValue(self.config_manager.proxy_port)
        row.addWidget(self.listen_port)

        self.mode_combo = QComboBox()
        for label, value in MODE_LABELS:
            self.mode_combo.addItem(label, value)
        self.mode_combo.setCurrentIndex(
            max(0, [v for _, v in MODE_LABELS].index(self.config_manager.proxy_mode)))
        self.mode_combo.currentIndexChanged.connect(self.on_mode_changed)
        row.addWidget(self.mode_combo)

        row.addStretch()

        self.start_btn = QPushButton("启动代理")
        self.start_btn.clicked.connect(self.on_start_proxy)
        row.addWidget(self.start_btn)

        self.stop_btn = QPushButton("停止代理")
        self.stop_btn.clicked.connect(self.on_stop_proxy)
        StyleHelper.set_button_type(self.stop_btn, "danger")
        row.addWidget(self.stop_btn)

        box.addLayout(row)

        row2 = QHBoxLayout()
        self.sysproxy_check = QCheckBox("启动代理时自动接管系统代理")
        self.sysproxy_check.setChecked(self.config_manager.proxy_set_system_proxy)
        self.sysproxy_check.stateChanged.connect(self.on_sysproxy_pref_changed)
        row2.addWidget(self.sysproxy_check)

        self.sysproxy_btn = QPushButton("设为系统代理")
        self.sysproxy_btn.clicked.connect(self.on_toggle_system_proxy)
        StyleHelper.set_button_type(self.sysproxy_btn, "default")
        row2.addWidget(self.sysproxy_btn)
        row2.addStretch()

        self.status_detail = QLabel("")
        self.status_detail.setStyleSheet("color: #8c8c8c;")
        row2.addWidget(self.status_detail)
        box.addLayout(row2)

        group.setLayout(box)
        return group

    def _build_stats_row(self):
        row = QHBoxLayout()
        row.setSpacing(10)
        self.stat_cards = {}
        for key, title in (("total", "累计连接"), ("proxied", "走节点"),
                           ("accel", "加速直连"), ("traffic", "本次流量")):
            card = QGroupBox(title)
            card_layout = QVBoxLayout()
            value = QLabel("0")
            value.setStyleSheet("font-size: 20px; font-weight: 600;")
            card_layout.addWidget(value)
            self.stat_cards[key] = value
            card.setLayout(card_layout)
            row.addWidget(card, 1)
        return row

    def _build_body(self):
        body = QHBoxLayout()
        body.setSpacing(10)

        left = QVBoxLayout()
        left.setSpacing(10)
        right = QVBoxLayout()
        right.setSpacing(10)
        body.addLayout(left, 3)
        body.addLayout(right, 2)

        left.addWidget(self._build_subscription_group())
        left.addWidget(self._build_accel_group())
        right.addWidget(self._build_rules_group())
        right.addWidget(self._build_conn_group())
        right.addStretch()
        return body

    # -- 机场 / 节点 -------------------------------------------------
    def _build_subscription_group(self):
        group = QGroupBox("机场订阅 / 节点")
        box = QVBoxLayout()

        row = QHBoxLayout()
        self.sub_url = QLineEdit()
        self.sub_url.setPlaceholderText("订阅地址（Clash YAML 或 base64 通用订阅），也可填本地文件路径")
        row.addWidget(self.sub_url, 3)
        self.sub_name = QLineEdit()
        self.sub_name.setPlaceholderText("备注名（可空）")
        self.sub_name.setMaximumWidth(140)
        row.addWidget(self.sub_name, 1)
        add_btn = QPushButton("添加 / 更新")
        add_btn.clicked.connect(self.on_add_subscription)
        row.addWidget(add_btn)
        box.addLayout(row)

        row2 = QHBoxLayout()
        self.manual_uri = QLineEdit()
        self.manual_uri.setPlaceholderText("手动添加：ss:// / trojan:// / socks5:// / http:// 链接")
        row2.addWidget(self.manual_uri, 3)
        manual_btn = QPushButton("添加节点")
        manual_btn.clicked.connect(self.on_add_manual_node)
        StyleHelper.set_button_type(manual_btn, "default")
        row2.addWidget(manual_btn)
        import_btn = QPushButton("导入文件")
        import_btn.clicked.connect(self.on_import_file)
        StyleHelper.set_button_type(import_btn, "default")
        row2.addWidget(import_btn)
        box.addLayout(row2)

        self.node_table = QTableWidget(0, 5)
        self.node_table.setHorizontalHeaderLabels(["名称", "协议", "服务器", "延迟", "来源"])
        self.node_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.node_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.node_table.verticalHeader().setVisible(False)
        self.node_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.node_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.node_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.node_table.setMinimumHeight(170)
        self.node_table.doubleClicked.connect(lambda _i: self.on_use_node())
        box.addWidget(self.node_table)

        row3 = QHBoxLayout()
        test_btn = QPushButton("测速全部")
        test_btn.clicked.connect(self.on_test_nodes)
        StyleHelper.set_button_type(test_btn, "default")
        row3.addWidget(test_btn)
        use_btn = QPushButton("使用选中节点")
        use_btn.clicked.connect(self.on_use_node)
        row3.addWidget(use_btn)
        del_btn = QPushButton("删除选中")
        del_btn.clicked.connect(self.on_delete_node)
        StyleHelper.set_button_type(del_btn, "default")
        row3.addWidget(del_btn)
        row3.addStretch()
        self.sub_hint = QLabel("还没有节点，先添加订阅或手动填一条链接")
        self.sub_hint.setStyleSheet("color: #8c8c8c;")
        row3.addWidget(self.sub_hint)
        box.addLayout(row3)

        group.setLayout(box)
        return group

    # -- 优选 IP -----------------------------------------------------
    def _build_accel_group(self):
        group = QGroupBox("GitHub / Steam 优选 IP")
        box = QVBoxLayout()

        row = QHBoxLayout()
        self.gh_check = QCheckBox("GitHub")
        self.gh_check.setChecked(self.config_manager.proxy_accel_groups.get("github", True))
        self.steam_check = QCheckBox("Steam")
        self.steam_check.setChecked(self.config_manager.proxy_accel_groups.get("steam", True))
        row.addWidget(self.gh_check)
        row.addWidget(self.steam_check)

        self.extra_domains = QLineEdit()
        self.extra_domains.setPlaceholderText("额外域名，逗号分隔（可空）")
        self.extra_domains.setText(", ".join(self.config_manager.proxy_extra_domains))
        row.addWidget(self.extra_domains, 3)

        self.optimize_btn = QPushButton("测速优选")
        self.optimize_btn.clicked.connect(self.on_optimize)
        row.addWidget(self.optimize_btn)
        box.addLayout(row)

        self.ip_table = QTableWidget(0, 4)
        self.ip_table.setHorizontalHeaderLabels(["域名", "优选 IP", "延迟", "来源"])
        self.ip_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.ip_table.verticalHeader().setVisible(False)
        self.ip_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.ip_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.ip_table.setMinimumHeight(190)
        box.addWidget(self.ip_table)

        row3 = QHBoxLayout()
        write_btn = QPushButton("写入 hosts")
        write_btn.setToolTip("需要管理员权限；只写 SkyGuard 自己的段落，可随时还原")
        write_btn.clicked.connect(self.on_write_hosts)
        row3.addWidget(write_btn)
        restore_btn = QPushButton("还原 hosts")
        restore_btn.clicked.connect(self.on_restore_hosts)
        StyleHelper.set_button_type(restore_btn, "default")
        row3.addWidget(restore_btn)
        clear_btn = QPushButton("清空记录")
        clear_btn.clicked.connect(self.on_clear_ip_cache)
        StyleHelper.set_button_type(clear_btn, "default")
        row3.addWidget(clear_btn)
        row3.addStretch()
        self.accel_hint = QLabel("")
        self.accel_hint.setStyleSheet("color: #8c8c8c;")
        row3.addWidget(self.accel_hint)
        box.addLayout(row3)

        group.setLayout(box)
        return group

    # -- 规则 --------------------------------------------------------
    def _build_rules_group(self):
        group = QGroupBox("分流规则")
        box = QVBoxLayout()

        tip = QLabel("规则从上到下匹配，命中即停。final 必须放最后。")
        tip.setStyleSheet("color: #8c8c8c;")
        tip.setWordWrap(True)
        box.addWidget(tip)

        self.rule_table = QTableWidget(0, 3)
        self.rule_table.setHorizontalHeaderLabels(["类型", "匹配值", "动作"])
        self.rule_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.rule_table.verticalHeader().setVisible(False)
        self.rule_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.rule_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rule_table.setMinimumHeight(210)
        box.addWidget(self.rule_table)

        row = QHBoxLayout()
        self.rule_type = QComboBox()
        for rtype in RULE_TYPES:
            self.rule_type.addItem(rtype)
        self.rule_type.setToolTip("domain-suffix：域名后缀；ip-cidr：IP 段；final：兜底")
        row.addWidget(self.rule_type, 1)
        self.rule_value = QLineEdit()
        self.rule_value.setPlaceholderText("匹配值，如 github.com")
        row.addWidget(self.rule_value, 2)
        self.rule_action = QComboBox()
        for label, value in ACTION_LABELS:
            self.rule_action.addItem(label, value)
        row.addWidget(self.rule_action, 1)
        add_btn = QPushButton("添加")
        add_btn.clicked.connect(self.on_add_rule)
        row.addWidget(add_btn)
        box.addLayout(row)

        row2 = QHBoxLayout()
        del_btn = QPushButton("删除选中")
        del_btn.clicked.connect(self.on_delete_rule)
        StyleHelper.set_button_type(del_btn, "default")
        row2.addWidget(del_btn)
        reset_btn = QPushButton("恢复默认")
        reset_btn.clicked.connect(self.on_reset_rules)
        StyleHelper.set_button_type(reset_btn, "default")
        row2.addWidget(reset_btn)
        row2.addStretch()
        box.addLayout(row2)

        group.setLayout(box)
        return group

    # -- 连接监控 ----------------------------------------------------
    def _build_conn_group(self):
        group = QGroupBox("最近连接")
        box = QVBoxLayout()

        self.conn_table = QTableWidget(0, 5)
        self.conn_table.setHorizontalHeaderLabels(["时间", "目标", "动作", "规则", "流量"])
        self.conn_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.conn_table.verticalHeader().setVisible(False)
        self.conn_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.conn_table.setMinimumHeight(230)
        box.addWidget(self.conn_table)

        row = QHBoxLayout()
        clear_btn = QPushButton("清空列表")
        clear_btn.clicked.connect(self.on_clear_logs)
        StyleHelper.set_button_type(clear_btn, "default")
        row.addWidget(clear_btn)
        row.addStretch()
        self.conn_hint = QLabel("")
        self.conn_hint.setStyleSheet("color: #8c8c8c;")
        row.addWidget(self.conn_hint)
        box.addLayout(row)

        group.setLayout(box)
        return group

    def _style_pill(self, running):
        color = "#52c41a" if running else "#bfbfbf"
        self.status_pill.setStyleSheet(
            f"color: {color}; font-weight: 600; padding: 2px 8px; border-radius: 9px;")
        self.status_pill.setText("● 运行中" if running else "● 未运行")

    # ------------------------------------------------------------------
    # 服务启停
    # ------------------------------------------------------------------
    def on_mode_changed(self):
        mode = self.mode_combo.currentData()
        self.proxy.set_mode(mode)
        self.config_manager.set_proxy_config(mode=mode)
        self.refresh_status()

    def on_sysproxy_pref_changed(self):
        self.config_manager.set_proxy_config(
            set_system_proxy=self.sysproxy_check.isChecked())

    def on_start_proxy(self):
        port = self.listen_port.value()
        host = self.listen_host.currentText()
        self.proxy.host = host
        self.proxy.port = port
        self.proxy.set_mode(self.mode_combo.currentData())
        self.proxy.set_rules(self._rules_for_engine())
        ok = self.proxy.start()
        if not ok:
            QMessageBox.critical(self, "代理服务", "启动失败：\n" + "\n".join(self.proxy.bind_errors or
                                                                        ["端口被占用，换个端口试试"]))
            self._style_pill(False)
            return

        self.config_manager.set_proxy_config(enabled=True, host=host, port=port,
                                             mode=self.mode_combo.currentData())
        self._style_pill(True)
        self.status_changed.emit(True)

        if self.sysproxy_check.isChecked():
            ok2, msg = system_proxy.set_proxy(f"127.0.0.1:{port}")
            self.conn_hint.setText(msg)
            if not ok2:
                QMessageBox.warning(self, "系统代理", msg)
        self.refresh_status()

    def on_stop_proxy(self):
        port = self.proxy.port
        was_system = system_proxy.is_pointing_to(port)
        self.proxy.stop()
        self._style_pill(False)
        self.config_manager.set_proxy_config(enabled=False)
        self.status_changed.emit(False)
        if was_system:
            ok, msg = system_proxy.clear_proxy()
            self.conn_hint.setText(msg)
        self.refresh_status()

    def on_toggle_system_proxy(self):
        port = self.proxy.port
        if system_proxy.is_pointing_to(port):
            ok, msg = system_proxy.clear_proxy()
        else:
            if not self.proxy.running:
                QMessageBox.information(self, "系统代理", "请先启动本地代理，再设置系统代理。")
                return
            ok, msg = system_proxy.set_proxy(f"127.0.0.1:{port}")
        self.conn_hint.setText(msg)
        if not ok:
            QMessageBox.warning(self, "系统代理", msg)
        self.refresh_status()

    def refresh_status(self):
        info = system_proxy.current()
        proxy_state = (f"系统代理：{info['server']}" if info["enabled"]
                       else "系统代理：未启用")
        node = self._current_node()
        node_state = f"节点：{node.name}" if node else "节点：未选择（加速规则仍可用）"
        self.status_detail.setText(f"{node_state}    |    {proxy_state}")
        self.sysproxy_btn.setText("取消系统代理" if system_proxy.is_pointing_to(self.proxy.port)
                                  else "设为系统代理")

    def refresh_stats(self):
        snap = self.proxy.stats.snapshot()
        self.stat_cards["total"].setText(str(snap["total"]))
        self.stat_cards["proxied"].setText(str(snap["proxied"]))
        self.stat_cards["accel"].setText(str(snap["accel"]))
        traffic = f"↑{format_bytes(snap['up'])}  ↓{format_bytes(snap['down'])}"
        self.stat_cards["traffic"].setText(traffic)

        rows = snap["recent"]
        self.conn_table.setRowCount(len(rows))
        for r, item in enumerate(rows):
            target = f"{item['host']}:{item['port']}"
            if item["node"]:
                target += f"  ({item['node']})"
            traffic_text = f"{format_bytes(item['up'])} / {format_bytes(item['down'])}"
            values = [item["time"], target, item["action"], item["rule"], traffic_text]
            for c, text in enumerate(values):
                cell = QTableWidgetItem(str(text))
                if c in (0, 2, 4):
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if item["result"] not in ("完成", "连接中"):
                    cell.setToolTip(item["result"])
                self.conn_table.setItem(r, c, cell)

    def on_clear_logs(self):
        self.proxy.stats.reset()
        self.refresh_stats()

    # ------------------------------------------------------------------
    # 节点
    # ------------------------------------------------------------------
    def refresh_node_table(self, latencies=None):
        latencies = latencies or {}
        nodes = self.node_store.all_nodes()
        self.node_table.setRowCount(len(nodes))
        for r, node in enumerate(nodes):
            ms = latencies.get(node.uid)
            values = [
                ("★ " if node.uid == self.selected_uid else "") + node.name,
                node.type.upper(),
                node.server_label,
                f"{ms} ms" if ms else "—",
                node.subscription or "手动",
            ]
            for c, text in enumerate(values):
                cell = QTableWidgetItem(text)
                if c in (1, 3, 4):
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if c == 0:
                    cell.setToolTip(node.uid)
                self.node_table.setItem(r, c, cell)

        total = len(nodes)
        subs = len(self.node_store.subscriptions)
        self.sub_hint.setText(f"{subs} 个订阅 · 共 {total} 个可用节点"
                              if total else "还没有节点，先添加订阅或手动填一条链接")
        self.refresh_status()

    def on_add_subscription(self):
        url = self.sub_url.text().strip()
        if not url:
            QMessageBox.information(self, "订阅", "请先填写订阅地址。")
            return
        name = self.sub_name.text().strip()
        self.sub_hint.setText("正在拉取订阅…")

        def work():
            text = fetch_subscription(url)
            nodes, skipped = parse_subscription(text, name or url)
            return nodes, skipped

        def done(result):
            nodes, skipped = result
            if not nodes:
                detail = "、".join(f"{k}×{v}" for k, v in skipped.items())
                tip = f"没有可用的节点（{detail}）" if detail else "订阅里没有识别到节点"
                extra = "；".join(f"{k} 暂不支持（{KNOWN_UNSUPPORTED.get(k, '')}）"
                                 for k in skipped)
                QMessageBox.warning(self, "订阅", tip + ("\n" + extra if extra else ""))
                self.sub_hint.setText("订阅解析失败")
                return
            self.node_store.upsert_subscription(name or url, url, nodes)
            self.refresh_node_table()
            msg = f"已导入 {len(nodes)} 个节点"
            if skipped:
                msg += "，跳过：" + "、".join(f"{k}×{v}" for k, v in skipped.items())
            self.sub_hint.setText(msg)
            self.sub_url.clear()
            self.sub_name.clear()

        self._run(work, done, lambda e: self.sub_hint.setText(f"拉取失败：{e}"))

    def on_add_manual_node(self):
        uri = self.manual_uri.text().strip()
        if not uri:
            return
        node = parse_proxy_uri(uri)
        if not node or not node.supported:
            scheme = uri.split("://", 1)[0].lower() if "://" in uri else ""
            tip = KNOWN_UNSUPPORTED.get(scheme)
            QMessageBox.warning(self, "添加节点",
                                f"无法识别的链接{f'（{tip}）' if tip else ''}。\n"
                                "支持 ss:// / trojan:// / socks5:// / http://")
            return
        if not self.node_store.add_manual(node):
            QMessageBox.information(self, "添加节点", "该节点已存在。")
            return
        self.manual_uri.clear()
        self.refresh_node_table()
        self.sub_hint.setText(f"已添加节点 {node.name}")

    def on_import_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "导入订阅文件", "", "订阅文件 (*.yaml *.yml *.txt *.json);;所有文件 (*)")
        if not path:
            return
        self.sub_url.setText(path)
        self.sub_name.setText(os.path.basename(path))
        self.on_add_subscription()

    def on_test_nodes(self):
        if self._testing_nodes:
            return
        nodes = self.node_store.all_nodes()
        if not nodes:
            QMessageBox.information(self, "测速", "还没有节点。")
            return
        self._testing_nodes = True
        self.sub_hint.setText(f"正在测速 {len(nodes)} 个节点…")

        def work():
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda n: (n.uid, probe_node(n)), nodes))
            return {uid: ms for uid, ms in results if ms}

        def done(latencies):
            self._testing_nodes = False
            self.refresh_node_table(latencies)
            good = len(latencies)
            self.sub_hint.setText(f"测速完成：{good}/{len(nodes)} 个节点可用")

        def failed(err):
            self._testing_nodes = False
            self.sub_hint.setText(f"测速失败：{err}")

        self._run(work, done, failed)

    def on_use_node(self):
        row = self.node_table.currentRow()
        nodes = self.node_store.all_nodes()
        if row < 0 or row >= len(nodes):
            return
        node = nodes[row]
        self.selected_uid = node.uid
        self.config_manager.set_proxy_config(selected_node=node.uid)
        self.refresh_node_table()
        self.sub_hint.setText(f"当前节点：{node.name}")
        self.refresh_status()

    def on_delete_node(self):
        row = self.node_table.currentRow()
        nodes = self.node_store.all_nodes()
        if row < 0 or row >= len(nodes):
            return
        node = nodes[row]
        if node.subscription and node.subscription != "手动添加":
            QMessageBox.information(self, "删除节点",
                                    "订阅节点不能单独删除，请更新或移除对应订阅。")
            return
        self.node_store.remove_node(node.uid)
        if self.selected_uid == node.uid:
            self.selected_uid = ""
            self.config_manager.set_proxy_config(selected_node="")
        self.refresh_node_table()

    # ------------------------------------------------------------------
    # 优选 IP
    # ------------------------------------------------------------------
    def _target_domains(self):
        domains = []
        if self.gh_check.isChecked():
            domains += DOMAIN_GROUPS["github"][1]
        if self.steam_check.isChecked():
            domains += DOMAIN_GROUPS["steam"][1]
        for extra in self.extra_domains.text().replace("，", ",").split(","):
            extra = extra.strip()
            if extra:
                domains.append(extra)
        # 去重保序
        seen = set()
        unique = []
        for d in domains:
            if d not in seen:
                seen.add(d)
                unique.append(d)
        return unique

    def on_optimize(self):
        if self._optimizing:
            return
        domains = self._target_domains()
        if not domains:
            QMessageBox.information(self, "优选 IP", "请至少勾选一组目标或填写额外域名。")
            return
        self._optimizing = True
        self.optimize_btn.setEnabled(False)
        self.accel_hint.setText(f"正在测速 0/{len(domains)}…")

        def progress(done, total, domain):
            self._ui(lambda: self.accel_hint.setText(f"正在测速 {done}/{total}… {domain}"))

        def work():
            return ip_optimizer.optimize_domains(
                domains, top_n=self.config_manager.proxy_top_n, progress=progress)

        def done(results):
            self._optimizing = False
            self.optimize_btn.setEnabled(True)
            self.ip_cache.update(results)
            self.refresh_ip_table()
            usable = sum(1 for r in results if r["ips"])
            self.accel_hint.setText(f"完成：{usable}/{len(results)} 个域名拿到可用 IP")
            self._save_accel_prefs()

        def failed(e):
            self._optimizing = False
            self.optimize_btn.setEnabled(True)
            self.accel_hint.setText(f"测速失败：{e}")

        self._run(work, done, failed)

    def _save_accel_prefs(self):
        self.config_manager.set_proxy_config(
            accel_groups={"github": self.gh_check.isChecked(),
                          "steam": self.steam_check.isChecked()},
            extra_domains=[d.strip() for d in
                           self.extra_domains.text().replace("，", ",").split(",") if d.strip()],
        )

    def refresh_ip_table(self):
        pairs = self.ip_cache.as_hosts_pairs()
        self.ip_table.setRowCount(len(pairs))
        for r, (domain, ip) in enumerate(pairs):
            item = self.ip_cache.data.get(domain, {})
            entries = item.get("ips") or []
            best = entries[0] if entries else {}
            values = [domain, ip, f"{best.get('ms', 0)} ms" if best.get("ms") else "—",
                      best.get("source", "")]
            for c, text in enumerate(values):
                cell = QTableWidgetItem(str(text))
                if c in (2, 3):
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.ip_table.setItem(r, c, cell)
        if pairs:
            self.accel_hint.setText(f"已缓存 {len(pairs)} 个域名的优选 IP")

    def on_write_hosts(self):
        ok, msg, count = ip_optimizer.write_hosts(self.ip_cache.as_hosts_pairs())
        (QMessageBox.information if ok else QMessageBox.warning)(self, "写入 hosts", msg)
        self.accel_hint.setText(msg.splitlines()[0])

    def on_restore_hosts(self):
        ok, msg = ip_optimizer.restore_hosts()
        (QMessageBox.information if ok else QMessageBox.warning)(self, "还原 hosts", msg)
        self.accel_hint.setText(msg)

    def on_clear_ip_cache(self):
        if QMessageBox.question(self, "清空记录", "确定要清空优选 IP 缓存吗？") \
                != QMessageBox.StandardButton.Yes:
            return
        self.ip_cache.data.clear()
        self.ip_cache.save()
        self.refresh_ip_table()
        self.accel_hint.setText("已清空优选 IP 缓存")

    # ------------------------------------------------------------------
    # 规则
    # ------------------------------------------------------------------
    def refresh_rule_table(self):
        rules = self._rules_for_engine()
        self.rule_table.setRowCount(len(rules))
        for r, rule in enumerate(rules):
            values = [rule.get("type", ""), rule.get("value", "") or "（兜底）",
                      rule.get("action", "")]
            for c, text in enumerate(values):
                cell = QTableWidgetItem(str(text))
                if c != 1:
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.rule_table.setItem(r, c, cell)

    def _save_rules_from_table(self):
        rules = []
        for r in range(self.rule_table.rowCount()):
            rtype = self.rule_table.item(r, 0).text() if self.rule_table.item(r, 0) else ""
            value = self.rule_table.item(r, 1).text() if self.rule_table.item(r, 1) else ""
            action = self.rule_table.item(r, 2).text() if self.rule_table.item(r, 2) else ""
            if value == "（兜底）":
                value = ""
            rules.append({"type": rtype, "value": value, "action": action})
        self.config_manager.set_proxy_config(rules=rules)
        self.proxy.set_rules(rules)

    def on_add_rule(self):
        rtype = self.rule_type.currentText()
        value = self.rule_value.text().strip()
        action = self.rule_action.currentData()
        if rtype != "final" and not value:
            return
        rows = self.rule_table.rowCount()
        # final 永远放最后
        insert_at = rows
        for r in range(rows):
            item = self.rule_table.item(r, 0)
            if item and item.text() == "final":
                insert_at = r
                break
        self.rule_table.insertRow(insert_at)
        for c, text in enumerate([rtype, value or "（兜底）", action]):
            cell = QTableWidgetItem(text)
            if c != 1:
                cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.rule_table.setItem(insert_at, c, cell)
        self.rule_value.clear()
        self._save_rules_from_table()

    def on_delete_rule(self):
        row = self.rule_table.currentRow()
        if row < 0:
            return
        if self.rule_table.item(row, 0) and self.rule_table.item(row, 0).text() == "final":
            QMessageBox.information(self, "规则", "final 兜底规则不能删除。")
            return
        self.rule_table.removeRow(row)
        self._save_rules_from_table()

    def on_reset_rules(self):
        self.config_manager.set_proxy_config(rules=[])
        self.proxy.set_rules(DEFAULT_RULES)
        self.refresh_rule_table()

    # ------------------------------------------------------------------
    # 退出
    # ------------------------------------------------------------------
    def shutdown(self):
        """程序退出：停服务并还原系统代理，避免把用户的网络留在半截状态。"""
        try:
            port = self.proxy.port
            was_system = system_proxy.is_pointing_to(port)
            if self.proxy.running:
                self.proxy.stop()
            if was_system:
                system_proxy.clear_proxy()
        except Exception as e:
            logger.warning(f"退出时清理代理失败: {e}")
