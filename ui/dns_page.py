#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""DNS 过滤器页面（借鉴 AdGuard Home 的能力组织）

- 服务控制：启动 / 接管 / 恢复 / 停止
- 上游服务器：UDP / DoH / DoT，支持顺序优先与并行最快两种策略
- 查询日志：客户端 / 类型 / 结果 / 上游 / 耗时，可筛选、搜索、暂停
- 统计：Top 客户端、Top 查询、Top 被拦截、查询类型分布
- 过滤器：多份订阅列表 + 自定义规则（AdGuard 语法，支持 @@ 例外）
- DNS 重写：域名直出指定 IP

所有耗时操作（查询测试、延迟探测、列表更新、接管恢复）都放线程，
通过信号回主线程更新界面。
"""

import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFrame, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea,
    QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from core import dns_lists
from core.dns_filter import (
    DnsFilter, QTYPE_A, SUPPORTED_PROTOCOLS, Upstream, build_query,
)
from core.selfcheck import check_dns
from ui.selfcheck_dialog import show_results
from ui.styles import StyleHelper
from utils import dns_takeover
from utils.logger import logger
from utils.privilege import ensure_admin

BLOCKLIST_SUBSCRIBE_URL = "https://anti-ad.net/hosts"

RESULT_FILTERS = (
    ("全部", "all"),
    ("已拦截", "blocked"),
    ("上游拦截", "upstream_blocked"),
    ("放行", "allow"),
    ("缓存命中", "cached"),
    ("重写", "rewrite"),
    ("失败", "fail"),
)


def _blocklist_path():
    return os.path.join(os.path.expanduser("~"), ".skyguard", "dns-blocklist.txt")


def _fmt_ts(ts):
    if not ts:
        return "从未更新"
    import time
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(ts)))


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
        self.filter.upstream_strategy = config_manager.dns_strategy
        self.filter.cache_min_ttl = config_manager.dns_cache_min_ttl
        self.filter.cache_max_ttl = config_manager.dns_cache_max_ttl
        self.filter.stats.query_log.paused = not config_manager.dns_log_enabled
        self.filter.set_rewrites(config_manager.dns_rewrites)

        self._adapters = []
        self._probing = False
        self._updating_lists = False
        self.ui_call.connect(lambda f: f())
        self.setup_ui()
        self._rebuild_filter_rules()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_stats)
        self.refresh_timer.start(2000)

    def _ui(self, func):
        """线程安全地把界面更新投递回主线程。"""
        self.ui_call.emit(func)

    def on_tab_changed(self, index):
        """切到日志页时立即刷新一次，不等 2 秒轮询。"""
        if index == 1:
            self.refresh_log(force=True)

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

        # --- 顶部状态条（两行布局，避免一行塞满撑出横向滚动） ---
        top_group = QGroupBox("服务控制")
        top_box = QVBoxLayout()
        top_box.setSpacing(8)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        self.status_pill = QLabel("● 未运行")
        self.status_pill.setObjectName("dnsStatusPill")
        self._style_pill(False)
        top_row.addWidget(self.status_pill)

        self.listen_label = QLabel(
            f"监听 {'、'.join(self._listen_hosts())} :: 端口 {self.config_manager.dns_port}")
        self.listen_label.setStyleSheet("color: #8c8c8c;")
        self.listen_label.setWordWrap(True)
        top_row.addWidget(self.listen_label, 1)

        top_box.addLayout(top_row)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self.restore_btn = QPushButton("恢复系统 DNS")
        self.restore_btn.clicked.connect(self.on_restore_dns)
        StyleHelper.set_button_type(self.restore_btn, "default")
        btn_row.addWidget(self.restore_btn)

        self.takeover_btn = QPushButton("接管系统 DNS")
        self.takeover_btn.clicked.connect(self.on_takeover)
        StyleHelper.set_button_type(self.takeover_btn, "default")
        btn_row.addWidget(self.takeover_btn)

        self.start_takeover_btn = QPushButton("启动并接管 DNS")
        self.start_takeover_btn.clicked.connect(self.on_start_and_takeover)
        btn_row.addWidget(self.start_takeover_btn)

        self.selfcheck_btn = QPushButton("自检")
        self.selfcheck_btn.setToolTip("实测 DNS 服务：监听、上游解析、拦截、重写、缓存、日志"
                                      "（用临时端口，不影响当前服务）")
        self.selfcheck_btn.clicked.connect(self.on_selfcheck)
        StyleHelper.set_button_type(self.selfcheck_btn, "default")
        btn_row.addWidget(self.selfcheck_btn)

        self.stop_btn = QPushButton("停止服务")
        self.stop_btn.setToolTip("停止本地 DNS 服务，并自动恢复系统 DNS")
        self.stop_btn.clicked.connect(self.on_stop)
        StyleHelper.set_button_type(self.stop_btn, "danger")
        btn_row.addWidget(self.stop_btn)
        btn_row.addStretch()

        top_box.addLayout(btn_row)
        top_group.setLayout(top_box)
        layout.addWidget(top_group)

        # --- 内嵌页签（对齐 AdGuard Home 的功能分区） ---
        self.tabs = QTabWidget()
        self.service_tab = self._build_service_tab()
        self.log_tab = self._build_log_tab()
        self.filter_tab = self._build_filter_tab()
        self.tabs.addTab(self.service_tab, "  服务  ")
        self.tabs.addTab(self.log_tab, "  查询日志  ")
        self.tabs.addTab(self.filter_tab, "  过滤器与重写  ")
        self.tabs.currentChanged.connect(self.on_tab_changed)
        layout.addWidget(self.tabs)

        self.refresh_adapters()
        self.reload_upstream_table()
        self.reload_list_table()
        self.reload_rewrite_table()
        self.refresh_stats()

    # ---------------- 服务页 ----------------
    def _build_service_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(10)

        # 统计卡片行
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

        body = QHBoxLayout()
        body.setSpacing(10)
        layout.addLayout(body)
        left_col = QVBoxLayout()
        left_col.setSpacing(10)
        right_col = QVBoxLayout()
        right_col.setSpacing(10)
        body.addLayout(left_col, 3)
        body.addLayout(right_col, 2)

        # 当前状态
        state_group = QGroupBox("当前状态")
        state_layout = QVBoxLayout()
        self.state_label = QLabel("服务：未运行")
        self.state_label.setWordWrap(True)
        self.state_label.setTextFormat(Qt.TextFormat.RichText)
        state_layout.addWidget(self.state_label)
        state_group.setLayout(state_layout)
        left_col.addWidget(state_group)

        # 上游服务器
        upstream_group = QGroupBox("上游服务器")
        upstream_layout = QVBoxLayout()

        opt_row = QHBoxLayout()
        opt_row.addWidget(QLabel("策略"))
        self.strategy_combo = QComboBox()
        self.strategy_combo.addItem("顺序优先（失败再换下一个）", "sequential")
        self.strategy_combo.addItem("并行最快（同时问，先回先用）", "parallel")
        self.strategy_combo.setCurrentIndex(
            1 if self.config_manager.dns_strategy == "parallel" else 0)
        self.strategy_combo.currentIndexChanged.connect(self.on_strategy_changed)
        opt_row.addWidget(self.strategy_combo, 1)

        opt_row.addWidget(QLabel("缓存 TTL"))
        self.min_ttl = QSpinBox()
        self.min_ttl.setRange(0, 86400)
        self.min_ttl.setValue(self.config_manager.dns_cache_min_ttl)
        self.min_ttl.setSuffix(" 秒起")
        self.min_ttl.setToolTip("上游返回的 TTL 小于此值时按此值缓存")
        self.min_ttl.valueChanged.connect(self.on_ttl_changed)
        opt_row.addWidget(self.min_ttl)

        self.max_ttl = QSpinBox()
        self.max_ttl.setRange(10, 604800)
        self.max_ttl.setValue(self.config_manager.dns_cache_max_ttl)
        self.max_ttl.setSuffix(" 秒封顶")
        self.max_ttl.setToolTip("上游返回的 TTL 大于此值时按此值缓存")
        self.max_ttl.valueChanged.connect(self.on_ttl_changed)
        opt_row.addWidget(self.max_ttl)
        upstream_layout.addLayout(opt_row)

        self.upstream_table = QTableWidget(0, 5)
        self.upstream_table.setHorizontalHeaderLabels(["名称", "协议", "地址", "状态", "延迟"])
        self.upstream_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.upstream_table.verticalHeader().setVisible(False)
        self.upstream_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.upstream_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.upstream_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.upstream_table.setMinimumHeight(170)
        self.upstream_table.itemSelectionChanged.connect(self.on_upstream_selected)
        upstream_layout.addWidget(self.upstream_table)

        add_row = QHBoxLayout()
        self.new_name = QLineEdit()
        self.new_name.setPlaceholderText("名称（可留空）")
        self.new_proto = QComboBox()
        self.new_proto.addItems(list(SUPPORTED_PROTOCOLS))
        self.new_addr = QLineEdit()
        self.new_addr.setPlaceholderText("地址：223.5.5.5:53 / https://dns.alidns.com/dns-query")
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
        default_btn.setToolTip("选中的上游优先使用；失败时按策略尝试其余上游")
        default_btn.clicked.connect(self.on_set_default_upstream)
        op_row.addWidget(probe_btn)
        op_row.addWidget(del_btn)
        op_row.addWidget(default_btn)
        op_row.addStretch()
        upstream_layout.addLayout(op_row)

        self.upstream_hint = QLabel("")
        self.upstream_hint.setStyleSheet("color: #8c8c8c;")
        self.upstream_hint.setWordWrap(True)
        upstream_layout.addWidget(self.upstream_hint)

        upstream_group.setLayout(upstream_layout)
        left_col.addWidget(upstream_group, 1)

        # 系统 DNS 接管
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

        # 维护
        maint_group = QGroupBox("维护")
        maint_layout = QVBoxLayout()
        for text, slot in (
            ("清空 DNS 缓存", self.on_clear_cache),
            ("重新加载规则", self.on_reload_blocklist),
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
        return page

    # ---------------- 查询日志页 ----------------
    def _build_log_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(10)

        tool_row = QHBoxLayout()
        tool_row.setSpacing(8)
        self.log_result = QComboBox()
        for label, key in RESULT_FILTERS:
            self.log_result.addItem(label, key)
        self.log_result.currentIndexChanged.connect(lambda _i: self.refresh_log())
        tool_row.addWidget(self.log_result)

        self.log_search = QLineEdit()
        self.log_search.setPlaceholderText("搜索域名或客户端 IP")
        self.log_search.textChanged.connect(lambda _t: self.refresh_log())
        tool_row.addWidget(self.log_search, 1)

        self.log_pause = QCheckBox("暂停记录")
        self.log_pause.setToolTip("暂停后新的查询不再写入日志，已有记录保留")
        self.log_pause.setChecked(not self.config_manager.dns_log_enabled)
        self.log_pause.toggled.connect(self.on_toggle_log_pause)
        tool_row.addWidget(self.log_pause)

        clear_btn = QPushButton("清空日志")
        StyleHelper.set_button_type(clear_btn, "default")
        clear_btn.clicked.connect(self.on_clear_log)
        tool_row.addWidget(clear_btn)
        layout.addLayout(tool_row)

        self.log_table = QTableWidget(0, 6)
        self.log_table.setHorizontalHeaderLabels(
            ["时间", "客户端", "域名", "类型", "结果", "规则 / 上游"])
        self.log_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.log_table.verticalHeader().setVisible(False)
        self.log_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.log_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.log_table.setMinimumHeight(240)
        self.log_table.setToolTip("双击一行可把该域名加入自定义规则（拦截）")
        self.log_table.doubleClicked.connect(lambda _i: self.on_log_to_rule())
        layout.addWidget(self.log_table, 3)

        stat_group = QGroupBox("统计（基于当前日志窗口）")
        stat_layout = QVBoxLayout()
        tables_row = QHBoxLayout()
        tables_row.setSpacing(10)
        self.top_client_table = self._mini_table("Top 客户端", "客户端")
        self.top_domain_table = self._mini_table("Top 查询域名", "域名")
        self.top_blocked_table = self._mini_table("Top 被拦截", "域名")
        for t in (self.top_client_table, self.top_domain_table, self.top_blocked_table):
            tables_row.addWidget(t, 1)
        stat_layout.addLayout(tables_row)

        self.type_label = QLabel("暂无数据")
        self.type_label.setWordWrap(True)
        self.type_label.setStyleSheet("color: #595959;")
        stat_layout.addWidget(self.type_label)
        stat_group.setLayout(stat_layout)
        layout.addWidget(stat_group, 2)
        return page

    def _mini_table(self, title, first_col):
        group = QGroupBox(title)
        box = QVBoxLayout()
        table = QTableWidget(0, 2)
        table.setHorizontalHeaderLabels([first_col, "次数"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setMinimumHeight(140)
        box.addWidget(table)
        group.setLayout(box)
        group._table = table
        return group

    # ---------------- 过滤器与重写页 ----------------
    def _build_filter_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(10)

        list_group = QGroupBox("过滤器列表")
        list_layout = QVBoxLayout()
        tip = QLabel("列表按勾选启用，规则与自定义规则一起生效；"
                     "配置里只存地址与统计，规则内容缓存在本地，离线也能用。")
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #8c8c8c;")
        list_layout.addWidget(tip)

        self.list_table = QTableWidget(0, 4)
        self.list_table.setHorizontalHeaderLabels(["启用", "名称", "规则数", "更新于"])
        self.list_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.list_table.verticalHeader().setVisible(False)
        self.list_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.list_table.setMinimumHeight(150)
        self.list_table.itemChanged.connect(self.on_list_item_changed)
        list_layout.addWidget(self.list_table)

        add_row = QHBoxLayout()
        self.list_name = QLineEdit()
        self.list_name.setPlaceholderText("名称（可空）")
        self.list_url = QLineEdit()
        self.list_url.setPlaceholderText("列表地址，如 https://anti-ad.net/adguard.txt")
        self.list_interval = QSpinBox()
        self.list_interval.setRange(0, 720)
        self.list_interval.setValue(24)
        self.list_interval.setSuffix(" 小时更新")
        self.list_interval.setToolTip("0 表示不自动更新")
        add_btn = QPushButton("添加")
        add_btn.clicked.connect(self.on_add_list)
        add_row.addWidget(self.list_name, 1)
        add_row.addWidget(self.list_url, 3)
        add_row.addWidget(self.list_interval)
        add_row.addWidget(add_btn)
        list_layout.addLayout(add_row)

        op_row = QHBoxLayout()
        update_btn = QPushButton("更新选中")
        update_btn.clicked.connect(lambda: self.on_update_lists(only_selected=True))
        update_all_btn = QPushButton("更新全部")
        update_all_btn.clicked.connect(lambda: self.on_update_lists(only_selected=False))
        del_btn = QPushButton("删除选中")
        StyleHelper.set_button_type(del_btn, "default")
        del_btn.clicked.connect(self.on_del_list)
        op_row.addWidget(update_btn)
        op_row.addWidget(update_all_btn)
        op_row.addWidget(del_btn)
        op_row.addStretch()
        list_layout.addLayout(op_row)

        self.list_hint = QLabel("")
        self.list_hint.setStyleSheet("color: #8c8c8c;")
        self.list_hint.setWordWrap(True)
        list_layout.addWidget(self.list_hint)
        list_group.setLayout(list_layout)

        custom_group = QGroupBox("自定义规则")
        custom_layout = QVBoxLayout()
        self.custom_summary = QLabel("0 条")
        self.custom_summary.setStyleSheet("color: #8c8c8c;")
        custom_layout.addWidget(self.custom_summary)
        custom_row = QHBoxLayout()
        edit_btn = QPushButton("编辑规则")
        edit_btn.clicked.connect(self.on_edit_custom_rules)
        hint = QLabel("支持：||ads.com^ 拦截、@@||ok.ads.com^ 例外、*.ads.com 通配、/正则/")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #8c8c8c;")
        custom_row.addWidget(edit_btn)
        custom_row.addWidget(hint, 1)
        custom_layout.addLayout(custom_row)
        custom_group.setLayout(custom_layout)

        rewrite_group = QGroupBox("DNS 重写")
        rewrite_layout = QVBoxLayout()
        rewrite_tip = QLabel("把域名直接解析到指定 IP（如 nas.home → 192.168.1.10），"
                             "优先于上游解析；支持 *.lan 通配。")
        rewrite_tip.setWordWrap(True)
        rewrite_tip.setStyleSheet("color: #8c8c8c;")
        rewrite_layout.addWidget(rewrite_tip)

        self.rewrite_table = QTableWidget(0, 2)
        self.rewrite_table.setHorizontalHeaderLabels(["域名", "IP"])
        self.rewrite_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.rewrite_table.verticalHeader().setVisible(False)
        self.rewrite_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rewrite_table.setMinimumHeight(130)
        rewrite_layout.addWidget(self.rewrite_table)

        rw_row = QHBoxLayout()
        self.rw_domain = QLineEdit()
        self.rw_domain.setPlaceholderText("域名，如 nas.home 或 *.lan")
        self.rw_ip = QLineEdit()
        self.rw_ip.setPlaceholderText("IP，如 192.168.1.10")
        rw_add = QPushButton("添加")
        rw_add.clicked.connect(self.on_add_rewrite)
        rw_del = QPushButton("删除选中")
        StyleHelper.set_button_type(rw_del, "default")
        rw_del.clicked.connect(self.on_del_rewrite)
        rw_row.addWidget(self.rw_domain, 2)
        rw_row.addWidget(self.rw_ip, 2)
        rw_row.addWidget(rw_add)
        rw_row.addWidget(rw_del)
        rewrite_layout.addLayout(rw_row)
        rewrite_group.setLayout(rewrite_layout)

        layout.addWidget(list_group, 2)
        layout.addWidget(custom_group)
        layout.addWidget(rewrite_group, 2)
        return page

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
                f.write("\n".join(sorted({d.strip().rstrip('.') for d in DEFAULT_BLOCKLIST
                                          if '*' not in d and '/' not in d})) + "\n")
        except Exception as e:
            logger.warning(f"初始化 DNS 黑名单文件失败: {e}")

    def _sync_upstreams_to_filter(self):
        self.filter.set_upstreams(
            [Upstream.from_dict(u) for u in self.config_manager.dns_upstreams],
            selected=self.config_manager.dns_selected_upstream,
        )
        self.filter.upstream_strategy = self.config_manager.dns_strategy
        self.filter.cache_min_ttl = self.config_manager.dns_cache_min_ttl
        self.filter.cache_max_ttl = self.config_manager.dns_cache_max_ttl
        self.filter.set_rewrites(self.config_manager.dns_rewrites)

    def _rebuild_filter_rules(self):
        """把「过滤器列表缓存 + 自定义规则」编译进过滤器。"""
        lines, counts = dns_lists.merged_rules(self.config_manager.dns_lists)
        rules = self.filter.set_filter_sources(lines, self.config_manager.dns_custom_rules)
        self.custom_summary.setText(
            f"自定义规则 {len(self.config_manager.dns_custom_rules)} 条 · "
            f"合计生效 {rules.count} 条（含例外 {rules.allow_count}）")
        return rules

    def _start_service(self):
        self._sync_upstreams_to_filter()
        self._rebuild_filter_rules()
        self.filter.port = self.config_manager.dns_port
        self.filter.block_action = self.config_manager.dns_block_action
        ok = self.filter.start()
        self._update_state()
        return ok, list(self.filter.bind_errors)

    def on_selfcheck(self):
        """自检 DNS 服务：临时端口起一份实例实测，不影响正在运行的服务与系统设置。"""
        if getattr(self, "_selfchecking", False):
            return
        self._selfchecking = True
        self.selfcheck_btn.setEnabled(False)
        self.state_label.setText(self.state_label.text() +
                                 "<br><span style='color:#8c8c8c;'>正在自检（约 1~3 秒）…</span>")

        def work():
            # 自检用「当前选优」的上游，这样结果直接回答「我配的 DNS 到底通不通、拦不拦广告」
            ups = self.config_manager.dns_upstreams
            sel = self.config_manager.dns_selected_upstream
            upstream = ups[sel] if 0 <= sel < len(ups) else None
            try:
                items = check_dns(upstream=upstream)
            except Exception as e:  # 自检本身异常也要回到界面
                logger.warning(f"DNS 自检异常: {e}")
                items = []
                self._ui(lambda: self._after_selfcheck(items, str(e)))
                return
            self._ui(lambda: self._after_selfcheck(items, None))

        threading_run(work)

    def _after_selfcheck(self, items, error):
        self._selfchecking = False
        self.selfcheck_btn.setEnabled(True)
        self._update_state()
        if error:
            QMessageBox.warning(self, "DNS 自检", f"自检过程出错：\n{error}")
            return
        show_results(self, items, "DNS 自检")

    def on_start_and_takeover(self):
        if not ensure_admin(self, "启动并接管系统 DNS"):
            return
        ok, errors = self._start_service()
        if not ok:
            QMessageBox.critical(self, "DNS 服务", "服务启动失败：\n" + "\n".join(errors))
            return
        self.on_takeover(start_if_needed=False)

    def on_takeover(self, start_if_needed=True):
        if not ensure_admin(self, "接管系统 DNS"):
            return
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
        # 代理（mihomo 内核）可能正把 DNS 指向本机，停掉后代理会解析不了域名
        if self._proxy_depends_on_me():
            answer = QMessageBox.question(
                self, "停止 DNS 服务",
                "检测到本地代理正在运行，且它的域名解析使用的是本机 DNS。\n\n"
                "停止 DNS 后，代理会无法解析域名（网页打不开）。\n"
                "建议先在「网络加速」页停止代理，或保持 DNS 运行。\n\n"
                "仍要停止 DNS 服务吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
        # 先恢复 DNS 再停服务，避免系统 DNS 指向已停止的本机端口
        if dns_takeover._load_backup():
            restored, _err = dns_takeover.restore_all()
            if restored:
                logger.info(f"停止 DNS 服务前已恢复系统 DNS: {restored}")
        self.filter.stop()
        self._update_state()

    def _proxy_depends_on_me(self):
        """本地代理是否在跑（端口可连通）。它会把内核 DNS 指向本机服务。"""
        import socket
        try:
            port = int(self.config_manager.proxy_port or 7890)
        except (TypeError, ValueError):
            port = 7890
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    # 上游管理
    # ------------------------------------------------------------------
    def on_strategy_changed(self, _index):
        strategy = self.strategy_combo.currentData()
        self.config_manager.set_dns_config(strategy=strategy)
        self.filter.upstream_strategy = strategy

    def on_ttl_changed(self, _value):
        self.config_manager.set_dns_config(
            cache_min_ttl=self.min_ttl.value(),
            cache_max_ttl=max(self.min_ttl.value() + 10, self.max_ttl.value()))
        self.filter.cache_min_ttl = self.config_manager.dns_cache_min_ttl
        self.filter.cache_max_ttl = self.config_manager.dns_cache_max_ttl

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
                    item = self.upstream_table.item(row, col)
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
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
        # 地址能说明协议时以地址为准：用户把 DoH 地址选成「UDP」是最常见的填错方式
        if addr.lower().startswith(("http://", "https://")) and proto != "DoH":
            proto = "DoH"
        if proto == "DoH" and not addr.lower().startswith(("http://", "https://")):
            QMessageBox.information(self, "添加上游",
                                    "DoH 地址必须是完整 URL，例如 https://dns.alidns.com/dns-query")
            return
        ups = self.config_manager.dns_upstreams
        ups.append({"name": name or f"{proto}-{addr}", "proto": proto, "address": addr})
        self.config_manager.set_dns_config(upstreams=ups)
        self.new_name.clear()
        self.new_addr.clear()
        self.reload_upstream_table()
        # 服务已在运行时立即生效，否则用户会以为新上游没用上（必须重启才生效）
        if self.filter.running:
            self._sync_upstreams_to_filter()
            self.upstream_hint.setText(
                f"已添加 {name or addr}，已即时生效。建议点「测延迟」确认可达。")

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
        if self.filter.running:
            self._sync_upstreams_to_filter()

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
    # 查询日志 / 统计
    # ------------------------------------------------------------------
    def refresh_log(self, force=False):
        if not self.isVisible():
            return
        # 日志表只在「查询日志」页可见时刷新，避免无谓的表格重绘
        if not force and getattr(self, "log_tab", None) is not None \
                and self.tabs.currentWidget() is not self.log_tab:
            return
        log = self.filter.stats.query_log
        result = self.log_result.currentData() or "all"
        rows = log.snapshot(result=result, search=self.log_search.text(), limit=200)
        self.log_table.setRowCount(len(rows))
        for r, e in enumerate(rows):
            cells = [e["time"], e["client"], e["domain"], e["qtype"],
                     e["result_label"], e["rule"] or e["upstream"] or "-"]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(str(text))
                if e["result"] == "blocked":
                    item.setForeground(Qt.GlobalColor.darkRed)
                elif e["result"] == "upstream_blocked":
                    # 上游 DNS 自己拦的（返回 0.0.0.0），用橙色与本地规则区分
                    item.setForeground(QColor("#d46b08"))
                elif e["result"] == "cached":
                    item.setForeground(Qt.GlobalColor.darkGray)
                self.log_table.setItem(r, c, item)

        agg = log.aggregates(top_n=8)
        self._fill_mini(self.top_client_table, agg["top_clients"])
        self._fill_mini(self.top_domain_table, agg["top_domains"])
        self._fill_mini(self.top_blocked_table, agg["top_blocked"])
        self.type_label.setText(self._type_bar(agg["by_type"]))

    def _fill_mini(self, group, pairs):
        table = group._table
        table.setRowCount(len(pairs))
        for r, (name, count) in enumerate(pairs):
            table.setItem(r, 0, QTableWidgetItem(str(name)))
            table.setItem(r, 1, QTableWidgetItem(str(count)))

    @staticmethod
    def _type_bar(pairs):
        if not pairs:
            return "暂无数据"
        total = sum(c for _, c in pairs) or 1
        lines = []
        for name, count in pairs:
            ratio = count * 100 / total
            bar = "█" * max(1, int(round(ratio / 5)))
            lines.append(f"{name:<6} {ratio:5.1f}%  {bar}  ({count})")
        return "查询类型分布：\n" + "   ".join(lines[:6])

    def on_toggle_log_pause(self, paused):
        self.filter.stats.query_log.paused = bool(paused)
        self.config_manager.set_dns_config(log_enabled=not paused)
        self.refresh_log()

    def on_clear_log(self):
        self.filter.stats.query_log.clear()
        self.refresh_log()

    def on_log_to_rule(self):
        row = self.log_table.currentRow()
        if row < 0:
            return
        item = self.log_table.item(row, 2)
        if item is None:
            return
        domain = item.text().strip()
        if not domain:
            return
        if QMessageBox.question(
                self, "加入自定义规则",
                f"把 {domain} 加入自定义拦截规则？\n（会写入自定义规则列表并立即生效）") \
                != QMessageBox.StandardButton.Yes:
            return
        rules = list(self.config_manager.dns_custom_rules)
        rule = f"||{domain}^"
        if rule not in rules:
            rules.append(rule)
            self.config_manager.set_dns_config(custom_rules=rules)
            self._rebuild_filter_rules()

    # ------------------------------------------------------------------
    # 过滤器列表
    # ------------------------------------------------------------------
    def reload_list_table(self):
        entries = self.config_manager.dns_lists
        if not entries:
            entries = [dict(e) for e in dns_lists.DEFAULT_LISTS]
            self.config_manager.set_dns_config(lists=entries)
            self.config_manager.dns_lists = entries
        self.list_table.blockSignals(True)
        self.list_table.setRowCount(len(entries))
        for row, e in enumerate(entries):
            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk.setCheckState(Qt.CheckState.Checked if e.get("enabled", True)
                              else Qt.CheckState.Unchecked)
            self.list_table.setItem(row, 0, chk)
            self.list_table.setItem(row, 1, QTableWidgetItem(e.get("name") or e.get("url", "")))
            self.list_table.setItem(row, 2, QTableWidgetItem(str(e.get("count", 0))))
            self.list_table.setItem(row, 3, QTableWidgetItem(_fmt_ts(e.get("updated", 0))))
        self.list_table.blockSignals(False)

    def on_list_item_changed(self, item):
        if item.column() != 0:
            return
        row = item.row()
        entries = self.config_manager.dns_lists
        if row >= len(entries):
            return
        entries[row]["enabled"] = item.checkState() == Qt.CheckState.Checked
        self.config_manager.set_dns_config(lists=entries)
        rules = self._rebuild_filter_rules()
        self.list_hint.setText(f"已应用，当前生效规则 {rules.count} 条")

    def on_add_list(self):
        url = self.list_url.text().strip()
        if not url:
            QMessageBox.information(self, "添加列表", "请填写列表地址。")
            return
        entry = {
            "name": self.list_name.text().strip() or url,
            "url": url,
            "enabled": True,
            "interval": self.list_interval.value(),
            "count": 0,
            "updated": 0,
        }
        entries = list(self.config_manager.dns_lists) + [entry]
        self.config_manager.set_dns_config(lists=entries)
        self.config_manager.dns_lists = entries
        self.list_name.clear()
        self.list_url.clear()
        self.reload_list_table()
        self.on_update_lists(only_selected=False, targets=[entry])

    def on_del_list(self):
        row = self.list_table.currentRow()
        entries = self.config_manager.dns_lists
        if row < 0 or row >= len(entries):
            return
        entries.pop(row)
        self.config_manager.set_dns_config(lists=entries)
        self.reload_list_table()
        self._rebuild_filter_rules()

    def on_update_lists(self, only_selected=False, targets=None):
        if self._updating_lists:
            return
        entries = self.config_manager.dns_lists
        if targets is not None:
            todo = targets
        elif only_selected:
            row = self.list_table.currentRow()
            if row < 0 or row >= len(entries):
                QMessageBox.information(self, "更新列表", "请先选中一行。")
                return
            todo = [entries[row]]
        else:
            todo = [e for e in entries if e.get("enabled", True)]
        if not todo:
            QMessageBox.information(self, "更新列表", "没有启用的列表可更新。")
            return

        self._updating_lists = True
        self.list_hint.setText(f"正在更新 {len(todo)} 个列表…")

        def work():
            results = []
            for e in todo:
                count, err = dns_lists.update_list(e)
                results.append((e.get("name") or e.get("url"), count, err))
            self._ui(lambda: self._after_update_lists(results))
        threading_run(work)

    def _after_update_lists(self, results):
        self._updating_lists = False
        self.config_manager.set_dns_config(lists=self.config_manager.dns_lists)
        self.reload_list_table()
        rules = self._rebuild_filter_rules()
        ok = [f"{n}（{c} 条）" for n, c, err in results if not err]
        bad = [f"{n}：{err}" for n, c, err in results if err]
        parts = []
        if ok:
            parts.append("更新成功：" + "、".join(ok))
        if bad:
            parts.append("失败：" + "；".join(bad))
        parts.append(f"当前生效 {rules.count} 条")
        self.list_hint.setText("；".join(parts))

    # ------------------------------------------------------------------
    # 自定义规则 / 重写
    # ------------------------------------------------------------------
    def on_edit_custom_rules(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("自定义过滤规则")
        dlg.resize(560, 420)
        box = QVBoxLayout(dlg)
        tip = QLabel("一行一条。||ads.com^ 拦截该域及子域；@@||ok.ads.com^ 放行；"
                     "*.ads.com 通配；/正则/ 正则匹配；# 与 ! 开头为注释。")
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #8c8c8c;")
        box.addWidget(tip)
        editor = QPlainTextEdit()
        editor.setPlainText("\n".join(self.config_manager.dns_custom_rules))
        editor.setPlaceholderText("||ads.example.com^\n@@||cdn.example.com^")
        box.addWidget(editor, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save
                                   | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        box.addWidget(buttons)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        rules = [ln.strip() for ln in editor.toPlainText().splitlines() if ln.strip()]
        self.config_manager.set_dns_config(custom_rules=rules)
        applied = self._rebuild_filter_rules()
        self.list_hint.setText(f"自定义规则已保存，当前生效 {applied.count} 条")

    def reload_rewrite_table(self):
        rw = self.config_manager.dns_rewrites
        self.rewrite_table.setRowCount(len(rw))
        for row, (domain, ip) in enumerate(sorted(rw.items())):
            self.rewrite_table.setItem(row, 0, QTableWidgetItem(domain))
            self.rewrite_table.setItem(row, 1, QTableWidgetItem(ip))

    def on_add_rewrite(self):
        domain = self.rw_domain.text().strip().lower()
        ip = self.rw_ip.text().strip()
        if not domain or not ip:
            QMessageBox.information(self, "DNS 重写", "请填写域名和 IP。")
            return
        from core.dns_filter import ip_to_rdata
        if not ip_to_rdata(ip):
            QMessageBox.warning(self, "DNS 重写", f"{ip} 不是合法的 IPv4 / IPv6 地址。")
            return
        rw = dict(self.config_manager.dns_rewrites)
        rw[domain] = ip
        self.config_manager.set_dns_config(rewrites=rw)
        self.config_manager.dns_rewrites = rw
        self.filter.set_rewrites(rw)
        self.rw_domain.clear()
        self.rw_ip.clear()
        self.reload_rewrite_table()

    def on_del_rewrite(self):
        row = self.rewrite_table.currentRow()
        if row < 0:
            return
        item = self.rewrite_table.item(row, 0)
        if item is None:
            return
        rw = dict(self.config_manager.dns_rewrites)
        rw.pop(item.text(), None)
        self.config_manager.set_dns_config(rewrites=rw)
        self.config_manager.dns_rewrites = rw
        self.filter.set_rewrites(rw)
        self.reload_rewrite_table()

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
        self.filter.clear_cache()
        self.filter.stats.reset()
        QMessageBox.information(self, "维护", "DNS 缓存、统计与查询日志已清空。")

    def on_reload_blocklist(self):
        applied = self._rebuild_filter_rules()
        QMessageBox.information(self, "维护", f"规则已重新加载：{applied.count} 条生效。")

    def on_open_blocklist(self):
        try:
            subprocess.Popen(["notepad.exe", self.blocklist_path])
        except Exception as e:
            QMessageBox.warning(self, "黑名单", f"打开失败：{e}")

    def on_export(self):
        path, _ = QFileDialog.getSaveFileName(self, "导出 DNS 配置", "dns-config.json", "JSON (*.json)")
        if not path:
            return
        try:
            data = self.filter.export_config()
            data["lists"] = self.config_manager.dns_lists
            data["custom_rules"] = self.config_manager.dns_custom_rules
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            QMessageBox.information(self, "导出配置", "导出完成。")
        except Exception as e:
            QMessageBox.warning(self, "导出配置", f"导出失败：{e}")

    def on_import(self):
        path, _ = QFileDialog.getOpenFileName(self, "导入 DNS 配置", "", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ups = [Upstream.from_dict(d).to_dict() for d in data.get("upstreams", [])]
            if not ups:
                raise ValueError("配置中没有上游服务器")
            kwargs = dict(
                upstreams=ups,
                selected_upstream=int(data.get("selected", 0)),
                port=int(data.get("port", self.config_manager.dns_port)),
                block_action=data.get("block_action", self.config_manager.dns_block_action),
            )
            if data.get("strategy") in ("sequential", "parallel"):
                kwargs["strategy"] = data["strategy"]
            if isinstance(data.get("rewrites"), dict):
                kwargs["rewrites"] = data["rewrites"]
            if isinstance(data.get("custom_rules"), list):
                kwargs["custom_rules"] = [str(r) for r in data["custom_rules"]]
            if isinstance(data.get("lists"), list):
                kwargs["lists"] = data["lists"]
            self.config_manager.set_dns_config(**kwargs)
            self.reload_upstream_table()
            self.reload_list_table()
            self.reload_rewrite_table()
            self._rebuild_filter_rules()
            self.listen_label.setText(
                f"监听 {'、'.join(self._listen_hosts())} :: 端口 {self.config_manager.dns_port}")
            if self.filter.running:
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

        self.refresh_log()
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
        rules = self.filter.rules
        lines = [
            f"<b>服务：</b>{'运行中' if running else '未运行'} · 端口 {self.filter.port}"
            + (f"（监听失败：{'; '.join(self.filter.bind_errors)}）"
               if running and self.filter.bind_errors else ""),
            f"<b>线路：</b>{sel.name + '（' + sel.proto + '）' if sel else '未配置上游'}",
            f"<b>策略：</b>{'并行最快' if self.filter.upstream_strategy == 'parallel' else '顺序优先'}",
            f"<b>规则：</b>{rules.count} 条（例外 {rules.allow_count}）· "
            f"重写 {len(self.filter.rewrites)} 条",
            f"<b>系统 DNS：</b>{dns_state}",
        ]
        self.state_label.setText("<br>".join(lines))

    def _style_pill(self, running):
        color = "#52c41a" if running else "#8c8c8c"
        bg = "#f6ffed" if running else "#f5f5f5"
        self.status_pill.setStyleSheet(
            f"color: {color}; background-color: {bg}; border-radius: 4px; "
            f"padding: 2px 8px; font-weight: 600;")

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
