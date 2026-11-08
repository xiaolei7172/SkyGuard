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

import math
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton,
    QScrollArea, QSpinBox, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget, QFrame,
)

from core import ip_optimizer
from core.ip_optimizer import DOMAIN_GROUPS, IpCache
from core import clash_kernel
from core.clash_kernel import KernelNotFound, MihomoKernel
from core.geo import get_classifier
from core.local_proxy import (
    ACTION_ACCEL, ACTION_DIRECT, ACTION_PROXY, ACTION_REJECT,
    DEFAULT_RULES, MODE_DIRECT, MODE_GLOBAL, MODE_RULE, MODE_SMART,
    MODES, LocalProxy, RuleEngine, format_bytes,
)
from core.proxy_connectors import probe_node
from core.proxy_nodes import (
    KNOWN_UNSUPPORTED, NodeStore, ProxyNode, fetch_subscription,
    fetch_subscription_ex, format_traffic,
    parse_proxy_uri, parse_subscription,
)
from ui.styles import StyleHelper
from utils import system_proxy
from utils.logger import logger


class TrafficGraph(QWidget):
    """上下行实时速率折线图（Clash Verge 的流量图，轻量自绘版）。

    push(up, down) 喂入每秒速率（字节/秒），内部保留最近 max_points 个点，
    自动按峰值归一化，零依赖、无定时器，只在数据到来时重绘。
    """

    def __init__(self, max_points=120, parent=None):
        super().__init__(parent)
        self.max_points = max_points
        self.up = deque(maxlen=max_points)
        self.down = deque(maxlen=max_points)
        self.setMinimumHeight(96)
        self.setToolTip("每秒上下行速率（自动按峰值缩放）")

    def push(self, up_rate, down_rate):
        self.up.append(max(0.0, float(up_rate)))
        self.down.append(max(0.0, float(down_rate)))
        self.update()

    def clear(self):
        self.up.clear()
        self.down.clear()
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        bg = self.palette().color(self.backgroundRole())
        painter.fillRect(QRectF(0, 0, w, h), bg)

        peak = max(list(self.up) + list(self.down) + [1.0])
        # 网格
        painter.setPen(QPen(self.palette().color(self.foregroundRole()), 1))
        for i in range(1, 3):
            y = h * i / 3.0
            painter.drawLine(QPointF(0, y), QPointF(w, y))
        for i in range(1, 6):
            x = w * i / 6.0
            painter.drawLine(QPointF(x, 0), QPointF(x, h))

        def series(values, color):
            if len(values) < 2:
                return
            poly = QPolygonF()
            n = len(values)
            for i, v in enumerate(values):
                x = w * i / max(1, self.max_points - 1)
                y = h - min(1.0, v / peak) * (h - 4) - 2
                poly.append(QPointF(x, y))
            painter.setPen(QPen(color, 1.6))
            painter.drawPolyline(poly)

        series(self.down, Qt.GlobalColor.darkCyan)
        series(self.up, Qt.GlobalColor.darkGreen)

        painter.setPen(self.palette().color(self.foregroundRole()))
        label = f"↓{format_bytes(peak)} 峰值  ·  {len(self.up)}s"
        metrics = painter.fontMetrics()
        rect = QRectF(4, 3, metrics.horizontalAdvance(label) + 10, 16)
        painter.fillRect(rect, bg)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, label)


def _delay_color(ms):
    """延迟配色：绿 <200ms，黄 <500ms，其余红（Clash Verge 口径）。"""
    try:
        ms = int(ms)
    except (TypeError, ValueError):
        return None
    if ms <= 0:
        return None
    if ms < 200:
        return QColor("#389e0d")
    if ms < 500:
        return QColor("#d48806")
    return QColor("#cf1322")

MODE_LABELS = (
    ("智能分流", MODE_SMART),
    ("仅按规则", MODE_RULE),
    ("全局代理", MODE_GLOBAL),
    ("全部直连", MODE_DIRECT),
)
ACTION_LABELS = (
    ("加速直连", ACTION_ACCEL),
    ("直连", ACTION_DIRECT),
    ("代理", ACTION_PROXY),
    ("拒绝", ACTION_REJECT),
)

# 规则类型：界面显示短中文标签，存储仍是内核识别的英文类型
RULE_TYPE_LABELS = (
    ("后缀", "domain-suffix"),
    ("域名", "domain"),
    ("关键字", "domain-keyword"),
    ("正则", "domain-regex"),
    ("IP 段", "ip-cidr"),
    ("兜底", "final"),
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
        if self.selected_uid.startswith("kernel:"):
            self.selected_kernel_node = self.selected_uid[len("kernel:"):]
        self._optimizing = False
        self._testing_nodes = False
        self._last_proxy_error = ""
        self._stats_sig = None
        self._status_cache = (0.0, None)
        self.geo = get_classifier()
        self.kernel = None                 # Clash(mihomo) 内核实例，engine=clash 时使用
        self.selected_kernel_node = ""     # 内核模式下选中的节点名

        self.proxy = LocalProxy(
            host=config_manager.proxy_host,
            port=config_manager.proxy_port,
            rules=self._rules_for_engine(),
            mode=config_manager.proxy_mode,
            node_provider=self._current_node,
            accel_ip_provider=self.ip_cache.best_for_suffix,
            geo=self.geo,
        )
        self.proxy.stats.reset()

        self.ui_call.connect(lambda f: f())
        self.setup_ui()

        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self.refresh_stats)
        self.stats_timer.start(1500)

        # 订阅自动更新巡检（每 5 分钟看一次谁到期）
        self.sub_timer = QTimer(self)
        self.sub_timer.timeout.connect(self._auto_update_subscriptions)
        self.sub_timer.start(300_000)
        self._last_traffic = None

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
    def _shrinkable_combo(self, combo):
        """下拉框允许收窄，窄窗口时不会把页面撑出横向滚动。

        注意：不要对 QComboBox 局部 setStyleSheet——带样式的盒子模型会把
        minimumSizeHint 反而撑大（实测 75 -> 91px），这里保持无局部样式。
        """
        combo.setStyleSheet("")

    @staticmethod
    def _adaptive_combo(combo, min_chars=4, min_width=56):
        """下拉框按最少字符数收窄，且布局给空间时会自然展开。

        位于拉伸槽位（stretch > 0）的组合框使用，窄窗口不会撑出横向滚动，
        宽窗口下仍会随行内其他控件一起变宽，不会截断显示。
        QComboBox 的 minimumSizeHint 不受 AdjustToMinimumContentsLength
        影响，必须显式 setMinimumWidth 才能真正压低布局最小宽度。
        """
        combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        combo.setMinimumContentsLength(min_chars)
        combo.setMinimumWidth(min_width)

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
        self._shrinkable_combo(self.listen_host)
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
        self.mode_combo.setToolTip("智能分流：国内直连 / 国外走代理；其余模式按名称理解")
        self._shrinkable_combo(self.mode_combo)
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
        # 允许换行并放开最小宽度限制，窄窗口时折叠而不是把整页撑出横向滚动
        self.status_detail.setWordWrap(True)
        self.status_detail.setMinimumWidth(0)
        self.status_detail.setSizePolicy(self.status_detail.sizePolicy().horizontalPolicy(),
                                         self.status_detail.sizePolicy().verticalPolicy())
        row2.addWidget(self.status_detail, 1)
        box.addLayout(row2)

        row3 = QHBoxLayout()
        engine_label = QLabel("内核")
        row3.addWidget(engine_label)
        self.engine_combo = QComboBox()
        self.engine_combo.addItem("内置引擎（ss / trojan / http / socks5）", "builtin")
        self.engine_combo.addItem("Clash 内核 mihomo（全协议，含 hysteria2 / vless）", "clash")
        eng_index = self.engine_combo.findData(
            getattr(self.config_manager, "proxy_engine", "builtin"))
        self.engine_combo.setCurrentIndex(max(0, eng_index))
        self.engine_combo.currentIndexChanged.connect(self.on_engine_changed)
        self._shrinkable_combo(self.engine_combo)
        row3.addWidget(self.engine_combo, 1)
        self.kernel_btn = QPushButton("下载内核")
        self.kernel_btn.clicked.connect(self.on_locate_or_download_kernel)
        StyleHelper.set_button_type(self.kernel_btn, "default")
        row3.addWidget(self.kernel_btn)
        self.kernel_label = QLabel(self._kernel_state_text())
        self.kernel_label.setStyleSheet("color: #8c8c8c;")
        self.kernel_label.setWordWrap(True)
        row3.addWidget(self.kernel_label, 2)
        box.addLayout(row3)

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

        left.addWidget(self._build_traffic_group())
        left.addWidget(self._build_subscription_group())
        left.addWidget(self._build_accel_group())
        right.addWidget(self._build_rules_group())
        right.addWidget(self._build_conn_group())
        right.addStretch()
        return body

    # -- 实时流量图 ---------------------------------------------------
    def _build_traffic_group(self):
        group = QGroupBox("实时速率")
        box = QVBoxLayout()
        self.traffic_graph = TrafficGraph()
        box.addWidget(self.traffic_graph)
        legend = QHBoxLayout()
        for color, text in (("#237804", "■ 上行"), ("#006d75", "■ 下行")):
            tag = QLabel(f'<span style="color:{color};font-weight:700;">{text}</span>')
            legend.addWidget(tag)
        legend.addStretch()
        self.rate_label = QLabel("—")
        self.rate_label.setStyleSheet("color: #8c8c8c;")
        legend.addWidget(self.rate_label)
        box.addLayout(legend)
        group.setLayout(box)
        return group

    # -- 机场 / 节点 -------------------------------------------------
    def _build_subscription_group(self):
        group = QGroupBox("机场订阅 / 节点")
        box = QVBoxLayout()

        # 订阅列表（Clash Verge 风格：显示节点数 / 流量 / 到期 / 更新时间）
        self.sub_table = QTableWidget(0, 4)
        self.sub_table.setHorizontalHeaderLabels(["订阅", "节点数", "流量 / 到期", "更新于"])
        self.sub_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.sub_table.verticalHeader().setVisible(False)
        self.sub_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.sub_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.sub_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.sub_table.setMaximumHeight(110)
        self.sub_table.setToolTip("双击更新该订阅；流量与到期信息来自订阅响应头（若机场提供）")
        self.sub_table.doubleClicked.connect(lambda _i: self.on_update_subscriptions(True))
        box.addWidget(self.sub_table)

        row = QHBoxLayout()
        self.sub_url = QLineEdit()
        self.sub_url.setPlaceholderText("订阅地址（Clash YAML 或 base64 通用订阅），也可填本地文件路径")
        row.addWidget(self.sub_url, 3)
        self.sub_name = QLineEdit()
        self.sub_name.setPlaceholderText("备注名（可空）")
        self.sub_name.setMaximumWidth(140)
        row.addWidget(self.sub_name, 1)
        self.sub_interval = QComboBox()
        self.sub_interval.setToolTip("自动更新间隔（内置引擎生效；Clash 内核由内核自己定时拉取）")
        for label, minutes in (("手动", 0), ("6h", 360), ("12h", 720),
                               ("24h", 1440), ("48h", 2880)):
            self.sub_interval.addItem(label, minutes)
        self.sub_interval.setCurrentIndex(3)
        row.addWidget(self.sub_interval)
        add_btn = QPushButton("添加/更新")
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

        self.node_search = QLineEdit()
        self.node_search.setPlaceholderText("搜索节点（名称 / 服务器 / 来源）")
        self.node_search.textChanged.connect(lambda _t: self.refresh_node_table())
        self.node_search.setMaximumHeight(26)
        box.addWidget(self.node_search)

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
        test_btn = QPushButton("测速")
        test_btn.setToolTip("对全部节点逐个测延迟")
        test_btn.clicked.connect(self.on_test_nodes)
        StyleHelper.set_button_type(test_btn, "default")
        row3.addWidget(test_btn)
        self.sort_btn = QPushButton("按延迟排序")
        self.sort_btn.setToolTip("按延迟从低到高排序（再点一次恢复默认顺序）")
        self.sort_btn.setCheckable(True)
        self.sort_btn.toggled.connect(lambda _on: self.refresh_node_table())
        StyleHelper.set_button_type(self.sort_btn, "default")
        row3.addWidget(self.sort_btn)
        use_btn = QPushButton("使用节点")
        use_btn.setToolTip("使用当前选中的节点（也可直接双击该行）")
        use_btn.clicked.connect(self.on_use_node)
        row3.addWidget(use_btn)
        del_btn = QPushButton("删除选中")
        del_btn.clicked.connect(self.on_delete_node)
        StyleHelper.set_button_type(del_btn, "default")
        row3.addWidget(del_btn)
        row3.addStretch()
        box.addLayout(row3)

        self.sub_hint = QLabel("还没有节点，先添加订阅或手动填一条链接")
        self.sub_hint.setStyleSheet("color: #8c8c8c;")
        self.sub_hint.setWordWrap(True)
        box.addWidget(self.sub_hint)

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
        box.addLayout(row3)

        self.accel_hint = QLabel("")
        self.accel_hint.setStyleSheet("color: #8c8c8c;")
        self.accel_hint.setWordWrap(True)
        box.addWidget(self.accel_hint)

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
        self.rule_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.rule_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.rule_table.verticalHeader().setVisible(False)
        self.rule_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.rule_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rule_table.setMinimumHeight(210)
        box.addWidget(self.rule_table)

        row = QHBoxLayout()
        self.rule_type = QComboBox()
        for label, rtype in RULE_TYPE_LABELS:
            self.rule_type.addItem(label, rtype)
        self.rule_type.setToolTip(
            "后缀=域名及其子域；域名=完整域名；关键字=包含即命中；"
            "正则=域名正则；IP 段=如 140.82.0.0/16；兜底=其余流量")
        self._adaptive_combo(self.rule_type)
        row.addWidget(self.rule_type, 1)
        self.rule_value = QLineEdit()
        self.rule_value.setPlaceholderText("匹配值，如 github.com")
        row.addWidget(self.rule_value, 2)
        self.rule_action = QComboBox()
        for label, value in ACTION_LABELS:
            self.rule_action.addItem(label, value)
        self._adaptive_combo(self.rule_action)
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

        geo_row = QHBoxLayout()
        self.geo_label = QLabel(f"国内 IP 库：{self.geo.source}")
        self.geo_label.setStyleSheet("color: #8c8c8c;")
        self.geo_label.setWordWrap(True)
        geo_row.addWidget(self.geo_label, 1)
        update_db_btn = QPushButton("更新 IP 库")
        update_db_btn.setToolTip("从 APNIC 重新下载中国大陆 IPv4 段，约 3MB，更新到用户目录")
        update_db_btn.clicked.connect(self.on_update_geodb)
        StyleHelper.set_button_type(update_db_btn, "default")
        geo_row.addWidget(update_db_btn)
        box.addLayout(geo_row)

        # 规则命中测试（Clash Verge 的连接/规则页常用能力）
        test_row = QHBoxLayout()
        self.rule_probe = QLineEdit()
        self.rule_probe.setPlaceholderText("测试：输入域名或 IP，看会走哪条规则")
        test_btn = QPushButton("测试走向")
        test_btn.clicked.connect(self.on_probe_rule)
        StyleHelper.set_button_type(test_btn, "default")
        test_row.addWidget(self.rule_probe, 1)
        test_row.addWidget(test_btn)
        box.addLayout(test_row)
        self.rule_probe_result = QLabel("")
        self.rule_probe_result.setWordWrap(True)
        self.rule_probe_result.setStyleSheet("color: #389e0d;")
        box.addWidget(self.rule_probe_result)

        group.setLayout(box)
        return group

    def on_probe_rule(self):
        """用当前规则引擎（与代理同源）判定一个目标的走向。"""
        host = self.rule_probe.text().strip()
        if not host:
            self.rule_probe_result.setText("请输入域名或 IP。")
            self.rule_probe_result.setStyleSheet("color: #8c8c8c;")
            return
        engine = self.proxy.engine
        action, reason = engine.match(host)
        label = {"DIRECT": "直连", "PROXY": "走代理节点",
                 "REJECT": "拦截", "ACCEL": "加速直连"}.get(action, action)
        mode_name = dict(MODE_LABELS).get(engine.mode, engine.mode)
        color = {"DIRECT": "#389e0d", "PROXY": "#0958d9",
                 "REJECT": "#cf1322", "ACCEL": "#389e0d"}.get(action, "#595959")
        self.rule_probe_result.setText(
            f"[{mode_name}] {host} → <b>{label}</b>（{reason}）")
        self.rule_probe_result.setStyleSheet(f"color: {color};")

    # -- 连接监控 ----------------------------------------------------
    def _build_conn_group(self):
        group = QGroupBox("连接监控")
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
        close_btn = QPushButton("断开选中")
        close_btn.setToolTip("断开选中的活动连接（Clash 内核模式可用）")
        close_btn.clicked.connect(self.on_close_selected_conn)
        StyleHelper.set_button_type(close_btn, "default")
        row.addWidget(close_btn)
        close_all_btn = QPushButton("断开全部")
        close_all_btn.clicked.connect(self.on_clear_logs)
        StyleHelper.set_button_type(close_all_btn, "default")
        row.addWidget(close_all_btn)
        row.addStretch()
        self.conn_hint = QLabel("")
        self.conn_hint.setStyleSheet("color: #8c8c8c;")
        row.addWidget(self.conn_hint)
        box.addLayout(row)

        group.setLayout(box)
        return group

    def on_close_selected_conn(self):
        """断开一条活动连接（内核模式：调 mihomo API；内置模式暂不支持）。"""
        if self._engine() != "clash":
            QMessageBox.information(self, "断开连接",
                                    "内置引擎暂不支持断开单条连接，可切到 Clash 内核使用。")
            return
        if not (self.kernel is not None and self.kernel.running):
            return
        row = self.conn_table.currentRow()
        conn_ids = getattr(self, "_conn_ids", [])
        if row < 0 or row >= len(conn_ids):
            QMessageBox.information(self, "断开连接", "请先在表格中选中一条连接。")
            return
        conn_id = conn_ids[row]
        if not conn_id:
            return

        def work():
            self.kernel.close_connection(conn_id)

        self._run(work, lambda _r: self.conn_hint.setText("已断开选中连接"),
                  lambda e: self.conn_hint.setText(f"断开失败：{e}"))

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

    # -- 内核（mihomo）-----------------------------------------------
    def _kernel_state_text(self):
        path = clash_kernel.find_kernel(
            getattr(self.config_manager, "proxy_kernel_path", ""))
        if path:
            short = path if len(path) <= 60 else "…" + path[-58:]
            return f"已找到：{short}"
        return "未找到内核，点击右侧按钮自动下载（约 12MB）"

    def _engine(self):
        return self.engine_combo.currentData() or "builtin"

    def _engine_running(self):
        if self._engine() == "clash":
            return self.kernel is not None and self.kernel.running
        return self.proxy.running

    def _clash_mode(self):
        """SkyGuard 模式 → mihomo 模式。smart 用 rule 引擎 + GEOIP,CN,DIRECT。"""
        mode = self.mode_combo.currentData()
        return "rule" if mode == MODE_SMART else mode

    def _local_dns_available(self):
        """DNS 过滤器在跑时让内核 DNS 走本机 53，代理流量同样经过广告过滤。"""
        import socket
        try:
            with socket.create_connection(("127.0.0.1", 53), timeout=0.3):
                return True
        except OSError:
            return False

    def on_engine_changed(self):
        engine = self._engine()
        self.config_manager.set_proxy_config(engine=engine)
        if self._engine_running():
            # 运行中切换内核：直接按新引擎重启，系统代理指向不变
            self.on_stop_proxy()
            self.on_start_proxy()
        self.kernel_label.setText(self._kernel_state_text())

    def on_locate_or_download_kernel(self):
        path = clash_kernel.find_kernel(
            getattr(self.config_manager, "proxy_kernel_path", ""))
        if path:
            self.kernel_label.setText(f"已找到：{path}")
            QMessageBox.information(self, "Clash 内核", f"使用内核：\n{path}")
            return
        if not QMessageBox.question(
                self, "下载内核",
                "未找到 mihomo 内核，是否从 GitHub 自动下载官方版（约 12MB）？\n"
                "也可以把 mihomo.exe 放到 %USERPROFILE%\\.skyguard\\core\\ 目录。"
                ) == QMessageBox.StandardButton.Yes:
            return
        self.kernel_btn.setEnabled(False)
        self.kernel_label.setText("正在下载内核…")

        def work():
            return clash_kernel.download_kernel(progress=lambda m: self._ui(
                lambda: self.kernel_label.setText(m)))

        def done(result):
            self.kernel_btn.setEnabled(True)
            self.kernel_label.setText(f"已下载：{result}")
            self.sub_hint.setText("内核下载完成，可以启动代理了")

        def failed(err):
            self.kernel_btn.setEnabled(True)
            self.kernel_label.setText(f"下载失败：{err}")
            self.sub_hint.setText(f"内核下载失败：{err}")

        self._run(work, done, failed)

    def _start_clash(self, port, host):
        """用 mihomo 内核启动代理。成功返回 True。"""
        kernel_path = clash_kernel.find_kernel(
            getattr(self.config_manager, "proxy_kernel_path", ""))
        if not kernel_path:
            QMessageBox.warning(self, "Clash 内核",
                                "未找到 mihomo 内核，请先点击「下载内核」。\n"
                                "内核原生支持 hysteria2 / vless 等全部协议。")
            return False
        if self.kernel is not None:
            self.kernel.stop()
        try:
            kernel = MihomoKernel(
                kernel_path,
                os.path.join(os.path.expanduser("~"), ".skyguard", "clash"),
                mixed_port=port,
                api_port=self.config_manager.proxy_clash_api_port,
                allow_lan=(host == "0.0.0.0"))
            accel_domains = set(self.ip_cache.data.keys())
            config = clash_kernel.build_config(
                subscriptions=self.node_store.subscriptions,
                manual_nodes=[n for n in (ProxyNode.from_dict(m)
                                          for m in self.node_store.manual)
                              if n and n.supported],
                rules=self._rules_for_engine(),
                mixed_port=port,
                api_port=self.config_manager.proxy_clash_api_port,
                allow_lan=(host == "0.0.0.0"),
                clash_mode=self._clash_mode(),
                local_dns=self._local_dns_available(),
                accel_domains=accel_domains)
            kernel.start(config)
        except (KernelNotFound, RuntimeError) as e:
            QMessageBox.critical(self, "代理服务", f"Clash 内核启动失败：\n{e}")
            self._style_pill(False)
            return False
        self.kernel = kernel
        if self.selected_kernel_node:
            try:
                kernel.select_proxy(self.selected_kernel_node)
            except OSError as e:
                logger.debug(f"恢复选中节点失败: {e}")
        return True

    def _stop_kernel(self):
        if self.kernel is not None:
            try:
                self.kernel.stop()
            except Exception as e:
                logger.debug(f"停止内核失败: {e}")
            self.kernel = None

    def on_start_proxy(self):
        port = self.listen_port.value()
        host = self.listen_host.currentText()
        mode = self.mode_combo.currentData()
        self.config_manager.set_proxy_config(enabled=True, host=host, port=port, mode=mode)

        if self._engine() == "clash":
            self.proxy.stop()          # 内核模式下内置引擎保持停止
            self.proxy.port = port     # 供系统代理判断使用
            if not self._start_clash(port, host):
                return
        else:
            self._stop_kernel()
            if self.proxy.running and (self.proxy.port != port or self.proxy.host != host):
                # 端口/监听地址改了，先停掉旧监听再按新参数起
                self.proxy.stop()
            self.proxy.host = host
            self.proxy.port = port
            self.proxy.set_mode(mode)
            self.proxy.set_rules(self._rules_for_engine())
            ok = self.proxy.start()
            if not ok:
                QMessageBox.critical(self, "代理服务", "启动失败：\n" + "\n".join(self.proxy.bind_errors or
                                                                            ["端口被占用，换个端口试试"]))
                self._style_pill(False)
                return

        self._style_pill(True)
        self.status_changed.emit(True)
        self.refresh_node_table()

        if self.sysproxy_check.isChecked():
            ok2, msg = system_proxy.set_proxy(f"127.0.0.1:{port}")
            self.conn_hint.setText(msg)
            if not ok2:
                QMessageBox.warning(self, "系统代理", msg)
        self.refresh_status()

    def on_stop_proxy(self):
        port = self.proxy.port
        was_system = system_proxy.is_pointing_to(port)
        self._stop_kernel()
        self.proxy.stop()
        self._style_pill(False)
        self.config_manager.set_proxy_config(enabled=False)
        self.status_changed.emit(False)
        if was_system:
            ok, msg = system_proxy.clear_proxy()
            self.conn_hint.setText(msg)
        self.refresh_status()
        self.refresh_node_table()

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

    def refresh_status(self, force=False):
        now = time.time()
        if not force and self._status_cache[1] is not None and now - self._status_cache[0] < 2.0:
            info = self._status_cache[1]
        else:
            info = system_proxy.current()
            self._status_cache = (now, info)
        proxy_state = (f"系统代理：{info['server']}" if info["enabled"]
                       else "系统代理：未启用")
        if self._engine() == "clash":
            if self.kernel is not None and self.kernel.running:
                if self.selected_kernel_node:
                    node_state = f"节点：{self.selected_kernel_node}"
                else:
                    node_state = "节点：未选择（内核用默认第一个节点）"
            else:
                node_state = "节点：内核未运行"
        else:
            node = self._current_node()
            if node:
                node_state = f"节点：{node.name}"
            elif self.proxy.engine.mode == MODE_SMART:
                node_state = "节点：未选择（国外站点会直连兜底，建议加一条订阅）"
            else:
                node_state = "节点：未选择（加速规则仍可用）"
        self.status_detail.setText(f"{node_state}    |    {proxy_state}")
        self.sysproxy_btn.setText("取消系统代理" if system_proxy.is_pointing_to(self.proxy.port)
                                  else "设为系统代理")

    def refresh_stats(self):
        # 页面不可见时不刷新，避免后台空转
        if not self.isVisible():
            return
        if self._engine() == "clash":
            self._refresh_stats_kernel()
            return
        snap = self.proxy.stats.snapshot()
        self.stat_cards["total"].setText(str(snap["total"]))
        self.stat_cards["proxied"].setText(str(snap["proxied"]))
        self.stat_cards["accel"].setText(str(snap["accel"]))
        traffic = f"↑{format_bytes(snap['up'])}  ↓{format_bytes(snap['down'])}"
        self.stat_cards["traffic"].setText(traffic)
        self._push_rates(snap["up"], snap["down"])

        rows = snap["recent"]
        # 数据没变化就不重建表格，避免每秒抢焦点、滚动条乱跳
        head = rows[0] if rows else {}
        sig = (snap["total"], snap["active"], len(rows), head.get("time"),
               head.get("up"), head.get("down"), head.get("result"))
        if sig == self._stats_sig:
            return
        self._stats_sig = sig
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

    def _refresh_stats_kernel(self):
        """mihomo 内核模式：统计与连接列表来自 RESTful API。"""
        if not (self.kernel is not None and self.kernel.running):
            return
        try:
            info = self.kernel.traffic()
            conns = self.kernel.recent_connections(limit=60)
        except OSError as e:
            logger.debug(f"读取内核状态失败: {e}")
            return
        self.stat_cards["total"].setText(str(info["active"]))
        proxied = sum(1 for c in conns
                      if c["node"] not in ("DIRECT", "REJECT", ""))
        self.stat_cards["proxied"].setText(str(proxied))
        self.stat_cards["accel"].setText(str(len(conns) - proxied))
        traffic = f"↑{format_bytes(info['up'])}  ↓{format_bytes(info['down'])}"
        self.stat_cards["traffic"].setText(traffic)
        self._push_rates(info["up"], info["down"])

        rows = []
        for c in reversed(conns):
            action = "直连" if c["node"] in ("DIRECT", "") else (
                "拦截" if c["node"] == "REJECT" else "代理")
            rows.append({
                "time": (c["start"] or "")[11:19],
                "host": c["host"], "port": c["port"], "node": c["node"],
                "action": action, "rule": c["rule"], "result": "连接中",
                "up": c["up"], "down": c["down"],
            })
        head = rows[0] if rows else {}
        sig = (info["active"], info["up"], info["down"], len(rows),
               head.get("time"), head.get("up"), head.get("down"))
        if sig == self._stats_sig:
            return
        self._stats_sig = sig
        self._conn_ids = [c["id"] for c in reversed(conns)]
        self.conn_table.setRowCount(len(rows))
        for r, item in enumerate(rows):
            target = f"{item['host']}:{item['port']}"
            if item["node"] and item["node"] not in ("DIRECT", "REJECT"):
                target += f"  ({item['node']})"
            traffic_text = f"{format_bytes(item['up'])} / {format_bytes(item['down'])}"
            values = [item["time"], target, item["action"], item["rule"], traffic_text]
            for c, text in enumerate(values):
                cell = QTableWidgetItem(str(text))
                if c in (0, 2, 4):
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.conn_table.setItem(r, c, cell)

    def _push_rates(self, up_total, down_total):
        """把累计字节数换算成每秒速率，喂给流量曲线。"""
        now = time.monotonic()
        last = self._last_traffic
        self._last_traffic = (now, up_total, down_total)
        if not last or now <= last[0]:
            return
        dt = now - last[0]
        up_rate = max(0.0, (up_total - last[1]) / dt)
        down_rate = max(0.0, (down_total - last[2]) / dt)
        self.traffic_graph.push(up_rate, down_rate)
        self.rate_label.setText(f"↑ {format_bytes(int(up_rate))}/s   ↓ {format_bytes(int(down_rate))}/s")

    def on_clear_logs(self):
        if self._engine() == "clash":
            if self.kernel is not None and self.kernel.running:
                try:
                    self.kernel.close_all_connections()
                except OSError as e:
                    logger.debug(f"清空内核连接失败: {e}")
            self._stats_sig = None
            self.conn_table.setRowCount(0)
            self.refresh_stats()
            return
        self.proxy.stats.reset()
        self.refresh_stats()

    # ------------------------------------------------------------------
    # 节点
    # ------------------------------------------------------------------
    def refresh_node_table(self, latencies=None):
        latencies = latencies or {}
        self.refresh_sub_table()
        if self._engine() == "clash":
            self._refresh_node_table_kernel(latencies)
            return
        keyword = self.node_search.text().strip().lower()
        nodes = self.node_store.all_nodes()
        rows = []
        for node in nodes:
            label = " ".join((node.name, node.server, node.subscription or ""))
            if keyword and keyword not in label.lower():
                continue
            rows.append((node, latencies.get(node.uid)))
        if self.sort_btn.isChecked():
            rows.sort(key=lambda pair: (pair[1] or 99999, pair[0].name))
        self.node_table.setRowCount(len(rows))
        for r, (node, ms) in enumerate(rows):
            values = [
                ("★ " if node.uid == self.selected_uid else "") + node.name,
                node.type.upper(),
                node.server_label,
                f"{ms} ms" if ms else "—",
                node.subscription or "手动",
            ]
            for c, text in enumerate(values):
                cell = QTableWidgetItem(str(text))
                if c in (1, 3, 4):
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if c == 0:
                    cell.setToolTip(node.uid)
                if c == 3 and ms:
                    cell.setForeground(_delay_color(ms))
                self.node_table.setItem(r, c, cell)

        total = len(nodes)
        subs = len(self.node_store.subscriptions)
        shown = f" · 筛出 {len(rows)} 个" if keyword else ""
        self.sub_hint.setText(f"{subs} 个订阅 · 共 {total} 个可用节点{shown}"
                              if total else "还没有节点，先添加订阅或手动填一条链接")
        self.refresh_status()

    def _refresh_node_table_kernel(self, latencies):
        """内核模式：节点列表来自 mihomo（订阅里的 hysteria2/vless 等全部在内）。"""
        skip = {"DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS",
                "GLOBAL", "GLOBAL ", "PROXY", "节点选择"}
        rows = []
        if self.kernel is not None and self.kernel.running:
            try:
                info = self.kernel.proxies()
            except OSError as e:
                logger.debug(f"读取内核节点失败: {e}")
                info = {}
            for name, meta in info.items():
                if name in skip or "all" in meta:
                    continue
                if str(meta.get("type", "")).lower() in ("direct", "reject",
                                                        "compatible", "pass"):
                    continue
                rows.append((name, meta))
        keyword = self.node_search.text().strip().lower()
        if keyword:
            rows = [(n, m) for n, m in rows if keyword in n.lower()]
        decorated = []
        for name, meta in rows:
            hist = meta.get("history") or []
            ms = latencies.get(name) or (hist[-1].get("delay") if hist else 0)
            decorated.append((name, meta, ms))
        if self.sort_btn.isChecked():
            decorated.sort(key=lambda item: (item[2] or 99999, item[0]))
        self.node_table.setRowCount(len(decorated))
        for r, (name, meta, ms) in enumerate(decorated):
            values = [
                ("★ " if name == self.selected_kernel_node else "") + name,
                str(meta.get("type", "")).upper(),
                "—",
                f"{ms} ms" if ms else "—",
                "内核",
            ]
            for c, text in enumerate(values):
                cell = QTableWidgetItem(str(text))
                if c in (1, 3, 4):
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if c == 3 and ms:
                    cell.setForeground(_delay_color(ms))
                self.node_table.setItem(r, c, cell)
        if rows:
            self.sub_hint.setText(f"mihomo 内核 · {len(rows)} 个节点"
                                  "（订阅由内核自动拉取与更新）")
        elif self.kernel is not None and self.kernel.running:
            self.sub_hint.setText("内核已启动但还没有节点，请先添加订阅后重启代理")
        else:
            self.sub_hint.setText("Clash 内核未运行，启动代理后订阅会自动拉取")
        self.refresh_status()

    def on_add_subscription(self):
        url = self.sub_url.text().strip()
        if not url:
            QMessageBox.information(self, "订阅", "请先填写订阅地址。")
            return
        name = self.sub_name.text().strip()
        if self._engine() == "clash":
            # 内核模式：订阅交给 mihomo 拉取，hysteria2 / vless 等协议原生支持
            self.node_store.add_subscription(name or url, url)
            self.node_store.set_subscription_state(
                name or url, interval=self.sub_interval.currentData())
            self.sub_url.clear()
            self.sub_name.clear()
            self.sub_hint.setText("订阅已保存，mihomo 将自动拉取（含 hysteria2 / vless 节点）")
            if self.kernel is not None and self.kernel.running:
                self.on_stop_proxy()
                self.on_start_proxy()
            else:
                self.refresh_node_table()
            return
        self.sub_hint.setText("正在拉取订阅…")

        def work():
            text, meta = fetch_subscription_ex(url)
            nodes, skipped = parse_subscription(text, name or url)
            return nodes, skipped, meta

        def done(result):
            nodes, skipped, meta = result
            if not nodes:
                detail = "、".join(f"{k}×{v}" for k, v in skipped.items())
                tip = f"没有可用的节点（{detail}）" if detail else "订阅里没有识别到节点"
                extra = "；".join(f"{k} 暂不支持（{KNOWN_UNSUPPORTED.get(k, '')}）"
                                 for k in skipped)
                hint = ("\n提示：内置引擎不支持 hysteria2 / vless，"
                        "在上方把内核切换为「Clash 内核 mihomo」即可全部支持。")
                QMessageBox.warning(self, "订阅", tip + ("\n" + extra if extra else "") + hint)
                self.sub_hint.setText("订阅解析失败（可切换 Clash 内核后重试）")
                return
            self.node_store.upsert_subscription(name or url, url, nodes, meta=meta)
            self.node_store.set_subscription_state(
                name or url, interval=self.sub_interval.currentData())
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

    # ------------------------------------------------------------------
    # 订阅面板（Clash Verge 风格：流量 / 到期 / 自动更新）
    # ------------------------------------------------------------------
    def refresh_sub_table(self):
        subs = self.node_store.subscriptions
        self._sub_row_urls = []
        self.sub_table.setRowCount(len(subs))
        for r, sub in enumerate(subs):
            name = sub.get("name") or sub.get("url", "")
            if not sub.get("enabled", True):
                name += "（已停用）"
            meta = sub.get("meta") or {}
            traffic = "—"
            if meta.get("info_present"):
                used = int(meta.get("upload", 0) or 0) + int(meta.get("download", 0) or 0)
                total = int(meta.get("total", 0) or 0)
                traffic = f"{format_traffic(used)} / {format_traffic(total) if total else '不限'}"
                if meta.get("expire"):
                    left_days = (int(meta["expire"]) - time.time()) / 86400
                    if left_days > 0:
                        traffic += f" · 剩 {left_days:.0f} 天"
                    else:
                        traffic += " · 已到期"
            updated = time.strftime("%m-%d %H:%M", time.localtime(sub["updated"])) \
                if sub.get("updated") else "从未更新"
            cells = [name, str(len(sub.get("nodes") or [])), traffic, updated]
            self._sub_row_urls.append(sub.get("url", ""))
            for c, text in enumerate(cells):
                cell = QTableWidgetItem(str(text))
                if c in (1, 3):
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if sub.get("error"):
                    cell.setToolTip(f"上次更新失败：{sub['error']}")
                self.sub_table.setItem(r, c, cell)

    def on_update_subscriptions(self, only_selected=False, targets=None):
        """更新订阅。内置引擎重新拉取并解析；内核模式让 mihomo 重拉 provider。"""
        if getattr(self, "_updating_subs", False):
            return
        subs = self.node_store.subscriptions
        if targets is not None:
            todo = targets
        elif only_selected:
            row = self.sub_table.currentRow()
            if row < 0 or row >= len(subs):
                QMessageBox.information(self, "更新订阅", "请先在订阅列表中选中一行。")
                return
            todo = [subs[row]]
        else:
            todo = [s for s in subs if s.get("enabled", True)]
        if not todo:
            self.sub_hint.setText("没有可更新的订阅")
            return

        self._updating_subs = True
        self.sub_hint.setText(f"正在更新 {len(todo)} 个订阅…")

        def work():
            results = []
            for sub in todo:
                name = sub.get("name") or sub.get("url", "")
                url = sub.get("url", "")
                if self._engine() == "clash":
                    # 内核模式：让 mihomo 立即重拉 provider
                    err = ""
                    try:
                        if self.kernel is not None and self.kernel.running:
                            self.kernel.update_provider(clash_kernel.provider_name(name))
                        else:
                            err = "内核未运行"
                    except OSError as e:
                        err = str(e)
                    results.append((name, 0, err))
                    continue
                try:
                    text, meta = fetch_subscription_ex(url)
                    nodes, skipped = parse_subscription(text, name)
                    if not nodes and not skipped and meta.get("local"):
                        raise ValueError("本地文件为空")
                    self.node_store.upsert_subscription(name, url, nodes, meta=meta)
                    results.append((name, len(nodes), None))
                except Exception as e:
                    self.node_store.update_subscription_meta(name, error=str(e))
                    results.append((name, 0, str(e)))
            return results

        def done(results):
            self._updating_subs = False
            ok = [f"{n}（{c} 节点）" for n, c, err in results if not err]
            bad = [f"{n}：{err}" for n, c, err in results if err]
            if self._engine() == "clash":
                self.refresh_node_table()
            parts = []
            if ok:
                parts.append("更新成功：" + "、".join(ok))
            if bad:
                parts.append("失败：" + "；".join(bad))
            self.sub_hint.setText("；".join(parts) if parts else "完成")
            self.refresh_node_table()

        def on_error(err):
            self._updating_subs = False
            self.sub_hint.setText(f"更新失败：{err}")

        self._run(work, done, on_error)

    def _auto_update_subscriptions(self):
        """到期自动更新（内置引擎）；内核模式下 mihomo 自己按 provider 间隔拉取。"""
        if not self.isVisible() or self._updating_subs:
            return
        if self._engine() == "clash":
            return
        due = self.node_store.due_subscriptions()
        if due:
            self.on_update_subscriptions(targets=due)

    def on_test_nodes(self):
        if self._testing_nodes:
            return
        if self._engine() == "clash":
            self._test_nodes_kernel()
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

    def _test_nodes_kernel(self):
        """内核模式测速：让 mihomo 对每个节点发真实探测请求。"""
        if not (self.kernel is not None and self.kernel.running):
            QMessageBox.information(self, "测速", "请先启动代理（Clash 内核）。")
            return
        self._testing_nodes = True
        self.sub_hint.setText("正在通过内核测速…")
        kernel = self.kernel

        def work():
            try:
                info = kernel.proxies()
            except OSError as e:
                raise RuntimeError(f"读取内核节点失败: {e}")
            skip = {"DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS",
                    "GLOBAL", "PROXY"}
            names = [n for n, m in info.items()
                     if n not in skip and "all" not in m]

            def probe(name):
                try:
                    return name, kernel.test_delay(name, timeout_ms=5000)
                except OSError:
                    return name, 0

            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(probe, names))
            return {n: ms for n, ms in results if ms}

        def done(latencies):
            self._testing_nodes = False
            self.refresh_node_table(latencies)
            self.sub_hint.setText(f"测速完成：{len(latencies)} 个节点可用")

        def failed(err):
            self._testing_nodes = False
            self.sub_hint.setText(f"测速失败：{err}")

        self._run(work, done, failed)

    def on_use_node(self):
        row = self.node_table.currentRow()
        if self._engine() == "clash":
            rows = getattr(self, "_kernel_rows", [])
            if row < 0 or row >= len(rows):
                return
            name = rows[row][0]
            self.selected_kernel_node = name
            self.config_manager.set_proxy_config(selected_node=f"kernel:{name}")
            if self.kernel is not None and self.kernel.running:
                try:
                    self.kernel.select_proxy(name)
                    self.sub_hint.setText(f"已切换节点：{name}")
                except OSError as e:
                    self.sub_hint.setText(f"切换节点失败：{e}")
            self.refresh_node_table()
            self.refresh_status()
            return
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
        if self._engine() == "clash":
            QMessageBox.information(self, "删除节点",
                                    "内核模式下节点来自订阅，由 mihomo 管理；"
                                    "请移除对应订阅或更新订阅内容。")
            return
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
        rtype = self.rule_type.currentData()
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

    def on_update_geodb(self):
        self.geo_label.setText("正在从 APNIC 下载国内 IP 段…")

        def work():
            return self.geo.update_from_network()

        def done(result):
            segments, cidrs = result
            self.geo_label.setText(f"国内 IP 库：{self.geo.source}")
            self.accel_hint.setText(f"IP 库已更新：{segments} 个网段 / {cidrs} 条 CIDR")
            self.proxy.set_geo(self.geo)

        def failed(err):
            self.geo_label.setText(f"国内 IP 库：{self.geo.source}")
            QMessageBox.warning(self, "更新 IP 库", f"更新失败：{err}")

        self._run(work, done, failed)

    # ------------------------------------------------------------------
    # 退出
    # ------------------------------------------------------------------
    def shutdown(self):
        """程序退出：停服务并还原系统代理，避免把用户的网络留在半截状态。"""
        try:
            port = self.proxy.port
            was_system = system_proxy.is_pointing_to(port)
            self._stop_kernel()
            if self.proxy.running:
                self.proxy.stop()
            if was_system:
                system_proxy.clear_proxy()
        except Exception as e:
            logger.warning(f"退出时清理代理失败: {e}")
