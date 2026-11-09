#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""历史统计中心页：清理历史 + DNS/代理每日用量。"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QFrame, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from ui.styles import StyleHelper
from utils import stats_history
from utils.clean_engine import format_size
from utils.logger import logger


def _card(title, value):
    """顶部统计小卡片。返回 (frame, value_label)。"""
    frame = QFrame()
    frame.setObjectName("statCard")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(12, 8, 12, 8)
    t = QLabel(title)
    t.setStyleSheet("color: #8c8c8c;")
    v = QLabel(value)
    v.setObjectName("statCardValue")
    lay.addWidget(t)
    lay.addWidget(v)
    return frame, v


class StatsPage(QWidget):
    """历史统计中心：累计清理、清理记录、每日 DNS/代理用量。"""

    def __init__(self, parent=None, config_manager=None):
        super().__init__(parent)
        self.config_manager = config_manager
        self._daily_sig = None
        self._init_ui()
        self.refresh()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # 顶部统计卡片
        cards_row = QHBoxLayout()
        self.card_total, self.lbl_total = _card("累计释放空间", "—")
        self.card_count, self.lbl_count = _card("清理次数", "—")
        self.card_dns, self.lbl_dns = _card("今日 DNS 查询 / 拦截", "—")
        self.card_proxy, self.lbl_proxy = _card("今日代理连接 / 流量", "—")
        for card in (self.card_total, self.card_count, self.card_dns, self.card_proxy):
            cards_row.addWidget(card, 1)
        layout.addLayout(cards_row)

        # 清理历史
        clean_group = QGroupBox("清理历史")
        clean_lay = QVBoxLayout()
        self.clean_table = QTableWidget(0, 5)
        self.clean_table.setHorizontalHeaderLabels(
            ["时间", "方式", "释放空间", "文件 / 目录", "规则数"])
        self.clean_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        self.clean_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.clean_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.clean_table.setAlternatingRowColors(True)
        clean_lay.addWidget(self.clean_table)
        clean_group.setLayout(clean_lay)
        layout.addWidget(clean_group, 3)

        # 每日用量
        daily_group = QGroupBox("近 30 天每日用量（DNS 查询/拦截 · 代理连接/流量）")
        daily_lay = QVBoxLayout()
        self.daily_table = QTableWidget(0, 6)
        self.daily_table.setHorizontalHeaderLabels(
            ["日期", "DNS 查询", "DNS 拦截", "代理连接", "上行", "下行"])
        self.daily_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        self.daily_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.daily_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.daily_table.setAlternatingRowColors(True)
        daily_lay.addWidget(self.daily_table)
        daily_group.setLayout(daily_lay)
        layout.addWidget(daily_group, 2)

        # 底部操作行
        bottom = QHBoxLayout()
        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.clicked.connect(self.refresh)
        StyleHelper.set_button_type(self.refresh_btn, "default")
        bottom.addWidget(self.refresh_btn)
        bottom.addStretch()
        self.summary_label = QLabel("")
        self.summary_label.setStyleSheet("color: #8c8c8c;")
        bottom.addWidget(self.summary_label, 1)
        layout.addLayout(bottom)

    # ------------------------------------------------------------------
    def refresh(self):
        """重新聚合并填充两个表格与顶部卡片。"""
        try:
            self._refresh_clean()
            self._refresh_daily()
        except Exception as e:
            logger.warning(f"统计页刷新失败: {e}")

    def _refresh_clean(self):
        reports = stats_history.load_clean_reports()
        totals = stats_history.clean_totals(reports)
        self.lbl_total.setText(format_size(totals["total_size"]))
        self.lbl_count.setText(f"{totals['count']} 次")

        self.clean_table.setRowCount(len(reports))
        for r, item in enumerate(reports):
            values = [
                item["time"],
                "回收站" if item["to_recycle"] else "直接删除",
                format_size(item["total_size"]),
                f"{item['total_files']} / {item['total_dirs']}",
                str(item["rule_count"]),
            ]
            for c, text in enumerate(values):
                cell = QTableWidgetItem(str(text))
                if c in (1, 2, 3, 4):
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.clean_table.setItem(r, c, cell)

    def _refresh_daily(self):
        rows = stats_history.load_daily(30)
        head = rows[-1] if rows else {}
        sig = tuple((r["date"], r["dns_queries"], r["dns_blocked"],
                     r["proxy_total"], r["proxy_up"], r["proxy_down"])
                    for r in rows)
        if sig == self._daily_sig:
            return
        self._daily_sig = sig

        self.lbl_dns.setText(
            f"{head.get('dns_queries', 0):,} / {head.get('dns_blocked', 0):,}")
        self.lbl_proxy.setText(
            f"{head.get('proxy_total', 0):,} · ↑{format_size(head.get('proxy_up', 0))}"
            f" ↓{format_size(head.get('proxy_down', 0))}")

        self.daily_table.setRowCount(len(rows))
        for r, item in enumerate(rows):
            values = [
                item["date"],
                f"{item['dns_queries']:,}",
                f"{item['dns_blocked']:,}",
                f"{item['proxy_total']:,}",
                format_size(item["proxy_up"]),
                format_size(item["proxy_down"]),
            ]
            for c, text in enumerate(values):
                cell = QTableWidgetItem(str(text))
                if c > 0:
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.daily_table.setItem(r, c, cell)

        active_days = sum(1 for r in rows
                          if r["dns_queries"] or r["proxy_total"])
        self.summary_label.setText(f"共 {len(rows)} 天记录，其中 {active_days} 天有活动")

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh()
