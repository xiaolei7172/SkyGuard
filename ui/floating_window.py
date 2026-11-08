#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
桌面悬浮窗：网速 / CPU / 内存 / 温度 常驻小窗

为什么单独一个模块
------------------
主窗口是"打开才看"的，而网速、温度这类数字是"余光扫一眼"的需求——为此
每次点开主窗口显然不合理。悬浮窗独立成文件，避免 main_window.py 继续膨胀
（它已经 2500+ 行），也便于单独调试。

几个刻意的取舍
--------------
1. **采集放线程里**：温度走 WMI，单次 100~500 ms。放在主线程的 QTimer 里
   会周期性卡住窗口拖动，所以采集整体丢进 QThread，UI 只接收信号。
2. **自绘圆角背景**：Windows 上用 QSS 的 border-radius 配
   WA_TranslucentBackground 会出现黑边，改为 paintEvent 自己画。
3. **位置写回配置**：拖完就存，下次启动原地出现；屏幕分辨率变了则夹回
   可见区域，避免窗口跑到屏幕外面找不回来。
4. **温度读不到就显示 "—"**：不猜、不用 CPU 占用率冒充温度。
"""

import time

from PySide6.QtCore import QPoint, QRectF, Qt, QThread, Signal
from PySide6.QtGui import QAction, QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QApplication, QHBoxLayout, QLabel, QMenu, QVBoxLayout, QWidget

from core.system_metrics import SystemMetrics, format_rate
from ui.styles import AntColors, AntColorsDark, theme_manager
from utils import logger


# 悬浮窗显示项：key -> (图标, 名称, 配置字段, 数值列宽)
ITEMS = (
    ("download", "↓", "下载"),
    ("upload", "↑", "上传"),
    ("cpu", "⚙", "CPU"),
    ("memory", "▤", "内存"),
    ("temp", "🌡", "温度"),
)

OPACITY_STEPS = (0.60, 0.75, 0.85, 0.95, 1.00)


class _MetricsThread(QThread):
    """常驻采集线程：每秒采一次，通过信号把快照交给 UI。"""

    sampled = Signal(dict)

    def __init__(self, interval=1.0, parent=None):
        super().__init__(parent)
        self._interval = max(0.5, float(interval))
        self._running = True
        self._metrics = SystemMetrics()

    def run(self):
        # WMI 在当前线程需要单独初始化 COM，否则 win32com 直接抛异常
        try:
            import pythoncom

            pythoncom.CoInitialize()
        except Exception:
            pythoncom = None

        try:
            while self._running:
                started = time.monotonic()
                try:
                    self.sampled.emit(self._metrics.sample())
                except Exception as e:  # 采集失败不该打死线程
                    logger.error(f"悬浮窗指标采集失败: {e}")
                # 用 wait 而不是 sleep：stop() 能立刻唤醒退出，不用等满一秒
                remaining = self._interval - (time.monotonic() - started)
                if self._running and remaining > 0:
                    self.msleep(int(remaining * 1000))
        finally:
            if pythoncom is not None:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

    def stop(self):
        self._running = False
        self.wait(1500)


class FloatingWindow(QWidget):
    """无边框置顶悬浮窗。"""

    def __init__(self, config_manager, icon_path=None, owner=None):
        # 刻意不挂 Qt 父窗口：主窗口"最小化到托盘"时会 hide()，
        # 子窗口会跟着一起消失——而悬浮窗恰恰要在这时继续显示。
        # 引用由 MainWindow.floating_window 持有，不会被 GC。
        super().__init__(None)
        self.config_manager = config_manager
        self.icon_path = icon_path
        self._owner = owner

        self._drag_offset = None
        self._dragging = False
        self._values = {}
        self._thread = None

        self.setWindowTitle("SkyGuard 悬浮窗")
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool  # Tool 不进任务栏、不抢焦点
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)

        self._build_ui()
        self._apply_geometry()
        self.apply_theme()

        theme_manager.theme_changed.connect(self._on_theme_changed)

    # ------------------------------------------------------------------
    # 构建
    # ------------------------------------------------------------------
    def _build_ui(self):
        outer = QVBoxLayout(self)
        # 留出内边距给自绘圆角，避免文字贴边
        outer.setContentsMargins(10, 8, 10, 10)
        outer.setSpacing(3)

        self._rows = {}
        for key, icon, label in ITEMS:
            row = QWidget(self)
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(4)

            name_label = QLabel(f"{icon} {label}", row)
            value_label = QLabel("—", row)
            value_label.setAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            )
            # 数字列固定宽，数值跳动时整行不会左右抽动
            value_label.setMinimumWidth(96)

            row_layout.addWidget(name_label)
            row_layout.addStretch(1)
            row_layout.addWidget(value_label)

            outer.addWidget(row)
            self._rows[key] = (row, name_label, value_label)
            row.setVisible(self._item_enabled(key))

        hint = QLabel("拖我移动 · 双击锁定 · 右键设置", self)
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(hint)
        self._hint = hint

        self.setFixedWidth(208)
        self.refresh_visibility()
        self._apply_font()

    def _apply_font(self):
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        for key, (_, name_label, value_label) in self._rows.items():
            name_font = QFont()
            name_font.setPointSize(9)
            name_label.setFont(name_font)
            mono.setPointSize(9)
            mono.setBold(True)
            value_label.setFont(mono)
        hint_font = QFont()
        hint_font.setPointSize(7)
        self._hint.setFont(hint_font)

    # ------------------------------------------------------------------
    # 配置读取
    # ------------------------------------------------------------------
    def _item_enabled(self, key):
        """显示项开关统一走 ConfigManager，避免两处各自解析配置键。"""
        getter = getattr(self.config_manager, "get_floating_item", None)
        if getter is not None:
            return getter(key)
        return True

    def _opacity(self):
        return float(getattr(self.config_manager, "floating_opacity", 0.9) or 0.9)

    def _locked(self):
        return bool(getattr(self.config_manager, "floating_locked", False))

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def start(self):
        """显示并按需启动采集线程。"""
        self.refresh_visibility()
        self._apply_geometry()
        self.show()
        self.raise_()
        if self._thread is None:
            interval = float(getattr(self.config_manager, "floating_interval", 1.0) or 1.0)
            self._thread = _MetricsThread(interval=interval, parent=self)
            self._thread.sampled.connect(self._on_sampled)
            self._thread.start()

    def stop(self):
        """隐藏并停掉采集线程（关闭功能时调用，避免空转耗电）。"""
        self.hide()
        if self._thread is not None:
            self._thread.stop()
            self._thread = None

    def shutdown(self):
        """程序退出时调用。"""
        if self._thread is not None:
            self._thread.stop()
            self._thread = None
        try:
            theme_manager.theme_changed.disconnect(self._on_theme_changed)
        except (TypeError, RuntimeError):
            # 没连上或已被 Qt 自动断开，忽略即可
            pass

    # ------------------------------------------------------------------
    # 数据刷新
    # ------------------------------------------------------------------
    def _on_sampled(self, data):
        self._values = data
        self._render_values(data)

    def _render_values(self, data):
        colors = self._colors()

        down = data.get("download_bps") or 0
        up = data.get("upload_bps") or 0
        self._set_value("download", format_rate(down))
        self._set_value("upload", format_rate(up))

        cpu = data.get("cpu_percent")
        self._set_value("cpu", "—" if cpu is None else f"{cpu:.0f}%",
                        self._level_color(cpu, colors))

        mem = data.get("mem_percent")
        mem_text = "—"
        if mem is not None:
            used = data.get("mem_used")
            total = data.get("mem_total")
            if used and total:
                mem_text = f"{mem:.0f}% {used / 1024 ** 3:.0f}/{total / 1024 ** 3:.0f}G"
            else:
                mem_text = f"{mem:.0f}%"
        self._set_value("memory", mem_text, self._level_color(mem, colors))

        cpu_temp = data.get("cpu_temp")
        gpu_temp = data.get("gpu_temp")
        if cpu_temp is None and gpu_temp is None:
            temp_text, temp_color = "—", colors.GRAY_6
            source = data.get("temp_source") or ""
            tip = ("温度不可用：需要 LibreHardwareMonitor/OpenHardwareMonitor 运行，"
                   "或主板支持 ACPI 热区")
            self._rows["temp"][0].setToolTip(tip if not source else f"数据源：{source}")
        else:
            # 单源给完整单位，双源拼一起省宽度：28°C 或 56°/62°C
            if cpu_temp is not None and gpu_temp is not None:
                temp_text = f"{cpu_temp:.0f}°/{gpu_temp:.0f}°C"
            elif cpu_temp is not None:
                temp_text = f"{cpu_temp:.0f}°C"
            else:
                temp_text = f"G{gpu_temp:.0f}°C"
            hottest = max(t for t in (cpu_temp, gpu_temp) if t is not None)
            temp_color = self._level_color(hottest, colors)
            self._rows["temp"][0].setToolTip(f"数据源：{data.get('temp_source') or '未知'}")
        self._set_value("temp", temp_text, temp_color)

    def _set_value(self, key, text, color=None):
        _, _, value_label = self._rows[key]
        value_label.setText(text)
        if color is not None:
            value_label.setStyleSheet(f"color: {color};")

    @staticmethod
    def _level_color(value, colors):
        """占用率/温度分档配色：越低越普通，越高越刺眼。"""
        if value is None:
            return colors.GRAY_6
        if value >= 88:
            return colors.ERROR_6
        if value >= 72:
            return colors.WARNING_6
        return colors.GRAY_10

    def _colors(self):
        return AntColorsDark if theme_manager.is_dark_theme() else AntColors

    # ------------------------------------------------------------------
    # 主题 / 外观
    # ------------------------------------------------------------------
    def _on_theme_changed(self, _theme=None):
        self.apply_theme()
        if self._values:
            self._render_values(self._values)

    def apply_theme(self):
        colors = self._colors()
        for key, (_, name_label, value_label) in self._rows.items():
            name_label.setStyleSheet(f"color: {colors.GRAY_7};")
            value_label.setStyleSheet(f"color: {colors.GRAY_10};")
        self._hint.setStyleSheet(f"color: {colors.GRAY_6};")
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        dark = theme_manager.is_dark_theme()
        # 卡片底色：浅色用白、深色用近黑，透明度由配置控制
        bg = QColor(28, 28, 30) if dark else QColor(255, 255, 255)
        bg.setAlphaF(min(1.0, max(0.5, self._opacity())))
        border = QColor(255, 255, 255, 40) if dark else QColor(0, 0, 0, 26)

        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        painter.setBrush(bg)
        painter.setPen(QPen(border, 1))
        painter.drawRoundedRect(rect, 12, 12)
        super().paintEvent(event)

    def refresh_visibility(self):
        """按配置显示/隐藏每一行，并重算窗口高度。"""
        visible_count = 0
        for key, (row, _, _) in self._rows.items():
            enabled = self._item_enabled(key)
            row.setVisible(enabled)
            visible_count += 1 if enabled else 0

        # 高度交给布局算，别手写行高——字体缩放（125%/150%）下会错位
        self.setFixedWidth(208)
        layout = self.layout()
        if layout is not None:
            layout.invalidate()
            layout.activate()
            self.setFixedHeight(max(46, layout.sizeHint().height()))

    # ------------------------------------------------------------------
    # 位置
    # ------------------------------------------------------------------
    def _apply_geometry(self):
        x = getattr(self.config_manager, "floating_pos_x", None)
        y = getattr(self.config_manager, "floating_pos_y", None)
        screen = QApplication.primaryScreen()
        avail = screen.availableGeometry() if screen else None

        if x is None or y is None:
            if avail:
                # 默认贴右下角，避开任务栏
                x = avail.right() - self.width() - 24
                y = avail.bottom() - self.height() - 24
            else:
                x, y = 100, 100
        elif avail:
            # 分辨率变化后原来的坐标可能落在屏幕外，夹回可见区域
            x = min(max(x, avail.left()), avail.right() - self.width())
            y = min(max(y, avail.top()), avail.bottom() - self.height())

        self.move(int(x), int(y))

    def _save_position(self):
        self.config_manager.set_floating_position(self.x(), self.y())

    # ------------------------------------------------------------------
    # 交互
    # ------------------------------------------------------------------
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and not self._locked():
            self._drag_offset = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            self._dragging = True
            event.accept()

    def mouseMoveEvent(self, event):
        if self._dragging and self._drag_offset is not None:
            self.move(event.globalPosition().toPoint() - self._drag_offset)
            event.accept()

    def mouseReleaseEvent(self, event):
        if self._dragging:
            self._dragging = False
            self._drag_offset = None
            self._save_position()
            event.accept()

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._set_locked(not self._locked())
            event.accept()

    def wheelEvent(self, event):
        # 滚轮调透明度：比进菜单点更快
        current = self._opacity()
        steps = list(OPACITY_STEPS)
        idx = min(range(len(steps)), key=lambda i: abs(steps[i] - current))
        idx = max(0, min(len(steps) - 1, idx + (1 if event.angleDelta().y() > 0 else -1)))
        new_value = steps[idx]
        if new_value != current:
            self.config_manager.set_floating_opacity(new_value)
            self.update()
        event.accept()

    def contextMenuEvent(self, event):
        menu = QMenu(self)

        items_menu = QMenu("显示项目", menu)
        for key, icon, label in ITEMS:
            action = QAction(f"{icon} {label}", items_menu)
            action.setCheckable(True)
            action.setChecked(self._item_enabled(key))
            action.triggered.connect(lambda checked, k=key: self._toggle_item(k, checked))
            items_menu.addAction(action)
        menu.addMenu(items_menu)

        opacity_menu = QMenu("不透明度", menu)
        for value in OPACITY_STEPS:
            action = QAction(f"{int(value * 100)}%", opacity_menu)
            action.setCheckable(True)
            action.setChecked(abs(self._opacity() - value) < 0.01)
            action.triggered.connect(lambda _=False, v=value: self._set_opacity(v))
            opacity_menu.addAction(action)
        menu.addMenu(opacity_menu)

        lock_action = QAction("锁定位置", menu)
        lock_action.setCheckable(True)
        lock_action.setChecked(self._locked())
        lock_action.triggered.connect(self._set_locked)
        menu.addAction(lock_action)

        menu.addSeparator()

        hide_action = QAction("隐藏悬浮窗", menu)
        hide_action.triggered.connect(self._hide_and_sync)
        menu.addAction(hide_action)

        menu.exec(event.globalPos())

    def _hide_and_sync(self):
        """从悬浮窗自己关掉时，要把主窗口的勾选状态同步过去。"""
        self.config_manager.set_floating_enabled(False)
        self.stop()
        owner = self._owner
        if owner is not None and hasattr(owner, "sync_floating_action"):
            owner.sync_floating_action()

    def _toggle_item(self, key, checked):
        self.config_manager.set_floating_item(key, checked)
        self.refresh_visibility()
        if self._values:
            self._render_values(self._values)

    def _set_opacity(self, value):
        self.config_manager.set_floating_opacity(value)
        self.update()

    def _set_locked(self, locked):
        self.config_manager.set_floating_locked(bool(locked))


def create_floating_window(config_manager, icon_path=None, owner=None):
    """工厂函数：日志里留一条，方便排查"悬浮窗不显示"这类问题。"""
    try:
        window = FloatingWindow(config_manager, icon_path, owner)
        logger.debug("悬浮窗已创建")
        return window
    except Exception as e:
        logger.error(f"创建悬浮窗失败: {e}")
        return None
