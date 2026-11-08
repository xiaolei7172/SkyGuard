#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
配置管理模块
"""

import os
import yaml
from utils.logger import logger
from utils.system_utils import check_auto_start, enable_auto_start, disable_auto_start
from config.app_config import APP_INFO, DEFAULT_CONFIG, SYSTEM_CONFIG


class ConfigManager:
    """配置管理类"""

    def __init__(self, custom_app_info=None, custom_default_config=None, custom_system_config=None):
        """
        初始化配置管理器

        Args:
            custom_app_info (dict, optional): 自定义应用信息，用于覆盖默认值
            custom_default_config (dict, optional): 自定义默认配置，用于覆盖默认值
            custom_system_config (dict, optional): 自定义系统配置，用于覆盖默认值
        """
        # 合并配置
        self.app_info = APP_INFO.copy()
        if custom_app_info:
            self.app_info.update(custom_app_info)

        self.default_config = DEFAULT_CONFIG.copy()
        if custom_default_config:
            self._deep_update(self.default_config, custom_default_config)

        self.system_config = SYSTEM_CONFIG.copy()
        if custom_system_config:
            self.system_config.update(custom_system_config)

        # 设置配置路径
        self.config_dir = os.path.join(os.path.expanduser("~"), self.system_config["config_dir_name"])
        self.log_dir = os.path.join(self.config_dir, self.system_config["log_dir_name"])
        self.config_file = os.path.join(self.config_dir, self.system_config["config_file_name"])

        # 应用设置 - 使用 default_config 默认配置初始化
        self.show_notifications = self.default_config["notifications"]["enabled"]
        self.auto_start = self.default_config["application"]["auto_start"]
        self.monitor_enabled = self.default_config["monitor"]["enabled"]
        self.close_to_tray = self.default_config["application"]["close_to_tray"]
        self.log_retention_days = self.default_config["logging"]["retention_days"]
        self.log_rotation = self.default_config["logging"]["rotation"]
        self.debug_mode = self.default_config["logging"]["debug_mode"]
        self.theme = self.default_config["application"]["theme"]
        self.check_update_on_start = self.default_config["application"]["check_update_on_start"]

        # 内存清理设置
        self.memory_cleaner_enabled = self.default_config["memory_cleaner"]["enabled"]
        self.memory_cleaner_brute_mode = self.default_config["memory_cleaner"]["brute_mode"]
        self.memory_cleaner_switches = self.default_config["memory_cleaner"]["switches"].copy()
        self.memory_cleaner_interval = self.default_config["memory_cleaner"]["interval"]
        self.memory_cleaner_threshold = self.default_config["memory_cleaner"]["threshold"]
        self.memory_cleaner_cooldown = self.default_config["memory_cleaner"]["cooldown"]

        # I/O优先级设置
        self.io_priority_processes = self.default_config["io_priority"]["processes"].copy()

        # 悬浮窗设置
        floating = self.default_config["floating_window"]
        self.floating_enabled = floating["enabled"]
        self.floating_opacity = floating["opacity"]
        self.floating_locked = floating["locked"]
        self.floating_interval = floating["interval"]
        self.floating_pos_x = floating["x"]
        self.floating_pos_y = floating["y"]
        self.floating_items = dict(floating["items"])

        # DNS 过滤器设置
        self._load_dns_config(self.default_config["dns_filter"])

        # 网络加速（代理）设置
        self._load_proxy_config(self.default_config["proxy"])

        # 确保配置目录存在
        self._ensure_directories()

        # 加载配置文件
        self.load_config()

    def _deep_update(self, d, u):
        """
        递归更新嵌套字典

        Args:
            d (dict): 要更新的目标字典
            u (dict): 包含更新值的字典
        """
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._deep_update(d[k], v)
            else:
                d[k] = v

    def _ensure_directories(self):
        """确保配置和日志目录存在"""
        # 确保配置目录存在
        if not os.path.exists(self.config_dir):
            try:
                os.makedirs(self.config_dir)
                logger.debug(f"已创建配置目录: {self.config_dir}")
            except Exception as e:
                logger.error(f"创建配置目录失败: {str(e)}")

        # 确保日志目录存在
        if not os.path.exists(self.log_dir):
            try:
                os.makedirs(self.log_dir)
                logger.debug(f"已创建日志目录: {self.log_dir}")
            except Exception as e:
                logger.error(f"创建日志目录失败: {str(e)}")

    def load_config(self):
        """
        加载配置文件

        Returns:
            bool: 是否加载成功
        """
        # 如果配置文件存在，则读取
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    config_data = yaml.safe_load(f)

                # 如果配置文件为空或无效，使用默认配置
                if not config_data:
                    config_data = self.default_config
                    logger.warning("配置文件为空或无效，将使用默认配置")

                # 读取通知设置
                if "notifications" in config_data and "enabled" in config_data["notifications"]:
                    self.show_notifications = bool(config_data["notifications"]["enabled"])
                    logger.debug(f"已从配置文件加载通知设置: {self.show_notifications}")

                # 读取日志设置
                if "logging" in config_data:
                    if "retention_days" in config_data["logging"]:
                        self.log_retention_days = int(config_data["logging"]["retention_days"])
                    if "rotation" in config_data["logging"]:
                        self.log_rotation = config_data["logging"]["rotation"]
                    if "debug_mode" in config_data["logging"]:
                        self.debug_mode = bool(config_data["logging"]["debug_mode"])
                        logger.debug(f"已从配置文件加载调试模式设置: {self.debug_mode}")

                # 读取应用设置
                if "application" in config_data:
                    if "auto_start" in config_data["application"]:
                        self.auto_start = bool(config_data["application"]["auto_start"])
                        # 检查实际开机自启状态与配置是否一致
                        actual_auto_start = check_auto_start(self.app_info["name"])
                        if self.auto_start != actual_auto_start:
                            logger.warning(
                                f"开机自启配置与实际状态不一致，配置为:{self.auto_start}，实际为:{actual_auto_start}，将以配置为准"
                            )

                        # 确保开机自启状态与配置一致
                        if self.auto_start:
                            enable_auto_start(self.app_info["name"])
                        else:
                            disable_auto_start(self.app_info["name"])

                        logger.debug(f"已从配置文件加载开机自启设置: {self.auto_start}")
                    else:
                        # 如果配置中没有自启设置，检查启动文件夹中是否已设置
                        if check_auto_start(self.app_info["name"]):
                            # 如果启动文件夹中已设置，则更新配置
                            self.auto_start = True
                            logger.debug("检测到启动文件夹中已设置开机自启，已更新配置")

                    # 读取关闭行为设置
                    if "close_to_tray" in config_data["application"]:
                        self.close_to_tray = bool(config_data["application"]["close_to_tray"])
                        logger.debug(
                            f"已从配置文件加载关闭行为设置: {'最小化到后台' if self.close_to_tray else '直接退出'}"
                        )

                    # 读取主题设置
                    if "theme" in config_data["application"]:
                        theme_value = config_data["application"]["theme"]
                        if theme_value in ["light", "dark"]:
                            self.theme = theme_value
                            logger.debug(f"已从配置文件加载主题设置: {self.theme}")
                        else:
                            logger.warning(
                                f"配置文件中的主题值无效: {theme_value}，使用默认值: {self.default_config['application']['theme']}"
                            )
                            self.theme = self.default_config["application"]["theme"]

                    # 读取启动时检查更新设置
                    if "check_update_on_start" in config_data["application"]:
                        self.check_update_on_start = bool(config_data["application"]["check_update_on_start"])
                        logger.debug(f"已从配置文件加载启动时检查更新设置: {self.check_update_on_start}")

                # 读取监控设置
                if "monitor" in config_data and "enabled" in config_data["monitor"]:
                    self.monitor_enabled = bool(config_data["monitor"]["enabled"])
                    logger.debug(f"已从配置文件加载监控设置: {self.monitor_enabled}")

                # 读取内存清理设置
                if "memory_cleaner" in config_data:
                    if "enabled" in config_data["memory_cleaner"]:
                        self.memory_cleaner_enabled = bool(config_data["memory_cleaner"]["enabled"])
                    if "brute_mode" in config_data["memory_cleaner"]:
                        self.memory_cleaner_brute_mode = bool(config_data["memory_cleaner"]["brute_mode"])
                    if "switches" in config_data["memory_cleaner"] and isinstance(
                        config_data["memory_cleaner"]["switches"], list
                    ):
                        for i, switch in enumerate(config_data["memory_cleaner"]["switches"]):
                            if i < len(self.memory_cleaner_switches):
                                self.memory_cleaner_switches[i] = bool(switch)
                    if "interval" in config_data["memory_cleaner"]:
                        self.memory_cleaner_interval = int(config_data["memory_cleaner"]["interval"])
                        # 确保配置值合法
                        if self.memory_cleaner_interval < 60:
                            self.memory_cleaner_interval = 60
                    if "threshold" in config_data["memory_cleaner"]:
                        self.memory_cleaner_threshold = float(config_data["memory_cleaner"]["threshold"])
                        # 确保配置值在合法范围
                        if self.memory_cleaner_threshold < 30:
                            self.memory_cleaner_threshold = 30
                        elif self.memory_cleaner_threshold > 95:
                            self.memory_cleaner_threshold = 95
                    if "cooldown" in config_data["memory_cleaner"]:
                        self.memory_cleaner_cooldown = int(config_data["memory_cleaner"]["cooldown"])
                        # 确保配置值合法
                        if self.memory_cleaner_cooldown < 30:
                            self.memory_cleaner_cooldown = 30
                    logger.debug("已从配置文件加载内存清理设置")

                # 读取I/O优先级设置
                if "io_priority" in config_data and "processes" in config_data["io_priority"]:
                    self.io_priority_processes = config_data["io_priority"]["processes"]
                    logger.debug(f"已从配置文件加载I/O优先级设置，进程数量: {len(self.io_priority_processes)}")

                # 读取悬浮窗设置（旧版配置文件没有这一段，保持默认即可）
                if isinstance(config_data.get("floating_window"), dict):
                    self._load_floating_config(config_data["floating_window"])

                # 读取 DNS 过滤器设置
                if isinstance(config_data.get("dns_filter"), dict):
                    self._load_dns_config(config_data["dns_filter"])

                # 读取网络加速设置
                if isinstance(config_data.get("proxy"), dict):
                    self._load_proxy_config(config_data["proxy"])

                logger.debug("配置文件加载成功")
                return True
            except Exception as e:
                logger.error(f"加载配置文件失败: {str(e)}")
                # 使用默认配置
                self._create_default_config()
                return False
        else:
            # 如果配置文件不存在，则创建默认配置文件
            logger.debug("配置文件不存在，将创建默认配置文件")
            self._create_default_config()
            return True

    def _create_default_config(self):
        """创建默认配置文件"""
        try:
            # 使用默认配置
            with open(self.config_file, "w", encoding="utf-8") as f:
                yaml.dump(self.default_config, f, default_flow_style=False, allow_unicode=True)

            # 从默认配置中重新加载设置
            self.show_notifications = self.default_config["notifications"]["enabled"]
            self.log_retention_days = self.default_config["logging"]["retention_days"]
            self.log_rotation = self.default_config["logging"]["rotation"]
            self.debug_mode = self.default_config["logging"]["debug_mode"]
            self.auto_start = self.default_config["application"]["auto_start"]
            self.close_to_tray = self.default_config["application"]["close_to_tray"]
            self.theme = self.default_config["application"]["theme"]
            self.check_update_on_start = self.default_config["application"]["check_update_on_start"]
            self.monitor_enabled = self.default_config["monitor"]["enabled"]

            # 加载内存清理默认设置
            self.memory_cleaner_enabled = self.default_config["memory_cleaner"]["enabled"]
            self.memory_cleaner_brute_mode = self.default_config["memory_cleaner"]["brute_mode"]
            self.memory_cleaner_switches = self.default_config["memory_cleaner"]["switches"].copy()
            self.memory_cleaner_interval = self.default_config["memory_cleaner"]["interval"]
            self.memory_cleaner_threshold = self.default_config["memory_cleaner"]["threshold"]
            self.memory_cleaner_cooldown = self.default_config["memory_cleaner"]["cooldown"]

            # 加载I/O优先级默认设置
            self.io_priority_processes = self.default_config["io_priority"]["processes"].copy()

            # 加载悬浮窗默认设置
            self._load_floating_config(self.default_config["floating_window"])

            # 加载 DNS 过滤器默认设置
            self._load_dns_config(self.default_config["dns_filter"])

            # 加载网络加速默认设置
            self._load_proxy_config(self.default_config["proxy"])

            logger.debug("已创建并加载默认配置")
        except Exception as e:
            logger.error(f"创建默认配置文件失败: {str(e)}")

    def save_config(self):
        """
        保存配置到文件

        Returns:
            bool: 保存是否成功
        """
        try:
            # 构建配置数据
            config_data = {
                "notifications": {"enabled": self.show_notifications},
                "logging": {
                    "retention_days": self.log_retention_days,
                    "rotation": self.log_rotation,
                    "debug_mode": self.debug_mode,
                },
                "application": {
                    "auto_start": self.auto_start,
                    "close_to_tray": self.close_to_tray,
                    "theme": self.theme,
                    "check_update_on_start": self.check_update_on_start,
                },
                "monitor": {"enabled": self.monitor_enabled},
                "memory_cleaner": {
                    "enabled": self.memory_cleaner_enabled,
                    "brute_mode": self.memory_cleaner_brute_mode,
                    "switches": self.memory_cleaner_switches,
                    "interval": self.memory_cleaner_interval,
                    "threshold": self.memory_cleaner_threshold,
                    "cooldown": self.memory_cleaner_cooldown,
                },
                "io_priority": {"processes": self.io_priority_processes},
                "floating_window": {
                    "enabled": self.floating_enabled,
                    "opacity": self.floating_opacity,
                    "locked": self.floating_locked,
                    "interval": self.floating_interval,
                    "x": self.floating_pos_x,
                    "y": self.floating_pos_y,
                    "items": self.floating_items,
                },
                "dns_filter": {
                    "enabled": self.dns_enabled,
                    "port": self.dns_port,
                    "listen_lan": self.dns_listen_lan,
                    "block_action": self.dns_block_action,
                    "selected_upstream": self.dns_selected_upstream,
                    "upstreams": self.dns_upstreams,
                },
                "proxy": {
                    "enabled": self.proxy_enabled,
                    "mode": self.proxy_mode,
                    "host": self.proxy_host,
                    "port": self.proxy_port,
                    "allow_lan": self.proxy_allow_lan,
                    "set_system_proxy": self.proxy_set_system_proxy,
                    "selected_node": self.proxy_selected_node,
                    "rules": self.proxy_rules,
                    "accel_groups": self.proxy_accel_groups,
                    "extra_domains": self.proxy_extra_domains,
                    "top_n": self.proxy_top_n,
                },
            }

            # 保存到文件
            with open(self.config_file, "w", encoding="utf-8") as f:
                yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)

            logger.debug("配置已保存")
            return True
        except Exception as e:
            logger.error(f"保存配置文件失败: {str(e)}")
            return False

    # ------------------------------------------------------------------
    # 悬浮窗
    # ------------------------------------------------------------------
    def _load_floating_config(self, cfg):
        """从配置字典读取悬浮窗设置，非法值回落到默认值。

        旧版配置文件里没有 floating_window 段，这里所有取值都带默认兜底，
        升级后不需要用户手动改配置。
        """
        default = self.default_config["floating_window"]

        def as_bool(key):
            value = cfg.get(key, default[key])
            return bool(value) if isinstance(value, bool) else default[key]

        def as_float(key, low, high):
            try:
                value = float(cfg.get(key, default[key]))
            except (TypeError, ValueError):
                return default[key]
            return min(high, max(low, value))

        self.floating_enabled = as_bool("enabled")
        self.floating_locked = as_bool("locked")
        self.floating_opacity = as_float("opacity", 0.5, 1.0)
        self.floating_interval = as_float("interval", 0.5, 5.0)

        for axis in ("x", "y"):
            raw = cfg.get(axis, default[axis])
            try:
                value = int(raw) if raw is not None else None
            except (TypeError, ValueError):
                value = None
            setattr(self, f"floating_pos_{axis}", value)

        items = cfg.get("items")
        merged = dict(default["items"])
        if isinstance(items, dict):
            for key, value in items.items():
                if key in merged and isinstance(value, bool):
                    merged[key] = value
        self.floating_items = merged

        logger.debug(f"已从配置文件加载悬浮窗设置: 启用={self.floating_enabled}")

    def _load_dns_config(self, cfg):
        """从配置字典读取 DNS 过滤器设置，非法值回落默认。"""
        default = self.default_config["dns_filter"]
        self.dns_enabled = bool(cfg.get("enabled", default["enabled"]))
        try:
            self.dns_port = min(65535, max(1, int(cfg.get("port", default["port"]))))
        except (TypeError, ValueError):
            self.dns_port = default["port"]
        self.dns_listen_lan = bool(cfg.get("listen_lan", default["listen_lan"]))
        action = cfg.get("block_action", default["block_action"])
        self.dns_block_action = action if action in ("blackhole", "nxdomain") else default["block_action"]
        try:
            self.dns_selected_upstream = max(0, int(cfg.get("selected_upstream", default["selected_upstream"])))
        except (TypeError, ValueError):
            self.dns_selected_upstream = 0
        upstreams = cfg.get("upstreams")
        if isinstance(upstreams, list) and upstreams:
            cleaned = []
            for u in upstreams:
                if not isinstance(u, dict):
                    continue
                addr = str(u.get("address", "")).strip()
                proto = str(u.get("proto", "UDP")).strip().upper()
                if not addr or proto not in ("UDP", "DOH", "DOT"):
                    continue
                cleaned.append({"name": str(u.get("name", "")).strip() or f"{proto}-{addr}",
                                "proto": {"DOH": "DoH", "DOT": "DoT"}.get(proto, "UDP"),
                                "address": addr})
            self.dns_upstreams = cleaned or [dict(x) for x in default["upstreams"]]
        else:
            self.dns_upstreams = [dict(x) for x in default["upstreams"]]
        logger.debug(f"已从配置文件加载 DNS 过滤器设置: 端口={self.dns_port} 上游={len(self.dns_upstreams)}")

    # ------------------------------------------------------------------
    # 网络加速（本地代理）
    # ------------------------------------------------------------------
    def _load_proxy_config(self, cfg):
        """加载代理设置，旧配置文件没有这一段时全部走默认值。"""
        default = self.default_config["proxy"]

        def as_bool(key):
            return bool(cfg.get(key, default[key]))

        self.proxy_enabled = as_bool("enabled")
        self.proxy_set_system_proxy = as_bool("set_system_proxy")
        self.proxy_allow_lan = as_bool("allow_lan")

        mode = str(cfg.get("mode", default["mode"])).lower()
        self.proxy_mode = mode if mode in ("rule", "global", "direct") else default["mode"]

        host = str(cfg.get("host", default["host"])).strip()
        self.proxy_host = host or default["host"]
        try:
            self.proxy_port = min(65535, max(1, int(cfg.get("port", default["port"]))))
        except (TypeError, ValueError):
            self.proxy_port = default["port"]

        self.proxy_selected_node = str(cfg.get("selected_node", "") or "")

        rules = cfg.get("rules")
        if isinstance(rules, list) and rules:
            cleaned = []
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                cleaned.append({
                    "type": str(rule.get("type", "")).strip().lower(),
                    "value": str(rule.get("value", "")).strip(),
                    "action": str(rule.get("action", "")).strip().upper(),
                })
            self.proxy_rules = cleaned
        else:
            self.proxy_rules = []

        groups = cfg.get("accel_groups")
        merged = dict(default["accel_groups"])
        if isinstance(groups, dict):
            for key in merged:
                if key in groups:
                    merged[key] = bool(groups[key])
        self.proxy_accel_groups = merged

        extra = cfg.get("extra_domains")
        if isinstance(extra, list):
            self.proxy_extra_domains = [str(d).strip() for d in extra if str(d).strip()]
        else:
            self.proxy_extra_domains = []

        try:
            self.proxy_top_n = min(8, max(1, int(cfg.get("top_n", default["top_n"]))))
        except (TypeError, ValueError):
            self.proxy_top_n = default["top_n"]

        logger.debug(f"已加载网络加速设置: 端口={self.proxy_port} 模式={self.proxy_mode} "
                     f"规则={len(self.proxy_rules) or '默认'}")

    def _save_proxy(self):
        if not self.save_config():
            logger.warning("网络加速设置保存失败，本次修改仅在当前会话生效")

    def set_proxy_config(self, **kwargs):
        """批量更新代理配置项并落盘。"""
        mapping = {
            "enabled": "proxy_enabled",
            "mode": "proxy_mode",
            "host": "proxy_host",
            "port": "proxy_port",
            "allow_lan": "proxy_allow_lan",
            "set_system_proxy": "proxy_set_system_proxy",
            "selected_node": "proxy_selected_node",
            "rules": "proxy_rules",
            "accel_groups": "proxy_accel_groups",
            "extra_domains": "proxy_extra_domains",
            "top_n": "proxy_top_n",
        }
        for key, value in kwargs.items():
            attr = mapping.get(key)
            if attr:
                setattr(self, attr, value)
        self._save_proxy()

    def _save_dns(self):
        """DNS 过滤器设置变更后落盘。"""
        if not self.save_config():
            logger.warning("DNS 过滤器设置保存失败，本次修改仅在当前会话生效")

    def set_dns_config(self, **kwargs):
        """批量更新 DNS 过滤器配置项并保存。"""
        mapping = {
            "enabled": "dns_enabled",
            "port": "dns_port",
            "listen_lan": "dns_listen_lan",
            "block_action": "dns_block_action",
            "selected_upstream": "dns_selected_upstream",
            "upstreams": "dns_upstreams",
        }
        for key, value in kwargs.items():
            attr = mapping.get(key)
            if attr:
                setattr(self, attr, value)
        self._save_dns()


    def _save_floating(self):
        """悬浮窗设置变更后落盘。写失败只记日志，不影响界面继续用。"""
        if not self.save_config():
            logger.warning("悬浮窗设置保存失败，本次修改仅在当前会话生效")

    def set_floating_enabled(self, enabled):
        self.floating_enabled = bool(enabled)
        self._save_floating()

    def set_floating_position(self, x, y):
        self.floating_pos_x = int(x)
        self.floating_pos_y = int(y)
        self._save_floating()

    def set_floating_opacity(self, opacity):
        self.floating_opacity = min(1.0, max(0.5, float(opacity)))
        self._save_floating()

    def set_floating_locked(self, locked):
        self.floating_locked = bool(locked)
        self._save_floating()

    def set_floating_interval(self, seconds):
        self.floating_interval = min(5.0, max(0.5, float(seconds)))
        self._save_floating()

    def set_floating_item(self, key, enabled):
        """key 为 download/upload/cpu/memory/temp 之一。"""
        if key in self.floating_items:
            self.floating_items[key] = bool(enabled)
            self._save_floating()

    def get_floating_item(self, key):
        return bool(self.floating_items.get(key, True))

    def get_app_name(self):
        """获取应用名称"""
        return self.app_info["name"]

    def get_app_version(self):
        """获取应用版本"""
        return self.app_info["version"]

    def get_app_author(self):
        """获取应用作者"""
        return self.app_info["author"]

    def get_app_description(self):
        """获取应用描述"""
        return self.app_info["description"]

    def get_github_repo(self):
        """获取GitHub仓库地址"""
        return self.app_info["github_repo"]

    def get_github_api_url(self):
        """获取GitHub API URL"""
        return self.app_info["github_api_url"]

    def get_github_releases_url(self):
        """获取GitHub发布页面URL"""
        return self.app_info["github_releases_url"]
