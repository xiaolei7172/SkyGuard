#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""通知模块单元测试。

原文件是上游遗留的 Demo 脚本（import 时就弹真实系统通知、图标路径写死成
作者的 E:/GitHub/...），导致整套测试必然报错。这里改成用 mock 隔离
windows_toasts 的真实调用，只验证 utils.notification 的组装与容错逻辑。
"""

import os
import queue
import threading
import unittest
from unittest import mock

from config.app_config import APP_INFO
from utils import notification as notif


class TestFindIconPath(unittest.TestCase):
    def test_returns_existing_file_in_dev_tree(self):
        path = notif.find_icon_path()
        self.assertIsNotNone(path, "开发目录下应能定位到 assets/icon/favicon.ico")
        self.assertTrue(os.path.isfile(path))

    def test_returns_none_when_nothing_found(self):
        with mock.patch.object(notif.os.path, "exists", return_value=False):
            self.assertIsNone(notif.find_icon_path())


class TestSendNotification(unittest.TestCase):
    def setUp(self):
        self.fake_toaster = mock.Mock()
        patcher = mock.patch.object(notif, "get_toaster", return_value=self.fake_toaster)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_basic_send_returns_true_and_shows_once(self):
        ok = notif.send_notification("标题", "内容")
        self.assertTrue(ok)
        self.fake_toaster.show_toast.assert_called_once()

    def test_icon_only_added_when_file_exists(self):
        toast = mock.Mock()
        with mock.patch.object(notif, "Toast", return_value=toast):
            notif.send_notification("标题", "内容", icon_path="不存在的图标.ico")
            toast.AddImage.assert_not_called()

            real_icon = notif.find_icon_path()
            notif.send_notification("标题", "内容", icon_path=real_icon)
            toast.AddImage.assert_called_once()

    def test_dict_and_str_buttons_both_supported(self):
        toast = mock.Mock()
        with mock.patch.object(notif, "Toast", return_value=toast):
            notif.send_notification("标题", "内容", buttons=[
                {"text": "打开", "action": "open", "launch": "https://example.org"},
                {"text": "忽略"},
                "确定",
            ])
        self.assertEqual(toast.AddAction.call_count, 3)

    def test_swallows_error_and_returns_false(self):
        toast = mock.Mock()
        toast.AddImage.side_effect = RuntimeError("图标坏了")
        with mock.patch.object(notif, "Toast", return_value=toast):
            # 图标异常只降级警告，不影响发送
            self.assertTrue(notif.send_notification("标题", "内容", icon_path=notif.find_icon_path()))

        self.fake_toaster.show_toast.side_effect = RuntimeError("通知服务不可用")
        self.assertFalse(notif.send_notification("标题", "内容"))


class TestNotificationThread(unittest.TestCase):
    def test_consumes_string_and_dict_messages_then_stops(self):
        q = queue.Queue()
        q.put("纯文本提示")
        q.put({"title": "自定义标题", "message": "字典消息", "silent": False})
        stop = threading.Event()

        calls = []

        def fake_send(title, message, **kwargs):
            calls.append((title, message, kwargs))
            return True

        with mock.patch.object(notif, "send_notification", side_effect=fake_send):
            thread = threading.Thread(
                target=notif.notification_thread, args=(q, None, stop), daemon=True)
            thread.start()
            # 等待两条消息都处理完（最多 5 秒）
            tick = threading.Event()
            for _ in range(100):
                if q.unfinished_tasks == 0:
                    break
                tick.wait(0.05)
            stop.set()
            thread.join(timeout=3)

        self.assertFalse(thread.is_alive(), "停止事件应能让通知线程退出")
        self.assertEqual(len(calls), 2)
        self.assertIn(APP_INFO["name"], calls[0][0])
        self.assertEqual(calls[1][0], "自定义标题")
        self.assertFalse(calls[1][2]["silent"])


if __name__ == "__main__":
    unittest.main()
