#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""启动项建议引擎测试"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.startup_advisor import (  # noqa: E402
    VERDICT_DISABLE, VERDICT_KEEP, VERDICT_OPTIONAL,
    Advice, advise, summarize, program_missing, extract_program,
)


REAL_EXE = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"),
                        "System32", "notepad.exe")


class FakeItem:
    def __init__(self, name, command=None, kind="run", enabled=True, editable=True, detail=""):
        self.key = f"{kind}:{name}"
        self.name = name
        self.command = REAL_EXE if command is None else command
        self.kind = kind
        self.enabled = enabled
        self.editable = editable
        self.detail = detail


class TestAdvise(unittest.TestCase):
    def test_keep_security(self):
        for name in ("Windows Security notification icon", "360安全卫士", "火绒安全软件", "Kaspersky Security"):
            a = advise(FakeItem(name))
            self.assertEqual(a.verdict, VERDICT_KEEP, name)

    def test_keep_ime(self):
        for name in ("搜狗拼音输入法", "ctfmon", "QQ拼音"):
            a = advise(FakeItem(name, r"C:\Windows\System32\ctfmon.exe"))
            self.assertEqual(a.verdict, VERDICT_KEEP, name)

    def test_disable_updater(self):
        for name in ("Adobe Updater", "Java Update Scheduler", "SunloginClientUpdate",
                     "搜狗输入法升级程序", "MicrosoftEdgeUpdate"):
            a = advise(FakeItem(name))
            self.assertEqual(a.verdict, VERDICT_DISABLE, name)

    def test_disable_game_and_media(self):
        for name in ("Steam", "WeGame", "EpicGamesLauncher", "网易云音乐", "爱奇艺", "迅游加速器"):
            a = advise(FakeItem(name))
            self.assertEqual(a.verdict, VERDICT_DISABLE, name)

    def test_optional_chat_and_cloud(self):
        for name in ("微信", "钉钉", "OneDrive", "百度网盘", "Docker Desktop"):
            a = advise(FakeItem(name))
            self.assertEqual(a.verdict, VERDICT_OPTIONAL, name)

    def test_optional_hardware(self):
        a = advise(FakeItem("Realtek HD Audio Manager"))
        self.assertEqual(a.verdict, VERDICT_OPTIONAL)

    def test_invalid_path_wins(self):
        a = advise(FakeItem("OldTool", r"C:\NotExist\definitely_missing_12345.exe"))
        self.assertEqual(a.verdict, VERDICT_DISABLE)
        self.assertEqual(a.category, "无效残留")

    def test_system_service_keep(self):
        a = advise(FakeItem("Windows Update", r"C:\Windows\system32\svchost.exe", kind="service",
                            editable=False, detail="系统组件"))
        self.assertEqual(a.verdict, VERDICT_KEEP)
        a = advise(FakeItem("SomeVendorSvc", kind="service",
                            editable=False, detail="第三方服务"))
        self.assertEqual(a.verdict, VERDICT_OPTIONAL)

    def test_unknown_conservative(self):
        a = advise(FakeItem("MyOwnScript"))
        self.assertEqual(a.verdict, VERDICT_OPTIONAL)

    def test_impact_score_range(self):
        a = advise(FakeItem("Steam"))
        self.assertGreater(a.score, 0)
        self.assertLessEqual(a.score, 100)
        self.assertGreater(a.est_ms, 0)

    def test_program_missing(self):
        self.assertTrue(program_missing(r"C:\看\不存在\x.exe"))
        self.assertFalse(program_missing(r"rundll32.exe shell32.dll,Control_RunDLL"))
        self.assertFalse(program_missing(r'"C:\Windows\System32\notepad.exe" /a'))

    def test_extract_program(self):
        self.assertEqual(extract_program(r'"C:\Program Files\A B\app.exe" -min'),
                         r"C:\Program Files\A B\app.exe")
        self.assertEqual(extract_program(r"C:\Tools\a.exe --silent"), r"C:\Tools\a.exe")

    def test_summarize(self):
        items = [
            FakeItem("Steam"),
            FakeItem("微信"),
            FakeItem("360安全卫士"),
            FakeItem("Adobe Updater", enabled=False),
        ]
        advices = {i.key: advise(i) for i in items}
        s = summarize(items, advices)
        self.assertEqual(s["total"], 4)
        self.assertEqual(s["enabled"], 3)
        self.assertEqual(s["suggest_disable"], 1)   # 只有 Steam（更新器已禁用）
        self.assertGreater(s["est_saving_ms"], 0)


class TestAdviceDict(unittest.TestCase):
    def test_to_dict(self):
        a = Advice(VERDICT_DISABLE, "自动更新", "r", "i", 900, 30)
        d = a.to_dict()
        self.assertEqual(d["label"], "建议关闭")
        self.assertEqual(d["verdict"], VERDICT_DISABLE)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestNoFalseKeep(unittest.TestCase):
    """OneDrive / Teams 属可按需关闭，不能因为带 Microsoft 前缀就判保留"""

    def test_onedrive_optional(self):
        for name in ("Microsoft OneDrive", "OneDrive", "Microsoft Teams"):
            a = advise(FakeItem(name))
            self.assertEqual(a.verdict, VERDICT_OPTIONAL, name)


class TestSystemTaskProtected(unittest.TestCase):
    """\\Microsoft\\ 下的系统计划任务不应被推荐关闭"""

    def test_windows_task_keep(self):
        for task_path in (r"\Microsoft\Windows\InstallService\ScanForUpdates",
                          r"\Microsoft\Windows\UpdateOrchestrator\Reboot"):
            item = FakeItem("ScanForUpdates", kind="task")
            item.task_path = task_path
            self.assertEqual(advise(item).verdict, VERDICT_KEEP, task_path)


class TestPathNotMisjudged(unittest.TestCase):
    """安装路径里碰巧带 steam/update 不应改变判定（规则按名称匹配）"""

    def test_path_keyword_ignored(self):
        # 真实存在的程序，但命令行参数里带 steam 路径
        item = FakeItem("LosslessScaling", REAL_EXE + ' "E:\\Steam\\steam.exe"')
        self.assertNotEqual(advise(item).verdict, VERDICT_DISABLE)
