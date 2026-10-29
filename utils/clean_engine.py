#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
磁盘清理引擎

职责：把 clean_rules.py 里的声明式规则翻译成实际的"扫描 → 预览 → 删除"动作。

安全设计（这类功能的生命线）：
  1. 只删规则显式声明的路径，绝不按"文件类型"全盘扫；
  2. 保护区硬拦截：系统关键目录、盘根、用户目录根部一律拒删；
  3. 删除默认走回收站（SHFileOperation + FOF_ALLOWUNDO），可撤销；
  4. 不跟随符号链接 / 目录联接，避免穿越到保护区；
  5. 每次清理落地 JSON 报告，可追溯、可复盘。

不引入任何第三方依赖：回收站与清空回收站均用 ctypes 调 Win32 API，
删除到回收站的能力不依赖 send2trash。
"""

import os
import json
import time
import ctypes
import subprocess
from ctypes import wintypes

import psutil

from utils.logger import logger
from utils.clean_rules import get_rules


# ==========================================
# Win32：回收站相关
# ==========================================
class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", ctypes.c_uint16),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]


FO_DELETE = 3
FOF_SILENT = 0x0004
FOF_NOCONFIRMATION = 0x0010
FOF_ALLOWUNDO = 0x0040
FOF_NOERRORUI = 0x0400
FOF_NOCONFIRMMKDIR = 0x0200

SHERB_NOCONFIRMATION = 0x00000001
SHERB_NOPROGRESSUI = 0x00000002
SHERB_NOSOUND = 0x00000004

REPORT_DIR = os.path.join(os.path.expanduser("~"), ".skyguard", "reports")

# 保护区：任何删除路径只要落在这些目录里（或等于它们）就拒绝
PROTECTED_DIRS = [
    os.path.expandvars(r"%SystemRoot%\System32"),
    os.path.expandvars(r"%SystemRoot%\SysWOW64"),
    os.path.expandvars(r"%SystemRoot%\WinSxS"),
    os.path.expandvars(r"%SystemRoot%\Fonts"),
    os.path.expandvars(r"%SystemRoot%\assembly"),
    os.path.expandvars(r"%ProgramFiles%"),
    os.path.expandvars(r"%ProgramFiles(x86)%"),
    os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu"),
    os.path.expandvars(r"%USERPROFILE%\.ssh"),
    os.path.expandvars(r"%USERPROFILE%\.gitconfig"),
]

# 保护区里允许例外放行的子路径（清理规则确实需要动的）
PROTECTED_EXCEPTIONS = [
    os.path.expandvars(r"%ProgramData%\Microsoft\Windows\WER"),
]


def _norm(p):
    try:
        return os.path.normcase(os.path.abspath(os.path.expandvars(p)))
    except (OSError, ValueError):
        return ""


def _is_protected(path):
    """判断路径是否落在保护区（含盘根、用户目录根部等浅层路径）"""
    p = _norm(path)
    if not p:
        return True
    for ex in PROTECTED_EXCEPTIONS:
        ex_n = _norm(ex)
        if ex_n and (p == ex_n or p.startswith(ex_n + os.sep)):
            return False
    for root in PROTECTED_DIRS:
        r = _norm(root)
        if r and (p == r or p.startswith(r + os.sep)):
            return True
    # 盘根与一级目录（C:\ 或 C:\Windows、C:\Users）一律拒删：
    # 只保护深度 1，不能再收紧——C:\Windows\Temp 这类标准清理目标是深度 2，
    # 收紧到 <=2 会把系统临时文件清理直接误杀（实测踩过）。
    drive, tail = os.path.splitdrive(p)
    segments = [seg for seg in tail.split(os.sep) if seg]
    if len(segments) <= 1:
        return True
    # 用户目录根部
    for root in (os.path.expanduser("~"), os.path.expandvars("%APPDATA%"), os.path.expandvars("%LOCALAPPDATA%")):
        if p == _norm(root):
            return True
    return False


def _is_reparse_point(path):
    """符号链接 / 目录联接：一律不进入，防止穿越"""
    try:
        attrs = os.lstat(path).st_file_attributes
        return bool(attrs & 0x400) or os.path.islink(path)
    except (OSError, AttributeError):
        return False


def _expand_wildcard(template):
    """展开含 * 的路径模板 → 实际存在的目录列表（逐段展开，避免全盘 glob）"""
    template = os.path.expandvars(template)
    parts = template.split(os.sep)
    # 盘符段单独处理（C: 展开会变成 C:\）
    current = [parts[0] + os.sep if len(parts[0]) == 2 and parts[0][1] == ":" else parts[0]]
    for seg in parts[1:]:
        if not seg:
            continue
        nxt = []
        for base in current:
            if "*" in seg or "?" in seg:
                try:
                    with os.scandir(base) as it:
                        for e in it:
                            if not e.is_dir(follow_symlinks=False):
                                continue
                            if _is_reparse_point(e.path):
                                continue
                            if _wildcard_match(seg, e.name):
                                nxt.append(e.path)
                except OSError:
                    continue
            else:
                cand = os.path.join(base, seg)
                if os.path.isdir(cand) and not _is_reparse_point(cand):
                    nxt.append(cand)
        current = nxt
    return current


def _wildcard_match(pattern, name):
    """仅支持 * 和 ? 的轻量通配，避免 fnmatch 把 [] 当字符集"""
    import re
    rx = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(rx, name, re.IGNORECASE) is not None


class CleanEngine:
    """磁盘清理引擎"""

    def __init__(self):
        self.rules = get_rules()

    # --------------------------------------
    # 规则辅助
    # --------------------------------------
    def get_rule(self, key):
        for r in self.rules:
            if r["key"] == key:
                return r
        return None

    @staticmethod
    def _process_running(names):
        if not names:
            return None
        lowered = {n.lower() for n in names}
        for p in psutil.process_iter(["name"]):
            try:
                if (p.info["name"] or "").lower() in lowered:
                    return p.info["name"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    # --------------------------------------
    # 扫描
    # --------------------------------------
    def scan_rule(self, rule):
        """扫描单条规则 → {"files": n, "size": bytes, "dirs": n, "targets": [...], "samples": [...]}"""
        result = {"key": rule["key"], "files": 0, "size": 0, "dirs": 0, "targets": 0, "samples": [], "skipped": ""}

        if rule.get("special") == "recycle_bin":
            size, count = self._recycle_bin_size()
            result.update({"files": count, "size": size})
            return result

        if rule.get("special") == "dism":
            result["skipped"] = "系统组件清理需执行时才能统计"
            return result

        busy = self._process_running(rule.get("skip_if_running"))
        if busy:
            result["skipped"] = f"{busy} 正在运行，已跳过"
            return result

        for target in rule.get("targets", []):
            for base in _expand_wildcard(target["path"]):
                if _is_protected(base) and target.get("mode") != "files":
                    logger.debug(f"跳过受保护目录：{base}")
                    continue
                self._measure_dir(base, target, result)
                result["targets"] += 1

        return result

    def _measure_dir(self, base, target, result):
        pattern = target.get("pattern", "*")
        mode = target.get("mode", "files")
        recursive = target.get("recursive", True)

        if mode == "contents":
            self._walk(base, recursive, result, match_all=True)
        elif mode == "files":
            self._walk(base, recursive, result, match_all=False, pattern=pattern)
        elif mode == "dirs":
            try:
                with os.scandir(base) as it:
                    for e in it:
                        if e.is_dir(follow_symlinks=False) and _wildcard_match(pattern, e.name):
                            if _is_protected(e.path):
                                continue
                            result["dirs"] += 1
                            self._walk(e.path, True, result, match_all=True)
            except OSError:
                pass

    def _walk(self, root, recursive, result, match_all=False, pattern="*"):
        try:
            with os.scandir(root) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if _is_reparse_point(e.path):
                                continue
                            if recursive:
                                self._walk(e.path, True, result, match_all, pattern)
                            continue
                        if not e.is_file(follow_symlinks=False):
                            continue
                        if not match_all and not _wildcard_match(pattern, e.name):
                            continue
                        if _is_protected(e.path):
                            continue
                        size = e.stat(follow_symlinks=False).st_size
                        result["files"] += 1
                        result["size"] += size
                        if len(result["samples"]) < 8:
                            result["samples"].append(e.path)
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            return

    def _recycle_bin_size(self):
        """统计回收站占用（各盘 $Recycle.Bin）"""
        total, count = 0, 0
        for part in psutil.disk_partitions(all=False):
            root = os.path.join(part.mountpoint, "$Recycle.Bin")
            if not os.path.isdir(root):
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(root):
                    dirnames[:] = [d for d in dirnames if not _is_reparse_point(os.path.join(dirpath, d))]
                    for f in filenames:
                        try:
                            total += os.path.getsize(os.path.join(dirpath, f))
                            count += 1
                        except OSError:
                            pass
            except OSError:
                continue
        return total, count

    def scan(self, rule_keys, progress=None):
        """批量扫描，返回汇总"""
        summary = {"rules": {}, "total_size": 0, "total_files": 0, "total_dirs": 0}
        todo = [self.get_rule(k) for k in rule_keys]
        todo = [r for r in todo if r]
        for i, rule in enumerate(todo, 1):
            if progress:
                progress(f"正在扫描：{rule['name']}", int(i / max(len(todo), 1) * 100))
            res = self.scan_rule(rule)
            summary["rules"][rule["key"]] = res
            summary["total_size"] += res["size"]
            summary["total_files"] += res["files"]
            summary["total_dirs"] += res["dirs"]
        return summary

    # --------------------------------------
    # 删除
    # --------------------------------------
    def _send_to_recycle_bin(self, paths):
        """批量送回收站（一次 API 调用传多个路径）"""
        if not paths:
            return 0, 0
        ok = 0
        for i in range(0, len(paths), 200):
            chunk = paths[i:i + 200]
            op = SHFILEOPSTRUCTW()
            op.hwnd = None
            op.wFunc = FO_DELETE
            # pFrom 需双 \0 结尾的连续字符串
            op.pFrom = "\0".join(chunk) + "\0\0"
            op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOF_NOCONFIRMMKDIR
            try:
                ret = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
                if ret == 0 and not op.fAnyOperationsAborted:
                    ok += len(chunk)
            except OSError as e:
                logger.error(f"送回收站失败：{e}")
        return ok, len(paths) - ok

    @staticmethod
    def _delete_permanently(paths):
        ok = 0
        for p in paths:
            try:
                if os.path.isdir(p) and not _is_reparse_point(p):
                    import shutil
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    os.remove(p)
                ok += 1
            except OSError:
                continue
        return ok, len(paths) - ok

    @staticmethod
    def empty_recycle_bin():
        try:
            ret = ctypes.windll.shell32.SHEmptyRecycleBinW(
                None, None, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
            )
            return ret == 0
        except OSError as e:
            logger.error(f"清空回收站失败：{e}")
            return False

    def _collect_paths(self, rule):
        """把规则展开成待删文件/目录清单"""
        files, dirs = [], []
        for target in rule.get("targets", []):
            mode = target.get("mode", "files")
            pattern = target.get("pattern", "*")
            recursive = target.get("recursive", True)
            for base in _expand_wildcard(target["path"]):
                if mode in ("contents", "dirs") and _is_protected(base):
                    continue
                if mode == "contents":
                    self._collect_walk(base, recursive, True, "*", files)
                elif mode == "files":
                    self._collect_walk(base, recursive, False, pattern, files)
                elif mode == "dirs":
                    try:
                        with os.scandir(base) as it:
                            for e in it:
                                if e.is_dir(follow_symlinks=False) and _wildcard_match(pattern, e.name) \
                                        and not _is_protected(e.path) and not _is_reparse_point(e.path):
                                    dirs.append(e.path)
                    except OSError:
                        pass
        return files, dirs

    def _collect_walk(self, root, recursive, match_all, pattern, out):
        try:
            with os.scandir(root) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if recursive and not _is_reparse_point(e.path):
                                self._collect_walk(e.path, True, match_all, pattern, out)
                            continue
                        if not e.is_file(follow_symlinks=False):
                            continue
                        if not match_all and not _wildcard_match(pattern, e.name):
                            continue
                        if _is_protected(e.path):
                            continue
                        out.append(e.path)
                    except OSError:
                        continue
        except OSError:
            return

    def clean(self, rule_keys, to_recycle=True, progress=None):
        """执行清理，返回报告 dict"""
        report = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "to_recycle": to_recycle,
            "rules": [],
            "total_size": 0,
            "total_files": 0,
            "total_dirs": 0,
            "failures": 0,
            "messages": [],
        }

        todo = [self.get_rule(k) for k in rule_keys]
        todo = [r for r in todo if r]

        for i, rule in enumerate(todo, 1):
            if progress:
                progress(f"正在清理：{rule['name']}", int((i - 1) / max(len(todo), 1) * 100))

            entry = {"key": rule["key"], "name": rule["name"], "files": 0, "size": 0, "dirs": 0, "note": ""}

            if rule.get("special") == "recycle_bin":
                if self.empty_recycle_bin():
                    entry["note"] = "回收站已清空"
                else:
                    entry["note"] = "清空失败（可能已被清空或无权限）"
                report["rules"].append(entry)
                continue

            if rule.get("special") == "dism":
                entry["note"] = self._run_dism()
                report["rules"].append(entry)
                continue

            busy = self._process_running(rule.get("skip_if_running"))
            if busy:
                entry["note"] = f"{busy} 正在运行，已跳过"
                report["rules"].append(entry)
                continue

            files, dirs = self._collect_paths(rule)
            size = 0
            for p in files:
                try:
                    size += os.path.getsize(p)
                except OSError:
                    pass

            if to_recycle:
                ok_f, fail_f = self._send_to_recycle_bin(files)
                ok_d, fail_d = self._send_to_recycle_bin(dirs)
            else:
                ok_f, fail_f = self._delete_permanently(files)
                ok_d, fail_d = self._delete_permanently(dirs)

            entry.update({
                "files": ok_f, "size": size, "dirs": ok_d,
                "note": "" if (fail_f + fail_d) == 0 else f"{fail_f + fail_d} 项被占用/无权限跳过",
            })
            report["total_files"] += ok_f
            report["total_dirs"] += ok_d
            report["total_size"] += size
            report["failures"] += fail_f + fail_d
            report["rules"].append(entry)
            logger.info(f"清理 {rule['name']}：{ok_f} 个文件 / {ok_d} 个目录 / {size/1024/1024:.1f} MB")

        if progress:
            progress("清理完成", 100)

        self._save_report(report)
        return report

    @staticmethod
    def _run_dism():
        """调用系统 DISM 清理 WinSxS 被取代组件（耗时长）"""
        cmd = ["Dism.exe", "/Online", "/Cleanup-Image", "/StartComponentCleanup", "/Quiet", "/NoRestart"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if proc.returncode == 0:
                return "组件清理完成（无法前置统计释放量）"
            return f"DISM 返回码 {proc.returncode}"
        except subprocess.TimeoutExpired:
            return "DISM 超时（超过 60 分钟）"
        except OSError as e:
            return f"DISM 调用失败：{e}"

    @staticmethod
    def _save_report(report):
        try:
            os.makedirs(REPORT_DIR, exist_ok=True)
            fn = f"clean_{time.strftime('%Y%m%d_%H%M%S')}.json"
            with open(os.path.join(REPORT_DIR, fn), "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        except OSError as e:
            logger.warning(f"清理报告写入失败：{e}")


_engine = None


def get_clean_engine():
    global _engine
    if _engine is None:
        _engine = CleanEngine()
    return _engine


def format_size(size):
    """字节 → 可读大小"""
    size = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} GB"
