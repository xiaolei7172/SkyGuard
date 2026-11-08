#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
全盘空间分析引擎

回答一个朴素的问题：这台机器还有多少空间可以优化、分别藏在哪？

设计原则：
  1. 只读 —— 本模块**绝不删除任何东西**，只做测量与建议；
     真正清理走 clean_engine 的声明式规则（送回收站、可还原）。
  2. 分档 —— risk 0 可安全释放、1 谨慎、2 仅提示（如休眠文件、大文件、重复文件）。
  3. 可中断 —— 全盘扫描耗时不可控，所有遍历都接受 cancel 事件与进度回调。
  4. 不穿越 —— 符号链接 / 目录联接一律跳过，避免重复统计与越界。

扫描内容：
  · 各固定磁盘容量与占用
  · 系统可清理项：回收站、Windows.old、更新缓存、错误报告、临时文件、休眠文件、
    内存转储、系统还原点
  · 应用缓存：浏览器 / 微信 / QQ / 常见软件（复用 clean_engine 的规则测量）
  · 开发工具缓存：pip / npm / yarn / pnpm / Gradle / Maven / NuGet / conda / Cargo / Go / Docker / WSL
  · 安装包残留：下载 / 桌面 / 文档里的大体积安装包
  · 大文件 Top N、重复文件、长期未动的大文件（深度模式）
"""

import os
import time
import heapq
import hashlib
import subprocess

import psutil

from utils.logger import logger
from utils.clean_engine import (
    get_clean_engine, format_size, _is_reparse_point,
)

# 遍历时永远不进入的目录（系统目录 + 权限敏感目录）
SKIP_DIR_NAMES = {
    "windows", "program files", "program files (x86)", "$recycle.bin",
    "system volume information", "recovery", "msocache", "config.msi",
    "windows.old", "程序文件", "$windows.~bt", "$windows.~ws",
}

# 网络文件系统：扫描会因网络抖动长时间阻塞，一律不纳入
REMOTE_FS = {
    "cifs", "smbfs", "nfs", "nfs4", "afpfs", "webdav", "davfs", "ftp",
    "sshfs", "9p", "ceph", "glusterfs", "fuse.sshfs",
}

# 开发工具缓存：(名称, 路径模板, 说明, 清理方式)
DEV_CACHES = [
    ("pip 缓存", r"%LocalAppData%\pip\Cache", "Python 包下载缓存", "pip cache purge"),
    ("npm 缓存", r"%LocalAppData%\npm-cache", "Node.js 包缓存", "npm cache clean --force"),
    ("yarn 缓存", r"%LocalAppData%\Yarn\Cache", "Yarn 包缓存", "yarn cache clean"),
    ("pnpm 存储", r"%LocalAppData%\pnpm\store", "pnpm 全局内容寻址存储", "pnpm store prune"),
    ("Gradle 缓存", r"%USERPROFILE%\.gradle\caches", "Android/Java 构建缓存", "可删除，下次构建重新下载"),
    ("Maven 仓库", r"%USERPROFILE%\.m2\repository", "Java 依赖仓库", "删除后首次构建需重新下载"),
    ("NuGet 缓存", r"%USERPROFILE%\.nuget\packages", ".NET 包缓存", "可删除，还原时重新下载"),
    ("Conda 包缓存", r"%USERPROFILE%\anaconda3\pkgs", "Anaconda 包缓存", "conda clean -a"),
    ("Conda 包缓存", r"%USERPROFILE%\miniconda3\pkgs", "Miniconda 包缓存", "conda clean -a"),
    ("Cargo 缓存", r"%USERPROFILE%\.cargo\registry", "Rust 依赖缓存", "可删除，构建时重新下载"),
    ("Go 模块缓存", r"%USERPROFILE%\go\pkg\mod", "Go 依赖缓存", "go clean -modcache"),
    ("Docker 数据", r"%LocalAppData%\Docker\wsl\data\ext4.vhdx", "Docker 镜像与容器数据", "docker system prune -a"),
    ("WSL 虚拟磁盘", r"%LocalAppData%\Packages\*\LocalState\ext4.vhdx", "WSL 发行版磁盘文件", "wsl --manage <发行版> --set-sparse true"),
]

# 安装包类型
PACKAGE_EXTS = (".exe", ".msi", ".iso", ".zip", ".7z", ".rar", ".dmg", ".pkg")

# 大文件阈值
BIG_FILE_MIN = 200 * 1024 * 1024      # 200MB
DUP_FILE_MIN = 10 * 1024 * 1024       # 10MB
OLD_FILE_DAYS = 730                   # 2 年未修改

# 系统占用的固定大小文件：不能删，也不该出现在「大文件」建议里
SYSTEM_FILE_NAMES = {
    "pagefile.sys", "swapfile.sys", "hiberfil.sys", "memory.dmp",
    "ntuser.dat", "ntuser.dat.log1", "ntuser.dat.log2",
}


def _finding(key, group, name, detail, path, size, count=0, risk=0,
             rule_keys=(), action="", action_text=""):
    return {
        "key": key,
        "group": group,
        "name": name,
        "detail": detail,
        "path": path,
        "size": size,
        "count": count,
        "risk": risk,                 # 0 安全 / 1 谨慎 / 2 仅提示
        "rule_keys": list(rule_keys),  # 可交给 clean_engine 清理的规则
        "action": action,             # rule / open / cmd
        "action_text": action_text,
    }


def _iter_files(root, cancel=None):
    """遍历目录下所有文件（跳过链接与系统目录），产出 (path, stat)"""
    stack = [root]
    while stack:
        if cancel is not None and cancel.is_set():
            return
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if _is_reparse_point(e.path):
                                continue
                            if e.name.lower() in SKIP_DIR_NAMES:
                                continue
                            stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            yield e.path, e.stat(follow_symlinks=False)
                    except OSError:
                        continue
        except OSError:
            continue


def _wildcard_match(pattern, name):
    """仅支持 * 和 ? 的轻量通配（与 clean_engine 保持一致，避免 [] 被当字符集）"""
    import re
    rx = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(rx, name, re.IGNORECASE) is not None


def _expand_pattern_path(template):
    """展开路径中任意层级的 * / ? （末段可以是文件，如 ext4.vhdx）"""
    template = os.path.expandvars(template)
    parts = [p for p in template.split(os.sep) if p]
    if not parts:
        return []
    first = parts[0]
    current = [first + os.sep if len(first) == 2 and first[1] == ":" else first]
    for seg in parts[1:]:
        nxt = []
        for base in current:
            if "*" in seg or "?" in seg:
                try:
                    with os.scandir(base) as it:
                        for e in it:
                            if _wildcard_match(seg, e.name):
                                nxt.append(e.path)
                except OSError:
                    continue
            else:
                cand = os.path.join(base, seg)
                if os.path.exists(cand):
                    nxt.append(cand)
        current = nxt
    return current


def dir_size(path, cancel=None, progress=None, label=""):
    """统计目录或文件占用 → (bytes, 文件数)"""
    if not path:
        return 0, 0
    if os.path.isfile(path):
        try:
            return os.path.getsize(path), 1
        except OSError:
            return 0, 0
    total, count = 0, 0
    for _p, st in _iter_files(path, cancel):
        total += st.st_size
        count += 1
        if progress and count % 2000 == 0:
            progress(f"{label}：已扫描 {count} 个文件", -1)
    return total, count


class DiskAnalyzer:
    """全盘空间分析（只读）"""

    def __init__(self):
        self.engine = get_clean_engine()

    # --------------------------------------
    # 磁盘概览
    # --------------------------------------
    @staticmethod
    def overview(include_removable=False):
        """固定磁盘概览。

        include_removable=False 时排除 U 盘等可移动盘与网络盘：
        前者可能随时拔出，后者一旦断网会让遍历卡住数分钟。
        """
        result = []
        for part in psutil.disk_partitions(all=False):
            if "cdrom" in (part.opts or "") or not part.mountpoint:
                continue
            opts = (part.opts or "").lower()
            fstype = (part.fstype or "").lower()
            if fstype in REMOTE_FS or "remote" in opts or "network" in opts:
                logger.debug(f"跳过网络盘 {part.mountpoint}（{fstype}）")
                continue
            if not include_removable and "removable" in opts:
                logger.debug(f"跳过可移动盘 {part.mountpoint}")
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except OSError:
                continue
            result.append({
                "device": part.device,
                "mount": part.mountpoint,
                "fstype": part.fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent,
            })
        return result

    @staticmethod
    def _fixed_drives(include_removable=False):
        return [d["mount"] for d in DiskAnalyzer.overview(include_removable)]

    # --------------------------------------
    # 主流程
    # --------------------------------------
    def scan(self, deep=False, all_drives=True, progress=None, cancel=None):
        """全盘分析 → 结果 dict"""
        started = time.time()
        say = progress or (lambda msg, pct: None)
        overview = self.overview()
        findings = []

        def tick(msg, pct):
            say(msg, pct)

        def cancelled():
            return cancel is not None and cancel.is_set()

        # 1) 磁盘占用概览
        tick("正在读取磁盘容量…", 2)
        for d in overview:
            findings.append(_finding(
                key=f"disk:{d['mount']}", group="磁盘占用",
                name=f"{d['mount']} 已用空间",
                detail=f"{format_size(d['used'])} / {format_size(d['total'])}（{d['percent']:.0f}%）",
                path=d["mount"], size=d["used"], risk=2,
                action="open", action_text="剩余 " + format_size(d["free"]),
            ))

        # 2) 已知系统位置
        tick("正在检查系统残留与回收站…", 6)
        findings += self._scan_system(cancel)

        # 3) 应用缓存（复用清理规则的测量，risk<=1，排除已单列的回收站）
        tick("正在统计应用缓存…", 14)
        findings += self._scan_app_caches(cancel)

        # 4) 开发工具缓存
        tick("正在统计开发工具缓存…", 22)
        findings += self._scan_dev_caches(cancel, tick)

        # 5) 安装包残留
        tick("正在查找安装包残留…", 30)
        findings += self._scan_installers(cancel)

        # 6) 深度：大文件 / 重复 / 长期未动
        big_files, duplicates, old_files = [], [], []
        if deep:
            roots = self._fixed_drives() if all_drives else [os.environ.get("SystemDrive", "C:") + os.sep]
            tick("正在扫描大文件（深度模式）…", 36)
            big_files = self._scan_big_files(roots, cancel, tick)
            if not cancelled():
                tick("正在比对重复文件（深度模式）…", 72)
                duplicates = self._find_duplicates(big_files, cancel, tick)
            old_files = self._filter_old(big_files)

            for bf in big_files[:40]:
                findings.append(_finding(
                    key=f"file:{bf['path']}", group="大文件",
                    name=os.path.basename(bf["path"]),
                    detail=f"{format_size(bf['size'])}，{time.strftime('%Y-%m-%d', time.localtime(bf['mtime']))} 修改",
                    path=bf["path"], size=bf["size"], risk=2,
                    action="open", action_text="仅提示，请自行判断",
                ))
            for i, dup in enumerate(duplicates[:30], 1):
                findings.append(_finding(
                    key=f"dup:{i}:{dup['hash'][:8]}", group="重复文件",
                    name=f"重复组 {i}（{len(dup['paths'])} 份，可省 {format_size(dup['wasted'])}）",
                    detail=f"同一份 {format_size(dup['size'])} 的文件有 {len(dup['paths'])} 个副本"
                           "（仅在 200MB 以上的大文件中比对）",
                    path=dup["paths"][0], size=dup["wasted"], count=len(dup["paths"]), risk=2,
                    action="open", action_text="保留一份即可",
                ))
            for of in old_files[:20]:
                findings.append(_finding(
                    key=f"old:{of['path']}", group="长期未动",
                    name=os.path.basename(of["path"]),
                    detail=f"{format_size(of['size'])}，{time.strftime('%Y-%m-%d', time.localtime(of['mtime']))} 之后未修改",
                    path=of["path"], size=of["size"], risk=2,
                    action="open", action_text="可归档或删除",
                ))

        # 7) 汇总
        #    可一键清理 = 有 rule_keys（走 clean_engine，送回收站）
        #    需手动处理 = risk<=1 但只是给出路径/命令（开发缓存、安装包）
        #    仅提示     = risk==2（大文件、重复文件、休眠文件等），不计入磁盘占用
        disk_used = sum(d["used"] for d in overview)
        reclaimable = sum(f["size"] for f in findings
                          if f["risk"] <= 1 and f["rule_keys"])
        manual = sum(f["size"] for f in findings
                     if f["risk"] <= 1 and not f["rule_keys"] and f["group"] != "磁盘占用")
        notice = sum(f["size"] for f in findings
                     if f["risk"] >= 2 and f["group"] != "磁盘占用")

        tick("分析完成", 100)
        return {
            "overview": overview,
            "findings": findings,
            "big_files": big_files,
            "duplicates": duplicates,
            "old_files": old_files,
            "total_reclaimable": reclaimable,
            "total_manual": manual,
            "total_notice": notice,
            "disk_used": disk_used,
            "finding_count": len(findings),
            "elapsed": time.time() - started,
            "deep": deep,
            "cancelled": cancelled(),
        }

    # --------------------------------------
    # 系统残留
    # --------------------------------------
    def _scan_system(self, cancel):
        items = []
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        sysdrive = os.environ.get("SystemDrive", "C:") + os.sep

        # 回收站（各盘）
        # 注意：清空回收站不可恢复，因此不参与「一键清理可释放项」，
        # 只在这里如实展示，让用户去「规则清理」页单独确认。
        rb_size, rb_count = self._recycle_stats(cancel)
        if rb_size:
            items.append(_finding(
                "recycle_bin", "系统可清理", "回收站",
                f"各磁盘回收站共 {rb_count} 个文件；清空后不可恢复，需单独确认",
                sysdrive, rb_size, rb_count, risk=1,
                rule_keys=["recycle_bin"], action="rule",
                action_text="需到「规则清理」页单独清空",
            ))

        # Windows.old / 升级临时目录
        for name, path in (
            ("旧版 Windows（Windows.old）", os.path.join(sysdrive, "Windows.old")),
            ("Windows 升级临时文件（~BT）", os.path.join(sysdrive, "$WINDOWS.~BT")),
            ("Windows 升级临时文件（~WS）", os.path.join(sysdrive, "$WINDOWS.~WS")),
        ):
            if cancel is not None and cancel.is_set():
                return items
            if os.path.isdir(path):
                size, count = dir_size(path, cancel)
                items.append(_finding(
                    f"winold:{path}", "系统可清理", name,
                    "系统升级后的旧版本备份，确认新系统正常后可通过「磁盘清理」移除",
                    path, size, count, risk=1, action="cmd",
                    action_text="磁盘清理 → 清理系统文件",
                ))

        # 休眠文件
        hib = os.path.join(sysdrive, "hiberfil.sys")
        if os.path.isfile(hib):
            try:
                size = os.path.getsize(hib)
            except OSError:
                size = 0
            if size:
                items.append(_finding(
                    "hiberfil", "系统可清理", "休眠 / 快速启动文件",
                    "hiberfil.sys，占用等于内存容量的一部分；不用休眠可关闭以释放",
                    hib, size, 1, risk=2, action="cmd",
                    action_text="管理员执行 powercfg /h off",
                ))

        # 内存转储
        for name, path in (
            ("系统内存转储", os.path.join(sysroot, "MEMORY.DMP")),
            ("崩溃转储目录", os.path.join(sysroot, "Minidump")),
        ):
            if os.path.exists(path):
                size, count = dir_size(path, cancel)
                if size:
                    items.append(_finding(
                        f"dump:{path}", "系统可清理", name,
                        "蓝屏/崩溃时生成的内存镜像，排查完可删",
                        path, size, count, risk=1, action="open",
                        action_text="确认无需排查后可删",
                    ))

        # 系统还原点
        vss = self._shadow_storage()
        if vss:
            used, maxsize = vss
            items.append(_finding(
                "vss", "系统可清理", "系统还原点",
                f"还原点占用 {format_size(used)}（上限 {format_size(maxsize)}）；保留最近一个即可",
                "", used, 0, risk=2, action="cmd",
                action_text="系统属性 → 系统保护 → 配置",
            ))

        # 系统日志
        logs = os.path.join(sysroot, "Logs")
        if os.path.isdir(logs):
            size, count = dir_size(logs, cancel)
            if size:
                items.append(_finding(
                    "syslogs", "系统可清理", "系统日志（CBS/DISM 等）",
                    "排查系统问题时才需要，一般可删",
                    logs, size, count, risk=2, action="open",
                    action_text="可按需清理 *.log / *.cab",
                ))
        return items

    def _recycle_stats(self, cancel):
        total, count = 0, 0
        for mount in self._fixed_drives():
            root = os.path.join(mount, "$Recycle.Bin")
            if not os.path.isdir(root):
                continue
            s, c = dir_size(root, cancel)
            total += s
            count += c
        return total, count

    @staticmethod
    def _shadow_storage():
        """解析 vssadmin 的输出 → (已用, 上限)；非管理员通常失败，返回 None"""
        def run(args):
            try:
                proc = subprocess.run(
                    args, capture_output=True, timeout=20,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if proc.returncode != 0:
                    return ""
                # vssadmin 在中文系统输出 GBK，不能按 UTF-8 解，否则子线程直接抛异常
                raw = proc.stdout or b""
                for enc in ("gbk", "utf-8", "mbcs"):
                    try:
                        return raw.decode(enc)
                    except (UnicodeDecodeError, LookupError):
                        continue
                return raw.decode("gbk", "ignore")
            except (OSError, subprocess.TimeoutExpired):
                return ""

        out = run(["vssadmin", "list", "shadowstorage"])
        if not out:
            out = run(["vssadmin.exe", "list", "shadowstorage"])
        if not out:
            return None

        import re
        used = re.search(r"(?:已用|Used)\s*(?:的)?\s*(?:阴影副本|Shadow Copy)?\s*(?:存储|Storage)?\s*(?:空间|space)?\s*[:：]?\s*([\d.,]+)\s*(\w+)", out, re.IGNORECASE)
        maxs = re.search(r"(?:最大|Maximum)\s*(?:阴影副本|Shadow Copy)?\s*(?:存储|Storage)?\s*(?:空间|space)?\s*[:：]?\s*([\d.,]+)\s*(\w+)", out, re.IGNORECASE)

        def to_bytes(m):
            if not m:
                return 0
            try:
                num = float(m.group(1).replace(",", ""))
            except ValueError:
                return 0
            unit = m.group(2).lower()
            factors = {"b": 1, "bytes": 1, "kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3,
                       "tb": 1024 ** 4, "字节": 1, "kb字节": 1024, "mb字节": 1024 ** 2, "gb字节": 1024 ** 3}
            return int(num * factors.get(unit, 1))

        used_b, max_b = to_bytes(used), to_bytes(maxs)
        if used_b or max_b:
            return used_b, max_b
        return None

    # --------------------------------------
    # 应用缓存（复用清理规则）
    # --------------------------------------
    def _scan_app_caches(self, cancel):
        items = []
        keys = [r["key"] for r in self.engine.rules
                if r.get("risk", 0) <= 1 and r.get("special") != "recycle_bin"]
        summary = self.engine.scan(keys)
        for key, res in summary.get("rules", {}).items():
            if not res.get("size") or res.get("skipped"):
                continue
            rule = self.engine.get_rule(key)
            if not rule:
                continue
            # 规则的 group 决定归属：系统临时/组件归「系统可清理」，其余（浏览器、应用）归「应用缓存」
            group = "系统可清理" if rule.get("group") in ("系统临时", "系统组件（高级）", "回收站") else "应用缓存"
            items.append(_finding(
                f"rule:{key}", group, rule["name"],
                rule.get("desc", ""),
                "", res["size"], res.get("files", 0),
                risk=rule.get("risk", 0),
                rule_keys=[key], action="rule",
                action_text="可一键清理" if rule.get("risk", 0) == 0 else "谨慎清理",
            ))
        return items

    # --------------------------------------
    # 开发工具缓存
    # --------------------------------------
    def _scan_dev_caches(self, cancel, tick):
        items = []
        seen = set()
        for name, template, desc, howto in DEV_CACHES:
            if cancel is not None and cancel.is_set():
                return items
            if "*" in template or "?" in template:
                paths = _expand_pattern_path(template)
            else:
                expanded = os.path.expandvars(template)
                paths = [expanded] if os.path.exists(expanded) else []

            for p in paths:
                if p.lower() in seen:
                    continue
                seen.add(p.lower())
                size, count = dir_size(p, cancel, progress=tick, label=name)
                if size < 20 * 1024 * 1024:      # 小于 20MB 不值得列
                    continue
                items.append(_finding(
                    f"dev:{p}", "开发工具缓存", name,
                    f"{desc}；清理后不影响项目文件",
                    p, size, count, risk=1, action="cmd", action_text=howto,
                ))
        return items

    # --------------------------------------
    # 安装包残留
    # --------------------------------------
    def _scan_installers(self, cancel):
        items = []
        roots = [os.path.expanduser("~\\Downloads"), os.path.expanduser("~\\Desktop"),
                 os.path.expanduser("~\\Documents")]
        groups = {}
        for root in roots:
            if not os.path.isdir(root):
                continue
            for path, st in _iter_files(root, cancel):
                if cancel is not None and cancel.is_set():
                    return items
                low = path.lower()
                if not low.endswith(PACKAGE_EXTS):
                    continue
                if st.st_size < 50 * 1024 * 1024:
                    continue
                groups.setdefault(root, []).append((path, st))

        for root, files in groups.items():
            total = sum(st.st_size for _p, st in files)
            for path, st in files[:20]:
                items.append(_finding(
                    f"pkg:{path}", "安装包残留", os.path.basename(path),
                    f"{format_size(st.st_size)}，装完就没用了（{os.path.basename(root)}）",
                    path, st.st_size, 1, risk=1, action="open",
                    action_text="确认已安装后删除",
                ))
            if len(files) > 20:
                items.append(_finding(
                    f"pkg-more:{root}", "安装包残留", f"{os.path.basename(root)} 中还有 {len(files) - 20} 个安装包",
                    f"合计约 {format_size(total)}", root, total, len(files), risk=1,
                    action="open", action_text="打开目录筛选",
                ))
        return items

    # --------------------------------------
    # 大文件 / 重复 / 长期未动
    # --------------------------------------
    def _scan_big_files(self, roots, cancel, tick):
        heap = []          # (size, path, mtime)
        scanned = 0
        for root in roots:
            for path, st in _iter_files(root, cancel):
                if cancel is not None and cancel.is_set():
                    return self._heap_sorted(heap)
                scanned += 1
                if scanned % 5000 == 0:
                    # 遍历量不可预知，用对数式爬升给个可见的进度反馈
                    pct = 36 + min(32, scanned // 12000)
                    tick(f"已扫描 {scanned} 个文件，发现 {len(heap)} 个大文件…", pct)
                if st.st_size < BIG_FILE_MIN:
                    continue
                if os.path.basename(path).lower() in SYSTEM_FILE_NAMES:
                    continue
                entry = (st.st_size, path, st.st_mtime)
                if len(heap) < 60:
                    heapq.heappush(heap, entry)
                elif entry[0] > heap[0][0]:
                    heapq.heapreplace(heap, entry)
        return self._heap_sorted(heap)

    @staticmethod
    def _heap_sorted(heap):
        return [{"size": s, "path": p, "mtime": m}
                for s, p, m in sorted(heap, key=lambda x: -x[0])]

    def _find_duplicates(self, big_files, cancel, tick):
        """按大小分组 → 头 64KB 哈希 → 全文件哈希（限制规模，避免长时间占用）"""
        by_size = {}
        for f in big_files:
            by_size.setdefault(f["size"], []).append(f["path"])

        candidates = [(size, paths) for size, paths in by_size.items()
                      if len(paths) >= 2 and size >= DUP_FILE_MIN]
        candidates.sort(key=lambda x: -x[0])
        candidates = candidates[:80]      # 最多比 80 组

        def digest(path, limit=None):
            h = hashlib.sha1()
            try:
                with open(path, "rb") as fh:
                    remaining = limit
                    while True:
                        if cancel is not None and cancel.is_set():
                            return None
                        chunk = fh.read(1024 * 1024)
                        if not chunk:
                            break
                        if remaining is not None:
                            chunk = chunk[:remaining]
                            remaining -= len(chunk)
                        h.update(chunk)
                        if remaining is not None and remaining <= 0:
                            break
            except OSError:
                return None
            return h.hexdigest()

        groups = []
        for i, (size, paths) in enumerate(candidates, 1):
            if cancel is not None and cancel.is_set():
                break
            tick(f"正在比对重复文件（{i}/{len(candidates)} 组）…", 72)
            buckets = {}
            for p in paths:
                d = digest(p, 64 * 1024)
                if not d:
                    continue
                buckets.setdefault(d, []).append(p)
            for _d, same in buckets.items():
                if len(same) < 2:
                    continue
                full = {}
                for p in same:
                    fd = digest(p)
                    if not fd:
                        continue
                    full.setdefault(fd, []).append(p)
                for h, same2 in full.items():
                    if len(same2) < 2:
                        continue
                    groups.append({
                        "hash": h,
                        "size": size,
                        "paths": same2,
                        "wasted": size * (len(same2) - 1),
                    })
        groups.sort(key=lambda g: -g["wasted"])
        return groups

    @staticmethod
    def _filter_old(big_files):
        cutoff = time.time() - OLD_FILE_DAYS * 86400
        return [f for f in big_files if f["mtime"] < cutoff]


_analyzer = None


def get_disk_analyzer():
    global _analyzer
    if _analyzer is None:
        _analyzer = DiskAnalyzer()
    return _analyzer
