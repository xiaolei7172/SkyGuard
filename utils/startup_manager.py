#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
开机启动项管理

枚举 4 个位置：
  1. 注册表 Run / RunOnce（HKCU、HKLM、HKLM\\Wow6432Node）
  2. 启动文件夹（当前用户 + 所有用户）
  3. 计划任务（登录触发 / 开机触发）
  4. 系统服务（自启动，只读展示）

启停机制与任务管理器一致——写 StartupApproved 二进制值，不删除任何注册表项
和文件，因此**完全可逆**；改动前自动导出 .reg 备份，支持一键还原。
"""

import os
import json
import time
import struct

from utils.logger import logger

try:
    import winreg
except ImportError:  # 非 Windows 环境仅用于静态检查
    winreg = None

BACKUP_DIR = os.path.join(os.path.expanduser("~"), ".skyguard", "backup")

# Run 键：(显示名, 根键, 子键路径, 是否 32 位视图, StartupApproved 子键名)
RUN_KEYS = [
    ("HKCU\\...\\Run", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", False, "Run"),
    ("HKCU\\...\\RunOnce", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", False, "Run"),
    ("HKLM\\...\\Run", "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", False, "Run"),
    ("HKLM\\...\\RunOnce", "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", False, "Run"),
    ("HKLM\\...\\Run (32位)", "HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", False, "Run32"),
]

APPROVED_ROOT = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
STARTUP_FOLDER_APPROVED = "StartupFolder"

STARTUP_FOLDERS = [
    ("启动文件夹（当前用户）", os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "HKCU"),
    ("启动文件夹（所有用户）", os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"), "HKLM"),
]

ENABLED_BYTES = bytes([0x02, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0])


def _hive(name):
    return winreg.HKEY_CURRENT_USER if name == "HKCU" else winreg.HKEY_LOCAL_MACHINE


def _disabled_bytes():
    """禁用值：0x03 + 当前时间 FILETIME（任务管理器同款格式）"""
    ft = int((time.time() + 11644473600) * 10_000_000)
    return bytes([0x03, 0x00, 0x00, 0x00]) + struct.pack("<Q", ft)


def _read_approved(hive_name, subkey, value_name):
    """读 StartupApproved → True 启用 / False 禁用 / None 无记录（默认启用）"""
    try:
        with winreg.OpenKey(_hive(hive_name), rf"{APPROVED_ROOT}\{subkey}", 0, winreg.KEY_READ) as k:
            data, _ = winreg.QueryValueEx(k, value_name)
            if isinstance(data, bytes) and data:
                # 首字节奇数=禁用（03/09），偶数=启用（02/06）
                return data[0] % 2 == 0
    except OSError:
        return None
    return None


def _write_approved(hive_name, subkey, value_name, enable):
    """写 StartupApproved（不改动启动项本身，可逆）"""
    path = rf"{APPROVED_ROOT}\{subkey}"
    try:
        with winreg.CreateKeyEx(_hive(hive_name), path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, value_name, 0, winreg.REG_BINARY,
                              ENABLED_BYTES if enable else _disabled_bytes())
        return True
    except OSError as e:
        logger.error(f"写入 StartupApproved 失败（{subkey}\\{value_name}）：{e}")
        return False


class StartupItem:
    """一个启动项"""

    __slots__ = ("key", "name", "kind", "location", "command", "enabled", "editable",
                 "hive", "approved_subkey", "approved_name", "task_path", "detail")

    def __init__(self, key, name, kind, location, command, enabled,
                 editable=True, hive="HKCU", approved_subkey="", approved_name="",
                 task_path="", detail=""):
        self.key = key
        self.name = name
        self.kind = kind               # run / runonce / folder / task / service
        self.location = location
        self.command = command
        self.enabled = enabled
        self.editable = editable
        self.hive = hive
        self.approved_subkey = approved_subkey
        self.approved_name = approved_name
        self.task_path = task_path
        self.detail = detail

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


class StartupManager:
    """启动项管理器"""

    # --------------------------------------
    # 枚举
    # --------------------------------------
    def enum_all(self, include_services=True):
        items = []
        items += self._enum_registry()
        items += self._enum_folders()
        items += self._enum_tasks()
        if include_services:
            items += self._enum_services()
        return items

    def _enum_registry(self):
        items = []
        for label, hive_name, subkey, _wow, approved_sub in RUN_KEYS:
            try:
                with winreg.OpenKey(_hive(hive_name), subkey, 0, winreg.KEY_READ) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _t = winreg.EnumValue(k, i)
                            i += 1
                        except OSError:
                            break
                        if not isinstance(value, str) or not value.strip():
                            continue
                        approved = _read_approved(hive_name, approved_sub, name)
                        items.append(StartupItem(
                            key=f"reg:{hive_name}:{subkey}:{name}",
                            name=name,
                            kind="runonce" if "RunOnce" in subkey else "run",
                            location=label,
                            command=value.strip(),
                            enabled=True if approved is None else approved,
                            hive=hive_name,
                            approved_subkey=approved_sub,
                            approved_name=name,
                        ))
            except OSError:
                continue
        return items

    def _enum_folders(self):
        items = []
        for label, folder, hive_name in STARTUP_FOLDERS:
            if not os.path.isdir(folder):
                continue
            try:
                for entry in os.scandir(folder):
                    if not entry.is_file():
                        continue
                    if entry.name.lower() == "desktop.ini":
                        continue
                    if entry.name.lower().endswith(".disabled"):
                        continue
                    approved = _read_approved(hive_name, STARTUP_FOLDER_APPROVED, entry.name)
                    items.append(StartupItem(
                        key=f"folder:{hive_name}:{entry.path}",
                        name=os.path.splitext(entry.name)[0],
                        kind="folder",
                        location=label,
                        command=entry.path,
                        enabled=True if approved is None else approved,
                        hive=hive_name,
                        approved_subkey=STARTUP_FOLDER_APPROVED,
                        approved_name=entry.name,
                    ))
            except OSError as e:
                logger.debug(f"读取启动文件夹失败 {folder}：{e}")
        return items

    def _enum_tasks(self):
        """计划任务：只列登录触发(3)/开机触发(1) 的任务"""
        items = []
        try:
            import win32com.client
        except ImportError:
            logger.debug("未安装 pywin32，跳过计划任务枚举")
            return items
        try:
            sched = win32com.client.Dispatch("Schedule.Service")
            sched.Connect()
            root = sched.GetFolder("\\")
            stack = [root]
            guard = 0
            while stack and guard < 500:
                folder = stack.pop()
                guard += 1
                try:
                    for task in folder.GetTasks(1):
                        try:
                            triggers = task.Definition.Triggers
                            types = {t.Type for t in triggers}
                            if not types & {1, 3}:      # 1=开机 3=登录
                                continue
                            action = ""
                            try:
                                acts = task.Definition.Actions
                                if acts.Count > 0:
                                    action = getattr(acts.Item(1), "Path", "") or ""
                            except Exception:
                                pass
                            items.append(StartupItem(
                                key=f"task:{task.Path}",
                                name=task.Name,
                                kind="task",
                                location="计划任务",
                                command=action,
                                enabled=bool(task.Enabled),
                                task_path=task.Path,
                                detail=f"触发器类型：{'开机' if 1 in types else '登录'}",
                            ))
                        except Exception:
                            continue
                    for sub in folder.GetFolders(0):
                        stack.append(sub)
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"计划任务枚举失败：{e}")
        return items

    def _enum_services(self):
        """自启动服务（只读）"""
        items = []
        try:
            import win32service
        except ImportError:
            return items
        try:
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
            try:
                resume = 0
                while True:
                    try:
                        services, total, resume = win32service.EnumServiceStatus(scm, None, 0, resume)
                    except Exception:
                        break
                    for svc in services:
                        name, display = svc[0], svc[1]
                        if svc[2] != win32service.SERVICE_AUTO_START:
                            continue
                        path = ""
                        try:
                            h = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_CONFIG)
                            path = win32service.QueryServiceConfig(h)[3]
                            win32service.CloseServiceHandle(h)
                        except Exception:
                            pass
                        system_svc = "\\system32\\" in path.lower() or "\\windows\\" in path.lower()
                        items.append(StartupItem(
                            key=f"service:{name}",
                            name=display or name,
                            kind="service",
                            location="系统服务",
                            command=path or name,
                            enabled=True,
                            editable=False,
                            detail="系统组件" if system_svc else "第三方服务",
                        ))
                    if resume == 0:
                        break
            finally:
                win32service.CloseServiceHandle(scm)
        except Exception as e:
            logger.debug(f"服务枚举失败：{e}")
        return items

    # --------------------------------------
    # 启停
    # --------------------------------------
    def set_enabled(self, item, enable):
        """启用/禁用单个启动项（可逆）"""
        if not item.editable:
            return False, "系统服务项仅支持查看"
        if item.kind in ("run", "runonce", "folder"):
            ok = _write_approved(item.hive, item.approved_subkey, item.approved_name, enable)
            return ok, "" if ok else "写入 StartupApproved 失败（可能缺少管理员权限）"
        if item.kind == "task":
            return self._set_task_enabled(item, enable)
        return False, "未知类型"

    def _set_task_enabled(self, item, enable):
        try:
            import win32com.client
            sched = win32com.client.Dispatch("Schedule.Service")
            sched.Connect()
            # task_path 形如 \Microsoft\Windows\...\Name
            path = item.task_path
            folder_path, _, task_name = path.rpartition("\\")
            folder = sched.GetFolder(folder_path or "\\")
            task = folder.GetTask(task_name)
            task.Enabled = bool(enable)
            return True, ""
        except Exception as e:
            return False, f"计划任务操作失败：{e}"

    # --------------------------------------
    # 备份 / 还原（纯 winreg 实现，不依赖 reg.exe）
    # 说明：早期版本用 subprocess 调 reg.exe 导出，实测在受策略限制的机器上
    # 会被直接拦截（安全软件/组策略禁用 reg.exe 很常见），备份静默失败。
    # 这里改为直接读注册表值并落盘 JSON + 生成可读 .reg，零外部依赖。
    # --------------------------------------
    BACKUP_KEYS = [
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        # StartupApproved 的启用/禁用状态存在**子键**里（Run / Run32 / StartupFolder），
        # 只备份父键会把启停状态漏掉——实测还原后禁用项仍是禁用，必须逐个列全。
        ("HKCU", rf"{APPROVED_ROOT}\Run"),
        ("HKCU", rf"{APPROVED_ROOT}\Run32"),
        ("HKCU", rf"{APPROVED_ROOT}\StartupFolder"),
        ("HKLM", rf"{APPROVED_ROOT}\Run"),
        ("HKLM", rf"{APPROVED_ROOT}\Run32"),
        ("HKLM", rf"{APPROVED_ROOT}\StartupFolder"),
    ]

    @staticmethod
    def _dump_key(hive_name, subkey):
        """读取一个键下的全部值 → {name: {"type": int, "data": ...}}"""
        values = {}
        try:
            with winreg.OpenKey(_hive(hive_name), subkey, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        name, data, vtype = winreg.EnumValue(k, i)
                        i += 1
                    except OSError:
                        break
                    if isinstance(data, bytes):
                        values[name] = {"type": vtype, "data": data.hex()}
                    else:
                        values[name] = {"type": vtype, "data": data}
        except OSError:
            pass
        return values

    @staticmethod
    def _reg_value_line(name, vtype, data):
        """生成 .reg 文件里的一行"""
        name_part = "@" if name == "" else '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'
        if vtype == winreg.REG_SZ:
            return f'{name_part}="{str(data).replace(chr(92), chr(92)*2).replace(chr(34), chr(92)+chr(34))}"'
        if vtype == winreg.REG_EXPAND_SZ:
            hexs = str(data).encode("utf-16-le").hex()
            parts = ",".join(hexs[i:i + 2] for i in range(0, len(hexs), 2))
            return f"{name_part}=hex(2):{parts},00,00"
        if vtype == winreg.REG_DWORD:
            return f"{name_part}=dword:{int(data) & 0xFFFFFFFF:08x}"
        if vtype == winreg.REG_BINARY:
            parts = ",".join(f"{b:02x}" for b in data)
            return f"{name_part}=hex:{parts}"
        return f"; 跳过不支持的注册表类型 {vtype}: {name}"

    def backup(self, tag="auto"):
        """导出启动项相关注册表 → 备份目录（JSON 快照 + 可读 .reg + 清单）"""
        os.makedirs(BACKUP_DIR, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        out_dir = os.path.join(BACKUP_DIR, f"{stamp}_{tag}")
        os.makedirs(out_dir, exist_ok=True)

        snapshot = {}
        exported = 0
        reg_lines = ["Windows Registry Editor Version 5.00", ""]
        for hive_name, subkey in self.BACKUP_KEYS:
            values = self._dump_key(hive_name, subkey)
            if not values:
                continue
            exported += 1
            snapshot[f"{hive_name}\\{subkey}"] = values
            hive_full = "HKEY_CURRENT_USER" if hive_name == "HKCU" else "HKEY_LOCAL_MACHINE"
            reg_lines.append(f"[{hive_full}\\{subkey}]")
            for name, v in values.items():
                if v["type"] == winreg.REG_BINARY:
                    reg_lines.append(self._reg_value_line(name, v["type"], bytes.fromhex(v["data"])))
                else:
                    reg_lines.append(self._reg_value_line(name, v["type"], v["data"]))
            reg_lines.append("")

        try:
            with open(os.path.join(out_dir, "registry_backup.json"), "w", encoding="utf-8") as f:
                json.dump(snapshot, f, ensure_ascii=False, indent=2)
            with open(os.path.join(out_dir, "startup_backup.reg"), "w", encoding="utf-16") as f:
                f.write("\r\n".join(reg_lines))     # .reg 必须 UTF-16 LE 带 BOM
        except OSError as e:
            logger.error(f"写入备份失败：{e}")
            return out_dir, 0

        # 清单快照（便于 diff 与人工核对）
        try:
            items = self.enum_all(include_services=False)
            with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
                json.dump({"time": stamp, "exported_keys": exported,
                           "items": [i.to_dict() for i in items]}, f, ensure_ascii=False, indent=2)
        except OSError as e:
            logger.warning(f"写入启动项清单失败：{e}")

        logger.info(f"启动项备份完成：{out_dir}（{exported} 个注册表位置）")
        return out_dir, exported

    def list_backups(self):
        if not os.path.isdir(BACKUP_DIR):
            return []
        dirs = []
        for name in os.listdir(BACKUP_DIR):
            p = os.path.join(BACKUP_DIR, name)
            if os.path.isdir(p) and os.path.exists(os.path.join(p, "registry_backup.json")):
                dirs.append((name, p))
        return sorted(dirs, reverse=True)

    def restore(self, backup_dir):
        """从 JSON 快照还原（把每个键恢复成备份时的样子）"""
        snap_file = os.path.join(backup_dir, "registry_backup.json")
        if not os.path.isfile(snap_file):
            return False, "备份文件不存在（缺 registry_backup.json）"
        try:
            with open(snap_file, "r", encoding="utf-8") as f:
                snapshot = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            return False, f"读取备份失败：{e}"

        restored, failed = 0, []
        for key_path, values in snapshot.items():
            hive_name, _, subkey = key_path.partition("\\")
            try:
                with winreg.CreateKeyEx(_hive(hive_name), subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ) as k:
                    # 先清空现有值，保证与快照一致（不多不少）
                    existing = []
                    i = 0
                    while True:
                        try:
                            existing.append(winreg.EnumValue(k, i)[0])
                            i += 1
                        except OSError:
                            break
                    for name in existing:
                        if name not in values:
                            try:
                                winreg.DeleteValue(k, name)
                            except OSError:
                                pass
                    for name, v in values.items():
                        if v["type"] == winreg.REG_BINARY:
                            winreg.SetValueEx(k, name, 0, v["type"], bytes.fromhex(v["data"]))
                        else:
                            winreg.SetValueEx(k, name, 0, v["type"], v["data"])
                restored += 1
            except OSError as e:
                logger.error(f"还原 {key_path} 失败：{e}")
                failed.append(f"{key_path}（{e.strerror or e}）")
        if restored:
            msg = f"已还原 {restored} 个注册表位置（重启资源管理器或注销后生效）"
            if failed:
                msg += f"\n{len(failed)} 项失败，通常是缺少管理员权限：\n" + "\n".join(failed[:3])
            return True, msg
        if failed:
            return False, "还原失败（多为缺少管理员权限）：\n" + "\n".join(failed[:3])
        return False, "没有可还原的内容"


_manager = None


def get_startup_manager():
    global _manager
    if _manager is None:
        _manager = StartupManager()
    return _manager
