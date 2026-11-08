#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
系统 DNS 接管

通过 PowerShell 的 Set-DnsClientServerAddress / Get-DnsClientServerAddress
把指定网卡的 DNS 改指本机（127.0.0.1 / ::1），并在接管前把原 DNS 备份到
%USERPROFILE%\\.skyguard\\dns_backup.json，支持一键恢复。

SkyGuard 本身以管理员运行，无需再提权。
"""

import json
import os
import subprocess

from utils.logger import logger

BACKUP_FILE = os.path.join(os.path.expanduser("~"), ".skyguard", "dns_backup.json")
LOCAL_DNS = ["127.0.0.1", "::1"]


def _run_ps(script, timeout=30):
    """执行一段 PowerShell，返回 (stdout, error)。统一 UTF-8 输出。"""
    script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            return "", (result.stderr or "").strip() or f"exit {result.returncode}"
        return result.stdout, None
    except Exception as e:
        return "", str(e)


def list_adapters():
    """枚举有实体连接能力的网卡。返回 [{index, name, status}]。"""
    out, err = _run_ps(
        "Get-NetAdapter | Sort-Object Status -Descending | "
        "Select-Object ifIndex, Name, Status | ConvertTo-Json -Compress"
    )
    if err or not out.strip():
        return []
    data = json.loads(out)
    if isinstance(data, dict):
        data = [data]
    return [{"index": d.get("ifIndex"), "name": d.get("Name"), "status": d.get("Status")}
            for d in data if d.get("ifIndex") is not None]


def get_adapter_dns(index):
    """读取某网卡当前 DNS。返回 (ipv4_list, ipv6_list)。"""
    out, err = _run_ps(
        f"(Get-DnsClientServerAddress -InterfaceIndex {index} -ErrorAction SilentlyContinue | "
        "Select-Object AddressFamily, ServerAddresses | ConvertTo-Json -Compress)"
    )
    v4, v6 = [], []
    if err or not out.strip():
        return v4, v6
    data = json.loads(out)
    if isinstance(data, dict):
        data = [data]
    for d in data:
        addrs = d.get("ServerAddresses") or []
        if d.get("AddressFamily") == 23:  # AF_INET6 = 23，2 = IPv4
            v6 = list(addrs)
        else:
            v4 = list(addrs)
    return v4, v6


def take_over(index):
    """把某网卡 DNS 改指本机。先备份原值。返回 (ok, error)。"""
    v4, v6 = get_adapter_dns(index)
    _backup(index, v4, v6)
    addr_list = ",".join(f'"{a}"' for a in LOCAL_DNS)
    _, err = _run_ps(
        f"Set-DnsClientServerAddress -InterfaceIndex {index} "
        f"-ServerAddresses {addr_list} -ErrorAction Stop", timeout=20)
    if err:
        logger.error(f"网卡 {index} DNS 接管失败: {err}")
        return False, err
    logger.info(f"网卡 {index} 已接管 DNS -> {LOCAL_DNS}")
    return True, None


def restore(index=None):
    """恢复某网卡（None = 全部已接管的网卡）的原 DNS。返回 (restored_list, error)。"""
    backup = _load_backup()
    if not backup:
        return [], "没有可恢复的备份"
    targets = [backup[str(index)]] if index is not None and str(index) in backup else list(backup.values())
    restored = []
    failed = False
    for rec in targets:
        if "index" not in rec:
            continue
        idx = rec["index"]
        v4, v6 = rec.get("ipv4") or [], rec.get("ipv6") or []
        if not v4 and not v6:
            # 原来是自动获取：清掉静态设置
            _, err = _run_ps(
                f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses -ErrorAction Stop")
            if err:
                logger.error(f"网卡 {idx} 恢复自动获取失败: {err}")
                failed = True
                continue
        else:
            addrs = ",".join(f'"{a}"' for a in (v4 + v6))
            _, err = _run_ps(
                f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses {addrs} -ErrorAction Stop")
            if err:
                logger.error(f"网卡 {idx} 恢复失败: {err}")
                failed = True
                continue
        restored.append(rec.get("name") or f"网卡{idx}")
    if restored:
        for rec in targets:
            if rec.get("name") in restored or f"网卡{rec.get('index')}" in restored:
                backup = {k: v for k, v in backup.items() if v.get("index") != rec.get("index")}
        _save_backup(backup)
        logger.info(f"已恢复网卡 DNS: {restored}")
        return restored, None
    return [], "所有网卡恢复失败"


def restore_all():
    restored, err = restore(None)
    return restored, err


def is_taken_over(index):
    """判断某网卡当前是否指向本机 DNS。"""
    v4, v6 = get_adapter_dns(index)
    return bool(v4) and "127.0.0.1" in v4


def _backup(index, v4, v6):
    """备份某网卡当前 DNS。网卡名取不到时用「网卡N」占位，恢复逻辑不依赖名字。"""
    name = f"网卡{index}"
    try:
        out, err = _run_ps(
            f"(Get-NetAdapter -InterfaceIndex {index} -ErrorAction Stop).Name")
        if not err and out.strip():
            name = out.strip().splitlines()[-1].strip()
    except Exception:
        pass
    backup = _load_backup()
    backup[str(index)] = {"index": index, "name": name, "ipv4": v4, "ipv6": v6}
    _save_backup(backup)
    logger.debug(f"网卡 {index}({name}) 原 DNS 已备份: v4={v4} v6={v6}")


def _load_backup():
    try:
        if os.path.exists(BACKUP_FILE):
            with open(BACKUP_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"读取 DNS 备份失败: {e}")
    return {}


def _save_backup(backup):
    try:
        os.makedirs(os.path.dirname(BACKUP_FILE), exist_ok=True)
        with open(BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump(backup, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"写入 DNS 备份失败: {e}")
