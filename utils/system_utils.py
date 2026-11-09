#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
系统工具函数模块
"""

import ctypes
import os
import sys
import subprocess
from .logger import logger
from config.app_config import APP_INFO


def is_admin():
    """
    仅查询当前进程是否拥有管理员权限，不触发任何提权动作。

    Returns:
        bool: 是否以管理员权限运行
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as e:  # 非 Windows 或 API 不可用
        logger.debug(f"检测管理员权限失败: {e}")
        return False


def relaunch_as_admin():
    """
    以管理员身份重新启动自身（会弹 UAC）。调用方应在成功后退出当前进程。

    Returns:
        bool: 是否成功发起提权（用户拒绝 UAC 时返回 False）
    """
    try:
        if getattr(sys, "frozen", False):
            # 打包后 sys.executable 就是程序本体，参数不含脚本路径
            exe = sys.executable
            params = subprocess.list2cmdline(sys.argv[1:])
        else:
            exe = sys.executable
            script = os.path.abspath(sys.argv[0])
            params = subprocess.list2cmdline([script] + sys.argv[1:])
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        ok = int(ret) > 32  # >32 表示成功，<=32 是错误码
        if not ok:
            logger.warning(f"请求管理员权限失败，ShellExecuteW 返回 {ret}")
        return ok
    except Exception as e:
        logger.warning(f"以管理员身份重启失败: {e}")
        return False


def run_as_admin():
    """
    判断是否以管理员权限运行，如果不是则直接尝试提权重启（旧行为，保留兼容）。

    Returns:
        bool: 当前进程是否已具备管理员权限
    """
    if is_admin():
        return True
    relaunch_as_admin()
    return False


def check_single_instance(mutex_name=None):
    """
    检查程序是否已经在运行，确保只有一个实例
    
    Args:
        mutex_name (str, optional): 互斥体名称，如果不提供则使用默认名称
    
    Returns:
        bool: 如果是首次运行返回True，否则返回False
    """
    if mutex_name is None:
        app_name = APP_INFO["name"]
        mutex_name = f"Global\\{app_name}_MUTEX"
        
    mutex = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
    if ctypes.windll.kernel32.GetLastError() == 183:
        logger.warning("程序已经在运行中，无法启动多个实例！")
        
        # 显示提醒弹窗
        show_already_running_dialog(APP_INFO["name"])
        return False
    return True


def show_already_running_dialog(app_name=None):
    """
    显示程序已运行的提醒对话框
    
    Args:
        app_name (str): 应用名称
    """
    if app_name is None:
        app_name = APP_INFO["name"]
        
    try:
        # 使用Windows API显示消息框
        message = (
            f"{app_name} 已经在运行中！\n\n"
            "程序只允许运行一个实例。\n"
            f"请检查系统托盘是否有{app_name}图标。\n\n"
            "如果找不到运行中的程序，请尝试：\n"
            f"• 检查任务管理器中是否有{app_name}进程\n"
            "• 重启电脑后再次运行程序"
        )
        
        title = "程序已在运行中"
        
        # 使用Windows API显示消息框
        # MB_OK = 0x00000000, MB_ICONINFORMATION = 0x00000040, MB_TOPMOST = 0x00040000
        ctypes.windll.user32.MessageBoxW(
            0,  # 父窗口句柄
            message,  # 消息内容
            title,  # 标题
            0x00000040 | 0x00040000  # MB_ICONINFORMATION | MB_TOPMOST
        )
        
        logger.debug("已显示程序重复运行提醒对话框")
        
    except Exception as e:
        logger.error(f"显示程序重复运行对话框失败: {str(e)}")
        # 如果显示对话框失败，至少在控制台输出信息
        print(f"{app_name} 已经在运行中，无法启动多个实例！")


def get_program_path():
    """
    获取程序完整路径
    
    Returns:
        str: 程序完整路径
    """
    if getattr(sys, 'frozen', False):
        return sys.executable
    else:
        # 直接运行的python脚本
        return os.path.abspath(sys.argv[0])


def check_auto_start(app_name=None):
    """
    检查是否设置了开机自启（使用任务计划程序）
    
    Args:
        app_name (str): 应用名称
    
    Returns:
        bool: 是否设置了开机自启
    """
    if app_name is None:
        app_name = APP_INFO["name"]
        
    try:
        # 清理任务名称，避免特殊字符
        task_name = f"{app_name}_AutoStart".replace(" ", "_")
        
        # 使用schtasks命令查询任务是否存在
        result = subprocess.run(
            ["schtasks", "/query", "/tn", task_name],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # 如果返回码为0，表示任务存在
        return result.returncode == 0
            
    except Exception as e:
        logger.error(f"检查开机自启状态失败: {str(e)}")
        return False


def enable_auto_start(app_name=None):
    """
    设置开机自启（使用任务计划程序，可跳过UAC以管理员权限运行）
    
    Args:
        app_name (str): 应用名称
        
    Returns:
        bool: 操作是否成功
    """
    if app_name is None:
        app_name = APP_INFO["name"]
        
    try:
        # 清理任务名称，避免特殊字符
        task_name = f"{app_name}_AutoStart".replace(" ", "_")

        # 获取当前程序路径。源码态（非打包）不能把 .py 当任务命令——
        # 任务计划程序无法直接执行，必须落到 pythonw.exe + 脚本参数；
        # 冒烟等非常规调用（argv[0] 不是 .py）则放弃创建，避免写坏任务。
        if getattr(sys, "frozen", False):
            program_path = sys.executable
            program_args = "--minimized"
        else:
            script = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0].endswith(".py") else ""
            if not script or not os.path.isfile(script):
                logger.warning("无法确定自启目标脚本，跳过开机自启创建")
                return False
            pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
            program_path = pythonw if os.path.isfile(pythonw) else sys.executable
            program_args = f'"{script}" --minimized'

        # 用带 RegistrationInfo（作者 / 描述）的任务 XML 创建，比裸 schtasks /create
        # 更规范：任务在任务计划程序里有明确来源说明，也便于用户在系统中辨识。
        #（避免"无描述 + 最高权限 + 登录触发"的匿名任务特征）
        user = os.environ.get("USERNAME", "")
        domain = os.environ.get("USERDOMAIN", "")
        full_user = f"{domain}\\{user}" if domain and user else user

        task_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>SkyGuard</Author>
    <Description>{app_name} 开机自启（由 {app_name} 设置创建，可在程序内一键取消）</Description>
    <URI>\\{task_name}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{full_user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{full_user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>Highest</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{program_path}</Command>
      <Arguments>{program_args}</Arguments>
    </Exec>
  </Actions>
</Task>
"""

        # XML 定义保存为应用数据目录下的常驻配置（非临时文件）
        cfg_dir = os.path.join(os.path.expanduser("~"), ".skyguard")
        os.makedirs(cfg_dir, exist_ok=True)
        xml_path = os.path.join(cfg_dir, f"{task_name}.xml")
        with open(xml_path, "w", encoding="utf-16") as f:
            f.write(task_xml)

        # /create /xml: 按定义文件创建任务；/f: 覆盖现有任务
        result = subprocess.run([
            "schtasks", "/create",
            "/tn", task_name,
            "/xml", xml_path,
            "/f"
        ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)

        if result.returncode == 0:
            logger.debug(f"已设置开机自启（任务计划程序），任务名称: {task_name}")
            return True
        else:
            logger.error(f"设置开机自启失败，错误信息: {result.stderr}")
            return False

    except Exception as e:
        logger.error(f"设置开机自启失败: {str(e)}")
        return False


def disable_auto_start(app_name=None):
    """
    取消开机自启（删除任务计划程序中的任务）
    
    Args:
        app_name (str): 应用名称
        
    Returns:
        bool: 操作是否成功
    """
    if app_name is None:
        app_name = APP_INFO["name"]
        
    try:
        # 清理任务名称，避免特殊字符
        task_name = f"{app_name}_AutoStart".replace(" ", "_")
        
        # 使用schtasks命令删除任务
        # /delete: 删除任务
        # /tn: 任务名称
        # /f: 强制删除，不提示确认
        result = subprocess.run([
            "schtasks", "/delete",
            "/tn", task_name,
            "/f"
        ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        
        if result.returncode == 0:
            logger.debug(f"已取消开机自启，删除任务计划程序任务: {task_name}")
            return True
        else:
            # 如果任务不存在，返回码通常是1，这也算成功
            if "不存在" in result.stderr or "does not exist" in result.stderr.lower() or "找不到指定的文件" in result.stderr:
                logger.debug(f"任务计划程序任务不存在，无需删除: {task_name}")
                return True
            else:
                logger.error(f"取消开机自启失败，错误信息: {result.stderr}")
                return False
        
    except Exception as e:
        logger.error(f"取消开机自启失败: {str(e)}")
        return False


 