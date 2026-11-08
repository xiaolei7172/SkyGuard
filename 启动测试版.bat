@echo off
rem SkyGuard 本地测试版启动脚本（源码直跑，无需打包）
rem 双击运行；如弹出 UAC 提示请点"是"
chcp 65001 >nul
cd /d "%~dp0"
"C:\Program Files\Python312\python.exe" main.py
if errorlevel 1 (
  echo.
  echo 启动失败，请把上面的报错信息发给开发者。
  pause
)
