@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title Practice-encryption 启动器

rem ============================================================================
rem  Practice-encryption 启动器 —— 双击即可运行，分三段：
rem
rem    1/3  检查环境与依赖（解释器、版本、三项依赖逐项体检）
rem    2/3  有缺失就询问是否用 pip 安装 [Y/N]
rem    3/3  启动图形界面
rem
rem  可选环境变量（都不设也能正常跑）：
rem    PE_PYTHON    指定解释器，覆盖自动查找（例如另一个 venv 的 python.exe）
rem    PE_DRY_RUN=1 只打印第 3 段将要执行的命令，不真正启动（脚本自检用）
rem
rem  依赖口径：dearpygui 是必需项（图形界面本体）；numpy 与 z3-solver 是可选
rem  项，只影响测试套件（numpy 缺席跳过 Walsh/DDT 装置，z3 缺席跳过表达式层
rem  用例），不影响构建与界面。
rem
rem  【重要 · 编码】本文件必须是 GBK / cp936 编码，且**不得**在文件内 chcp 切换
rem  代码页：cmd 已在打开时按当前代码页缓冲了后续字节，中途切页会让重读错位，
rem  表现为若干行行首被吃掉（rem 行被当成命令执行）。中文 Windows 默认 936，
rem  故存 GBK 且全程不切页是最稳的组合。改动本文件时请保持 GBK 编码。
rem ============================================================================

echo.
echo ============================================================
echo   Practice-encryption 启动器
echo ============================================================
echo.
echo [1/3] 检查环境与依赖 ...
echo.

rem ---------------------------------------------------------------- 解释器查找
set "PY="
set "PYSRC="
if defined PE_PYTHON (
  set "PY=%PE_PYTHON%"
  set "PYSRC=PE_PYTHON 指定"
  goto :have_py
)
if exist ".venv\Scripts\python.exe" (
  set "PY=.venv\Scripts\python.exe"
  set "PYSRC=项目虚拟环境 .venv"
  goto :have_py
)
where py >nul 2>nul
if not errorlevel 1 (
  py -3.13 -c "import sys" >nul 2>nul
  if not errorlevel 1 (
    set "PY=py -3.13"
    set "PYSRC=py 启动器 (-3.13)"
    goto :have_py
)
)
where python >nul 2>nul
if not errorlevel 1 (
  set "PY=python"
  set "PYSRC=PATH 上的 python"
  goto :have_py
)
echo   [失败] 找不到可用的 Python 解释器。
echo          请安装 Python 3.11 或更高：https://www.python.org/downloads/
echo          或在本目录执行：python -m venv .venv
goto :die

have_py
%PY% -c "import sys;sys.exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>nul
if errorlevel 1 (
  echo   [失败] Python 版本过低，需要 3.11 或更高。当前版本：
  %PY% -c "import sys;print('         ',sys.version)"
  goto :die
)
for /f "delims=" %%v in ('%PY% -c "import sys;print(sys.version.split()[0])"') do set "PYVER=%%v"
echo   [正常] 解释器      : %PYSRC%
echo          版本        : %PYVER%

rem ------------------------------------------------------------------ 依赖体检
set "MISSING="
set "MISSPIP="
set "MISSREQ="

%PY% -c "import dearpygui" >nul 2>nul
if errorlevel 1 (
  echo   [缺失] dearpygui  —— 必需，图形界面本体
  set "MISSING=!MISSING! dearpygui"
  set "MISSPIP=!MISSPIP! dearpygui==2.3.1"
  set "MISSREQ=1"
) else (
  echo   [正常] dearpygui  —— 必需
)

%PY% -c "import numpy" >nul 2>nul
if errorlevel 1 (
  echo   [缺失] numpy      —— 可选，缺席时测试套件跳过 Walsh/DDT 装置
  set "MISSING=!MISSING! numpy"
  set "MISSPIP=!MISSPIP! numpy==2.5.3"
) else (
  echo   [正常] numpy      —— 可选
)

%PY% -c "import z3" >nul 2>nul
if errorlevel 1 (
  echo   [缺失] z3-solver  —— 可选，缺席时测试套件跳过表达式层用例
  set "MISSING=!MISSING! z3-solver"
  set "MISSPIP=!MISSPIP! z3-solver==5.1.0.0"
) else (
  echo   [正常] z3-solver  —— 可选
)

rem ------------------------------------------------------------------ 2/3 询问
echo.
echo [2/3] 依赖处理
if not defined MISSING (
  echo   依赖齐全，无需安装。
  goto :launch
)
echo   缺失依赖：%MISSING%
echo.
set "ANSWER="
set /p "ANSWER=  是否立即用 pip 安装？[Y/N] "
if /i "%ANSWER%"=="Y" goto :do_install
if /i "%ANSWER%"=="YES" goto :do_install
echo   已跳过安装。
if defined MISSREQ (
  echo   [失败] dearpygui 是启动图形界面的必需依赖，仍然缺失，无法继续。
  goto :die
)
echo   缺失的均为可选依赖，继续启动（相关测试套件会自动跳过）。
goto :launch

do_install
echo.
echo   正在安装：%MISSPIP%
echo.
%PY% -m pip install %MISSPIP%
if errorlevel 1 (
  echo.
  echo   [失败] pip 安装失败，详见上方输出。
  goto :die
)
echo.
echo   安装完成。

rem ------------------------------------------------------------------ 3/3 启动
launch
echo.
echo [3/3] 启动图形界面 ...
echo.
if defined PE_DRY_RUN (
  echo   [dry-run] 将要执行：%PY% -m pyshroud gui
  goto :end
)
%PY% -m pyshroud gui
if errorlevel 1 (
  echo.
  echo   图形界面以错误码 !ERRORLEVEL! 退出，详见上方输出。
  goto :end
)
echo   图形界面已正常退出。
goto :end

die
echo.
echo   启动中止。

end
echo.
echo   按任意键关闭本窗口 ...
pause >nul
endlocal
