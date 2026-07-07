@echo off
setlocal

set "ROOT=%~dp0"
set "BUILD_DIR=%ROOT%build"
set "OUT=%BUILD_DIR%\DiscordMiniBypass.exe"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

if not exist "%ROOT%third_party\windivert\include\windivert.h" (
  echo Missing third_party\windivert\include\windivert.h
  echo Download WinDivert x64 from https://github.com/basil00/WinDivert/releases
  exit /b 1
)

if not exist "%ROOT%third_party\windivert\lib\WinDivert.lib" (
  echo Missing third_party\windivert\lib\WinDivert.lib
  echo Download WinDivert x64 from https://github.com/basil00/WinDivert/releases
  exit /b 1
)

if not exist "%ROOT%third_party\windivert\bin\WinDivert.dll" (
  echo Missing third_party\windivert\bin\WinDivert.dll
  echo Download WinDivert x64 from https://github.com/basil00/WinDivert/releases
  exit /b 1
)

if not exist "%ROOT%third_party\windivert\bin\WinDivert64.sys" (
  echo Missing third_party\windivert\bin\WinDivert64.sys
  echo Download WinDivert x64 from https://github.com/basil00/WinDivert/releases
  exit /b 1
)

g++ -std=c++17 -O2 -Wall -Wextra ^
  "%ROOT%src\main.cpp" ^
  -I "%ROOT%third_party\windivert\include" ^
  "%ROOT%third_party\windivert\lib\WinDivert.lib" ^
  -lws2_32 ^
  -o "%OUT%"

if errorlevel 1 exit /b 1

if exist "%BUILD_DIR%\WinDivert.dll" (
  fc /b "%ROOT%third_party\windivert\bin\WinDivert.dll" "%BUILD_DIR%\WinDivert.dll" >nul
  if errorlevel 1 (
    copy /Y "%ROOT%third_party\windivert\bin\WinDivert.dll" "%BUILD_DIR%\" >nul
    if errorlevel 1 (
      echo Failed to copy WinDivert.dll. Stop DiscordMiniBypass.exe if it is running.
      exit /b 1
    )
  )
) else (
  copy /Y "%ROOT%third_party\windivert\bin\WinDivert.dll" "%BUILD_DIR%\" >nul
  if errorlevel 1 (
    echo Failed to copy WinDivert.dll.
    exit /b 1
  )
)

if exist "%BUILD_DIR%\WinDivert64.sys" (
  fc /b "%ROOT%third_party\windivert\bin\WinDivert64.sys" "%BUILD_DIR%\WinDivert64.sys" >nul
  if errorlevel 1 (
    copy /Y "%ROOT%third_party\windivert\bin\WinDivert64.sys" "%BUILD_DIR%\" >nul
    if errorlevel 1 (
      echo Failed to copy WinDivert64.sys. Stop DiscordMiniBypass.exe if it is running.
      exit /b 1
    )
  )
) else (
  copy /Y "%ROOT%third_party\windivert\bin\WinDivert64.sys" "%BUILD_DIR%\" >nul
  if errorlevel 1 (
    echo Failed to copy WinDivert64.sys.
    exit /b 1
  )
)

echo Built: %OUT%
