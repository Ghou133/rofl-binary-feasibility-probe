@echo off
setlocal

if "%~1"=="" (
  echo Drag a .rofl replay file onto this launcher.
  echo.
  echo Command-line usage:
  echo   "%~f0" "D:\Replays\12345678901.rofl"
  pause
  exit /b 2
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0play-rofl.ps1" "%~1"
set "PLAY_ROFL_EXIT=%ERRORLEVEL%"

if not "%PLAY_ROFL_EXIT%"=="0" pause
exit /b %PLAY_ROFL_EXIT%
