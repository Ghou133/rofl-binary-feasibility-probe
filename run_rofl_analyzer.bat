@echo off
setlocal
node "%~dp0src\cli.js" %*
set "exit_code=%ERRORLEVEL%"
endlocal & exit /b %exit_code%
