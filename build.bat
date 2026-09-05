@echo off
rem build.bat - GhidraMCP one-click clean/compile/test/package/install
rem One-click entry point that delegates to build.ps1 (PowerShell 7+).
rem Usage: build.bat [phase]   phases: all | clean | compile | test | package | install

setlocal
set "SCRIPT_DIR=%~dp0"

rem Prefer pwsh (PowerShell 7+) since build.ps1 uses -Encoding UTF-8 (not in Windows PowerShell 5.1)
where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%build.ps1" %*
    exit /b %ERRORLEVEL%
)

rem Fall back to Windows PowerShell (5.1) core features still work except UTF-8 enum
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%build.ps1" %*
exit /b %ERRORLEVEL%