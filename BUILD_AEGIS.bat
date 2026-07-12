@echo off
REM AEGIS Standalone Windows Executable Build Script
echo ============================================================
echo AEGIS Cybersecurity Suite - Executable Builder (v2.0.0)
echo ============================================================
echo.

python build_aegis.py

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Executable created at: dist\AEGIS.exe
    echo You can upload dist\AEGIS.exe to GitHub Releases for free distribution!
) else (
    echo.
    echo [ERROR] Build failed. Please check console output.
)
pause
