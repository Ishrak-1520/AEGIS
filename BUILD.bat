@echo off
REM Build CyberGuard Pro Executable
REM This script creates a standalone .exe file

echo ============================================================
echo Building CyberGuard Pro Executable
echo ============================================================
echo.

REM Clean previous builds
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "CyberGuardPro.spec" del "CyberGuardPro.spec"

echo Cleaned previous build files...
echo.
echo Starting PyInstaller build...
echo.

REM Run PyInstaller
python -m PyInstaller ^
    --name=CyberGuardPro ^
    --onefile ^
    --windowed ^
    --exclude-module=tensorflow ^
    --exclude-module=transformers ^
    --exclude-module=nltk ^
    --exclude-module=spacy ^
    --exclude-module=torch ^
    --add-data="database/schema.sql;database" ^
    --hidden-import=PyQt5.QtCore ^
    --hidden-import=PyQt5.QtGui ^
    --hidden-import=PyQt5.QtWidgets ^
    --hidden-import=cryptography ^
    --hidden-import=psutil ^
    main.py

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================================
    echo BUILD SUCCESSFUL!
    echo ============================================================
    echo.
    echo Executable created at: dist\CyberGuardPro.exe
    echo File size: 
    dir dist\CyberGuardPro.exe | find "CyberGuardPro.exe"
    echo.
    echo You can now run the application by double-clicking:
    echo   dist\CyberGuardPro.exe
    echo.
    echo Note: First run may take a few seconds to extract files.
    echo ============================================================
) else (
    echo.
    echo ============================================================
    echo BUILD FAILED!
    echo ============================================================
    echo Please check the error messages above.
)

pause
