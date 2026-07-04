@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo  WeChat Message Extractor — Build Pipeline
echo ============================================================
echo.

:: ── Step 1: Install / upgrade build dependencies ──
echo [1/3] Installing build dependencies...
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
py -m pip install pyinstaller pyarmor
echo.

:: ── Step 2: Obfuscate source with PyArmor ──
echo [2/3] Obfuscating Python source with PyArmor...

:: Clean previous obfuscation output
if exist "dist_obf" rmdir /s /q dist_obf

:: Obfuscate the main scripts into dist_obf/
:: PyArmor 8+ syntax (use `pyarmor gen` for generation)
py -m pyarmor gen ^
    --output dist_obf ^
    --platform windows.x86_64 ^
    main.py extractor.py app_config.py updater.py licensing.py

if %errorlevel% neq 0 (
    echo.
    echo WARNING: PyArmor obfuscation failed.
    echo Falling back to building WITHOUT obfuscation.
    echo To fix: ensure PyArmor 8+ is installed and licensed.
    echo.
    goto :build_direct
)

:: Copy all obfuscated files over originals for PyInstaller to consume
echo Obfuscation successful.
echo.

:: ── Step 3: Build with PyInstaller using obfuscated code ──
echo [3/3] Building standalone executable with PyInstaller...
pushd dist_obf
copy /y "..\build.spec" "build.spec" >nul
pyinstaller build.spec --clean --noconfirm
popd

if exist "dist_obf\dist\WeChatExtractor.exe" (
    if not exist "dist" mkdir dist
    copy /y "dist_obf\dist\WeChatExtractor.exe" "dist\WeChatExtractor.exe" >nul
    echo.
    echo ============================================================
    echo  BUILD SUCCESSFUL (obfuscated)
    echo  Output: dist\WeChatExtractor.exe
    echo ============================================================
) else (
    echo.
    echo ERROR: PyInstaller build failed. Check output above.
)
goto :done

:build_direct
echo [3/3] Building standalone executable with PyInstaller (no obfuscation)...
pyinstaller build.spec --clean --noconfirm

if exist "dist\WeChatExtractor.exe" (
    echo.
    echo ============================================================
    echo  BUILD SUCCESSFUL (not obfuscated)
    echo  Output: dist\WeChatExtractor.exe
    echo ============================================================
) else (
    echo.
    echo ERROR: PyInstaller build failed. Check output above.
)

:done
echo.
pause
