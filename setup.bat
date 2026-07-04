@echo off
cd /d "%~dp0"
echo Installing dependencies with Python launcher...

where py >nul 2>nul
if %errorlevel% neq 0 (
	echo.
	echo Error: Python launcher ^(py^) was not found.
	echo Please reinstall Python and enable "Add Python to PATH".
	pause
	exit /b 1
)

py -m pip install --upgrade pip
py -m pip install -r requirements.txt

if %errorlevel% neq 0 (
	echo.
	echo Standard install failed. Trying fallback install without PyAudio...
	py -m pip install pywxdump --no-deps
	py -m pip install psutil pycryptodomex pywin32 pymem silk-python requests pyahocorasick lz4 blackboxprotobuf lxml dbutils fastapi uvicorn python-dotenv
)

py -c "import pywxdump; print('pywxdump import ok')"
if %errorlevel% neq 0 (
	echo.
	echo Error: pywxdump still failed to import.
	echo Try installing Python 3.12, then run setup.bat again.
	pause
	exit /b 1
)

echo.
echo Setup complete! Run "run.bat" to start the application.
pause
