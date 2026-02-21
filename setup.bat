@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   CYBERSENTINEL - FIRST-TIME SETUP
echo   AI-Enhanced Honeypot ^& Threat Intelligence System
echo ============================================================
echo.

:: ── 1. Check Python ────────────────────────────────────────────
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Python is not installed or not in PATH.
    echo  Please install Python 3.10+ from https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo  Found: %%i
echo.

:: ── 2. Check Node.js ───────────────────────────────────────────
echo [2/5] Checking Node.js installation...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Node.js is not installed or not in PATH.
    echo  Please install Node.js 18+ from https://nodejs.org/
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node --version 2^>^&1') do echo  Found: Node.js %%i
echo.

:: ── 3. Install Python packages ─────────────────────────────────
echo [3/5] Installing Python dependencies...
echo  Running: pip install -r requirements.txt
echo.
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Failed to install Python packages.
    echo  Try running: pip install -r requirements.txt  manually.
    pause
    exit /b 1
)
echo.
echo  [OK] Python dependencies installed.
echo.

:: ── 4. Install Node.js packages ────────────────────────────────
echo [4/5] Installing frontend dependencies...
echo  Running: npm install  (inside frontend\)
echo.
cd frontend
call npm install
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Failed to install Node packages.
    cd ..
    pause
    exit /b 1
)
cd ..
echo.
echo  [OK] Frontend dependencies installed.
echo.

:: ── 5. Create .env if missing ──────────────────────────────────
echo [5/5] Checking environment configuration...
if not exist ".env" (
    echo  .env file not found. Creating from template...
    (
        echo # AI-Enhanced Honeypot Configuration
        echo # Get a free key at: https://aistudio.google.com/app/apikey
        echo GEMINI_API_KEY=YOUR_GEMINI_API_KEY_HERE
    ) > .env
    echo.
    echo  ============================================================
    echo   ACTION REQUIRED:
    echo   A .env file has been created. Before running the system,
    echo   open .env and replace YOUR_GEMINI_API_KEY_HERE with your
    echo   actual API key from https://aistudio.google.com/app/apikey
    echo  ============================================================
    echo.
) else (
    echo  [OK] .env file already exists.
    echo.
)

:: ── Done ───────────────────────────────────────────────────────
echo ============================================================
echo   SETUP COMPLETE!
echo.
echo   To start the system, run:  start_system.bat
echo.
echo   Make sure your GEMINI_API_KEY is set in .env before starting.
echo ============================================================
echo.
pause
