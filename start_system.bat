@echo off
echo ============================================================
echo   AI-ENHANCED HONEYPOT ^& DECEPTION SYSTEM
echo ============================================================
echo.

:: Quick dependency check — remind user to run setup.bat first
python -c "import fastapi, uvicorn, sqlalchemy, asyncssh" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [WARNING] Some Python dependencies seem missing.
    echo  Please run setup.bat first, then try again.
    echo.
    pause
    exit /b 1
)

if not exist ".env" (
    echo  [WARNING] .env file not found!
    echo  Please run setup.bat first and add your GEMINI_API_KEY.
    echo.
    pause
    exit /b 1
)

echo [1/3] Starting Backend (uvicorn on port 8000)...
start "Honeypot Backend" cmd /k "python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000"

echo [2/3] Starting Frontend Dashboard (port 5173)...
start "Frontend Dashboard" cmd /k "cd frontend && npm run dev"

echo [3/3] Waiting 5 seconds for backend to boot, then running attack simulation...
timeout /t 5 /nobreak >nul
start "Attack Simulator" cmd /k "python simulate_attack.py && pause"

echo.
echo ============================================================
echo   ALL SYSTEMS ONLINE
echo   Dashboard  : http://localhost:5173
echo   Backend API: http://localhost:8000
echo   Web Trap   : http://localhost:8000/admin
echo   SSH Trap   : localhost:2222
echo   MySQL Trap : localhost:3306
echo   FTP Trap   : localhost:21
echo ============================================================
echo.
pause
