@echo off
echo STARTING AI HONEYPOT SYSTEM...

start "Backend Server" cmd /k "python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000"
start "Frontend Dashboard" cmd /k "cd frontend && npm run dev"

echo System starting...
echo Access Dashboard at http://localhost:5173
echo SSH Honeypot (Fake) at localhost:2222
pause
