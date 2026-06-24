@echo off
:: CyberShield — Start both servers (Windows)
title CyberShield

echo.
echo  CyberShield v2 — AI Cybersecurity Platform
echo  ============================================
echo.

:: Check for venv
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
    echo  [OK] Virtual environment activated
)

:: Check ML model
if not exist ml_engine\saved_models\ensemble_model.pkl (
    echo  [..] ML model not found — training now, takes ~3 minutes...
    python scripts\train_model.py
)

echo  [>>] Starting Django API  =^>  http://localhost:8000
start "CyberShield Django API" cmd /k "python manage.py runserver 8000"

echo  [>>] Starting React UI    =^>  http://localhost:5173
cd ..\cybershield-ui
start "CyberShield React UI" cmd /k "npm run dev"
cd ..\cybershield

echo.
echo  ------------------------------------------
echo  Open browser: http://localhost:5173
echo  Login: admin / admin123
echo  Admin: http://localhost:8000/admin
echo  ------------------------------------------
echo.
pause
