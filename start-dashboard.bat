@echo off
echo ========================================
echo Starting AI-Driven DevSecOps Dashboard
echo ========================================
echo.

cd /d "%~dp0dashboard"

echo Checking for ai_analysis.json...
if exist "public\data\ai_analysis.json" (
    echo [OK] Analysis file found!
    for %%A in ("public\data\ai_analysis.json") do echo     Size: %%~zA bytes
) else (
    echo [WARNING] ai_analysis.json not found in public\data\
    echo Please copy your analysis file to: dashboard\public\data\ai_analysis.json
    echo.
    pause
    exit /b 1
)

echo.
echo Checking Node.js installation...
where npm >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] npm not found in PATH
    echo Please restart your terminal or add Node.js to PATH
    echo.
    pause
    exit /b 1
)
echo [OK] npm found!

echo.
echo Installing dependencies (if needed)...
if not exist "node_modules" (
    echo Running npm install...
    call npm install
) else (
    echo [OK] Dependencies already installed
)

echo.
echo ========================================
echo Starting development server...
echo ========================================
echo.
echo Dashboard will open at: http://localhost:5173
echo Press Ctrl+C to stop the server
echo.

call npm run dev

pause
