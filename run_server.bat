@echo off
echo ========================================================
echo    Starting Aegis Cyber SOC Security Platform
echo ========================================================
echo.
echo Launching REST API and Web Application on http://localhost:3000
echo Running in persistent SQLite database mode (aegis_soc.db)
echo.

agy-node src/backend/server.js
pause
