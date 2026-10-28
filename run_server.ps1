# Aegis Cyber SOC PowerShell Runner
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   Starting Aegis Cyber SOC Security Platform" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Launching REST API and Web Application on http://localhost:3000" -ForegroundColor Green
Write-Host "Running in persistent SQLite database mode (aegis_soc.db)" -ForegroundColor Yellow
Write-Host ""

agy-node src/backend/server.js
