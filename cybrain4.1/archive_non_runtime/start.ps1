# CyBrain Security Platform - PowerShell Startup Script
# =====================================================

Write-Host "═══════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  CyBrain Security Platform - Startup" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

# تفعيل البيئة الافتراضية
Write-Host "[*] تفعيل البيئة الافتراضية..." -ForegroundColor Yellow
& E:\PFE\.venv\Scripts\Activate.ps1

# التحقق من المتطلبات
Write-Host "[*] التحقق من المتطلبات..." -ForegroundColor Yellow
pip install -q -r requirements.txt

Write-Host ""
Write-Host "✓ التطبيق سيبدأ على http://127.0.0.1:5000" -ForegroundColor Green
Write-Host "✓ سيتم فتح المتصفح تلقائياً..." -ForegroundColor Green
Write-Host ""

# فتح المتصفح
Start-Sleep -Seconds 1
Start-Process "http://127.0.0.1:5000"

# تشغيل التطبيق
python app.py
