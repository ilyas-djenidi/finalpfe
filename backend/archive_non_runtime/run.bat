@echo off
chcp 65001 > nul
color 0A
echo ════════════════════════════════════════════════
echo   CyBrain Security Platform - Running on 5000
echo ════════════════════════════════════════════════
echo.

REM تفعيل Virtual Environment
echo [*] تفعيل البيئة الافتراضية...
call E:\PFE\.venv\Scripts\activate.bat

REM التحقق من المتطلبات
echo [*] التحقق من المتطلبات...
pip install -q -r requirements.txt

REM تشغيل التطبيق
echo [*] تشغيل التطبيق...
echo.
echo ✓ التطبيق يعمل على: http://127.0.0.1:5000
echo ✓ سيتم فتح المتصفح تلقائياً بعد قليل...
echo.

REM فتح المتصفح تلقائياً بعد ثانية واحدة
start http://127.0.0.1:5000
timeout /t 2 /nobreak > nul

REM تشغيل التطبيق
python app.py

pause
