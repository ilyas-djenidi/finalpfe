@echo off
REM تشغيل سريع بدون بيانات إضافية
cd /d "%~dp0"
call E:\PFE\.venv\Scripts\activate.bat && python app.py
