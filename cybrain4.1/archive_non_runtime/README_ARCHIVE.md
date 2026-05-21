# Archive Non-Runtime — دليل التنظيم

هذا المجلد يحتوي على جميع الملفات والأدلة **غير الضرورية للتشغيل الحي** للمشروع.

## محتويات المجلد

### 📄 ملفات توثيق

- **`KEPT_FILES.md`** — يشرح الملفات والمجلدات التي بقيت في جذر المشروع لأنها مطلوبة للتشغيل.
- **`ARCHIVED_FILES.md`** — يشرح الملفات المؤرشفة هنا ولماذا نقلتها.
- **`README.md`** — توثيق المشروع الأصلي.
- **`QUICK_START.md`** — دليل البدء السريع.

### 🐳 إنتاج / Docker

- **`docker-compose.yml`** — تركيب Docker Compose للبيئة الإنتاجية.
- **`Dockerfile`** — ملف Docker لبناء صورة المشروع.
- **`gunicorn.conf.py`** — إعدادات Gunicorn (خادم WSGI للإنتاج).

### 🖥️ سكريبتات البدء/الإيقاف

- `quick-start.bat` — بدء سريع (Windows).
- `run.bat` — تشغيل التطبيق (Windows).
- `start-server.bat`, `stop-server.bat`, `restart-server.bat` — تحكم الخادم (Windows).
- `start.ps1` — بدء عبر PowerShell.

### 🧪 اختبارات

- **`test_scanner.py`** — اختبارات قديمة للماسحات.
- **`tests/`** — مجلد اختبارات شامل (pytest، إلخ).

### 📋 إعدادات / تكوينات قديمة

- **`test_config.conf`** — ملف تكوين اختبار.
- **`.env.example`** — قالب متغيرات البيئة.
- **`httpd_cybrain_fixed14.conf`** — نسخة إعدادات Apache قديمة.

### 📄 وثائق ومقالات

- **`DOCUMENTATION_COMPLETE_PROJET_CYBRAIN_FR.txt`** — توثيق شامل (فرنسي).
- **`arch_extract.txt`** — ملاحظات معمارية.
- **`index.html`** — ملف HTML قديم (التطبيق يستخدم `templates/` الآن).

### 📚 عينة / مراجع

- **`sample/`** — مجلد العينات (عروض تقديمية، ملفات مرجعية).
  - `Presentation_PFE_CyBrain_FR.pptx` — عرض تقديمي (فرنسي).
  - `Architecture_ERD_Slides_FR.md` — شرائح المعمارية.
  - `Reponse_Exigences_Prof_FR.txt` — ردود على المتطلبات.

---

## كيفية استخدام هذا الأرشيف

### ✅ للمطورين (في التطوير اليومي)

**تجاهل هذا المجلد تماماً** — استخدم الملفات في جذر المشروع مباشرة:
```bash
cd ..  # العودة إلى جذر المشروع
python app.py  # تشغيل التطبيق
```

### 📦 للنشر / الإنتاج

استخدم ملفات Docker و Gunicorn من هنا:
```bash
docker build -t cybrain:latest -f archive_non_runtime/Dockerfile .
docker-compose -f archive_non_runtime/docker-compose.yml up
```

### 📖 للمرجعية / التوثيق

ابحث في `DOCUMENTATION_COMPLETE_PROJET_CYBRAIN_FR.txt` أو `arch_extract.txt` عن تفاصيل.

### 🗑️ الحذف الآمن

يمكنك حذف هذا المجلد بأكمله بأمان إذا كنت متأكداً من أنك لا تحتاجه:
```bash
rm -r archive_non_runtime/  # Linux/Mac
rmdir /S archive_non_runtime  # Windows PowerShell
```

---

## ملخص التنظيم

| الموقع | الملفات | الحالة |
|--------|--------|-------|
| جذر المشروع | `app.py`, `database.py`, `models.py`, إلخ | ✅ ضروري — لا تحذف |
| `templates/` | ملفات HTML | ✅ ضروري |
| `css/`, `js/` | موارد الواجهة | ✅ ضروري |
| `scanners/` | ماسحات البرنامج | ✅ ضروري |
| `migrations/` | هجرات DB | ✅ ضروري |
| `archive_non_runtime/` | ملفات وثائق/إنتاج | ⚠️ مرجعي — آمن للأرشفة |

---

**آخر تحديث:** 2026-05-20 (تنظيم المشروع)
