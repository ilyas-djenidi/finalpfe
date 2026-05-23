# 🌐 دليل فحص الشبكة — CyBrain NetScan

هذا الدليل يشرح كيفية استخدام منصة **CyBrain** لفحص شبكتك المنزلية أو الداخلية.

---

## 📋 المتطلبات الأساسية

### 1. تثبيت Nmap

**على Windows:**
- اذهب إلى: https://nmap.org/download.html
- حمّل نسخة Windows الأخيرة (مثال: `nmap-7.95-setup.exe`)
- ثبّت مع الخيارات الافتراضية
- تحقق من التثبيت:
  ```bash
  nmap --version
  ```

**على Linux:**
```bash
sudo apt update
sudo apt install nmap
nmap --version
```

### 2. تثبيت متطلبات Python

```bash
pip install -r requirements.txt
```

---

## 🚀 الطريقة 1: استخدام الواجهة الويب (الموصى به)

### تشغيل التطبيق

```bash
python app.py
```

انتظر حتى ترى:
```
 * Running on http://127.0.0.1:5000
```

### الوصول إلى الواجهة

1. افتح المتصفح على: **http://127.0.0.1:5000**
2. سجّل الدخول (إذا لم يكن عندك مستخدم، استخدم):
   - اسم المستخدم: `admin`
   - كلمة المرور: `admin` (غيّرها بعد أول دخول!)

### تشغيل فحص

1. اختر **نوع الفحص**:
   - 🌐 **شبكات خارجي** — فحص أجهزة خارجية (مثل سيرفر على الإنترنت)
   - 🔌 **شبكات داخلي** — فحص الشبكة المحلية (LAN)

2. أدخل **الهدف**:
   - IP مفردة: `192.168.1.1`
   - نطاق CIDR: `192.168.1.0/24` (فحص كل الأجهزة في الشبكة)

3. اختياري — خيارات متقدمة:
   - ☑ **تفصيل عميق** — فحص أعمق (أبطأ لكن أدق)
   - ☑ **فحص CVE تلقائي** — البحث عن ثغرات معروفة

4. اضغط **بدء الفحص الأمني** ⚡

### عرض النتائج

- المنافذ المكتشفة
- الخدمات المشغّلة
- درجات الخطورة (🟢 منخفضة، 🟡 متوسطة، 🔴 عالية)
- تقرير PDF اختياري

---

## 🖥️ الطريقة 2: استخدام سطر الأوامر (للمطورين)

### تشغيل فحص بسيط

```bash
python scripts/run_netscan.py 192.168.1.1 --out result.json
```

### فحص عميق (أبطأ، أدق)

```bash
python scripts/run_netscan.py 192.168.1.0/24 --internal --deep --out deep_scan.json
```

### خيارات متقدمة

| الخيار | الشرح | مثال |
|--------|-------|------|
| `TARGET` | عنوان IP أو نطاق CIDR | `192.168.1.1` أو `10.0.0.0/8` |
| `--deep` | فحص أعمق (OS detection، scripts) | `--deep` |
| `--internal` | وضع LAN (أبطأ، أدق للشبكات الداخلية) | `--internal` |
| `--out FILE` | ملف الناتج JSON | `--out result.json` |

### أمثلة عملية

**فحص سريع على جهاز واحد:**
```bash
python scripts/run_netscan.py 192.168.1.10 --out quick.json
```

**فحص عميق على كل الشبكة المحلية:**
```bash
python scripts/run_netscan.py 192.168.1.0/24 --internal --deep --out full_scan.json
```

**فحص خادم خارجي:**
```bash
python scripts/run_netscan.py example.com --out external.json
```

---

## 📊 فهم النتائج JSON

ملف الناتج يحتوي على:

```json
{
  "target": "192.168.1.1",
  "scan_type": "external",
  "vulnerabilities": [
    {
      "title": "منفذ مفتوح: 22/tcp (ssh)",
      "severity": "medium",
      "port": 22,
      "protocol": "tcp",
      "service": "ssh",
      "version": "OpenSSH 7.4",
      "description": "المنفذ 22/tcp مفتوح يُشغّل ssh",
      "host": "192.168.1.1"
    }
  ],
  "meta": {
    "scan_time": "2026-05-20T18:45:30Z",
    "deep": false,
    "hosts_up": "1",
    "total_hosts": "1"
  }
}
```

### شرح المفاتيح

- **`severity`** (خطورة):
  - 🟢 `info` — معلومة فقط
  - 🟡 `medium` — متوسط (تتطلب مراقبة)
  - 🔴 `high` — عالي (تتطلب معالجة)

- **`port`** — رقم المنفذ (مثل SSH على 22)

- **`service`** — اسم الخدمة (ssh, http, mysql, إلخ)

---

## ⚠️ تحذيرات أمنية وقانونية

### ✅ مسموح به

- فحص أجهزتك الشخصية
- فحص شبكتك المنزلية/الداخلية
- فحص سيرفرات تملكها أنت

### ❌ ممنوع

- فحص أجهزة أخرى بدون إذن كتابي
- فحص خوادم حكومية أو حساسة بدون ترخيص
- استخدام النتائج لأغراض تخريبية

---

## 🔧 استكشاف الأخطاء

### المشكلة: "nmap program was not found"

**الحل:**
```bash
# تحقق من التثبيت
nmap --version

# إذا لم يعمل، ثبّت nmap:
# Windows: https://nmap.org/download.html
# Linux: sudo apt install nmap
```

### المشكلة: "Permission denied" على Linux

**الحل:**
```bash
# نسخة مصغرة (بدون root):
nmap -sV --unprivileged 192.168.1.1

# أو مع sudo:
sudo python scripts/run_netscan.py 192.168.1.1 --out result.json
```

### المشكلة: الفحص بطيء جداً

**الحل:**
```bash
# تجنب --deep و --internal
python scripts/run_netscan.py 192.168.1.1 --out result.json

# أو حدد منافذ محددة فقط (نسخة nmap المباشرة):
nmap --top-ports 100 192.168.1.1
```

---

## 📈 مثال عملي شامل

### السيناريو: فحص شبكتك المنزلية

**الخطوة 1:** تشغيل التطبيق
```bash
python app.py
```

**الخطوة 2:** فتح المتصفح
```
http://127.0.0.1:5000
```

**الخطوة 3:** تسجيل الدخول
- اسم المستخدم: `admin`
- كلمة المرور: `admin`

**الخطوة 4:** اختيار فحص شبكات داخلي
- النوع: 🔌 **شبكات داخلي**
- الهدف: `192.168.1.0/24`
- خيارات: ☑ تفصيل عميق

**الخطوة 5:** بدء الفحص
اضغط الزر الأزرق → انتظر النتائج

**الخطوة 6:** مراجعة النتائج
- كم جهاز موجود على الشبكة؟
- ما الخدمات المكتشفة؟
- هل هناك منافذ حساسة مفتوحة؟

---

## 📚 مراجع إضافية

- [Nmap Documentation](https://nmap.org/book/)
- [OWASP Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CVE Database](https://cve.mitre.org/)

---

**آخر تحديث:** 2026-05-20
**الإصدار:** CyBrain v1.0.0 (NetScan Edition)
