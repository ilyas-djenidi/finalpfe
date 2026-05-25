
# الفصل الثاني: تحليل وتصميم نظام SecuraX

---

## 1. مقدمة

قبل أن يُكتب أي سطر كود، لا بد من فهم النظام بشكل كامل: من يستخدمه؟ ماذا يحتاج؟ كيف تتفاعل مكوناته مع بعض؟ هذه المرحلة — التحليل والتصميم — هي التي تُحدد إذا كان المشروع سيُبنى على أسس صحيحة أم لا.

في هذا الفصل، نعرض البنية المعمارية الكاملة لـ **SecuraX**، ومخططات الحالات (Use Cases)، ومخططات التسلسل (Sequence Diagrams)، ومخططات الفئات (Class Diagrams) — كل ذلك بأسلوب يُوضّح للمستخدم والمطور والمُحكِّم كيف يعمل النظام من الداخل.

---

## 2. نموذج C4 للمعمارية

نعتمد نموذج **C4** (Context, Containers, Components, Code) لوصف المعمارية بشكل تدريجي من المستوى الأعلى إلى الأكثر تفصيلاً.

### 2.1 مخطط السياق (Context Diagram)

يُبيّن هذا المخطط موقع SecuraX بالنسبة للمستخدمين والأنظمة الخارجية:

```
                     ┌─────────────────────────────────┐
                     │                                 │
  [محلل أمني]  ──── │         منصة SecuraX            │ ──── [Gemini AI API]
  [مطور ويب]   ──── │   (نظام كشف ثغرات متكامل)       │ ──── [NIST NVD API]
  [مدير نظام]  ──── │                                 │
                     └─────────────────────────────────┘
                                    │
                                    ▼
                          [الهدف المفحوص]
                     (موقع ويب / كود مصدري / شبكة)
```

**الأطراف المتفاعلة:**
- **المستخدمون:** محلل أمني، مطور ويب، مسؤول نظام، طالب أمن
- **أنظمة خارجية:** Google Gemini API (الذكاء الاصطناعي)، NIST NVD (قاعدة بيانات الثغرات الرسمية)
- **الهدف المفحوص:** موقع ويب، ملف كود، ملف إعداد Apache، أو شبكة

### 2.2 مخطط الحاويات (Container Diagram)

```
┌─────────────────────────────────────────────────────────────┐
│                        منصة SecuraX                         │
│                                                             │
│   ┌──────────────────┐         ┌──────────────────────┐    │
│   │   واجهة أمامية  │  HTTP   │    خادم الخلفية      │    │
│   │  (React + Vite)  │ ──────▶ │   (Flask + Python)   │    │
│   │  Netlify CDN     │         │   Render.com          │    │
│   └──────────────────┘         └──────────────────────┘    │
│                                          │                   │
│                          ┌───────────────┼──────────────┐   │
│                          ▼               ▼              ▼   │
│                  ┌─────────────┐ ┌──────────────┐ ┌──────┐ │
│                  │ محركات الفح│ │  محرك الذكاء  │ │تقارير│ │
│                  │     ص (7)  │ │  الاصطناعي    │ │ MD/  │ │
│                  │  Python    │ │ (ai_agent.py) │ │CSV/  │ │
│                  └─────────────┘ └──────────────┘ │JSON) │ │
│                                                    └──────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. الخادم الخلفي (Backend) — التفاصيل

### 3.1 المكونات الرئيسية للنظام

يتكون الخادم الخلفي من المكونات التالية:

| المكوّن | الملف | الوظيفة |
|---------|------|---------|
| نقطة الدخول الرئيسية | `app.py` | إدارة المسارات والـ API |
| ماسح الويب | `url_scanner.py` | تنسيق فحص OWASP |
| فحوصات OWASP | `owasp_checks.py` | تطبيق الـ A01–A10 |
| كاشف إعدادات Apache | `detect_apache_misconf.py` | تحليل ملفات الإعداد |
| محلل الكود (SAST) | `code_analyzer.py` | فحص الكود المصدري |
| ماسح الشبكة | `network_scanner.py` | تنسيق فحص الشبكة |
| استطلاع الشبكة | `network_recon.py` | DNS، OS، المنافذ |
| ثغرات الشبكة | `network_vulns.py` | كشف ثغرات الخدمات |
| الذكاء الاصطناعي | `ai_agent.py` | Gemini + الوضع المحلي |

### 3.2 طبقة قاعدة البيانات

النظام في نسخته الحالية **بدون قاعدة بيانات تقليدية** — وهو قرار معماري مدروس. بدلاً من تخزين النتائج في قاعدة بيانات، تُحفظ التقارير كملفات في مجلد `/reports` بصيغ Markdown وCSV وJSON. هذا يُبسّط النشر كثيراً ويتوافق مع مبدأ "الحالة اللاذاكرية" (Stateless Architecture).

### 3.3 الفهرسة والربط بين المكونات

```
app.py (Flask Router)
    │
    ├── POST /scan_url ──────── url_scanner.py ──── owasp_checks.py
    │                                          └─── report_generator.py
    │
    ├── POST /scan_apache ────── detect_apache_misconf.py
    │
    ├── POST /scan_code ─────── code_analyzer.py
    │
    ├── POST /scan_network ──── network_scanner.py ── network_recon.py
    │                                              └── network_vulns.py
    │
    ├── POST /api/analyze ────── ai_agent.py (Gemini أو Offline)
    │
    └── POST /api/chat ───────── ai_agent.py (chat mode)
```

---

## 4. مخطط العلاقات بين الكيانات (Entity Relationship)

رغم أن النظام الحالي لا يستخدم قاعدة بيانات، إلا أن النسخة المستقبلية (Pro Version) ستحتاجها. هنا نوثّق البنية المفترضة:

```
┌─────────────┐         ┌───────────────────┐         ┌────────────────┐
│    User     │ 1 ── * │    ScanReport      │ 1 ── * │    Finding     │
├─────────────┤         ├───────────────────┤         ├────────────────┤
│ id          │         │ id                │         │ id             │
│ email       │         │ user_id (FK)      │         │ report_id (FK) │
│ password    │         │ target            │         │ owasp_id       │
│ role        │         │ scan_type         │         │ title          │
│ created_at  │         │ risk_level        │         │ severity       │
└─────────────┘         │ findings_count    │         │ description    │
                        │ ai_analysis       │         │ cwe_id         │
                        │ created_at        │         │ cvss_score     │
                        └───────────────────┘         └────────────────┘
```

---

## 5. تحليل النظام باستخدام مخططات الحالات (Use Case Diagrams)

### 5.1 الأطراف الفاعلة والحالات

حددنا ثلاثة أنواع من المستخدمين:

- **المستخدم العادي (User):** يمكنه التسجيل والدخول والاطلاع على الواجهة
- **المحلل الأمني (Analyst):** يشغّل الفحوصات ويستعرض النتائج ويستخدم الذكاء الاصطناعي
- **المسؤول (Admin):** يُدير المستخدمين والنظام ويطّلع على سجلات النشاط

### 5.2 مخطط الحالات — المحلل الأمني

```plantuml
@startuml
left to right direction
skinparam packageStyle rectangle

actor "المستخدم" as User
actor "المحلل الأمني" as Analyst
actor "المسؤول" as Admin
actor "Gemini AI" as AI

User <|-- Analyst
Analyst <|-- Admin

rectangle "نظام SecuraX" {
  usecase "التسجيل / الدخول" as UC_Auth
  usecase "فحص موقع ويب (OWASP A01-A10)" as UC_Web
  usecase "فحص إعدادات Apache" as UC_Apache
  usecase "تحليل الكود المصدري (SAST)" as UC_SAST
  usecase "فحص الشبكة" as UC_Net
  usecase "استعراض النتائج" as UC_View
  usecase "تحميل التقرير" as UC_Report
  usecase "الدردشة مع الذكاء الاصطناعي" as UC_Chat
  usecase "تحليل النتائج بالذكاء الاصطناعي" as UC_AI
  usecase "إصلاح الكود تلقائياً" as UC_FixCode
  usecase "تصليب إعدادات Apache" as UC_FixApache
}

User --> UC_Auth
Analyst --> UC_Web
Analyst --> UC_Apache
Analyst --> UC_SAST
Analyst --> UC_Net
Analyst --> UC_View
Analyst --> UC_Report
Analyst --> UC_Chat

UC_Web <.. UC_AI : <<extend>>
UC_SAST <.. UC_FixCode : <<extend>>
UC_Apache <.. UC_FixApache : <<extend>>

UC_AI --> AI
UC_Chat --> AI
UC_FixCode --> AI
UC_FixApache --> AI
@enduml
```

**شرح المخطط:** يُوضح هذا المخطط كيف يتفاعل المحلل الأمني مع الوظائف الأساسية للنظام، وكيف تمتد بعض الوظائف (مثل إصلاح الكود) كتوسعة اختيارية للوظائف الأصلية (مثل فحص الكود).

### 5.3 مخطط الحالات — المسؤول

المسؤول يرث كل صلاحيات المحلل، ويُضاف إليها:
- إدارة المستخدمين (إضافة، حذف، تعديل الصلاحيات)
- مراجعة سجل التدقيق (Audit Log)
- مراقبة إحصاءات النظام

---

## 6. تحليل النظام بمخططات التسلسل (Sequence Diagrams)

### 6.1 تسلسل فحص الموقع (Web URL Scan)

```plantuml
@startuml
autonumber
actor "المحلل" as User
participant "React Frontend" as FE
participant "Flask Backend\n(app.py)" as BE
participant "UrlScanner" as US
participant "OWASPChecker" as OC
participant "CybrainAgent (AI)" as AI
database "الموقع المستهدف" as Target

User -> FE : إدخال URL والضغط على "فحص"
FE -> BE : POST /scan_url {url: "http://target.com"}
BE -> BE : التحقق من URL (حظر IPs الداخلية)
BE -> US ** : new UrlScanner(url)
US -> Target : _check_connection() (3 محاولات)
Target --> US : HTTP 200 OK
BE -> US : scan()
US -> OC ** : new OWASPChecker(url)
US -> OC : _attach_extended()
US -> OC : run_all()
activate OC

OC -> Target : طلب HTML أولي
Target --> OC : استجابة HTML
OC -> OC : _spider_target(html)

par ThreadPoolExecutor (8 خيوط)
    OC -> Target : فحوصات متوازية (A01 → A08)
    Target --> OC : استجابات متعددة
end

OC -> Target : فحوصات تسلسلية (SQLi, SSRF, Log4Shell...)
Target --> OC : استجابات
OC --> US : النتائج (قائمة خام)
deactivate OC

US -> US : إزالة التكرار + ترتيب حسب الخطورة
US --> BE : JSON {findings, total, risk}
BE --> FE : استجابة JSON
FE -> User : عرض النتائج

opt طلب تحليل ذكاء اصطناعي
    User -> FE : الضغط على "تحليل بالذكاء الاصطناعي"
    FE -> BE : POST /api/analyze_findings
    BE -> AI : analyze_findings(findings)
    alt Gemini API متاح
        AI -> AI : استدعاء Gemini API
    else تجاوز حد الطلبات
        AI -> AI : المحرك المحلي (offline mode)
    end
    AI --> BE : تقرير Markdown
    BE --> FE : {analysis: "..."}
    FE -> User : عرض التقرير الذكي
end
@enduml
```

### 6.2 تسلسل فحص الكود المصدري (SAST)

```plantuml
@startuml
autonumber
actor "المحلل" as User
participant "React Frontend" as FE
participant "Flask Backend" as BE
participant "CodeAnalyzer" as CA
participant "CybrainAgent (AI)" as AI

User -> FE : رفع ملف ZIP يحتوي الكود
FE -> BE : POST /scan_code {file: zip_data}
BE -> BE : فحص حجم الملف (حماية من ZIP Bomb)
BE -> CA ** : new CodeAnalyzer()
CA -> CA : _detect_language(filename)
CA -> CA : تطبيق أنماط الكشف (SQLi, XSS, Hardcoded Creds...)
CA --> BE : JSON {findings, language, total}
BE --> FE : النتائج
FE -> User : عرض الثغرات مع أرقام الأسطر

opt طلب إصلاح تلقائي
    User -> FE : الضغط على "إصلاح الكود"
    FE -> BE : POST /api/fix_code
    BE -> AI : fix_code(vulnerable_code, filename)
    AI --> BE : {fixed_code, explanation}
    BE --> FE : الكود المُصحَّح
    FE -> User : عرض الكود بعد التصحيح
end
@enduml
```

### 6.3 تسلسل تسجيل الدخول والمصادقة

```plantuml
@startuml
autonumber
actor "المستخدم" as User
participant "React Frontend" as FE
participant "Flask Backend" as BE

User -> FE : إدخال البريد الإلكتروني وكلمة المرور
FE -> BE : POST /login {email, password}
BE -> BE : CSRF Token التحقق من
BE -> BE : Rate Limiting (10 محاولات/دقيقة)
BE -> BE : bcrypt.checkpw(password, hash)
alt بيانات صحيحة
    BE --> FE : {success: true, token: JWT}
    FE -> User : التحويل إلى لوحة التحكم
else بيانات خاطئة
    BE -> BE : تسجيل المحاولة الفاشلة
    alt 5 محاولات فاشلة
        BE --> FE : {error: "الحساب مُقفَل 15 دقيقة"}
    else محاولات أقل من 5
        BE --> FE : {error: "بيانات غير صحيحة"}
    end
end
@enduml
```

---

## 7. تحليل النظام بمخطط الفئات (Class Diagram)

```plantuml
@startuml
skinparam classAttributeIconSize 0

class UrlScanner {
  + target_url: str
  + session: requests.Session
  + last_findings: list
  - _raw_findings: list
  + __init__(target_url: str)
  + scan(): list
  - _check_connection(): bool
  - _attach_extended(checker: OWASPChecker)
  - _calc_overall_risk(): str
}

class OWASPChecker {
  + target: str
  + base: str
  + session: Session
  + findings: list
  + fast_mode: bool
  - _lock: threading.Lock
  + __init__(target_url: str, session: Session)
  + run_all(): list
  - _add(owasp_id, name, severity, title, desc)
  - _spider_target(html: str)
  - _a01_broken_access_control(resp)
  - _a02_security_misconfiguration(resp)
  - _a03_supply_chain(resp)
  - _a05_injection(resp)
  - _sqli_boolean()
  - _sqli_time_based()
}

class ExtendedChecks <<Mixin>> {
  - _race_condition_check()
  - _mass_assignment_check()
  - _log4shell_check()
  - _graphql_introspection()
}

class ApacheMisconfigDetector {
  + config_text: str
  + source_name: str
  + findings: list
  + detect(): list
  - _check_directory_listing()
  - _check_ssl_protocols()
  - _check_cleartext_password()
  - _check_cors()
}

class CodeAnalyzer {
  + language: str
  + findings: list
  + analyze(code: str, filename: str): dict
  - _detect_language(filename: str): str
  - _check_sqli(code: str): list
  - _check_xss(code: str): list
  - _check_hardcoded_creds(code: str): list
}

class NetworkScanner {
  + target: str
  + recon_data: dict
  + findings: list
  + scan(mode: str): list
  - _calc_overall_risk(): str
}

class CybrainAgent {
  + ai_active: bool
  + model: GenerativeModel
  + chat(message: str, context: dict): str
  + analyze_findings(findings: list, target: str, type: str): str
  + fix_code(code: str, filename: str): dict
  + fix_apache_config(config: str, findings: list): dict
  - _gemini(prompt: str, system: str): str
  - _analyze_offline(findings: list, target: str, type: str): str
}

class ReportGenerator {
  + target: str
  + findings: list
  + output_dir: str
  + generate_all()
  + generate_markdown(): str
  + generate_csv(): str
  + generate_json(): str
}

UrlScanner "1" *-- "1" OWASPChecker : ينشئ >
OWASPChecker <|.. ExtendedChecks : يُحقن وقت التشغيل
UrlScanner "1" *-- "1" ReportGenerator : ينشئ >
CybrainAgent "1" *-- "1" ReportGenerator : يستخدم >

note right of ExtendedChecks: تُحقن ديناميكياً عبر\nPython types.MethodType\nوقت التشغيل
@enduml
```

**شرح المخطط:** يُظهر هذا المخطط البنية الكائنية للنظام. الملاحظة الأهم هي الطريقة الديناميكية التي يُحقَن بها `ExtendedChecks` في `OWASPChecker` وقت التشغيل باستخدام `types.MethodType` — وهو نمط برمجي متقدم يوفر مرونة كبيرة دون تعقيد الكلاس الأصلي.

---

## 8. الخاتمة

في هذا الفصل قدّمنا الصورة الكاملة لتصميم SecuraX: من أعلى مستوى (مخطط السياق) وصولاً إلى تفاصيل الكلاسات والتسلسلات. هذا التصميم ليس نظرياً فحسب — بل هو ما يعمل فعلاً في النظام الذي طورناه وسنشرحه في الفصول التالية.
