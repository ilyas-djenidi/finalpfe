
# الفصل الثالث: التقنيات والخوارزميات — الذكاء الاصطناعي، الفحوصات المتعددة، والأمان الشامل

---

## 1. مقدمة

إذا كان الفصل السابق قد أجاب على سؤال "ماذا يفعل النظام؟"، فهذا الفصل يُجيب على "كيف يفعله؟". كل خوارزمية، كل قرار تصميمي، كل تقنية اخترناها — كانت لها أسباب واضحة وقرارات مدروسة.

في هذا الفصل، نشرح الخوارزميات الأساسية التي يقوم عليها النظام، وكيف دمجنا الذكاء الاصطناعي في صميم العمل لا كإضافة جانبية.

---

## 2. النماذج اللغوية الكبيرة (LLM)

### 2.1 التعريف

**النموذج اللغوي الكبير (Large Language Model)** هو شبكة عصبية عميقة مُدرَّبة على مليارات النصوص لتفهم اللغة الطبيعية وتولّدها. ما يجعلها ثورية هو قدرتها على التعميم: لم تُدرَّب على الأسئلة الأمنية تحديداً، لكنها رأت كمية هائلة من المعرفة الأمنية خلال التدريب، فاكتسبت فهماً عميقاً يُمكّنها من الإجابة على أسئلة لم تُسأل من قبل.

### 2.2 كيف يعمل Transformer (المعمارية الأساسية)

النماذج الكبيرة تعتمد على معمارية **Transformer** التي ظهرت عام 2017 من Google. الفكرة الجوهرية هي **آلية الانتباه (Attention Mechanism)**: عند معالجة كلمة في الجملة، ينتبه النموذج لكل الكلمات الأخرى في نفس الوقت لفهم السياق — لا يقرأ الجملة بالترتيب كما كانت النماذج القديمة تفعل.

### 2.3 طرق استخدام LLM في الأنظمة البرمجية

**الأسلوب الأول — استدعاء API مباشر:**
الأسلوب الذي اعتمدناه في SecuraX. ترسل الطلب إلى API Gemini مع prompt مُهندَس بعناية، وتستقبل الإجابة.

**الأسلوب الثاني — Fine-Tuning:**
ضبط دقيق للنموذج على بيانات خاصة بمجال معين. أكثر تكلفة لكن النتائج أكثر تخصصاً.

**الأسلوب الثالث — RAG (Retrieval-Augmented Generation):**
إضافة قاعدة بيانات خاصة تُسترجع منها المعلومات ذات الصلة وتُضاف إلى الـ prompt. نُخطط لاعتماده في النسخة Pro.

---

## 3. استخدام Gemini في SecuraX

### 3.1 نبذة عن Gemini

**Gemini 2.0 Flash** هو النموذج الذي طوّرته Google DeepMind، ويتميز بـ:
- سرعة استجابة عالية (مناسب جداً للتطبيقات التفاعلية)
- دعم نافذة سياق (Context Window) كبيرة
- متاح بمستوى مجاني يكفي للاستخدام الأكاديمي والمشاريع الناشئة

### 3.2 طريقة الدمج في النظام

```python
# ai_agent.py — الاتصال بـ Gemini
import google.generativeai as genai

genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))

model = genai.GenerativeModel(
    model_name="gemini-2.0-flash",
    system_instruction="أنت SecuraX، محلل أمني محترف..."
)

def _gemini(self, prompt: str, system: str) -> str:
    response = model.generate_content(prompt)
    return response.text
```

### 3.3 هندسة الـ Prompts (Prompt Engineering)

هندسة الـ Prompt هي فن صياغة الطلب للنموذج بطريقة تُحسّن جودة الإجابة. في SecuraX استخدمنا ثلاث تقنيات:

**أولاً — حقن الدور (Role Injection):**
```
"أنت SecuraX، محلل اختراق محترف. مهمتك تحليل النتائج الأمنية 
وتقديم تقرير تنفيذي مُنظَّم..."
```

**ثانياً — حقن السياق (Context Injection):**
مع كل طلب، نُدرج نتائج الفحص الفعلية كـ JSON حتى يُجيب النموذج على أساس بيانات حقيقية لا عامة.

**ثالثاً — تحديد صيغة الإخراج (Output Format):**
```
"نسّق إجابتك كـ Markdown احترافي. يشمل:
1. ملخص تنفيذي
2. أهم 5 ثغرات مُرتَّبة بالأولوية مع كود الإصلاح
3. تأثير على الامتثال (GDPR, PCI-DSS, ISO 27001)
4. نقاط الضعف حسب درجة CVSS"
```

### 3.4 مجالات استخدام الذكاء الاصطناعي في المنصة

| الوظيفة | الوصف |
|---------|-------|
| تحليل النتائج | تحويل قائمة الثغرات إلى تقرير تنفيذي مفهوم |
| إصلاح الكود | أخذ الكود الضعيف وإعادة كتابته بشكل آمن |
| تصليب Apache | توليد ملف `httpd.conf` جديد محصّن بالكامل |
| ChatBot الأمني | الإجابة على أسئلة OWASP وCVSS وMITRE بشكل تفاعلي |
| تقييم الامتثال | ربط كل ثغرة بمعيار GDPR أو PCI-DSS أو ISO 27001 |

### 3.5 الوضع المحلي (Offline Fallback)

واحدة من أهم الميزات في SecuraX هي أنها **لا تتوقف** إذا انقطع الاتصال بـ Gemini أو استُنفدت الحصة المجانية. المحرك المحلي يعمل كالتالي:

```python
def _analyze_offline(self, findings: list, target: str, scan_type: str) -> str:
    """
    محرك القواعد المحلي — يعمل بدون إنترنت
    قاعدة بيانات تحتوي +20 ثغرة مع: CVE، CWE، CVSS، السيناريو، كود الإصلاح
    """
    total_weight = sum(SEVERITY_WEIGHTS[f['severity']] for f in findings)
    score = max(0, 100 - min(total_weight * 3, 95))
    # CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1
    ...
    return markdown_report
```

---

## 4. نظام التخزين المؤقت (Caching) للاستجابات الذكية

لتقليل تكلفة API وتسريع الاستجابة، طبّقنا نظام تخزين مؤقت ذكي:

```python
# مفتاح الـ Cache = MD5(prompt + context)
cache_key = hashlib.md5((message + str(context)).encode()).hexdigest()

# TTL = 5 دقائق، الحد الأقصى = 200 إدخال (LRU)
if cache_key in self._cache:
    if time.time() - self._cache[cache_key]['time'] < 300:  # 5 min
        return self._cache[cache_key]['response']
```

هذا يعني أنه إذا طلب مستخدمان نفس التحليل بفارق دقائق، يُعيد النظام نفس الإجابة من الـ Cache دون استدعاء Gemini مرة أخرى.

---

## 5. خوارزميات كشف الثغرات

### 5.1 خوارزمية SQL Injection البولية (Boolean-Blind)

هذه من أذكى الخوارزميات في النظام. فكرتها: إذا كان الحقل عُرضة لـ SQLi، يجب أن يختلف الموقع في رده بين الشرطين الصحيح والخاطئ:

```
1. قِس طول استجابة الطلب العادي: len_baseline = len(GET /page?id=1)
2. أرسل الشرط الصحيح: GET /page?id=1 AND 1=1
   → قِس: len_true
3. أرسل الشرط الخاطئ: GET /page?id=1 AND 1=2
   → قِس: len_false
4. الحكم:
   - إذا كان (len_true - len_baseline) < 20 بايت     (الصحيح يشبه الأصل)
   - وكان (len_false - len_baseline) > 100 بايت      (الخاطئ يختلف كثيراً)
   → ثغرة SQL Injection مؤكدة ✓
```

**لماذا هذا أذكى من الطريقة البسيطة؟** لأن الطريقة البسيطة (البحث عن رسائل خطأ SQL) لا تكشف الثغرات الصامتة التي لا تظهر أخطاء ظاهرة، وهذه النوعية أخطر لأن المطور لا يعلم بها.

### 5.2 خوارزمية SQL Injection الزمنية (Time-Based)

```
1. قِس زمن الاستجابة الأصلي: t_baseline
2. أرسل: GET /page?id=1; SLEEP(3)--
3. قِس: t_elapsed
4. الحكم:
   - يجب أن يكون t_elapsed >= 3.0 ثانية (عتبة مطلقة)
   - ويجب أن يكون t_elapsed >= t_baseline + 2.4 ثانية (عتبة نسبية)
   → كلا الشرطين مطلوبان لتأكيد الثغرة
```

**لماذا شرطان؟** لأن الشرط الأول وحده قد يُخطئ إذا كان الخادم أصلاً بطيئاً. الشرط الثاني يضمن أن التأخير مرتبط بـ SLEEP حقاً لا ببطء الشبكة.

### 5.3 خوارزمية حساب درجة المخاطر (Risk Score)

```
المدخلات: قائمة الثغرات بمستوياتها (CRITICAL, HIGH, MEDIUM, LOW)

الخطوة 1: إيجاد المستوى الأعلى (الحالة الأسوأ)
→ النتيجة = المستوى الأعلى مباشرة
   (ثغرة واحدة CRITICAL = نظام عالي الخطورة)

للنقاط التفصيلية في الوضع المحلي:
الخطوة 2: حساب الوزن الكلي
  total_weight = CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1

الخطوة 3: النقاط النهائية
  score = max(0, 100 - min(total_weight × 3, 95))
  → النطاق: 5–100 (لا يصل صفراً إلا إذا كان نقياً تماماً)
```

### 5.4 الإزالة الفعّالة للمكررات (Deduplication)

```python
seen = set()
unique_findings = []
for finding in raw_findings:
    if finding['title'] not in seen:
        unique_findings.append(finding)
        seen.add(finding['title'])
```

لماذا نحتاج هذا؟ لأن 8 خيوط تعمل بالتوازي، وقد تكتشف كلها نفس الثغرة في نفس الوقت. بدون هذا، سيرى المستخدم نفس الثغرة 8 مرات.

### 5.5 الحقن الديناميكي للدوال (Metaprogramming)

هذا من أكثر الأنماط البرمجية إبداعاً في المشروع. بدل أن نضع كل فحوصات `ExtendedChecks` داخل `OWASPChecker` مباشرةً (مما يجعله ضخماً وصعب الصيانة)، نحقنها ديناميكياً وقت التشغيل:

```python
import types

def _attach_extended(self, checker):
    """
    يربط دوال ExtendedChecks بنسخة OWASPChecker وقت التشغيل
    فتحصل على وصول كامل لـ checker.session و checker._add()
    """
    for method_name in ['_race_condition_check', '_mass_assignment_check',
                        '_log4shell_check', '_graphql_introspection']:
        method = getattr(ExtendedChecks, method_name)
        setattr(checker, method_name, types.MethodType(method, checker))
```

النتيجة: كلاس `OWASPChecker` يبقى نظيفاً، و`ExtendedChecks` يمكن تطوير دوالها ونشرها بشكل مستقل.

---

## 6. الفحص المتوازي (Multithreading)

### 6.1 لماذا التوازي؟

فحص موقع ويب واحد يتطلب إرسال مئات الطلبات HTTP. لو أرسلناها واحدة تلو الأخرى، قد يستغرق الفحص الكامل **15–20 دقيقة**. بالتوازي (8 خيوط)، ينتهي في **2–3 دقائق**.

### 6.2 الأمان التزامني (Thread Safety)

عندما تكتب 8 خيوط في نفس القائمة في نفس الوقت، تحدث "حالة السباق" (Race Condition) وتتلف البيانات. الحل:

```python
class OWASPChecker:
    def __init__(self):
        self._lock = threading.Lock()  # قفل مشترك

    def _add(self, owasp_id, name, severity, title, desc):
        with self._lock:  # يُقفل القائمة أثناء الكتابة
            self.findings.append({...})
        # يُفتح القفل تلقائياً عند نهاية with
```

هذا يضمن أن خيطاً واحداً فقط يكتب في القائمة في أي لحظة، حتى لو 8 خيوط تنتظر.

---

## 7. أمان المنصة ذاتها

فكرة بناء منصة أمنية غير آمنة بحد ذاتها لا معنى لها. لذلك طبّقنا معايير الأمان على كل مكون:

### 7.1 التحقق من المدخلات ومنع SSRF

```python
BLOCKED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]
BLOCKED_HOSTS = ['localhost', 'metadata.google.internal', '169.254.169.254']

def _validate_url(url: str) -> bool:
    """
    يمنع SSRF — لا يسمح للمستخدم بتوجيه الفحص نحو الشبكات الداخلية
    """
    parsed = urlparse(url)
    if parsed.hostname in BLOCKED_HOSTS:
        return False
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    for network in BLOCKED_NETWORKS:
        if ip in network:
            return False
    return True
```

### 7.2 حماية ضد ZIP Bomb

```python
MAX_UNCOMPRESSED_SIZE = 150 * 1024 * 1024  # 150 MB

def extract_safe(zip_path):
    total_size = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            total_size += info.file_size
            if total_size > MAX_UNCOMPRESSED_SIZE:
                raise ValueError("ملف ZIP كبير جداً — محاولة هجوم ZIP Bomb محتملة")
```

### 7.3 معدل التقييد (Rate Limiting)

```python
# app.py
from flask_limiter import Limiter

limiter = Limiter(app, default_limits=["200 per day"])

@app.route('/scan_url', methods=['POST'])
@limiter.limit("5 per minute")  # 5 فحوصات/دقيقة كحد أقصى
def scan_url():
    ...

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("20 per hour")  # تحليل ذكاء اصطناعي مقيّد
def analyze():
    ...
```

---

## 8. فحص الاعتمادات (Dependency Scanning)

### 8.1 pip-audit لـ Python

```bash
pip-audit -r requirements.txt --format json
```

يستعلم من **قاعدة بيانات NIST NVD** (قاعدة البيانات الأمريكية الرسمية للثغرات) عن كل مكتبة Python وإصدارها. إذا وجد ثغرة CVE معروفة، يُبلّغ عنها مع درجة CVSS.

هذا يُعالج **OWASP A06:2021 — Vulnerable and Outdated Components** وهي من أكثر أسباب الاختراق شيوعاً: مكتبات قديمة يعرف الجميع ثغراتها إلا المطور الذي يستخدمها.

### 8.2 npm audit لـ Node.js

```bash
npm audit --json
```

نفس الفكرة لكن لمشاريع JavaScript. يستعلم من قاعدة بيانات npm Advisory.

---

## 9. كشف الثغرات في إعدادات Apache (22 فحصاً)

### 9.1 لماذا Apache تحديداً؟

Apache httpd هو من أكثر خوادم الويب انتشاراً في العالم، ويُقدَّر أنه يخدم أكثر من 30% من مواقع الإنترنت. إعداده الخاطئ مسؤول عن كثير من الاختراقات الفعلية في بيئات الإنتاج. لا توجد أداة مفتوحة المصدر ناضجة تُحلّل ملف `httpd.conf` بعمق — فكان هذا فجوة حقيقية ملأناها.

### 9.2 أمثلة على الفحوصات

```python
def _check_directory_listing(self):
    """CWE-548: Directory Listing"""
    if re.search(r'Options\s+.*\+Indexes', self.config_text, re.IGNORECASE):
        self._add("directory_listing", "CRITICAL",
                  "Options +Indexes مُفعَّل — يُظهر محتوى المجلدات للعموم",
                  "أضف: Options -Indexes")

def _check_ssl_protocols(self):
    """CWE-327: Weak SSL/TLS"""
    weak = ['SSLv2', 'SSLv3', 'TLSv1 ', 'TLSv1.1']
    for protocol in weak:
        if protocol in self.config_text:
            self._add("weak_tls", "HIGH",
                      f"بروتوكول {protocol} ضعيف مُفعَّل",
                      "استخدم: SSLProtocol TLSv1.2 TLSv1.3 فقط")

def _check_cleartext_password(self):
    """CWE-798: Hardcoded Credentials — CRITICAL"""
    pattern = r'(password|passwd|secret)\s*=\s*["\']?\w+'
    if re.search(pattern, self.config_text, re.IGNORECASE):
        self._add("cleartext_password", "CRITICAL",
                  "كلمة مرور واضحة في ملف الإعداد!",
                  "استخدم متغيرات البيئة أو AuthUserFile")
```

### 9.3 ميزة توليد الملف المُصحَّح

ميزة فريدة في SecuraX: بعد كشف الثغرات في ملف Apache، يُولّد النظام **ملف إعداد جديد مُصحَّح** يمكن تحميله وتطبيقه مباشرةً — مع تعليقات توضيحية عند كل تغيير.

---

## 10. معايير الأمان المعتمدة في المشروع

| المعيار | التطبيق في SecuraX |
|---------|-------------------|
| OWASP Top 10 (2025) | كل ماسح يُصنّف نتائجه حسب OWASP A01–A10 |
| CVSS v3.1 | درجة خطورة لكل ثغرة (0–10) |
| CWE (MITRE) | معرف ضعف لكل نتيجة |
| GDPR Art. 32 | تقييم الامتثال عبر محرك الذكاء الاصطناعي |
| PCI-DSS Req. 6.3 | تقييم الامتثال عبر محرك الذكاء الاصطناعي |
| ISO 27001 A.14.2 | تقييم الامتثال عبر محرك الذكاء الاصطناعي |
| PTES (Penetration Testing Execution Standard) | منهجية الفحص: استطلاع ← فحص ← كشف ← تقرير |

---

## 11. الخاتمة

في هذا الفصل كشفنا عن الأساس التقني الحقيقي لـ SecuraX: من خوارزميات كشف SQLi المتقدمة، إلى الحقن الديناميكي للدوال، إلى الذكاء الاصطناعي المزدوج مع وضع احتياطي دائم العمل. كل هذه القرارات لها مبرراتها التقنية الواضحة — وهي التي تجعل SecuraX نظاماً جاداً لا مجرد تجربة أكاديمية.
