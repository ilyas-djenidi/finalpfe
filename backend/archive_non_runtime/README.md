# NEXUS SECURITY — منصة التقييم الأمني

## هيكل المشروع

```
nexus-security/
│
├── index.html                  # HTML خالص — البنية فقط، بدون styles أو scripts مضمّنة
│
├── css/
│   ├── variables.css           # Design tokens — مصدر الحقيقة الوحيد لكل الألوان والمتغيرات
│   ├── base.css                # CSS Reset + عناصر HTML الأساسية
│   ├── layout.css              # الهياكل والمساحات (header, main, footer, grid)
│   ├── components.css          # مكونات UI (buttons, inputs, cards, badges...)
│   ├── animations.css          # كل @keyframes والحركات — مكان واحد للتحكم بالموشن
│   └── responsive.css          # Breakpoints فقط — overrides للشاشات الصغيرة
│
└── js/
    ├── config.js               # كل الثوابت والـ magic numbers — لا تكرارها في أي مكان آخر
    ├── utils.js                # دوال مساعدة خالصة (pure) — بدون DOM، قابلة للـ unit test
    ├── particles.js            # نظام الجسيمات المتحركة
    ├── validator.js            # منطق التحقق من المدخلات — pure functions، بدون DOM
    ├── ui.js                   # كل تعديلات الـ DOM وحالات الواجهة
    ├── form.js                 # منطق النموذج، CSRF، تقديم الفحص
    └── main.js                 # نقطة الدخول — يشغّل كل الوحدات بعد اكتمال DOM
```

## مبادئ التنظيم

| الملف          | المسؤولية                          | يعتمد على                  |
|----------------|------------------------------------|-----------------------------|
| `variables.css`| Design tokens فقط                 | —                           |
| `base.css`     | Reset + عناصر أساسية              | variables.css               |
| `layout.css`   | هيكل الصفحة                       | variables.css               |
| `components.css`| مظهر المكونات                    | variables.css               |
| `animations.css`| Keyframes + reduced-motion        | variables.css               |
| `responsive.css`| Media queries                    | الملفات الأخرى              |
| `config.js`    | Constants (frozen object)          | —                           |
| `utils.js`     | Pure helpers                       | —                           |
| `particles.js` | Particle DOM                       | config, utils               |
| `validator.js` | Input validation (pure)            | config                      |
| `ui.js`        | DOM manipulation                   | config, utils               |
| `form.js`      | Form logic + scan simulation       | config, utils, validator, ui|
| `main.js`      | Bootstrap                          | all modules                 |

## قواعد التطوير

1. **لا Magic Numbers** — كل القيم في `config.js` أو `variables.css`
2. **Validator لا يلمس DOM** — فقط يعيد نتائج، `ui.js` هو من يعرضها
3. **utils.js قابل للـ unit test** — لا يستورد DOM APIs
4. **animations.css** هو المكان الوحيد لـ `@keyframes`
5. **responsive.css** يحتوي overrides فقط، لا styles جديدة

## للإنتاج

في `form.js` ابحث عن التعليق `PRODUCTION NOTE` واستبدل الـ simulation بـ:

```javascript
const fd = new FormData(els.form);
fetch(config.API.SCAN_ENDPOINT, {
    method: config.API.METHOD,
    body: fd,
})
.then(res => res.json())
.then(data => handleResponse(data))
.catch(err => handleError(err));
```
