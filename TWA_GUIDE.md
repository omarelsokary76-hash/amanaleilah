# دليل تحويل "أمان العيلة" إلى تطبيق أندرويد (TWA)

آخر تحديث: 2026-10-05

## 0) قبل ما تبدأ: لازم تتأكد من الحاجات دي (من الموبايل، من غير تسجيل دخول)
افتح كل رابط، ولازم يشتغل:

| الرابط | المتوقع |
|---|---|
| `/manifest.json` | JSON فيه `id` و`shortcuts` و3 أيقونات |
| `/sw.js` | كود JavaScript |
| `/.well-known/assetlinks.json` | `[]` دلوقتي (هيتملّى بعد ما تحط البصمة) |
| `/privacy-policy` | سياسة الخصوصية |
| `/account-deletion` | صفحة طلب الحذف |
| `/fonts/cairo-arabic.woff2` | بينزّل ملف الخط |

وفي Cloudflare لازم تكون مسجّل: `ADMIN_KEY` و`ENCRYPTION_KEY` (ولّده من `/setup-key`) و`VAPID_PRIVATE_KEY` كـ Secrets، والكرون `* * * * *`.

## 1) PWABuilder (pwabuilder.com) - القيم اللي تحطها
- **URL:** `https://amanaleilah.aktyaraty.workers.dev`
- **Package ID:** اختار واحد ثابت، مثلًا `com.اسمك.amanaleilah` (إنجليزي، **مش بيتغيّر بعد الرفع**)
- **App name / Launcher name:** أمان العيلة
- **App version:** `1.0.0` و**Version code:** `1` (بيزيد مع كل نسخة)
- **Host:** `amanaleilah.aktyaraty.workers.dev`
- **Start URL:** `/`  |  **Display:** Standalone  |  **Orientation:** Portrait
- **Status bar / Navigation bar color:** `#6d28d9`
- **Splash screen color:** `#f5f3ff`
- **Icon:** `/icon-512.png`  |  **Maskable icon:** `/icon-512-maskable.png`
- **Fallback behavior:** Custom Tabs
- **Notification delegation:** ✅ شغّلها (بدونها الإشعارات مش هتوصل)
- **Location delegation:** ✅ شغّلها (لمشاركة الموقع)
- **Google Play Billing:** ❌ مقفول
- **Signing key:** New (أنشئ مفتاح جديد، **وانسخ الملف وكلمات السر في مكانين**، لو ضاعوا مش هتقدر تحدّث التطبيق)
- **مستوى الـ API:** لازم يكون **36 (أندرويد 16)** على الأقل. اتأكد إن PWABuilder بيبني عليه، ولو لأ حدّث الأداة.

هتاخد ملف `.aab` (ده اللي بيترفع على Play) وبصمة SHA-256 للمفتاح.

## 2) ربط التطبيق بالموقع (Digital Asset Links)
1. في Cloudflare ← Settings ← Variables ضيف (نوع Text):
   - `TWA_PACKAGE_NAME` = الـ Package ID
   - `TWA_SHA256_FINGERPRINT` = البصمة (كل بصمة شكلها `AA:BB:...` بـ 32 جزء)
2. Deploy، وافتح `/.well-known/assetlinks.json`: لازم يرجّع Package ID والبصمة.
3. **بعد ما ترفع على Play Console:** جوجل بتعيد توقيع التطبيق بمفتاحها. من Play Console ← سلامة التطبيق (App integrity) ← توقيع التطبيق، انسخ **App signing key certificate SHA-256**، وضيفه جنب البصمة القديمة مفصولة **بفاصلة**:
   `البصمة1, البصمة2`
   (الملف بيقبل أكتر من بصمة). لو نسيت الخطوة دي، التطبيق هيظهر بشريط عنوان المتصفح فوق بدل ملء الشاشة.

## 3) اختبار قبل النشر
1. ارفع الـ `.aab` على **Internal testing** في Play Console، وثبّته من Play على موبايلين.
2. اتأكد من: ملء الشاشة بدون شريط عنوان، إذن الإشعارات بيظهر (أندرويد 13+) ومنه بتوصل الإشعارات، إذن الموقع، زر الرجوع، والضغط المطوّل على الأيقونة بيظهر 3 اختصارات (الشات والأدوية والعائلة).
3. لو ظهر شريط العنوان: البصمة غلط أو لسه ما اتحدّثتش (نقطة 2.3).

## 4) اللي هيفضل خارج حدود التطبيق الحالي
- الجرس المتكرر زي المنبّه والتطبيق مقفول، واختيار نغمة من نغمات الموبايل جوّه التطبيق: محتاجين تطبيق أندرويد أصلي (مش TWA).
- لقطات شاشة للمتجر: لازم تصوّرها من الموبايل الفعلي (من غير بيانات حقيقية).
