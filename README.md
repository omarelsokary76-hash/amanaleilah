# أمان العيلة - Backend (Cloudflare Workers)

تطبيق تواصل عائلي للبالغين (18+) مبني على Cloudflare Workers + D1 + R2.

## 1. الملفات في المستودع ده

| الملف | الوظيفة |
|---|---|
| `worker.js` | كل الباك إند + الواجهة الأمامية (مدمجة كمتغير `INDEX_HTML` جوّه نفس الملف) |
| `wrangler.toml` | إعدادات Cloudflare (D1, R2, Cron, Rate Limiting) |
| `schema.sql` | الجداول الأساسية |
| `push_migration.sql` | جدول اشتراكات الإشعارات |
| `compliance_migration.sql` | أعمدة الالتزام بسياسة 18+ (age_confirmed, consent_at) |
| `auth_migration.sql` | نظام كلمة السر وسؤال الأمان (بدل الهاتف/PIN) |
| `coadmin_recovery_migration.sql` | نائب كبير عائلة + سؤالي أمان بدل واحد |
| `privacy_policy.md` | نسخة مرجعية نصية من سياسة الخصوصية (نفس محتوى صفحة `/privacy-policy` الحية اللي جوّه `worker.js`) |
| `store_listing.md` | نص صفحة Google Play (وصف، تصنيف، نموذج أمان البيانات) |

## 2. الإعداد الأول (مرة واحدة)

### أ) قاعدة البيانات (D1) - شغّل الملفات بالترتيب ده بالظبط:
```bash
wrangler d1 execute amanaleilah-db --remote --file=./schema.sql
wrangler d1 execute amanaleilah-db --remote --file=./push_migration.sql
wrangler d1 execute amanaleilah-db --remote --file=./compliance_migration.sql
wrangler d1 execute amanaleilah-db --remote --file=./auth_migration.sql
wrangler d1 execute amanaleilah-db --remote --file=./coadmin_recovery_migration.sql
```

**ملحوظة:** الكود بيفترض وجود جداول `chat_reports`, `private_messages`, وعمود `public_key` في `members` من migrations قديمة عندك مش موجودة في المستودع ده. تأكد إنها شغالة فعليًا على قاعدة بياناتك قبل النشر.

### ب) الأسرار (Secrets) - **إلزامية، التطبيق مش هيشتغل بأمان من غيرها:**
```bash
wrangler secret put ADMIN_KEY          # مفتاح لوحة الإدارة السرية
wrangler secret put ENCRYPTION_KEY     # لازم يتسجل، وإلا التطبيق هيرفض تخزين أي موقع جغرافي
wrangler secret put VAPID_PRIVATE_KEY  # لازم يتسجل، وإلا الإشعارات (Push) مش هتشتغل
```

### ج) Rate Limiting binding
موجود في `wrangler.toml` تحت `[[ratelimits]]`. محتاج **Wrangler CLI نسخة 4.36.0 أو أحدث**. تأكد بعد النشر إن الحماية دي فعلاً شغالة (جرب تدخل كلمة سر غلط كذا مرة بسرعة وشوف هل بيرفض بعد شوية).

### د) Durable Object لتكرار إنذار الاستغاثة
موجود في `wrangler.toml` تحت `[[durable_objects.bindings]]` و`[[migrations]]`. ده بيخلي زر الطوارئ يبعت إشعار متكرر كل 30 ثانية لباقي العائلة (حتى لو التطبيق مقفول عندهم)، لحد ما حد يضغط "تم الاطلاع" أو لحد 10 دقايق كحد أقصى. مفيش إعداد إضافي مطلوب منك، بس تأكد إن حساب Cloudflare بتاعك مفعّل عليه Durable Objects (متاحة في الخطة المجانية).

### د) النشر
```bash
wrangler deploy
```
الـ Cron Trigger (تنظيف البيانات القديمة + تنفيذ طلبات الحذف المؤجلة) بيتفعّل تلقائيًا مع النشر.

## 3. سياسة الخصوصية - بقت صفحة حية، مش ملف محتاج استضافة منفصلة

`privacy_policy.md` هو نفس المحتوى كمرجع نصي بس. **الصفحة الفعلية اللي تستخدمها في Google Play** بتتفعّل تلقائيًا بمجرد النشر على:
```
https://<دومين الـ Worker بتاعك>/privacy-policy
```
قبل النشر، عدّل القيم دي في `wrangler.toml` تحت `[vars]`:
```toml
PRIVACY_CONTACT_EMAIL = "بريدك الحقيقي"
PRIVACY_DEVELOPER_NAME = "اسمك أو اسم شركتك"
PRIVACY_POLICY_DATE = "تاريخ آخر تحديث"
```
لو نسيت تعدّلهم، الصفحة هتوضح رسالة تفتكرك بدل ما تعرض بيانات خاطئة بصمت.

## 4. قبل ما ترفع على Google Play - حاجات برّه نطاق الكود

- [ ] **تحويل التطبيق لـ APK/AAB** عن طريق TWA (Trusted Web Activity) - ده لسه معمولش خالص، ومطلوب إلزاميًا للرفع على Google Play
- [ ] ضبط الرابط الفعلي بتاعك في حقل "Privacy Policy" و"Account deletion" على Play Console: `https://<دومينك>/privacy-policy` و`https://<دومينك>/account-deletion`
- [ ] مراجعة قانونية مصرية لنقطة تخزين البيانات على Cloudflare (خارج مصر جغرافيًا)
- [ ] تفعيل خاصية "Restrict Minor Access" في Play Console بعد اختيار الجمهور 18+
- [ ] التأكد إن أيقونة وتصميم التطبيق في المتجر مايظهرش وكأنه موجّه للأطفال

## 5. ملخص الميزات الأمنية المُنفَّذة

- بدون رقم هاتف أو بريد إلكتروني - تسجيل الدخول بالاسم وكلمة السر
- سؤالا أمان (لازم إجابتين صح) للاسترجاع الذاتي لكلمة السر
- نائب كبير عائلة (co-admin) لتفادي توقف العائلة لو الأدمن الأساسي غاب
- تشفير AES-GCM للموقع الجغرافي، وE2E للشات الخاص
- حذف حساب/عائلة فوري من داخل التطبيق + رابط عام بمهلة 24 ساعة قابلة للإلغاء
- مراجعة بلاغات المحتوى من داخل تبويب العائلة
- إشعار طوارئ متكرر كل 30 ثانية (حتى لو التطبيق مقفول) لحد ما حد يؤكد إنه شاف النداء
- إصلاح زر حذف العضو (كان معطوب - الزرار موجود بس من غير أي كود بيستجيب له)
- حد أقصى لحجم ونوع ملفات الوسائط المرفوعة (15 ميجا، أنواع محددة)
