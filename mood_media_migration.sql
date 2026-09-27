-- migration: الحالة المزاجية (إيموجي) + مشاركة صور/صوت/فيديو في الشات الخاص المشفّر من طرف لطرف
-- شغّل الملف ده بعد كل الـ migrations السابقة (وبعد push_migration.sql و rate_limit_migration.sql):
--   wrangler d1 execute amanaleilah-db --remote --file=./mood_media_migration.sql

-- الحالة المزاجية: إيموجي + ملاحظة نصية قصيرة اختيارية، بتظهر لباقي أفراد العائلة
-- جنب اسم العضو في دائرة الصفحة الرئيسية وفي قائمة الأعضاء. العضو هو اللي بيحددها ويقدر يمسحها وقت ما يحب.
ALTER TABLE members ADD COLUMN mood_emoji TEXT;
ALTER TABLE members ADD COLUMN mood_text TEXT;
ALTER TABLE members ADD COLUMN mood_updated_at INTEGER;

-- مشاركة وسائط (صورة/صوت/فيديو) في الشات الخاص - بنفس مبدأ الشات الخاص النصي: الملف بيتشفّر
-- في المتصفح (AES-GCM) قبل ما يترفع، والسيرفر بيخزن بايتات مشفّرة بس في R2 ومفيش نسخة صريحة
-- منها أبدًا عندنا. عمود "ciphertext" النصي بيفضل فاضي ('') في رسايل الوسائط، والتشفير الفعلي
-- بيبقى في ملف R2 اللي مفتاحه في عمود media_key.
ALTER TABLE private_messages ADD COLUMN media_type TEXT;             -- 'image' | 'audio' | 'video'
ALTER TABLE private_messages ADD COLUMN media_key TEXT;              -- مفتاح الملف المشفّر في R2 (bucket: MEDIA)
ALTER TABLE private_messages ADD COLUMN media_content_type TEXT;     -- نوع الملف الأصلي (image/jpeg، audio/webm...) لعرضه صح بعد فك التشفير في المتصفح
