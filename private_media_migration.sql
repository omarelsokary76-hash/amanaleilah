-- migration: دعم إرسال وسائط (صورة/صوت/فيديو) في الشات الخاص، مشفّرة من طرف لطرف زي النص بالظبط
-- شغّل الملف ده مرة واحدة بعد باقي الـ migrations:
--   wrangler d1 execute amanaleilah-db --remote --file=./private_media_migration.sql

-- media_type: 'image' | 'audio' | 'video' (فاضي/NULL يعني الرسالة نص عادي مش وسائط)
-- media_key: مفتاح الملف المشفّر في R2 (السيرفر مش شايف محتواه، بايتات مشفّرة بس)
-- media_mime: نوع الملف الحقيقي (image/jpeg, audio/webm, ...) - مش سرّي، بيتخزن صريح عشان العرض يشتغل صح بعد فك التشفير
ALTER TABLE private_messages ADD COLUMN media_type TEXT;
ALTER TABLE private_messages ADD COLUMN media_key TEXT;
ALTER TABLE private_messages ADD COLUMN media_mime TEXT;
