-- migration: نوعين من موافقة كبير العيلة على الشات الخاص بين عضوين عاديين
--   permanent = 1  -> موافقة دائمة (مثلًا الإخوة) - بتفضل شغالة ومحتاجة موافقة مرة واحدة بس
--   permanent = 0  -> موافقة مرة واحدة - بتنتهي بعد 24 ساعة (expires_at) ولازم طلب جديد وموافقة جديدة
-- الموافقات الموجودة قبل الـ migration دي بتفضل دائمة (DEFAULT 1) عشان مايتقفلش شات شغّال.
-- شغّل الملف ده مرة واحدة بعد باقي الـ migrations:
--   wrangler d1 execute amanaleilah-db --remote --file=./private_permission_migration.sql

ALTER TABLE private_chat_permissions ADD COLUMN permanent INTEGER NOT NULL DEFAULT 1;
ALTER TABLE private_chat_permissions ADD COLUMN expires_at INTEGER;
