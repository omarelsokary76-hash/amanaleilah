-- migration: عمود المفتاح العام للشات الخاص المشفّر في جدول members
-- شغّله بس لو العمود مش موجود. اتأكد الأول من Cloudflare ← D1 ← Console:
--   SELECT name FROM pragma_table_info('members') WHERE name = 'public_key';
-- لو رجّع صف يبقى موجود - متشغّلش الملف ده. لو رجّع فاضي:
--   wrangler d1 execute amanaleilah-db --remote --file=./public_key_migration.sql
ALTER TABLE members ADD COLUMN public_key TEXT;
