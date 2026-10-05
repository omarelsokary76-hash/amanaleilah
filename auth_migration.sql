-- migration نظام كلمة السر وسؤال الأمان (بدل رقم الهاتف / رقم الـ PIN)
-- شغّل الملف ده بعد schema.sql و push_migration.sql و compliance_migration.sql:
--   wrangler d1 execute amanaleilah-db --remote --file=./auth_migration.sql

-- سؤال الأمان: بديل استرجاع كلمة السر الذاتي (بدل رقم الهاتف أو الإيميل)
ALTER TABLE members ADD COLUMN security_question TEXT;
ALTER TABLE members ADD COLUMN security_answer_hash TEXT;

-- ملحوظة: عمود "phone" في جدول members ما بيتحذفش (تقنيًا معقّد في SQLite) لكن بقى غير مستخدم
-- خالص - التطبيق بيخزنله قيمة فاضية '' دايمًا وبيتجاهله تمامًا. مفيش رقم هاتف بيتجمع من أي مستخدم جديد.
