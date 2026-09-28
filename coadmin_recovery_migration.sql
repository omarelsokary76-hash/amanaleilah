-- migration: نائب كبير عائلة (Co-admin) + تقوية الاسترجاع بسؤالين أمان بدل واحد
-- شغّل الملف ده بعد auth_migration.sql:
--   wrangler d1 execute amanaleilah-db --remote --file=./coadmin_recovery_migration.sql

-- علشان نميّز شكليًا مين "كبير العائلة الأساسي" (منشئها) عن أي نائب اتضاف بعدين -
-- الاتنين عندهم نفس الصلاحيات الفعلية (is_admin=1)، الفرق ده للعرض بس في الواجهة
ALTER TABLE members ADD COLUMN is_founder INTEGER NOT NULL DEFAULT 0;

-- سؤال أمان تاني وإجابته - عشان استرجاع كلمة السر يحتاج إجابتين صح مش واحدة
ALTER TABLE members ADD COLUMN security_question_2 TEXT;
ALTER TABLE members ADD COLUMN security_answer_hash_2 TEXT;
