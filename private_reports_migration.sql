-- جدول بلاغات الشات الخاص - بيخزن بس الرسالة اللي المُبلِّغ نفسه اختار يكشفها لكبير العائلة
-- (لأن السيرفر أصلاً مش قادر يفك تشفير باقي المحادثة - E2E encryption).
-- شغّل الملف ده بعد كل الـ migrations السابقة:
--   wrangler d1 execute amanaleilah-db --remote --file=./private_reports_migration.sql

CREATE TABLE IF NOT EXISTS private_chat_reports (
  id TEXT PRIMARY KEY,
  family_code TEXT NOT NULL,
  message_id TEXT,
  reporter_id TEXT NOT NULL,
  reported_member_id TEXT NOT NULL,
  message_text TEXT NOT NULL,
  reason TEXT,
  created_at INTEGER NOT NULL
);
