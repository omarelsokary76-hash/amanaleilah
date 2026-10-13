-- migration: بلاغات الشات الخاص (إبلاغ كبير العيلة عن رسالة وصلتك في محادثة خاصة)
-- الشات الخاص مشفّر من طرف لطرف، فالسيرفر مش قادر يقرأ الرسايل. لما عضو يبلّغ عن رسالة وصلته، جهازه هو اللي
-- بيبعت نص الرسالة دي بس (برضاه وبعد تأكيد صريح) كدليل لكبير العيلة - باقي المحادثة مبتتبعتش.
-- شغّل الملف ده مرة واحدة بعد باقي الـ migrations:
--   wrangler d1 execute amanaleilah-db --remote --file=./private_report_migration.sql

CREATE TABLE IF NOT EXISTS private_reports (
  id TEXT PRIMARY KEY,
  family_code TEXT NOT NULL,
  reporter_id TEXT NOT NULL,
  reported_id TEXT NOT NULL,       -- صاحب الرسالة المُبلَّغ عنها
  message_id TEXT,
  snapshot_text TEXT,              -- نص الرسالة كما أرسله المُبلِّغ (لو رسالة نصية)
  media_type TEXT,                 -- image | audio | video لو الرسالة وسائط (المحتوى نفسه مبيتبعتش)
  message_time INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_private_reports_family ON private_reports(family_code, created_at DESC);
