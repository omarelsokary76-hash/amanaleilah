-- شغّل الملف ده مرة واحدة على قاعدة البيانات الموجودة عندك بالفعل (زي ما عملت مع push_migration.sql)
-- عشان يضيف جدول الإبلاغ عن محتوى مخالف في شات العائلة، من غير ما تلمس باقي الجداول.

CREATE TABLE IF NOT EXISTS chat_reports (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  family_code TEXT NOT NULL,
  reporter_id TEXT,
  reason TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_family ON chat_reports(family_code, created_at DESC);
