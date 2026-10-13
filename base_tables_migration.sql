-- migration: الجداول والأعمدة الأساسية اللي الكود بيعتمد عليها ومكانتش في أي ملف تاني
-- (chat_reports, private_messages)
-- شغّله بعد schema.sql وقبل باقي الـ migrations:
--   wrangler d1 execute amanaleilah-db --remote --file=./base_tables_migration.sql

CREATE TABLE IF NOT EXISTS chat_reports (
  id TEXT PRIMARY KEY,
  message_id TEXT,
  family_code TEXT NOT NULL,
  reporter_id TEXT NOT NULL,
  reason TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_reports_family ON chat_reports(family_code, created_at DESC);

CREATE TABLE IF NOT EXISTS private_messages (
  id TEXT PRIMARY KEY,
  family_code TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  ciphertext TEXT,
  iv TEXT,
  timestamp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_private_messages_pair ON private_messages(family_code, sender_id, recipient_id, timestamp);

