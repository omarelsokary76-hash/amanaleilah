-- migration: ربط العائلات (شات مشترك + شات خاص بين عائلتين بموافقة كبيري العائلتين)
-- جداول جديدة بس (مفيش أي تعديل على الجداول الحالية). شغّله مرة واحدة بعد باقي الـ migrations:
--   wrangler d1 execute amanaleilah-db --remote --file=./xf_migration.sql
-- أو الصق محتواه في D1 > Console وشغّله جملة جملة.

CREATE TABLE IF NOT EXISTS family_links (
  id TEXT PRIMARY KEY,
  family_a TEXT NOT NULL,
  family_b TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  requested_by_family TEXT NOT NULL,
  requested_by_member TEXT,
  decided_by TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (family_a, family_b)
);
CREATE INDEX IF NOT EXISTS idx_family_links_a ON family_links(family_a, status);
CREATE INDEX IF NOT EXISTS idx_family_links_b ON family_links(family_b, status);

CREATE TABLE IF NOT EXISTS xf_messages (
  id TEXT PRIMARY KEY,
  link_id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  sender_name TEXT NOT NULL,
  sender_family TEXT NOT NULL,
  text TEXT,
  media_type TEXT,
  media_key TEXT,
  timestamp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_xf_messages_link ON xf_messages(link_id, timestamp);

CREATE TABLE IF NOT EXISTS xf_reports (
  id TEXT PRIMARY KEY,
  link_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  reporter_id TEXT NOT NULL,
  reporter_family TEXT NOT NULL,
  sender_family TEXT NOT NULL,
  reason TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_xf_reports_fam ON xf_reports(sender_family, reporter_family);

CREATE TABLE IF NOT EXISTS xf_private_permissions (
  link_id TEXT NOT NULL,
  member_a TEXT NOT NULL,
  member_b TEXT NOT NULL,
  ok_a INTEGER NOT NULL DEFAULT 0,
  ok_b INTEGER NOT NULL DEFAULT 0,
  rejected INTEGER NOT NULL DEFAULT 0,
  requested_by TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (link_id, member_a, member_b)
);

CREATE TABLE IF NOT EXISTS xf_private_messages (
  id TEXT PRIMARY KEY,
  link_id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  timestamp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_xf_pm_link ON xf_private_messages(link_id, timestamp);
