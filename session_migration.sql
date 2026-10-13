-- migration: جلسات الدخول (Session Tokens) + قفل الحساب بعد محاولات فاشلة
-- شغّل الملف ده بعد كل الـ migrations التانية:
--   wrangler d1 execute amanaleilah-db --remote --file=./session_migration.sql

-- توكن الدخول: بيتولّد وقت تسجيل الدخول ويتخزن مجزّأ (SHA-256) - النص الأصلي بيتبعت للجهاز بس ومبيتخزنش
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  member_id TEXT NOT NULL,
  family_code TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_member ON sessions(member_id);
CREATE INDEX IF NOT EXISTS idx_sessions_family ON sessions(family_code);

-- قفل الحساب بعد محاولات فاشلة متكررة (تسجيل دخول / استرجاع كلمة سر / تغيير كلمة سر) - على مستوى
-- (كود العائلة + الاسم) نفسه، مش على مستوى الـ IP بس، عشان مايتلفش حوالين rate_limits بسهولة
CREATE TABLE IF NOT EXISTS login_attempts (
  key TEXT PRIMARY KEY,
  fails INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);
