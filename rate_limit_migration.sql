-- جدول الحد من محاولات الدخول/التسجيل (Brute-force protection) - بديل مبني على D1
-- بدل Cloudflare Rate Limiting binding، عشان يشتغل على أي نسخة wrangler من غير أي إعداد إضافي.
-- شغّل الملف ده بعد كل الـ migrations السابقة:
--   wrangler d1 execute amanaleilah-db --remote --file=./rate_limit_migration.sql

CREATE TABLE IF NOT EXISTS rate_limits (
  id TEXT PRIMARY KEY,
  ip TEXT NOT NULL,
  timestamp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_time ON rate_limits(ip, timestamp);
