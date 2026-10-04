CREATE TABLE IF NOT EXISTS push_subscriptions (
  member_id TEXT PRIMARY KEY,
  family_code TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
