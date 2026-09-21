-- دائرة الأمان - هيكل قاعدة البيانات (Cloudflare D1)

CREATE TABLE IF NOT EXISTS families (
  code TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
  id TEXT PRIMARY KEY,
  family_code TEXT NOT NULL,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  relation TEXT NOT NULL,
  role TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  circle TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  FOREIGN KEY (family_code) REFERENCES families(code)
);
CREATE INDEX IF NOT EXISTS idx_members_family ON members(family_code);
CREATE INDEX IF NOT EXISTS idx_members_phone ON members(family_code, phone);

CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  family_code TEXT NOT NULL,
  type TEXT NOT NULL,
  occasion_type TEXT,
  member_id TEXT NOT NULL,
  member_name TEXT NOT NULL,
  text TEXT,
  lat REAL,
  lng REAL,
  accuracy INTEGER,
  timestamp INTEGER NOT NULL,
  FOREIGN KEY (family_code) REFERENCES families(code)
);
CREATE INDEX IF NOT EXISTS idx_events_family ON events(family_code, timestamp DESC);

CREATE TABLE IF NOT EXISTS chat_messages (
  id TEXT PRIMARY KEY,
  family_code TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  sender_name TEXT NOT NULL,
  text TEXT,
  media_type TEXT,
  media_key TEXT,
  timestamp INTEGER NOT NULL,
  FOREIGN KEY (family_code) REFERENCES families(code)
);
CREATE INDEX IF NOT EXISTS idx_chat_family ON chat_messages(family_code, timestamp ASC);
