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
  -- المفتاح العام لتشفير الشات الخاص من طرف لطرف (E2E). المفتاح الخاص مبيتخزنش هنا خالص - بيفضل جوّه جهاز المستخدم بس.
  public_key TEXT,
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
  -- lat/lng بيتخزنوا دلوقتي كنص مشفّر (AES-GCM، بادئة "enc:") مش كرقم عادي.
  -- SQLite/D1 مرن مع نوع البيانات فمفيش داعي لتغيير نوع العمود؛ الـWorker هو اللي بيشفّر/يفك التشفير.
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

CREATE TABLE IF NOT EXISTS chat_reports (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  family_code TEXT NOT NULL,
  reporter_id TEXT,
  reason TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_family ON chat_reports(family_code, created_at DESC);

-- الشات الخاص (1-to-1) بين عضوين - مشفّر من طرف لطرف. السيرفر بيخزن النص المشفر بس (ciphertext)
-- ومبيقدرش يفك تشفيره، لأن المفتاح الخاص مبيتبعتش له خالص.
CREATE TABLE IF NOT EXISTS private_messages (
  id TEXT PRIMARY KEY,
  family_code TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  timestamp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_private_a ON private_messages(family_code, sender_id, recipient_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_private_b ON private_messages(family_code, recipient_id, sender_id, timestamp);
