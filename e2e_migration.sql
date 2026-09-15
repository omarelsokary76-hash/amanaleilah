-- شغّل الملف ده مرة واحدة على قاعدة البيانات الموجودة عندك بالفعل (زي ما عملت مع push_migration.sql
-- وreport_migration.sql) عشان يضيف دعم الشات الخاص المشفر من طرف لطرف.

-- المفتاح العام لكل عضو (المفتاح الخاص بيفضل جوّه جهاز المستخدم بس، مبيتخزنش هنا خالص)
ALTER TABLE members ADD COLUMN public_key TEXT;

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
