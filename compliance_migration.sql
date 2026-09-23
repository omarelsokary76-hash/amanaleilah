-- migration الالتزام بالبرومت النهائي (18+)
-- شغّل الملف ده مرة واحدة بعد schema.sql و push_migration.sql:
--   wrangler d1 execute amanaleilah-db --remote --file=./compliance_migration.sql

-- إقرار العمر (18+) ووقت الموافقة على الشروط - لكل عضو
ALTER TABLE members ADD COLUMN age_confirmed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE members ADD COLUMN consent_at INTEGER;

-- مشاركة الموقع الطوعية بمدة محددة (ساعة / لحد ما يوقف) - بدون تتبع خلفي
CREATE TABLE IF NOT EXISTS location_shares (
  member_id TEXT PRIMARY KEY,
  family_code TEXT NOT NULL,
  expires_at INTEGER,        -- NULL = لحد ما يوقف يدويًا
  started_at INTEGER NOT NULL
);

-- الحظر بين الأعضاء (يمنع الشات الخاص ويخفي رسائل الشات العام من المحظور بالنسبة للحاظر)
CREATE TABLE IF NOT EXISTS blocks (
  blocker_id TEXT NOT NULL,
  blocked_id TEXT NOT NULL,
  family_code TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (blocker_id, blocked_id)
);

-- إذن الشات الخاص بين عضوين عاديين (لازم موافقة صريحة من كبير العائلة)
-- كبير العائلة نفسه معفى من هذا الجدول: يقدر يفتح شات خاص مع أي عضو مباشرة
CREATE TABLE IF NOT EXISTS private_chat_permissions (
  family_code TEXT NOT NULL,
  member_a TEXT NOT NULL,   -- الأصغر أبجديًا/رقميًا من الاتنين (ترتيب ثابت لتفادي تكرار الصف)
  member_b TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
  requested_by TEXT NOT NULL,
  approved_by TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER,
  PRIMARY KEY (family_code, member_a, member_b)
);

-- طلبات حذف الحساب/العائلة المقدَّمة من الصفحة العامة (بمهلة 24 ساعة قابلة للإلغاء - حماية من إساءة الاستخدام)
CREATE TABLE IF NOT EXISTS deletion_requests (
  id TEXT PRIMARY KEY,
  family_code TEXT NOT NULL,
  member_id TEXT NOT NULL,
  scope TEXT NOT NULL,          -- 'member' (عضو عادي) أو 'family' (كبير العائلة بيحذف العائلة كلها)
  requested_at INTEGER NOT NULL,
  execute_at INTEGER NOT NULL,  -- بعد 24 ساعة من requested_at
  status TEXT NOT NULL DEFAULT 'pending'  -- pending | cancelled | executed
);
-- سجل حذف العائلات والحسابات (للأغراض القانونية فقط - مين حذف ومتى)
CREATE TABLE IF NOT EXISTS deletion_log (
  id TEXT PRIMARY KEY,
  family_code TEXT NOT NULL,
  deleted_by TEXT,
  deleted_by_name TEXT,
  deleted_at INTEGER NOT NULL,
  reason TEXT
);
