// دائرة الأمان - Cloudflare Worker
// بيوصل التطبيق (الفرونت إند) بقاعدة بيانات D1 وتخزين ملفات R2

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}
function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    // Cache-Control: no-store مهم جدًا - من غيره المتصفح ممكن يخزّن رد قديم (فاشل مثلًا) ويوريه
    // للمستخدم بدل الرد الجديد، وده بيسبب مشاكل دخول غامضة صعب تشخيصها بعد أي تعديل في السيرفر.
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders() },
  });
}
function genId(prefix) {
  return (prefix || 'id') + '_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
}
function genCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let c = '';
  for (let i = 0; i < 6; i++) c += chars[Math.floor(Math.random() * chars.length)];
  return c;
}

// أسئلة الأمان الثابتة - بديل استرجاع كلمة السر الذاتي بدل رقم الهاتف أو الإيميل.
// أي إضافة/تعديل هنا لازم يتعمل في نفس القائمة في الواجهة (SECURITY_QUESTIONS جوه INDEX_HTML) عشان يفضلوا متطابقين.
const SECURITY_QUESTIONS = [
  'ما اسم أول مدرسة التحقت بها؟',
  'ما اسم الشارع اللي عشت فيه في طفولتك؟',
  'ما اسم حيوانك الأليف الأول؟',
  'ما اسم أقرب صديق ليك في المرحلة الابتدائية؟',
  'في أي مدينة اتولدت؟',
  'ما اسم والدتك قبل الزواج؟',
];
// بنطبّع إجابة سؤال الأمان قبل التشفير والمقارنة (نفس المعنى مهما اختلفت المسافات أو حالة الحروف)
function normalizeSecurityAnswer(answer) {
  return (answer || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

// ================= تشفير كلمة السر وإجابة سؤال الأمان (PBKDF2) =================
// بنخزن كلمة السر وإجابة سؤال الأمان كـ hash بس، مش نص صريح، حتى إحنا كمطورين ما نقدرش نشوفهم.
async function hashSecret(secret) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  return uint8ToB64url(concatBytes(salt, new Uint8Array(bits)));
}
async function verifySecret(secret, stored) {
  if (!stored || typeof secret !== 'string') return false;
  try {
    const combined = b64urlToUint8(stored);
    const salt = combined.slice(0, 16);
    const expectedHash = combined.slice(16);
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256));
    if (bits.length !== expectedHash.length) return false;
    let diff = 0;
    for (let i = 0; i < bits.length; i++) diff |= bits[i] ^ expectedHash[i];
    return diff === 0;
  } catch (e) { return false; }
}

async function getFamilyWithMembers(db, code) {
  const fam = await db.prepare('SELECT * FROM families WHERE code = ?').bind(code).first();
  if (!fam) return null;
  const { results: members } = await db.prepare('SELECT * FROM members WHERE family_code = ?').bind(code).all();
  return {
    code: fam.code,
    createdAt: fam.created_at,
    members: members.map(m => ({
      id: m.id, name: m.name, relation: m.relation,
      role: m.role, isAdmin: !!m.is_admin, isFounder: !!m.is_founder, status: m.status,
      circle: JSON.parse(m.circle || '[]'), publicKey: m.public_key || null,
    })),
  };
}

// ================= مساعدين خاصين بميزات الالتزام (18+، الحظر، الشات الخاص المقيّد) =================
async function isAdminMember(db, familyCode, memberId) {
  if (!memberId) return false;
  const row = await db.prepare('SELECT is_admin FROM members WHERE id = ? AND family_code = ?').bind(memberId, familyCode).first();
  return !!(row && row.is_admin);
}
// بنرتب أي زوج أعضاء بترتيب ثابت (أبجديًا) عشان صف الإذن في الجدول يتخزن مرة واحدة بس
// بغض النظر مين طلب الشات الخاص الأول
function sortPair(a, b) {
  return a < b ? [a, b] : [b, a];
}
async function isBlockedEitherWay(db, idA, idB) {
  const row = await db.prepare(
    'SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?) LIMIT 1'
  ).bind(idA, idB, idB, idA).first();
  return !!row;
}
async function isPrivateChatAllowed(db, familyCode, idA, idB) {
  if (await isAdminMember(db, familyCode, idA)) return true;
  if (await isAdminMember(db, familyCode, idB)) return true;
  const [x, y] = sortPair(idA, idB);
  const row = await db.prepare(
    'SELECT status FROM private_chat_permissions WHERE family_code = ? AND member_a = ? AND member_b = ?'
  ).bind(familyCode, x, y).first();
  return !!(row && row.status === 'approved');
}

// حذف عائلة بالكامل (كل الأعضاء والبيانات) - مُستخدَمة من مسار الحذف الفوري جوه التطبيق وكمان من تنفيذ طلبات الحذف المؤجلة
async function performFamilyDeletion(env, ctx, familyCode, deletedById, deletedByName, reason) {
  ctx.waitUntil(notifyFamilyDeleted(env, familyCode, deletedById));
  const { results: mediaRows } = await env.DB.prepare(
    "SELECT media_key FROM chat_messages WHERE family_code = ? AND media_key IS NOT NULL"
  ).bind(familyCode).all();
  for (const row of mediaRows) { await env.MEDIA.delete(row.media_key).catch(() => {}); }
  await env.DB.prepare('DELETE FROM chat_messages WHERE family_code = ?').bind(familyCode).run();
  await env.DB.prepare('DELETE FROM chat_reports WHERE family_code = ?').bind(familyCode).run().catch(() => {});
  await env.DB.prepare('DELETE FROM private_messages WHERE family_code = ?').bind(familyCode).run().catch(() => {});
  await env.DB.prepare('DELETE FROM private_chat_permissions WHERE family_code = ?').bind(familyCode).run().catch(() => {});
  await env.DB.prepare('DELETE FROM blocks WHERE family_code = ?').bind(familyCode).run().catch(() => {});
  await env.DB.prepare('DELETE FROM location_shares WHERE family_code = ?').bind(familyCode).run().catch(() => {});
  await env.DB.prepare('DELETE FROM deletion_requests WHERE family_code = ?').bind(familyCode).run().catch(() => {});
  await env.DB.prepare('DELETE FROM events WHERE family_code = ?').bind(familyCode).run();
  const { results: memberIds } = await env.DB.prepare('SELECT id FROM members WHERE family_code = ?').bind(familyCode).all();
  for (const m of memberIds) { await env.DB.prepare('DELETE FROM push_subscriptions WHERE member_id = ?').bind(m.id).run().catch(() => {}); }
  await env.DB.prepare('DELETE FROM members WHERE family_code = ?').bind(familyCode).run();
  await env.DB.prepare('DELETE FROM families WHERE code = ?').bind(familyCode).run();
  await env.DB.prepare(
    'INSERT INTO deletion_log (id, family_code, deleted_by, deleted_by_name, deleted_at, reason) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(genId('del'), familyCode, deletedById, deletedByName, Date.now(), reason).run().catch(() => {});
}

// حذف بيانات عضو عادي بس (مش العائلة كلها) - نفس المنطق مُستخدَم من مسار الحذف الفوري وطلبات الحذف المؤجلة
async function performMemberDeletion(env, familyCode, member, reason) {
  const { results: mediaRows } = await env.DB.prepare(
    'SELECT media_key FROM chat_messages WHERE family_code = ? AND sender_id = ? AND media_key IS NOT NULL'
  ).bind(familyCode, member.id).all();
  for (const row of mediaRows) { await env.MEDIA.delete(row.media_key).catch(() => {}); }
  await env.DB.prepare('DELETE FROM chat_messages WHERE family_code = ? AND sender_id = ?').bind(familyCode, member.id).run();
  await env.DB.prepare('DELETE FROM events WHERE family_code = ? AND member_id = ?').bind(familyCode, member.id).run();
  await env.DB.prepare('DELETE FROM private_messages WHERE family_code = ? AND (sender_id = ? OR recipient_id = ?)').bind(familyCode, member.id, member.id).run().catch(() => {});
  await env.DB.prepare('DELETE FROM private_chat_permissions WHERE family_code = ? AND (member_a = ? OR member_b = ?)').bind(familyCode, member.id, member.id).run().catch(() => {});
  await env.DB.prepare('DELETE FROM blocks WHERE family_code = ? AND (blocker_id = ? OR blocked_id = ?)').bind(familyCode, member.id, member.id).run().catch(() => {});
  await env.DB.prepare('DELETE FROM location_shares WHERE member_id = ?').bind(member.id).run().catch(() => {});
  await env.DB.prepare('DELETE FROM push_subscriptions WHERE member_id = ?').bind(member.id).run().catch(() => {});
  await env.DB.prepare('DELETE FROM deletion_requests WHERE member_id = ?').bind(member.id).run().catch(() => {});
  await env.DB.prepare('DELETE FROM members WHERE id = ?').bind(member.id).run();
  await env.DB.prepare(
    'INSERT INTO deletion_log (id, family_code, deleted_by, deleted_by_name, deleted_at, reason) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(genId('del'), familyCode, member.id, member.name, Date.now(), reason).run().catch(() => {});
}

// تنفيذ أي طلبات حذف مؤجلة (من الصفحة العامة) وصلت مهلتها الـ 24 ساعة - بتتنادى من الـ cron كل يوم
async function processDueDeletionRequests(env, ctx) {
  const now = Date.now();
  const { results } = await env.DB.prepare(
    'SELECT * FROM deletion_requests WHERE status = ? AND execute_at <= ?'
  ).bind('pending', now).all();
  for (const reqRow of results) {
    try {
      if (reqRow.scope === 'family') {
        const admin = await env.DB.prepare('SELECT * FROM members WHERE id = ?').bind(reqRow.member_id).first();
        if (admin) {
          await performFamilyDeletion(env, ctx, reqRow.family_code, admin.id, admin.name, 'تنفيذ طلب حذف مؤجّل من الصفحة العامة (كبير العائلة)');
        }
      } else {
        const member = await env.DB.prepare('SELECT * FROM members WHERE id = ?').bind(reqRow.member_id).first();
        if (member) {
          await performMemberDeletion(env, reqRow.family_code, member, 'تنفيذ طلب حذف مؤجّل من الصفحة العامة (عضو)');
        }
      }
      await env.DB.prepare('UPDATE deletion_requests SET status = ? WHERE id = ?').bind('executed', reqRow.id).run();
    } catch (e) { /* لو حصل خطأ، الطلب هيفضل pending ويتحاول تاني بكرة */ }
  }
}

// مفتاح الإدارة بقى لازم يتحط كـ secret على Cloudflare، مش مكتوب هنا في الكود.
// شغّل الأمر ده مرة واحدة من التيرمينال (هيطلب منك تكتب المفتاح، هيتخزن مشفّر عند Cloudflare):
//   wrangler secret put ADMIN_KEY
// لو مفيش ADMIN_KEY متسجل، أي طلب للوحة الإدارة هيترفض تلقائيًا (fail closed) بدل ما يشتغل بمفتاح افتراضي مكشوف.

function timingSafeEqual(a, b) {
  // مقارنة بزمن ثابت عشان نمنع هجوم قياس الوقت (timing attack) على المفتاح
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function checkAdminAuth(request, env) {
  const key = request.headers.get('x-admin-key');
  const expected = env && env.ADMIN_KEY;
  if (!expected) return false; // لو المفتاح مش متسجل كـ secret، امنع الدخول تمامًا
  if (!key) return false;
  return timingSafeEqual(key, expected);
}

// ================= جلسات الدخول (Session Tokens) =================
// المشكلة اللي ده بيحلها: قبل كده، أي أمر حساس (حذف عضو، ترقية لأدمن، تصفير كلمة سر عضو)
// كان بيتحقق بس من إن الـ memberId اللي بيبعته الطلب هو is_admin=1 في قاعدة البيانات - من غير أي
// إثبات إن اللي بيبعت الطلب فعلاً "هو" العضو ده. وبما إن GET /api/family/:code بيرجّع كل الأعضاء
// وIDs بتاعتهم لأي حد يعرف كود العائلة (والكود ده بيتشارك أصلاً كـ"كود دعوة")، كان أي حد يعرف الكود
// يقدر ينتحل أي عضو (حتى الأدمن) في الأوامر الحساسة من غير ما يعرف كلمة سره خالص.
// الحل: وقت تسجيل الدخول الناجح بكلمة السر، بنولّد توكن موقّع (HMAC) بيثبت هوية العضو، ولازم
// يترفق مع أي طلب حساس بعد كده عن طريق هيدر x-session-token.
// لازم يتسجل كـ secret على Cloudflare قبل النشر:
//   openssl rand -base64 32
//   wrangler secret put SESSION_SECRET
// لو مش متسجل، كل الأوامر الحساسة هترفض تلقائيًا (fail closed) - زي فلسفة باقي المفاتيح في التطبيق.
const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 يوم - نفس مدة "فضل مسجل دخول" في الواجهة
let _cachedSessionKey = null;
async function getSessionKey(env) {
  if (!env || !env.SESSION_SECRET) return null;
  if (_cachedSessionKey) return _cachedSessionKey;
  _cachedSessionKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(env.SESSION_SECRET),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
  return _cachedSessionKey;
}
async function createSessionToken(env, familyCode, memberId) {
  const key = await getSessionKey(env);
  if (!key) return null; // مفيش SESSION_SECRET متسجل - التطبيق هيشتغل بس من غير حماية إضافية لحد ما يتسجل
  const payload = { fc: (familyCode || '').toUpperCase(), mid: memberId, exp: Date.now() + SESSION_MAX_AGE_MS };
  const payloadB64 = uint8ToB64url(new TextEncoder().encode(JSON.stringify(payload)));
  const sigBytes = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64)));
  return payloadB64 + '.' + uint8ToB64url(sigBytes);
}
async function verifySessionToken(env, token) {
  if (!token || typeof token !== 'string' || token.indexOf('.') < 0) return null;
  const key = await getSessionKey(env);
  if (!key) return null;
  const dot = token.indexOf('.');
  const payloadB64 = token.slice(0, dot);
  const sigB64 = token.slice(dot + 1);
  try {
    const valid = await crypto.subtle.verify('HMAC', key, b64urlToUint8(sigB64), new TextEncoder().encode(payloadB64));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlToUint8(payloadB64)));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return { familyCode: payload.fc, memberId: payload.mid };
  } catch (e) { return null; }
}
// بيتحقق إن الطلب جاي فعليًا من الشخص اللي بيدّعي إنه هو (familyCode + memberId مطابقين لتوكن صحيح).
// ملحوظة مهمة: لو SESSION_SECRET مش متسجل لسه، بترجع true (fail-open مؤقت) عشان التطبيق يفضل شغال
// أثناء الترحيل، بس بمجرد ما تسجل السر هتتفعّل الحماية الكاملة تلقائيًا من غير أي تعديل تاني في الكود.
async function requireSession(request, env, familyCode, memberId) {
  if (!env || !env.SESSION_SECRET) return true;
  const token = request.headers.get('x-session-token');
  const session = await verifySessionToken(env, token);
  if (!session) return false;
  return session.familyCode === (familyCode || '').toUpperCase() && session.memberId === memberId;
}

// ================= حماية من محاولات تخمين كود العائلة / كلمة السر (Brute-force) =================
// مبني بالكامل على D1 (جدول rate_limits) - مش محتاج أي binding خاص من Cloudflare ولا نسخة معيّنة
// من wrangler، عشان محدش يقع في مشكلة نشر بسببه زي اللي حصلت مع Cloudflare Rate Limiting binding.
// بيحد كل IP بـ 10 محاولات كحد أقصى كل دقيقة على شاشات الدخول/التسجيل/إنشاء العائلة/الاسترجاع.
async function checkAuthRateLimit(request, env) {
  try {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown-ip';
    const now = Date.now();
    const windowStart = now - 60000; // آخر دقيقة بس
    const { count } = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM rate_limits WHERE ip = ? AND timestamp > ?'
    ).bind(ip, windowStart).first();
    if (count >= 10) return false;
    await env.DB.prepare('INSERT INTO rate_limits (id, ip, timestamp) VALUES (?, ?, ?)')
      .bind(genId('rl'), ip, now).run();
    return true;
  } catch (e) {
    return true; // أي عطل في جدول الـ rate limiting نفسه ميوقفش تسجيل الدخول العادي (fail-open للطوارئ بس)
  }
}

// ================= تشفير البيانات الحساسة (الموقع الجغرافي) =================
// كل موقع (lat/lng) بيتشفر بـ AES-GCM قبل ما يتخزن في قاعدة البيانات، وبيتفك بس وقت
// عرضه لأفراد العائلة المصرح لهم. المفتاح بيتسجل كـ secret على Cloudflare (مش مكتوب في الكود):
//   openssl rand -base64 32   ← يولّد مفتاح 32 بايت
//   wrangler secret put ENCRYPTION_KEY   ← يطلب منك تلصق المفتاح، ويتخزن مشفّر عند Cloudflare
// لو المفتاح مش متسجل، التطبيق بيرفض يخزّن أي موقع جغرافي خالص (fail closed) - أفضل من إنه
// يخزّنه كنص عادي من غير علم حد. لازم تسجل المفتاح قبل ما تنزل التطبيق فعليًا للناس.
let _cachedEncKey = null;
async function getEncryptionKey(env) {
  if (!env || !env.ENCRYPTION_KEY) return null;
  if (_cachedEncKey) return _cachedEncKey;
  const raw = atob(env.ENCRYPTION_KEY);
  const keyBytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) keyBytes[i] = raw.charCodeAt(i);
  _cachedEncKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  return _cachedEncKey;
}
// بنحط بادئة "enc:" على أي قيمة متشفرة، عشان لو رجعنا قرينا بيانات قديمة اتسجلت
// قبل ما نفعّل التشفير (نص عادي)، النظام يعرف يفرّق بينها وميحاولش يفك تشفيرها غلط.
async function encryptGeo(env, value) {
  if (value === null || value === undefined) return null;
  const key = await getEncryptionKey(env);
  if (!key) throw new Error('ENCRYPTION_KEY مش متسجل - رافضين نخزّن موقع جغرافي من غير تشفير');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(String(value));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc));
  const combined = concatBytes(iv, ciphertext);
  return 'enc:' + uint8ToB64url(combined);
}
async function decryptGeo(env, stored) {
  if (stored === null || stored === undefined) return null;
  if (typeof stored !== 'string' || !stored.startsWith('enc:')) {
    // قيمة قديمة مش متشفرة (اتسجلت قبل تفعيل التشفير) - نرجعها زي ما هي كرقم
    const num = parseFloat(stored);
    return isNaN(num) ? null : num;
  }
  const key = await getEncryptionKey(env);
  if (!key) return null; // متشفرة بس مفيش مفتاح دلوقتي - منقدرش نفكها
  try {
    const combined = b64urlToUint8(stored.slice(4));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const plainBytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    const num = parseFloat(new TextDecoder().decode(plainBytes));
    return isNaN(num) ? null : num;
  } catch (e) {
    return null; // بيانات تالفة أو مفتاح غلط
  }
}
async function decryptEventRow(env, e) {
  return {
    id: e.id, type: e.type, occasionType: e.occasion_type, memberId: e.member_id,
    memberName: e.member_name, text: e.text,
    lat: await decryptGeo(env, e.lat), lng: await decryptGeo(env, e.lng),
    accuracy: e.accuracy, timestamp: e.timestamp,
  };
}

// ================= حذف تلقائي للبيانات القديمة (Data Retention) =================
// امتثالًا لمبدأ "تقليل الاحتفاظ بالبيانات" في قانون حماية البيانات الشخصية،
// أي حدث (SOS/اطمئنان/مناسبة) أو رسالة شات أقدم من 30 يوم بيتحذف تلقائيًا كل يوم.
// (بيانات العائلة والأعضاء أنفسهم مش بتتحذف، لأنها مش "أحداث" مؤقتة - دي بيانات الحساب الأساسية)
const RETENTION_DAYS = 30;
async function cleanupOldData(env) {
  const cutoff = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
  let deletedEvents = 0, deletedMessages = 0, deletedMedia = 0;

  // 1. نمسح ملفات الوسائط من R2 الأول (صور/صوت/فيديو) اللي هتتحذف رسايلها
  const { results: mediaRows } = await env.DB.prepare(
    'SELECT media_key FROM chat_messages WHERE timestamp < ? AND media_key IS NOT NULL'
  ).bind(cutoff).all();
  for (const row of mediaRows) {
    await env.MEDIA.delete(row.media_key).catch(() => {});
    deletedMedia++;
  }

  // 2. نمسح رسايل الشات القديمة
  const chatResult = await env.DB.prepare('DELETE FROM chat_messages WHERE timestamp < ?').bind(cutoff).run();
  deletedMessages = chatResult.meta?.changes || 0;

  // 3. نمسح الأحداث القديمة (SOS / اطمئنان / مناسبات)
  const eventsResult = await env.DB.prepare('DELETE FROM events WHERE timestamp < ?').bind(cutoff).run();
  deletedEvents = eventsResult.meta?.changes || 0;

  // 4. نمسح رسايل الشات الخاص المشفرة القديمة كمان (نفس سياسة الاحتفاظ بالبيانات)
  await env.DB.prepare('DELETE FROM private_messages WHERE timestamp < ?').bind(cutoff).run();

  // 5. تنظيف جدول الحد من المحاولات - مش محتاجين نحتفظ بأي سجل أقدم من ساعة
  await env.DB.prepare('DELETE FROM rate_limits WHERE timestamp < ?').bind(Date.now() - 3600000).run().catch(() => {});

  return { deletedEvents, deletedMessages, deletedMedia, cutoff };
}


// ================= Web Push (إشعارات حقيقية عند SOS) =================
// المفتاح العام مش سر (بيتبعت للمتصفح أصلاً عشان يعمل subscribe)، فمفيش مشكلة إنه مكتوب هنا.
// المفتاح الخاص لازم يتسجل كـ secret على Cloudflare، مش مكتوب في الكود خالص:
//   wrangler secret put VAPID_PRIVATE_KEY   ← يطلب منك تلصق المفتاح، ويتخزن مشفّر عند Cloudflare
const VAPID_PUBLIC_KEY = 'BHNbX9qQHUFipNqIdsarAzbwt6lHJPjWHCzqYxRYMW0S1k1b_i5uqk5sLVXtuQ0YLcRBB-aEYO79tCofa_fTqjI';
const VAPID_SUBJECT = 'mailto:admin@amanaleilah.app';

function b64urlToUint8(b64url) {
  const pad = '='.repeat((4 - b64url.length % 4) % 4);
  const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(b64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}
function uint8ToB64url(bytes) {
  let str = '';
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

async function importVapidPrivateKey(env) {
  if (!env || !env.VAPID_PRIVATE_KEY) {
    throw new Error('VAPID_PRIVATE_KEY مش متسجل كـ secret - الإشعارات مش هتشتغل لحد ما تسجله');
  }
  const pub = b64urlToUint8(VAPID_PUBLIC_KEY); // 65 bytes: 0x04 || x(32) || y(32)
  const x = pub.slice(1, 33);
  const y = pub.slice(33, 65);
  const d = b64urlToUint8(env.VAPID_PRIVATE_KEY);
  const jwk = {
    kty: 'EC', crv: 'P-256', ext: true,
    x: uint8ToB64url(x), y: uint8ToB64url(y), d: uint8ToB64url(d),
  };
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

async function buildVapidHeader(env, endpoint) {
  const url = new URL(endpoint);
  const audience = url.origin;
  const header = { typ: 'JWT', alg: 'ES256' };
  const payload = { aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: VAPID_SUBJECT };
  const enc = new TextEncoder();
  const toB64url = (obj) => uint8ToB64url(enc.encode(JSON.stringify(obj)));
  const signingInput = toB64url(header) + '.' + toB64url(payload);
  const key = await importVapidPrivateKey(env);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(signingInput));
  const jwt = signingInput + '.' + uint8ToB64url(new Uint8Array(sig));
  return `vapid t=${jwt}, k=${VAPID_PUBLIC_KEY}`;
}

async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info }, key, length * 8
  );
  return new Uint8Array(bits);
}

async function encryptPushPayload(subscription, payloadObj) {
  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify(payloadObj));

  const userPublic = b64urlToUint8(subscription.keys.p256dh); // 65 bytes
  const authSecret = b64urlToUint8(subscription.keys.auth);   // 16 bytes

  // مفتاح مؤقت خاص بالسيرفر لهذه الرسالة بس
  const ephemeralKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const ephemeralPublicRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey)
  );

  const userPublicKey = await crypto.subtle.importKey(
    'raw', userPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: userPublicKey }, ephemeralKeyPair.privateKey, 256
    )
  );

  const infoEnc = new TextEncoder();
  const keyInfo = concatBytes(
    infoEnc.encode('WebPush: info\u0000'), userPublic, ephemeralPublicRaw
  );
  const ikm = await hkdf(authSecret, sharedSecret, keyInfo, 32);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cekInfo = infoEnc.encode('Content-Encoding: aes128gcm\u0000');
  const nonceInfo = infoEnc.encode('Content-Encoding: nonce\u0000');
  const cek = await hkdf(salt, ikm, cekInfo, 16);
  const nonce = await hkdf(salt, ikm, nonceInfo, 12);

  // padding delimiter (0x02) + بدون padding إضافي
  const padded = concatBytes(plaintext, new Uint8Array([2]));

  const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, padded)
  );

  const recordSize = new Uint8Array(4);
  new DataView(recordSize.buffer).setUint32(0, 4096, false);
  const idLen = new Uint8Array([ephemeralPublicRaw.length]);

  const body = concatBytes(salt, recordSize, idLen, ephemeralPublicRaw, ciphertext);
  return body;
}

async function sendWebPush(env, subscription, payloadObj) {
  try {
    const body = await encryptPushPayload(subscription, payloadObj);
    const authHeader = await buildVapidHeader(env, subscription.endpoint);
    const res = await fetch(subscription.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Encoding': 'aes128gcm',
        'TTL': '60',
        'Urgency': 'high',
        'Authorization': authHeader,
      },
      body,
    });
    return res.ok;
  } catch (e) {
    return false;
  }
}

async function notifyFamilySOS(env, familyCode, excludeMemberId, memberName) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT * FROM push_subscriptions WHERE family_code = ? AND member_id != ?'
    ).bind(familyCode, excludeMemberId).all();
    const payload = {
      title: '🚨 ' + memberName + ' محتاج مساعدة!',
      body: 'دوس هنا عشان تشوف التفاصيل والموقع فورًا',
      url: '/',
    };
    await Promise.all(results.map(row => sendWebPush(env, {
      endpoint: row.endpoint,
      keys: { p256dh: row.p256dh, auth: row.auth },
    }, payload)));
  } catch (e) { /* تجاهل أي خطأ في الإرسال عشان ما يبوظش حفظ الحدث نفسه */ }
}

async function notifyFamilyChatMessage(env, familyCode, excludeMemberId, senderName, text) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT * FROM push_subscriptions WHERE family_code = ? AND member_id != ?'
    ).bind(familyCode, excludeMemberId).all();
    const payload = {
      title: '💬 ' + senderName,
      body: text && text.trim() ? text.slice(0, 120) : 'أرسل مرفق جديد',
      url: '/',
    };
    await Promise.all(results.map(row => sendWebPush(env, {
      endpoint: row.endpoint,
      keys: { p256dh: row.p256dh, auth: row.auth },
    }, payload)));
  } catch (e) { /* تجاهل أي خطأ في الإرسال عشان ما يبوظش حفظ الرسالة نفسها */ }
}

// إشعار عام لصاحب رسالة خاصة جديدة (النص نفسه ميتبعتش في الإشعار، لأن السيرفر أصلاً مش قادر يفكه)
async function notifyPrivateMessage(env, familyCode, recipientId, senderName) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT * FROM push_subscriptions WHERE family_code = ? AND member_id = ?'
    ).bind(familyCode, recipientId).all();
    const payload = {
      title: '🔒 رسالة خاصة من ' + senderName,
      body: 'افتح التطبيق عشان تقراها',
      url: '/',
    };
    await Promise.all(results.map(row => sendWebPush(env, {
      endpoint: row.endpoint,
      keys: { p256dh: row.p256dh, auth: row.auth },
    }, payload)));
  } catch (e) { /* تجاهل أي خطأ في الإرسال */ }
}

// إشعار "كبير العائلة" بس (مش كل الأعضاء) لما حد يبلغ عن رسالة مخالفة
async function notifyFamilyReport(env, familyCode, reporterName) {
  try {
    const { results: admins } = await env.DB.prepare(
      'SELECT id FROM members WHERE family_code = ? AND is_admin = 1'
    ).bind(familyCode).all();
    if (!admins.length) return;
    const adminIds = admins.map(a => a.id);
    const { results } = await env.DB.prepare(
      `SELECT * FROM push_subscriptions WHERE family_code = ? AND member_id IN (${adminIds.map(() => '?').join(',')})`
    ).bind(familyCode, ...adminIds).all();
    const payload = {
      title: '🚩 إبلاغ عن رسالة',
      body: reporterName + ' أبلغ عن رسالة في شات العائلة، راجعها من التطبيق',
      url: '/',
    };
    await Promise.all(results.map(row => sendWebPush(env, {
      endpoint: row.endpoint,
      keys: { p256dh: row.p256dh, auth: row.auth },
    }, payload)));
  } catch (e) { /* تجاهل أي خطأ في الإرسال */ }
}

// إشعار كبير العائلة بس لما حد يطلب الانضمام للعائلة (محتاج موافقته الصريحة)
async function notifyFamilyNewJoinRequest(env, familyCode, name) {
  try {
    const { results: admins } = await env.DB.prepare(
      'SELECT id FROM members WHERE family_code = ? AND is_admin = 1'
    ).bind(familyCode).all();
    if (!admins.length) return;
    const adminIds = admins.map(a => a.id);
    const { results } = await env.DB.prepare(
      `SELECT * FROM push_subscriptions WHERE family_code = ? AND member_id IN (${adminIds.map(() => '?').join(',')})`
    ).bind(familyCode, ...adminIds).all();
    const payload = {
      title: '👋 طلب انضمام جديد',
      body: name + ' عايز ينضم للعائلة، محتاج موافقتك',
      url: '/',
    };
    await Promise.all(results.map(row => sendWebPush(env, {
      endpoint: row.endpoint,
      keys: { p256dh: row.p256dh, auth: row.auth },
    }, payload)));
  } catch (e) { /* تجاهل أي خطأ في الإرسال */ }
}

// إشعار كبير العائلة بس لما عضو يطلب إذن شات خاص مع عضو تاني
async function notifyAdminPrivateRequest(env, familyCode, requesterName, targetName) {
  try {
    const { results: admins } = await env.DB.prepare(
      'SELECT id FROM members WHERE family_code = ? AND is_admin = 1'
    ).bind(familyCode).all();
    if (!admins.length) return;
    const adminIds = admins.map(a => a.id);
    const { results } = await env.DB.prepare(
      `SELECT * FROM push_subscriptions WHERE family_code = ? AND member_id IN (${adminIds.map(() => '?').join(',')})`
    ).bind(familyCode, ...adminIds).all();
    const payload = {
      title: '🔒 طلب شات خاص',
      body: requesterName + ' عايز يبدأ شات خاص مع ' + targetName + '، يحتاج موافقتك',
      url: '/',
    };
    await Promise.all(results.map(row => sendWebPush(env, {
      endpoint: row.endpoint,
      keys: { p256dh: row.p256dh, auth: row.auth },
    }, payload)));
  } catch (e) { /* تجاهل أي خطأ في الإرسال */ }
}

// إشعار كل أفراد العائلة (ما عدا اللي حذف بنفسه) بإن العائلة اتحذفت نهائيًا
async function notifyFamilyDeleted(env, familyCode, excludeMemberId) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT * FROM push_subscriptions WHERE family_code = ? AND member_id != ?'
    ).bind(familyCode, excludeMemberId || '').all();
    const payload = {
      title: '⚠️ تم حذف العائلة',
      body: 'كبير العائلة حذف العائلة نهائيًا. هيتم تسجيل خروجك تلقائيًا.',
      url: '/',
    };
    await Promise.all(results.map(row => sendWebPush(env, {
      endpoint: row.endpoint,
      keys: { p256dh: row.p256dh, auth: row.auth },
    }, payload)));
  } catch (e) { /* تجاهل أي خطأ في الإرسال */ }
}

const ICON_192_B64 = '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';
const ICON_512_B64 = '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';
const ICON_512_MASKABLE_B64 = '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';

function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

const MANIFEST_JSON = JSON.stringify({
  name: 'أمان العيلة',
  short_name: 'أمان العيلة',
  description: 'دائرة أمان خاصة لعيلتك - تطمن على اللي بتحبهم وهم يطمنوا عليك',
  start_url: '/',
  scope: '/',
  display: 'standalone',
  orientation: 'portrait',
  background_color: '#f5f3ff',
  theme_color: '#6d28d9',
  lang: 'ar',
  dir: 'rtl',
  icons: [
    { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
    { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
    { src: '/icon-512-maskable.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
  ],
});

const SERVICE_WORKER_JS = `
// رفع رقم الإصدار ده (v2 -> v3) بيخلي أي نسخة قديمة متخزّنة عند المستخدمين تتمسح تلقائيًا
// فور ما الـ Service Worker الجديد يتفعّل (شوف activate تحت).
const CACHE_NAME = 'amanaleilah-shell-v3';
const SHELL_URLS = ['/', '/manifest.json', '/icon-192.png', '/icon-512.png'];

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(SHELL_URLS)).catch(() => {}));
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
  );
  self.clients.claim();
});

// استراتيجية التخزين المؤقت: "الأحدث الأول" (network-first) - يعني كل ما يكون فيه نت، المستخدم بياخد
// أحدث نسخة من التطبيق فورًا (مهم جدًا لتطبيق طوارئ عشان محدش يفضل شغال بنسخة قديمة فيها باج).
// الكاش بيتستخدم بس لو مفيش نت خالص، عشان التطبيق يفضل يفتح حتى أوفلاين.
self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // سيب طلبات الـ API الخارجي (amanaleilah workers) والخطوط تعدي عادي
  if (SHELL_URLS.includes(url.pathname)) {
    event.respondWith(
      fetch(req, { cache: 'no-store' }).then(res => {
        caches.open(CACHE_NAME).then(cache => cache.put(req, res.clone()));
        return res;
      }).catch(() => caches.match(req))
    );
  }
});

self.addEventListener('push', event => {
  let data = {};
  try { data = event.data.json(); } catch(e) { data = { title: 'أمان العيلة', body: '' }; }
  const isSos = (data.title || '').includes('🚨');
  const options = {
    body: data.body || '',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    vibrate: isSos ? [500,200,500,200,500,200,500,200,500] : [400,150,400,150,400],
    data: { url: data.url || '/' },
    requireInteraction: true,
    renotify: true,
    tag: 'amanaleilah-alert-' + Date.now(),
  };
  event.waitUntil(self.registration.showNotification(data.title || 'أمان العيلة', options));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data.url || '/'));
});
`;

const INDEX_HTML = "<!DOCTYPE html>\n<html lang=\"ar\" dir=\"rtl\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no\">\n<title>أمان العيلة - تسجيل الدخول</title>\n<link rel=\"manifest\" href=\"/manifest.json\">\n<link rel=\"icon\" href=\"/icon-192.png\">\n<link rel=\"apple-touch-icon\" href=\"/icon-192.png\">\n<meta name=\"theme-color\" content=\"#6d28d9\">\n<meta name=\"mobile-web-app-capable\" content=\"yes\">\n<meta name=\"apple-mobile-web-app-capable\" content=\"yes\">\n<meta name=\"apple-mobile-web-app-status-bar-style\" content=\"black-translucent\">\n<meta name=\"apple-mobile-web-app-title\" content=\"أمان العيلة\">\n<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n<link href=\"https://fonts.googleapis.com/css2?family=Cairo:wght@600;700;800;900&family=IBM+Plex+Sans+Arabic:wght@400;500;600&display=swap\" rel=\"stylesheet\">\n<style>\n  @keyframes sosPulse {\n    0%, 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0.5); }\n    50% { box-shadow: 0 0 0 8px rgba(239,68,68,0); }\n  }\n  :root {\n    --bg: #FFFFFF;\n    --card: #F6F2FE;\n    --card2: #EEE7FC;\n    --line: #E4D9FA;\n    --text: #241D33;\n    --muted: #8B84A0;\n    --sos: #EF4444;\n    --sos-dim: #FDEAEA;\n    --safe: #10B981;\n    --safe-dim: #E3F8F0;\n    --occasion: #7C3AED;\n    --occasion-dim: #F0E9FE;\n    --chat-me: #E7DBFB;\n    --chat-other: #FFFFFF;\n    --chat-accent: #7C3AED;\n  }\n  body.dark {\n    --bg: #14101F;\n    --card: #1D1830;\n    --card2: #262038;\n    --line: #332B4A;\n    --text: #F3F1FA;\n    --muted: #A9A1C2;\n    --sos: #F87171;\n    --sos-dim: #3A2228;\n    --safe: #34D399;\n    --safe-dim: #17322A;\n    --occasion: #A78BFA;\n    --occasion-dim: #2E2650;\n    --chat-me: #3B2E64;\n    --chat-other: #221C36;\n    --chat-accent: #A78BFA;\n  }\n  * { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }\n  html, body { overflow-x: hidden; width: 100%; }\n  body {\n    background: var(--bg);\n    color: var(--text);\n    font-family: 'IBM Plex Sans Arabic', sans-serif;\n    min-height: 100vh;\n    transition: background 0.25s ease, color 0.25s ease;\n  }\n  .wrap { max-width: 480px; margin: 0 auto; padding: 20px 16px 90px; }\n  h1, h2, h3 { font-family: 'Cairo', sans-serif; }\n\n  .onboard { min-height: 100vh; display: flex; flex-direction: column; justify-content: center; padding: 24px; }\n  .onboard-title { font-size: 34px; font-weight: 900; margin-bottom: 8px; }\n  .onboard-sub { color: var(--muted); font-size: 15px; margin-bottom: 36px; line-height: 1.6; }\n  .choice-card {\n    background: var(--card); border: 1px solid var(--line); border-radius: 18px;\n    padding: 20px; margin-bottom: 14px; cursor: pointer;\n  }\n  .choice-card h3 { font-size: 18px; margin-bottom: 4px; }\n  .choice-card p { color: var(--muted); font-size: 13px; }\n  .field { margin-bottom: 14px; }\n  .field label { display: block; font-size: 13px; color: var(--muted); margin-bottom: 6px; }\n  .field input, .field select {\n    width: 100%; background: var(--bg); border: 1px solid var(--line);\n    border-radius: 10px; padding: 13px 14px; color: var(--text);\n    font-family: inherit; font-size: 16px;\n  }\n  .field input:focus, .field select:focus { outline: 1px solid var(--occasion); }\n  .btn-primary {\n    width: 100%; background: var(--occasion); color: #FFFFFF; border: none;\n    border-radius: 12px; padding: 15px; font-family: 'Cairo', sans-serif;\n    font-weight: 700; font-size: 16px; cursor: pointer;\n  }\n  .btn-ghost {\n    width: 100%; background: none; border: 1px solid var(--line); color: var(--muted);\n    border-radius: 12px; padding: 13px; font-size: 14px; cursor: pointer; margin-top: 10px;\n  }\n  .btn-secondary {\n    width: 100%; background: var(--card2); color: var(--text); border: 1px solid var(--line);\n    border-radius: 12px; padding: 13px; font-family: 'Cairo', sans-serif;\n    font-weight: 700; font-size: 15px; cursor: pointer; margin-top: 8px;\n  }\n  .back-link { color: var(--muted); font-size: 13px; margin-bottom: 18px; cursor: pointer; display: inline-block; }\n  .note-box {\n    background: rgba(212,166,87,0.08); border: 1px solid rgba(212,166,87,0.25);\n    border-radius: 12px; padding: 12px 14px; font-size: 12px; color: var(--muted); line-height: 1.7; margin-top: 18px;\n  }\n  .hidden { display: none !important; }\n  .tabs-row {\n    display: flex;\n    gap: 10px;\n    margin-bottom: 24px;\n  }\n  .tab-btn {\n    flex: 1;\n    padding: 10px;\n    text-align: center;\n    border-radius: 12px;\n    border: 1px solid var(--line);\n    background: transparent;\n    color: var(--muted);\n    font-family: 'Cairo', sans-serif;\n    font-weight: 700;\n    font-size: 15px;\n    cursor: pointer;\n  }\n  .tab-btn.active {\n    background: var(--card);\n    border-color: var(--occasion);\n    color: var(--occasion);\n  }\n  .divider {\n    display: flex;\n    align-items: center;\n    gap: 10px;\n    margin: 16px 0;\n    color: var(--muted);\n    font-size: 12px;\n  }\n  .divider::before, .divider::after {\n    content: '';\n    flex: 1;\n    height: 1px;\n    background: var(--line);\n  }\n</style>\n</head>\n<body>\n\n<!-- LOGIN/REGISTER SCREEN -->\n<div id=\"loginScreen\" class=\"onboard hidden\">\n  <div class=\"onboard-title\" id=\"loginTitle\">أمان العيلة</div>\n<div style=\"font-size:11px;color:#D4A657;margin-bottom:6px;\">✅ نسخة محدثة - إصدار تجريبي 2</div>\n  <div class=\"onboard-sub\">تطبيق بسيط يخلّي أهل بيتك يطمنّوا عليك، وانت تطمن عليهم</div>\n  \n  <!-- Tabs -->\n  <div class=\"tabs-row\">\n    <button class=\"tab-btn active\" id=\"loginTabBtn\">🔐 تسجيل دخول</button>\n    <button class=\"tab-btn\" id=\"registerTabBtn\">📝 تسجيل جديد</button>\n  </div>\n\n  <!-- Login Tab -->\n  <div id=\"loginTabContent\">\n    <div class=\"field\">\n      <label>🔑 كود العائلة</label>\n      <input type=\"text\" id=\"loginCode\" placeholder=\"أدخل كود العائلة\" style=\"text-align:center;font-size:20px;letter-spacing:3px;\">\n    </div>\n    <div class=\"field\">\n      <label id=\"loginPinLabel\">🔒 كلمة السر</label>\n      <input type=\"password\" id=\"loginPin\" placeholder=\"كلمة السر\">\n    </div>\n    <button class=\"btn-primary\" id=\"loginSubmit\">دخول</button>\n    <div id=\"loginError\" style=\"color:var(--sos); font-size:13px; margin-top:10px; display:none;\"></div>\n    <div class=\"back-link\" id=\"openAdminRecoveryLink\" style=\"display:block; margin-top:14px;\">نسيت كلمة السر؟</div>\n  </div>\n\n  <!-- Forgot password - security question flow (متاح لأي عضو، مش بس كبير العائلة) -->\n  <div id=\"adminRecoveryBox\" class=\"hidden\">\n    <span class=\"back-link\" id=\"closeAdminRecovery\">‹ رجوع</span>\n    <h3 style=\"font-size:18px; margin-bottom:14px;\">استرجاع كلمة السر</h3>\n    <div id=\"recoveryStep1\">\n      <div class=\"field\">\n        <label>🔑 كود العائلة</label>\n        <input type=\"text\" id=\"recoveryCode2\" placeholder=\"كود العائلة\" style=\"text-align:center;letter-spacing:3px;\">\n      </div>\n      <div class=\"field\">\n        <label>👤 اسمك</label>\n        <input type=\"text\" id=\"recoveryNameInput\" placeholder=\"اكتب اسمك زي ما سجّلته بالظبط\">\n      </div>\n      <button class=\"btn-primary\" id=\"recoveryFindMemberBtn\">اعرض سؤال الأمان</button>\n      <div id=\"recoveryStep1Error\" style=\"color:var(--sos); font-size:13px; margin-top:10px; display:none;\"></div>\n    </div>\n    <div id=\"recoveryStep3\" class=\"hidden\">\n      <span class=\"back-link\" id=\"recoveryBackToMember\">‹ رجوع</span>\n      <div class=\"field\">\n        <label id=\"recoveryQuestionLabel\" style=\"font-weight:700;\"></label>\n        <input type=\"text\" id=\"recoveryAnswer\" placeholder=\"إجابتك\">\n      </div>\n      <div class=\"field\">\n        <label id=\"recoveryQuestionLabel2\" style=\"font-weight:700;\"></label>\n        <input type=\"text\" id=\"recoveryAnswer2\" placeholder=\"إجابتك\">\n      </div>\n      <div class=\"field\">\n        <label>🔒 كلمة سر جديدة</label>\n        <input type=\"password\" id=\"recoveryNewPin\" placeholder=\"6 حروف أو أرقام على الأقل\">\n      </div>\n      <button class=\"btn-primary\" id=\"recoverySubmitBtn\">استرجاع كلمة السر</button>\n      <div id=\"recoveryError\" style=\"color:var(--sos); font-size:13px; margin-top:10px; display:none;\"></div>\n    </div>\n  </div>\n\n  <!-- Register Tab -->\n  <div id=\"registerTabContent\" class=\"hidden\">\n    <div class=\"field\">\n      <label>🔑 كود العائلة</label>\n      <input type=\"text\" id=\"registerCode\" placeholder=\"أدخل كود العائلة\" style=\"text-align:center;font-size:20px;letter-spacing:3px;\">\n    </div>\n    <div class=\"field\">\n      <label>👤 اسمك أو أي اسم مستعار تحب تظهر بيه لعائلتك</label>\n      <input type=\"text\" id=\"registerName\" placeholder=\"مش شرط يكون اسمك الحقيقي - مثلاً: أحمد\">\n      <div style=\"font-size:11.5px; color:var(--muted); margin-top:5px;\">⚠️ افتكر الاسم ده - هتحتاجه لو نسيت كلمة السر يومًا (مش لازم للدخول العادي)</div>\n    </div>\n    <div class=\"field\">\n      <label>🔒 اختار كلمة سر هتستخدمها للدخول</label>\n      <input type=\"password\" id=\"registerPin\" placeholder=\"6 حروف أو أرقام على الأقل\">\n    </div>\n    <div class=\"field\">\n      <label>❓ سؤال أمان 1 (لو نسيت كلمة السر)</label>\n      <select id=\"registerSecurityQuestion\"></select>\n    </div>\n    <div class=\"field\">\n      <label>✏️ إجابتك على السؤال الأول</label>\n      <input type=\"text\" id=\"registerSecurityAnswer\" placeholder=\"اكتب إجابتك\">\n    </div>\n    <div class=\"field\">\n      <label>❓ سؤال أمان 2 (لازم يكون مختلف عن الأول)</label>\n      <select id=\"registerSecurityQuestion2\"></select>\n    </div>\n    <div class=\"field\">\n      <label>✏️ إجابتك على السؤال التاني</label>\n      <input type=\"text\" id=\"registerSecurityAnswer2\" placeholder=\"اكتب إجابتك\">\n    </div>\n    <div class=\"field\">\n      <label>صلتك بالعائلة</label>\n      <select id=\"registerRelation\">\n        <option value=\"ابن\">ابن</option>\n        <option value=\"ابنة\">ابنة</option>\n        <option value=\"أب\">أب</option>\n        <option value=\"أم\">أم</option>\n        <option value=\"جد\">جد</option>\n        <option value=\"جدة\">جدة</option>\n        <option value=\"عم\">عم</option>\n        <option value=\"عمة\">عمة</option>\n        <option value=\"خال\">خال</option>\n        <option value=\"خالة\">خالة</option>\n        <option value=\"أخرى\">قرابة أخرى</option>\n      </select>\n    </div>\n    <div style=\"display:flex; align-items:flex-start; gap:8px; margin:14px 0;\">\n      <input type=\"checkbox\" id=\"registerAgeConfirm\" style=\"margin-top:4px; flex-shrink:0;\">\n      <label for=\"registerAgeConfirm\" style=\"font-size:12px; color:var(--muted); line-height:1.6;\">\n        أقر بأني بلغت <strong>18 عامًا</strong> على الأقل. هذا التطبيق مخصص للبالغين فقط.\n      </label>\n    </div>\n    <div style=\"display:flex; align-items:flex-start; gap:8px; margin:14px 0;\">\n      <input type=\"checkbox\" id=\"registerConsent\" style=\"margin-top:4px; flex-shrink:0;\">\n      <label for=\"registerConsent\" style=\"font-size:12px; color:var(--muted); line-height:1.6;\">\n        أوافق على <span class=\"terms-link\" data-open-terms=\"1\" style=\"color:var(--occasion); text-decoration:underline; cursor:pointer;\">شروط استخدام التطبيق وسياسة الخصوصية</span>.\n      </label>\n    </div>\n    <button class=\"btn-primary\" id=\"registerSubmit\">تسجيل جديد</button>\n    <div id=\"registerError\" style=\"color:var(--sos); font-size:13px; margin-top:10px; display:none;\"></div>\n  </div>\n\n  <div id=\"registerPendingBox\" class=\"hidden\" style=\"background:var(--card2); border-radius:12px; padding:16px; margin-top:14px; text-align:center;\">\n    <div style=\"font-size:28px; margin-bottom:8px;\">⏳</div>\n    <div style=\"font-weight:700; margin-bottom:6px;\">طلبك اتبعت لكبير العائلة</div>\n    <div style=\"font-size:12.5px; color:var(--muted); line-height:1.7;\">لازم كبير العائلة يوافق على انضمامك الأول قبل ما تقدر تدخل. جرب تسجل دخول تاني بعد ما يوافق عليك.</div>\n    <button class=\"btn-secondary\" id=\"registerPendingBackBtn\" style=\"margin-top:12px;\">‹ رجوع لتسجيل الدخول</button>\n  </div>\n\n  <div class=\"divider\">أو</div>\n\n  <button class=\"btn-secondary\" id=\"createFamilyBtn\">➕ إنشاء عائلة جديدة</button>\n</div>\n\n<!-- ADMIN PANEL SCREEN (hidden control panel, no visible entry point) -->\n<div id=\"adminScreen\" class=\"hidden\">\n  <div class=\"admin-wrap\">\n\n    <!-- key prompt -->\n    <div id=\"adminLoginBox\" class=\"admin-login-box\">\n      <div class=\"onboard-title\" style=\"font-size:24px;\">لوحة التحكم</div>\n      <div class=\"onboard-sub\" style=\"margin-bottom:20px;\">أدخل مفتاح الإدارة</div>\n      <div class=\"field\"><input type=\"password\" id=\"adminKeyInput\" placeholder=\"مفتاح الإدارة\"></div>\n      <button class=\"btn-primary\" id=\"adminKeySubmit\">دخول</button>\n      <div id=\"adminLoginError\" style=\"color:var(--sos); font-size:13px; margin-top:10px; display:none;\"></div>\n      <div class=\"admin-back\" id=\"adminCancelLogin\" style=\"margin-top:18px;\">‹ رجوع</div>\n    </div>\n\n    <!-- dashboard -->\n    <div id=\"adminDashboard\" class=\"hidden\">\n      <div class=\"admin-header\">\n        <h2>لوحة التحكم</h2>\n        <button class=\"admin-logout\" id=\"adminLogoutBtn\">خروج</button>\n      </div>\n\n      <div class=\"admin-stats\" id=\"adminStats\"></div>\n\n      <div class=\"admin-tabs\">\n        <button class=\"admin-tab-btn active\" id=\"adminTabFamilies\">العائلات</button>\n        <button class=\"admin-tab-btn\" id=\"adminTabEvents\">آخر الأحداث</button>\n      </div>\n\n      <!-- families list -->\n      <div id=\"adminFamiliesList\"></div>\n\n      <!-- single family detail -->\n      <div id=\"adminFamilyDetail\" class=\"hidden\">\n        <span class=\"admin-back\" id=\"adminBackToFamilies\">‹ كل العائلات</span>\n        <div id=\"adminFamilyDetailContent\"></div>\n      </div>\n\n      <!-- events feed -->\n      <div id=\"adminEventsList\" class=\"hidden\"></div>\n    </div>\n\n  </div>\n</div>\n\n<!-- CREATE FAMILY SCREEN -->\n<div id=\"createFamilyScreen\" class=\"onboard hidden\">\n  <span class=\"back-link\" id=\"backFromCreateFamily\">‹ رجوع</span>\n  <h2 style=\"font-size:22px; margin-bottom:18px;\">🏠 إنشاء عائلة جديدة</h2>\n  <div style=\"background:var(--card2);border-radius:12px;padding:16px;margin-bottom:20px;text-align:center;\">\n    <div style=\"font-size:13px;color:var(--muted);\">كود العائلة (هيتولّد لوحده)</div>\n    <div id=\"newFamilyCode\" style=\"font-family:'Cairo';font-size:28px;font-weight:900;letter-spacing:5px;color:var(--occasion);margin-top:8px;\">------</div>\n    <div style=\"font-size:11px;color:var(--muted);margin-top:4px;\">ده الكود اللي هتشاركه مع عيلتك بعد كده</div>\n  </div>\n  <div class=\"field\">\n    <label>اسمك أو أي اسم مستعار تحب تظهر بيه لعائلتك</label>\n    <input type=\"text\" id=\"newFamilyName\" placeholder=\"مش شرط يكون اسمك الحقيقي - مثلاً: أحمد\">\n    <div style=\"font-size:11.5px; color:var(--muted); margin-top:5px;\">⚠️ افتكر الاسم ده - هتحتاجه لو نسيت كلمة السر يومًا (مش لازم للدخول العادي)</div>\n  </div>\n  <div class=\"field\">\n    <label>🔒 اختار كلمة سر هتستخدمها للدخول</label>\n    <input type=\"password\" id=\"newFamilyPin\" placeholder=\"6 حروف أو أرقام على الأقل\">\n  </div>\n  <div class=\"field\">\n    <label>❓ سؤال أمان 1 (لو نسيت كلمة السر)</label>\n    <select id=\"newFamilySecurityQuestion\"></select>\n  </div>\n  <div class=\"field\">\n    <label>✏️ إجابتك على السؤال الأول</label>\n    <input type=\"text\" id=\"newFamilySecurityAnswer\" placeholder=\"اكتب إجابتك\">\n  </div>\n  <div class=\"field\">\n    <label>❓ سؤال أمان 2 (لازم يكون مختلف عن الأول)</label>\n    <select id=\"newFamilySecurityQuestion2\"></select>\n  </div>\n  <div class=\"field\">\n    <label>✏️ إجابتك على السؤال التاني</label>\n    <input type=\"text\" id=\"newFamilySecurityAnswer2\" placeholder=\"اكتب إجابتك\">\n  </div>\n  <div class=\"field\">\n    <label>صلتك بالعائلة</label>\n    <select id=\"newFamilyRelation\">\n      <option value=\"أب\">أب</option>\n      <option value=\"أم\">أم</option>\n    </select>\n  </div>\n  <div style=\"display:flex; align-items:flex-start; gap:8px; margin:14px 0;\">\n    <input type=\"checkbox\" id=\"createAgeConfirm\" style=\"margin-top:4px; flex-shrink:0;\">\n    <label for=\"createAgeConfirm\" style=\"font-size:12px; color:var(--muted); line-height:1.6;\">\n      أقر بأني بلغت <strong>18 عامًا</strong> على الأقل. هذا التطبيق مخصص للبالغين فقط.\n    </label>\n  </div>\n  <div style=\"display:flex; align-items:flex-start; gap:8px; margin:14px 0;\">\n    <input type=\"checkbox\" id=\"createConsent\" style=\"margin-top:4px; flex-shrink:0;\">\n    <label for=\"createConsent\" style=\"font-size:12px; color:var(--muted); line-height:1.6;\">\n      أوافق على <span class=\"terms-link\" data-open-terms=\"1\" style=\"color:var(--occasion); text-decoration:underline; cursor:pointer;\">شروط استخدام التطبيق وسياسة الخصوصية</span>.\n    </label>\n  </div>\n  <div style=\"display:flex; align-items:flex-start; gap:8px; margin:14px 0;\">\n    <input type=\"checkbox\" id=\"createResponsibility\" style=\"margin-top:4px; flex-shrink:0;\">\n    <label for=\"createResponsibility\" style=\"font-size:12px; color:var(--muted); line-height:1.6;\">\n      أؤكد إني المسؤول عن إدارة هذه العائلة داخل التطبيق (الموافقة على انضمام الأفراد وحذفهم عند الحاجة)، بصفتي \"كبير العائلة\".\n    </label>\n  </div>\n  <button class=\"btn-primary\" id=\"createFamilySubmit\">إنشاء العائلة</button>\n  <div id=\"createFamilyError\" style=\"color:var(--sos); font-size:13px; margin-top:10px; display:none;\"></div>\n</div>\n\n<!-- MAIN APP -->\n<div id=\"mainScreen\" class=\"hidden\">\n  <div class=\"wrap\">\n    <div class=\"topbar\">\n      <div>\n        <h1 id=\"greeting\">أهلاً</h1>\n        <div class=\"fam-code\">كود العائلة: <span id=\"famCodeSmall\"></span></div>\n      </div>\n      <div class=\"status-dot\"><span class=\"dot\"></span><span id=\"lastUpdate\">محدّث الآن</span></div>\n    </div>\n\n    <div class=\"circle-row\" id=\"circleRow\"></div>\n\n    <div id=\"activeSosBanner\" class=\"hidden\" style=\"background:var(--sos); border-radius:12px; padding:14px; margin-bottom:14px; color:#fff; animation:sosPulse 1.5s infinite;\">\n      <div id=\"activeSosText\" style=\"font-weight:800; margin-bottom:10px; font-size:14px;\">🆘 نداء استغاثة</div>\n      <button class=\"btn-primary\" id=\"ackSosBtn\" style=\"background:#fff; color:var(--sos); margin:0;\">✓ تم الاطلاع - أوقف التنبيه</button>\n    </div>\n    <div id=\"pendingDeletionBanner\" class=\"hidden\" style=\"background:#FDEAEA; border:1px solid var(--sos); border-radius:12px; padding:12px 14px; margin-bottom:14px; font-size:12.5px; color:#7a1f1f;\">\n      <div id=\"pendingDeletionText\" style=\"margin-bottom:8px;\">⚠️ فيه طلب حذف معلّق</div>\n      <button class=\"btn-ghost\" id=\"cancelPendingDeletionBtn\" style=\"width:auto; padding:6px 14px; margin:0; font-size:12px; border-color:var(--sos); color:var(--sos);\">إلغاء طلب الحذف</button>\n    </div>\n\n    <!-- HOME TAB -->\n    <div id=\"homeTab\">\n      <div class=\"actions\">\n        <button class=\"action-btn sos\" id=\"sosBtn\">\n          <span class=\"icon\">🚨</span>\n          محتاج مساعدة الآن\n        </button>\n        <button class=\"action-btn safe\" id=\"safeBtn\">\n          <span class=\"icon\">✅</span>\n          وصلت بأمان\n        </button>\n        <button class=\"action-btn occasion\" id=\"occasionBtn\">\n          <span class=\"icon\">🎊</span>\n          مناسبات العيلة\n        </button>\n        <button class=\"btn-ghost\" id=\"shareLocationBtn\" style=\"grid-column: 1 / -1; margin-top: 0;\">📍 شارك موقعي</button>\n        <div id=\"activeShareBanner\" class=\"hidden\" style=\"grid-column: 1 / -1; background:var(--occasion-dim); border:1px solid var(--occasion); border-radius:12px; padding:10px 14px; font-size:12.5px; color:var(--occasion); display:flex; justify-content:space-between; align-items:center;\">\n          <span id=\"activeShareText\">📍 بتشارك موقعك دلوقتي</span>\n          <button class=\"btn-ghost\" id=\"stopShareBtn\" style=\"width:auto; padding:6px 12px; margin:0; font-size:12px; border-color:var(--occasion); color:var(--occasion);\">إيقاف</button>\n        </div>\n      </div>\n\n      <!-- لوحة متابعة العائلة - تظهر للأب/الأم بس، عشان يشوفوا حالة كل فرد بنظرة واحدة -->\n      <div id=\"familyOverview\" class=\"hidden\">\n        <div class=\"section-title\">👨‍👩‍👧‍👦 نظرة عامة على العيلة</div>\n        <div id=\"overviewGrid\" class=\"overview-grid\"></div>\n      </div>\n\n      <div class=\"section-title\">💬 المجلس العائلي</div>\n      <div id=\"chatContainer\" class=\"chat-container\"></div>\n      <div id=\"mediaUploadStatus\" style=\"font-size:12px;color:var(--occasion);margin-bottom:6px;\"></div>\n      <div class=\"chat-media-row\">\n        <button class=\"media-btn\" id=\"photoBtn\" title=\"صورة\">📷</button>\n        <button class=\"media-btn\" id=\"audioBtn\" title=\"تسجيل صوتي\">🎙️</button>\n        <button class=\"media-btn\" id=\"videoBtn\" title=\"فيديو\">🎥</button>\n      </div>\n      <input type=\"file\" id=\"photoInput\" accept=\"image/*\" class=\"hidden\">\n      <input type=\"file\" id=\"audioInput\" accept=\"audio/*\" class=\"hidden\">\n      <input type=\"file\" id=\"videoInput\" accept=\"video/*\" class=\"hidden\">\n      <div class=\"chat-input-row\">\n        <input type=\"text\" id=\"chatInput\" placeholder=\"اكتب رسالة للعيلة...\">\n        <button id=\"chatSendBtn\">إرسال</button>\n      </div>\n\n      <div class=\"section-title\">آخر التحديثات</div>\n      <div id=\"feedList\"></div>\n    </div>\n\n    <!-- FAMILY TAB -->\n    <div id=\"familyTab\" class=\"hidden\">\n      <div id=\"pendingMembersSection\" class=\"hidden\">\n        <div class=\"section-title\">⏳ طلبات انضمام محتاجة موافقتك</div>\n        <div id=\"pendingMembersList\"></div>\n      </div>\n      <div id=\"pendingPrivateSection\" class=\"hidden\">\n        <div class=\"section-title\">🔒 طلبات شات خاص محتاجة موافقتك</div>\n        <div id=\"pendingPrivateList\"></div>\n      </div>\n      <div id=\"pendingReportsSection\" class=\"hidden\">\n        <div class=\"section-title\">🚩 بلاغات على رسايل محتاجة مراجعتك</div>\n        <div id=\"pendingReportsList\"></div>\n      </div>\n      <div class=\"section-title\">أفراد العائلة</div>\n      <div id=\"memberList\"></div>\n      <div class=\"note-box\" id=\"trustNote\">\n        الأب والأم في دائرة أمانك دايمًا تلقائيًا. تقدر تضيف قرابة تانية لدائرتك بالضغط على \"أضف لدائرتي\" جنب اسمهم. \"كبير العائلة\" هو اللي أنشأ العائلة، وهو اللي يقدر يحذف أي عضو أو يوافق على انضمام عضو جديد، ويقدر يرقّي عضو تاني يبقى \"نائب كبير عائلة\" وله نفس الصلاحيات بالظبط (احتياطًا لو حصله ظرف). الشات الخاص متاح مع كبير العائلة (أو نائبه) مباشرة، أو مع أي عضو تاني بعد موافقة صريحة منهم.\n      </div>\n    </div>\n\n    <!-- SETTINGS TAB -->\n    <div id=\"settingsTab\" class=\"hidden\">\n      <div class=\"section-title\">📲 تثبيت التطبيق</div>\n      <div id=\"installBanner\" class=\"note-box\" style=\"margin-top:0;\"></div>\n      <button class=\"btn-secondary hidden\" id=\"installAppBtn\">📲 ثبّت التطبيق الآن</button>\n\n      <div class=\"section-title\">🌙 الوضع الليلي</div>\n      <div class=\"dark-toggle-row\">\n        <div>\n          <div style=\"font-weight:600; font-size:14px;\">الوضع الليلي</div>\n          <div style=\"font-size:11.5px; color:var(--muted); margin-top:2px;\">راحة أكتر للعين بالليل</div>\n        </div>\n        <button class=\"switch\" id=\"darkModeToggle\"><i></i></button>\n      </div>\n\n      <div class=\"section-title\">🎨 شكل المحادثة</div>\n      <div class=\"field\">\n        <select id=\"chatThemeSelect\">\n          <option value=\"rose\">🌸 وردي</option>\n          <option value=\"lavender\">💜 لافندر</option>\n          <option value=\"peach\">🍑 خوخي</option>\n          <option value=\"mint\">🌿 نعناعي</option>\n          <option value=\"sky\">💙 سماوي</option>\n          <option value=\"gold\">✨ ذهبي</option>\n        </select>\n      </div>\n\n      <div class=\"section-title\">🔔 نغمات الإشعارات</div>\n\n      <div style=\"font-weight:700; font-size:13px; margin-bottom:8px; color:var(--sos);\">🚨 عند الطوارئ</div>\n      <div class=\"field\">\n        <select id=\"sosToneSelect\">\n          <option value=\"siren\">صفارة إنذار (قوية)</option>\n          <option value=\"klaxon\">بوق متكرر</option>\n          <option value=\"bell\">جرس حاد</option>\n        </select>\n      </div>\n      <button class=\"btn-ghost\" id=\"testSosTone\" style=\"margin-bottom:8px;\">🔈 جرّب الصوت</button>\n      <div class=\"field\">\n        <label>أو اختار نغمة من نغمات إشعارات هاتفك (اختياري)</label>\n        <input type=\"file\" id=\"sosCustomFile\" accept=\"audio/*\">\n      </div>\n      <div id=\"sosCustomStatus\" style=\"font-size:12px;color:var(--safe);margin-bottom:16px;\"></div>\n\n      <div style=\"font-weight:700; font-size:13px; margin-bottom:8px; color:var(--safe);\">✅ عند الاطمئنان</div>\n      <div class=\"field\">\n        <select id=\"safeToneSelect\">\n          <option value=\"chime\">جرس هادي</option>\n          <option value=\"soft\">نغمة ناعمة</option>\n        </select>\n      </div>\n      <button class=\"btn-ghost\" id=\"testSafeTone\" style=\"margin-bottom:8px;\">🔈 جرّب الصوت</button>\n      <div class=\"field\">\n        <label>أو اختار نغمة من نغمات إشعارات هاتفك (اختياري)</label>\n        <input type=\"file\" id=\"safeCustomFile\" accept=\"audio/*\">\n      </div>\n      <div id=\"safeCustomStatus\" style=\"font-size:12px;color:var(--safe);margin-bottom:6px;\"></div>\n\n      <button class=\"btn-primary\" id=\"saveSoundPrefs\">حفظ التفضيلات</button>\n\n      <div class=\"section-title\">🔒 الأمان</div>\n      <div class=\"field\">\n        <label>غيّر كلمة سرك</label>\n        <input type=\"password\" id=\"newPinInput\" placeholder=\"كلمة سر جديدة (6 حروف أو أرقام على الأقل)\">\n      </div>\n      <button class=\"btn-secondary\" id=\"changePinBtn\">حفظ كلمة السر الجديدة</button>\n\n      <div class=\"section-title\">💊 تذكير الأدوية</div>\n      <div class=\"note-box\" style=\"margin-top:0;\">\n        أداة تذكير بس، مش أداة طبية ومفيش أي نصيحة أو تشخيص طبي هنا. البيانات دي بتتخزن على جهازك انت بس، والتذكير بيشتغل محليًا على المتصفح لما التطبيق يكون مفتوح.\n      </div>\n      <div id=\"medicationList\"></div>\n      <div class=\"field\">\n        <label>اسم الدواء</label>\n        <input type=\"text\" id=\"medName\" placeholder=\"مثلاً: حبوب الضغط\">\n      </div>\n      <div class=\"field\">\n        <label>معاد التذكير</label>\n        <input type=\"time\" id=\"medTime\">\n      </div>\n      <button class=\"btn-secondary\" id=\"addMedicationBtn\">➕ إضافة تذكير</button>\n\n      <button class=\"btn-ghost hidden\" id=\"deleteFamilyBtn\" style=\"margin-top:22px;color:var(--sos);border-color:var(--sos);\">🗑️ حذف العائلة نهائيًا</button>\n      <button class=\"btn-ghost hidden\" id=\"deleteMyAccountBtn\" style=\"margin-top:22px;color:var(--sos);border-color:var(--sos);\">🗑️ احذف حسابي نهائيًا</button>\n\n      <button class=\"btn-ghost\" id=\"logoutBtn\" style=\"margin-top:18px;color:var(--sos);border-color:var(--sos);\">🚪 تسجيل خروج</button>\n      <div class=\"note-box\">\n        المتصفح مش بيقدر يوصل لمكتبة نغمات الهاتف الأصلية (قيد أمان من أندرويد وآيفون)، فبنقدملك نغمات مدمجة قوية بدلها، أو تقدر ترفع أي ملف صوت عندك في الهاتف يتشغل بدلها. التفضيل ده خاص بجهازك انت بس.\n      </div>\n    </div>\n\n    <div class=\"note-box\">\n      هذا نموذج تجريبي — كل البيانات تُخزن ومشتركة بين كل أفراد العائلة عبر الإنترنت. اختر كود ثابت عند إنشاء العائلة.\n    </div>\n  </div>\n\n  <div class=\"tabbar\">\n    <button class=\"tab active\" id=\"tabHomeBtn\"><span class=\"icon\">🏠</span>الرئيسية<span id=\"chatUnreadBadge\" class=\"tab-badge hidden\">0</span></button>\n    <button class=\"tab\" id=\"tabFamilyBtn\"><span class=\"icon\">👪</span>العائلة</button>\n    <button class=\"tab\" id=\"tabSettingsBtn\"><span class=\"icon\">⚙️</span>الإعدادات</button>\n  </div>\n</div>\n\n<!-- OCCASION MODAL -->\n<div id=\"occasionModal\" class=\"modal-overlay hidden\">\n  <div class=\"modal\">\n    <h3>مناسبات العيلة</h3>\n    <div class=\"type-picker\">\n      <div class=\"type-pick sel-فرح\" data-type=\"فرح\">🎉 فرح</div>\n      <div class=\"type-pick sel-عيد\" data-type=\"عيد ميلاد\">🎂 عيد ميلاد</div>\n      <div class=\"type-pick sel-وفاة\" data-type=\"وفاة\">🕊️ حالة وفاة</div>\n      <div class=\"type-pick sel-اخرى\" data-type=\"أخرى\">📌 مناسبة أخرى</div>\n    </div>\n    <div class=\"field\">\n      <label>اسم المناسبة</label>\n      <input type=\"text\" id=\"occasionName\" placeholder=\"مثلاً: عيد ميلاد سارة، خطوبة أحمد...\">\n    </div>\n    <div class=\"field\">\n      <label>تفاصيل إضافية (اختياري)</label>\n      <textarea id=\"occasionText\" placeholder=\"اكتب أي تفاصيل تانية...\"></textarea>\n    </div>\n    <button class=\"btn-primary\" id=\"occasionSubmit\">إرسال للعائلة كلها</button>\n    <button class=\"btn-ghost\" id=\"occasionCancel\">إلغاء</button>\n  </div>\n</div>\n\n<!-- DELETE MY ACCOUNT MODAL (لأي عضو عادي غير كبير العائلة) -->\n<div id=\"deleteMyAccountModal\" class=\"modal-overlay hidden\">\n  <div class=\"modal\">\n    <h3 style=\"color:var(--sos);\">⚠️ حذف حسابي نهائيًا</h3>\n    <p style=\"color:var(--muted); font-size:12.5px; line-height:1.8; margin-bottom:14px;\">\n      هيتم حذف بياناتك الشخصية بالكامل ونهائيًا: رسايلك في الشات، أحداثك (طوارئ/اطمئنان/موقع)، ومحادثاتك الخاصة. هتخرج من العائلة نهائيًا ومش هتقدر تدخل تاني إلا لو اتسجلت من الأول وانضممت بموافقة كبير العائلة. الإجراء ده مش هيترجع.\n    </p>\n    <div class=\"field\">\n      <label>أدخل كلمة سرك للتأكيد</label>\n      <input type=\"password\" id=\"deleteMyAccountPin\">\n    </div>\n    <div id=\"deleteMyAccountError\" style=\"color:var(--sos); font-size:13px; margin-bottom:10px; display:none;\"></div>\n    <button class=\"btn-primary\" id=\"deleteMyAccountConfirmBtn\" style=\"background:var(--sos);\">حذف حسابي نهائيًا</button>\n    <button class=\"btn-ghost\" id=\"deleteMyAccountCancelBtn\">إلغاء</button>\n  </div>\n</div>\n\n<!-- DELETE FAMILY MODAL -->\n<div id=\"deleteFamilyModal\" class=\"modal-overlay hidden\">\n  <div class=\"modal\">\n    <h3 style=\"color:var(--sos);\">⚠️ حذف العائلة نهائيًا</h3>\n    <p style=\"color:var(--muted); font-size:12.5px; line-height:1.8; margin-bottom:14px;\">\n      سيؤدي هذا إلى حذف جميع بيانات العائلة نهائيًا، بما في ذلك الدردشة والأعضاء والمناسبات. هل أنت متأكد؟ الحذف فوري ولا يمكن التراجع عنه، ولا يوجد \"فترة سماح\".\n    </p>\n    <div class=\"field\">\n      <label id=\"deleteFamilyCodeLabel\">اكتب كود العائلة للتأكيد</label>\n      <input type=\"text\" id=\"deleteFamilyConfirmCode\" placeholder=\"اكتب كود العائلة بالظبط\">\n    </div>\n    <div class=\"field\">\n      <label>أدخل كلمة سرك للتحقق</label>\n      <input type=\"password\" id=\"deleteFamilyPin\">\n    </div>\n    <div id=\"deleteFamilyError\" style=\"color:var(--sos); font-size:13px; margin-bottom:10px; display:none;\"></div>\n    <button class=\"btn-primary\" id=\"deleteFamilyConfirmBtn\" style=\"background:var(--sos);\">حذف العائلة نهائيًا</button>\n    <button class=\"btn-ghost\" id=\"deleteFamilyCancelBtn\">إلغاء</button>\n  </div>\n</div>\n\n<!-- LOCATION SHARE DURATION MODAL -->\n<div id=\"locationShareModal\" class=\"modal-overlay hidden\">\n  <div class=\"modal\">\n    <h3>📍 شارك موقعك</h3>\n    <p style=\"color:var(--muted); font-size:12.5px; line-height:1.7; margin-bottom:14px;\">\n      المشاركة طوعية وبمدة تحددها انت. مفيش تتبع في الخلفية - المشاركة بتشتغل بس لما التطبيق مفتوح وظاهر على شاشتك، وبتوقف تلقائيًا لما المدة تخلص أو تقفل التطبيق.\n    </p>\n    <button class=\"btn-primary\" id=\"shareLocation1HourBtn\" style=\"margin-bottom:10px;\">⏱️ شارك موقعي لمدة ساعة</button>\n    <button class=\"btn-secondary\" id=\"shareLocationUntilStopBtn\">📍 شارك موقعي لحد ما أوقف</button>\n    <button class=\"btn-ghost\" id=\"locationShareCancelBtn\">إلغاء</button>\n  </div>\n</div>\n\n<!-- TERMS OF USE MODAL -->\n<div id=\"termsModal\" class=\"modal-overlay hidden\">\n  <div class=\"modal\" style=\"max-height:80vh; overflow-y:auto;\">\n    <h3>شروط استخدام التطبيق وسياسة الخصوصية</h3>\n    <div style=\"font-size:13px; color:var(--text); line-height:1.9; margin-top:10px;\">\n      <p><strong>0. التطبيق للبالغين فقط (18+)</strong><br>هذا التطبيق أداة تواصل عائلي للبالغين فقط. باستخدامك للتطبيق، أو بإنشائك عائلة فيه، أو بانضمامك لعائلة موجودة، فإنك تقر وتضمن أنك بلغت <strong>18 عامًا على الأقل</strong>. التطبيق <strong>لا يجمع أي بيانات لأي شخص أقل من 18 سنة أو أي طفل</strong> تحت أي ظرف، ولا يستهدف الأطفال أو القاصرين ولا يجوز إضافتهم إليه إطلاقًا، ولا يتحقق التطبيق من صلة القرابة الفعلية أو هوية المستخدمين.</p>\n      <p><strong>1. طبيعة التطبيق - \"الثقة مش المراقبة\"</strong><br>\"أمان العيلة\" تطبيق تواصل واطمئنان طوعي بين أفراد عائلة واحدة من البالغين، مش تطبيق تتبع ولا مراقبة. كل ميزة فيه بمبادرة المستخدم نفسه، ومفيش أي تتبع تلقائي أو خلفي لموقعك أو نشاطك في أي وقت.</p>\n      <p><strong>2. البيانات اللي بيجمعها التطبيق</strong><br>التطبيق <strong>مش بيطلب اسمك الحقيقي</strong> - تقدر تسجّل بأي اسم مستعار تحب تظهر بيه لعائلتك. الدخول اليومي بيتم بكود العائلة وكلمة السر بس، لكن الاسم بيفضل مهم لو نسيت كلمة السر يومًا (بيستخدم مع سؤالي الأمان للاسترجاع). بجانب كده: صلة القرابة، كلمة سر تختارها بنفسك للدخول، سؤالي أمان وإجابتيهما (للاسترجاع الذاتي لو نسيت كلمة السر)، وموقعك الجغرافي فقط لما تضغط بنفسك على زر \"شارك موقعي\" (بمدة تحددها انت: ساعة أو لحد ما توقف). <strong>مفيش رقم هاتف ولا بريد إلكتروني بيتجمع منك خالص</strong> في أي مرحلة. <u>زرار الطوارئ وزرار الاطمئنان لا يرسلان موقعك إطلاقًا</u> - إشعار نصي بس. إشعار زر الطوارئ بيتكرر تلقائيًا كل 30 ثانية لباقي أفراد عائلتك لحد ما حد يضغط \"تم الاطلاع\"، أو لحد أقصى 10 دقايق. مفيش تسجيل صوت أو فيديو تلقائي.</p>\n      <p><strong>2.1 التشفير ومدة الاحتفاظ بالبيانات</strong><br>موقعك الجغرافي بيتشفّر (AES-GCM) قبل ما يتخزن. تحديثات الحالة (SOS/اطمئنان/موقع/مناسبات) ورسايل الشات بيتم حذفها تلقائيًا بعد <strong>30 يوم</strong> من تاريخها.</p>\n      <p><strong>3. استخدام البيانات</strong><br>بياناتك بتُستخدم <u>فقط</u> داخل مجموعة عائلتك المغلقة. التطبيق <strong>لا يبيع بياناتك</strong> لأي طرف تالت، ولا يستخدمها لأي غرض إعلاني أو تسويقي.</p>\n      <p><strong>4. الشات العام والحظر والإبلاغ</strong><br>فيه شات عام واحد لكل عائلة. أي عضو يقدر يبلّغ عن أي رسالة (🚩)، أو يحظر أي عضو تاني (🚫) لمنعه من التواصل معاه في الشات الخاص. كبير العائلة بس هو اللي يقدر يحذف أي رسالة أو أي عضو من الشات العام.</p>\n      <p><strong>4.1 الشات الخاص (مقيّد ومشفّر من طرف لطرف)</strong><br>الشات الخاص متاح بس بين: (أ) كبير العائلة وأي عضو بالغ، أو (ب) أي عضوين بالغين بعد <strong>موافقة صريحة من كبير العائلة</strong> على كل زوج. يُمنع منعًا باتًا أي شات خاص مفتوح للجميع من غير قيد. المحادثات دي <strong>مشفّرة من طرف لطرف</strong>: حتى فريق التطبيق لا يقدر يقرأها، لأن مفتاح فك التشفير بيتولّد وبيفضل جوّه جهازك بس. لو مسحت بيانات المتصفح أو غيّرت جهازك من غير نسخة احتياطية، هتفقد قراءة محادثاتك الخاصة القديمة نهائيًا.</p>\n      <p><strong>4.2 تذكير الأدوية</strong><br>أداة تذكير بس، وليست أداة طبية، ولا تقدّم أي نصيحة أو تشخيص طبي. البيانات دي بتتخزن على جهازك انت بس ومش بتتبعت لأي سيرفر.</p>\n      <p><strong>5. مسؤوليتك ومسؤولية كبير العائلة</strong><br>بإنشائك عائلة في هذا التطبيق، تقر وتضمن أنك بلغت 18 عامًا على الأقل، وتصبح \"كبير العائلة\" ومسؤولًا عن إدارتها: قبول الأعضاء ورفضهم وحذفهم، والموافقة على طلبات الشات الخاص بين الأعضاء العاديين، وحذف أي محتوى مخالف. تقدر ترقّي عضو تاني تثق فيه ليبقى \"نائب كبير عائلة\" وله نفس الصلاحيات بالضبط - احتياطًا لو تعذّر عليك الدخول يومًا. أنت (وأي نائب رقّيته) تتحملون المسؤولية القانونية الكاملة عن أي محتوى أو سلوك داخل العائلة. التطبيق لا يتحقق من صلة القرابة أو الهوية، والمستخدم مسؤول مسؤولية كاملة عن دقة المعلومات التي يدخلها، والتطبيق غير مسؤول عن أي نزاع عائلي أو قانوني ناتج عن إدخال معلومات غير صحيحة.</p>\n      <p><strong>6. حذف البيانات والانسحاب النهائي</strong><br>تقدر تسحب موافقتك أو تطلب حذف حسابك في أي وقت. كبير العائلة (أو نائبه) هو اللي يقدر يحذف العائلة بالكامل نهائيًا من داخل التطبيق (تحقق ثانوي بكتابة كود العائلة وكلمة السر)، وده بيحذف فورًا كل بيانات العائلة (الشات، الأعضاء، المناسبات) من غير فترة سماح، ومفيش رجوع بعدها. بيتم الاحتفاظ بسجل حذف مبسّط (مين حذف ومتى) للأغراض القانونية فقط.</p>\n      <p><strong>7. لا ضمانات</strong><br>التطبيق أداة مساعدة للتواصل العائلي، ومش بديل عن جهات الطوارئ الرسمية (الشرطة، الإسعاف). في أي خطر حقيقي، تواصل فورًا مع الجهات الرسمية بجانب استخدام التطبيق.</p>\n      <p><strong>8. التعديلات</strong><br>ممكن يتم تحديث هذه الشروط من وقت لآخر لتحسين الخدمة أو الالتزام بمتطلبات قانونية، وهيتم إعلامك بأي تغيير جوهري.</p>\n    </div>\n    <button class=\"btn-primary\" id=\"termsCloseBtn\" style=\"margin-top:18px;\">فهمت، رجوع</button>\n  </div>\n</div>\n\n<!-- PRIVATE CHAT MODAL (شات خاص مشفر من طرف لطرف) -->\n<div id=\"privateChatModal\" class=\"modal-overlay hidden\">\n  <div class=\"modal\" style=\"max-height:88vh; display:flex; flex-direction:column;\">\n    <div style=\"display:flex; align-items:center; justify-content:space-between;\">\n      <h3 id=\"privateChatTitle\" style=\"margin:0;\">🔒 محادثة خاصة</h3>\n      <span id=\"privateChatCloseBtn\" style=\"cursor:pointer; font-size:20px; color:var(--muted);\">×</span>\n    </div>\n    <div id=\"privateChatDisclosure\" class=\"note-box\" style=\"font-size:12px; line-height:1.7; margin-top:10px;\">\n      🔒 المحادثة دي <strong>مشفّرة من طرف لطرف</strong>. حتى فريق التطبيق مش يقدر يقراها. لو مسحت بيانات المتصفح أو غيّرت جهازك، هتفقد إمكانية قراءة الرسايل القديمة.\n      <button class=\"btn-primary\" id=\"privateChatDisclosureOk\" style=\"margin-top:10px; width:100%;\">فهمت، ابدأ المحادثة</button>\n    </div>\n    <div id=\"privateChatBody\" class=\"hidden\" style=\"display:flex; flex-direction:column; flex:1; min-height:0;\">\n      <div id=\"privateChatContainer\" class=\"chat-container\" style=\"flex:1;\"></div>\n      <div class=\"chat-input-row\">\n        <input type=\"text\" id=\"privateChatInput\" placeholder=\"اكتب رسالة خاصة...\">\n        <button id=\"privateChatSendBtn\">إرسال</button>\n      </div>\n    </div>\n  </div>\n</div>\n\n<!-- TOAST CONTAINER -->\n<div id=\"toastContainer\" class=\"toast-container\"></div>\n\n<!-- CONFIRM MODAL (بدل confirm() الأصلية) -->\n<div id=\"confirmModal\" class=\"modal-overlay hidden\">\n  <div class=\"modal\">\n    <h3>تأكيد</h3>\n    <p id=\"confirmMessage\" style=\"color:var(--muted); font-size:14px; line-height:1.6; margin:10px 0 4px;\"></p>\n    <div style=\"display:flex; gap:10px; margin-top:16px;\">\n      <button class=\"btn-ghost\" id=\"confirmCancelBtn\" style=\"margin-top:0;\">إلغاء</button>\n      <button class=\"btn-primary\" id=\"confirmOkBtn\" style=\"margin-top:0;\">تأكيد</button>\n    </div>\n  </div>\n</div>\n\n<!-- APP LOADING OVERLAY (يظهر وقت أول تحميل بس) -->\n<div id=\"appLoadingOverlay\" class=\"app-loading hidden\">\n  <div class=\"app-loading-spinner\"></div>\n  <div class=\"app-loading-text\">جارِ التحميل...</div>\n</div>\n\n<style>\n  .chat-container {\n    display: flex;\n    flex-direction: column;\n    gap: 8px;\n    margin-bottom: 12px;\n    max-height: 60vh;\n    overflow-y: auto;\n    padding: 10px;\n    border-radius: 14px;\n    background: linear-gradient(180deg, var(--chat-me) 0%, var(--bg) 40%);\n  }\n  .chat-msg {\n    background: var(--chat-other);\n    border: 1px solid var(--line);\n    border-radius: 14px 14px 14px 4px;\n    padding: 8px 12px;\n    max-width: 78%;\n    align-self: flex-start;\n    box-shadow: 0 1px 3px rgba(0,0,0,0.06);\n  }\n  .chat-msg.me {\n    align-self: flex-end;\n    background: var(--chat-me);\n    border: none;\n    border-radius: 14px 14px 4px 14px;\n  }\n  .chat-msg .sender {\n    font-size: 11px;\n    color: var(--occasion);\n    font-weight: 600;\n    margin-bottom: 2px;\n    display: flex;\n    justify-content: space-between;\n    align-items: center;\n  }\n  .msg-delete-btn {\n    font-size: 12px;\n    color: var(--muted);\n    cursor: pointer;\n    padding: 2px 4px;\n  }\n  .msg-delete-btn:active { color: var(--sos); }\n  .msg-report-btn {\n    font-size: 12px;\n    color: var(--muted);\n    cursor: pointer;\n    padding: 2px 4px;\n  }\n  .msg-report-btn:active { color: var(--sos); }\n  .chat-msg .text {\n    font-size: 14px;\n    line-height: 1.5;\n    overflow-wrap: anywhere;\n    word-break: break-word;\n  }\n  .chat-msg .time {\n    font-size: 10px;\n    color: var(--muted);\n    margin-top: 3px;\n    text-align: left;\n    opacity: 0.8;\n  }\n  .chat-input-row {\n    display: flex;\n    gap: 8px;\n    margin-top: 6px;\n  }\n  .chat-input-row input {\n    flex: 1;\n    min-width: 0;\n    background: var(--bg);\n    border: 1px solid var(--line);\n    border-radius: 10px;\n    padding: 12px 14px;\n    color: var(--text);\n    font-family: inherit;\n    font-size: 16px;\n  }\n  .chat-input-row input:focus { outline: 1px solid var(--occasion); }\n  .chat-input-row button {\n    background: var(--chat-accent);\n    color: #FFFFFF;\n    border: none;\n    border-radius: 10px;\n    padding: 12px 18px;\n    font-family: 'Cairo', sans-serif;\n    font-weight: 700;\n    font-size: 14px;\n    cursor: pointer;\n    flex-shrink: 0;\n    white-space: nowrap;\n  }\n  .chat-input-row button:active { transform: scale(0.97); }\n  .chat-media-row { display: flex; gap: 8px; margin-bottom: 8px; }\n  .media-btn {\n    background: var(--chat-me); border: 1px solid var(--line); border-radius: 10px;\n    padding: 10px 14px; font-size: 17px; cursor: pointer;\n  }\n  .media-btn:active { transform: scale(0.94); }\n  .chat-msg img, .chat-msg video { width: 100%; max-height: 320px; object-fit: cover; border-radius: 8px; margin-top: 4px; display: block; }\n  .chat-msg audio { width: 100%; margin-top: 4px; }\n  .topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }\n  .topbar h1 { font-size: 22px; }\n  .topbar .fam-code {\n    font-size: 17px; font-weight: 900; font-family: 'Cairo', sans-serif;\n    color: var(--occasion); letter-spacing: 2px;\n    background: var(--card2); border: 1px solid var(--occasion);\n    border-radius: 8px; padding: 3px 10px; margin-top: 4px; display: inline-block;\n  }\n  .status-dot { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; color: var(--muted); }\n  .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--safe); }\n  .circle-row { display: flex; gap: 10px; overflow-x: auto; padding: 4px 0 16px; }\n  .avatar {\n    flex-shrink: 0; width: 54px; text-align: center; font-size: 11px; color: var(--muted);\n  }\n  .avatar .bubble {\n    width: 46px; height: 46px; border-radius: 50%; background: var(--card2);\n    border: 1.5px solid var(--line); display: flex; align-items: center; justify-content: center;\n    font-family: 'Cairo'; font-weight: 700; font-size: 15px; color: var(--text); margin: 0 auto 5px;\n  }\n  .avatar .bubble.parent { border-color: var(--occasion); }\n  .avatar .bubble.me { border-color: var(--safe); border-width: 2px; }\n  .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }\n  .action-btn {\n    border: none; border-radius: 16px; padding: 20px 14px; cursor: pointer;\n    display: flex; flex-direction: column; align-items: center; gap: 8px;\n    font-family: 'Cairo', sans-serif; font-weight: 700; font-size: 14px;\n  }\n  .action-btn .icon { font-size: 26px; }\n  .action-btn.sos { background: var(--sos); color: #fff; grid-column: 1 / -1; padding: 22px; }\n  .action-btn.safe { background: var(--safe-dim); color: var(--safe); border: 1px solid var(--safe); }\n  .action-btn.occasion { background: var(--occasion-dim); color: var(--occasion); border: 1px solid var(--occasion); }\n  .action-btn:active { transform: scale(0.97); }\n  .section-title { font-size: 15px; font-weight: 700; margin: 22px 0 10px 2px; color: var(--text); }\n  .feed-item {\n    background: var(--card); border-radius: 14px; padding: 14px 16px; margin-bottom: 10px;\n    border-right: 3px solid var(--line);\n  }\n  .feed-item.sos { border-right-color: var(--sos); }\n  .feed-item.safe { border-right-color: var(--safe); }\n  .feed-item.occasion { border-right-color: var(--occasion); }\n  .feed-item.join { border-right-color: var(--muted); }\n  .admin-badge { font-size: 10px; color: var(--occasion); border: 1px solid var(--occasion); border-radius: 6px; padding: 2px 6px; margin-right: 6px; }\n  .remove-btn { font-size: 11px; padding: 5px 10px; border-radius: 8px; border: 1px solid var(--sos); color: var(--sos); background: none; cursor: pointer; }\n  .feed-item .row1 { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; gap: 8px; }\n  .feed-item .when { display: inline-flex; align-items: center; gap: 6px; }\n  .feed-item .who { font-weight: 600; font-size: 14px; }\n  .feed-item .when { font-size: 11px; color: var(--muted); }\n  .feed-item .msg { font-size: 13.5px; color: var(--text); line-height: 1.6; }\n  .feed-item .loc-link { display: inline-block; margin-top: 8px; font-size: 12px; color: var(--occasion); text-decoration: none; }\n  .empty-feed { text-align: center; color: var(--muted); font-size: 13px; padding: 30px 0; }\n  .tabbar {\n    position: fixed; bottom: 0; left: 0; right: 0; background: var(--card);\n    border-top: 1px solid var(--line); display: flex; max-width: 480px; margin: 0 auto;\n  }\n  .tab {\n    flex: 1; text-align: center; padding: 12px 0 10px; color: var(--muted);\n    font-size: 12px; cursor: pointer; border: none; background: none; font-family: inherit;\n  }\n  .tab .icon { font-size: 18px; display: block; margin-bottom: 2px; }\n  .tab.active { color: var(--occasion); }\n  .modal-overlay {\n    position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex;\n    align-items: flex-end; z-index: 50;\n  }\n  .modal {\n    background: var(--card); width: 100%; max-width: 480px; margin: 0 auto;\n    border-radius: 20px 20px 0 0; padding: 22px 18px 28px;\n  }\n  .modal h3 { margin-bottom: 14px; }\n  textarea {\n    width: 100%; background: var(--bg); border: 1px solid var(--line); border-radius: 10px;\n    padding: 12px 14px; color: var(--text); font-family: inherit; font-size: 16px; min-height: 80px; resize: vertical;\n  }\n  .type-picker { display: flex; gap: 8px; margin-bottom: 14px; }\n  .type-pick {\n    flex: 1; padding: 10px; text-align: center; border-radius: 10px; border: 1px solid var(--line);\n    font-size: 13px; cursor: pointer; color: var(--muted);\n  }\n  .type-pick.sel-فرح.active { background: var(--occasion-dim); border-color: var(--occasion); color: var(--occasion); }\n  .type-pick.sel-عيد.active { background: #3A2A3E; border-color: #C58AD9; color: #C58AD9; }\n  .type-pick.sel-وفاة.active { background: #3A2E38; border-color: var(--muted); color: var(--text); }\n  .type-pick.sel-اخرى.active { background: #253238; border-color: #6FAECF; color: #6FAECF; }\n  .member-row {\n    display: flex; justify-content: space-between; align-items: center;\n    background: var(--card); border-radius: 12px; padding: 12px 14px; margin-bottom: 8px;\n  }\n  .member-row .info { display: flex; align-items: center; gap: 10px; }\n  .member-row .name { font-size: 14px; font-weight: 600; }\n  .member-row .rel { font-size: 11px; color: var(--muted); }\n  .trust-toggle {\n    font-size: 11px; padding: 5px 10px; border-radius: 8px; border: 1px solid var(--line);\n    color: var(--muted); cursor: pointer; background: none;\n  }\n  .trust-toggle.on { border-color: var(--safe); color: var(--safe); }\n  .note-box {\n    background: rgba(212,166,87,0.08); border: 1px solid rgba(212,166,87,0.25);\n    border-radius: 12px; padding: 12px 14px; font-size: 12px; color: var(--muted); line-height: 1.7; margin-top: 18px;\n  }\n  .hidden { display: none !important; }\n\n  /* ---- Admin panel (hidden control panel) ---- */\n  .admin-wrap { max-width: 480px; margin: 0 auto; padding: 20px 16px 60px; }\n  .admin-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }\n  .admin-header h2 { font-size: 20px; }\n  .admin-logout { font-size: 12px; color: var(--muted); background: none; border: 1px solid var(--line); border-radius: 8px; padding: 6px 10px; cursor: pointer; }\n  .admin-stats { display: grid; grid-template-columns: repeat(3,1fr); gap: 8px; margin-bottom: 22px; }\n  .admin-stat { background: var(--card); border-radius: 12px; padding: 12px 8px; text-align: center; }\n  .admin-stat .num { font-size: 20px; font-weight: 900; font-family: 'Cairo', sans-serif; color: var(--occasion); }\n  .admin-stat .lbl { font-size: 10.5px; color: var(--muted); margin-top: 2px; }\n  .admin-tabs { display: flex; gap: 8px; margin-bottom: 14px; }\n  .admin-tab-btn { flex: 1; padding: 9px; border-radius: 10px; border: 1px solid var(--line); background: none; color: var(--muted); font-family: inherit; font-size: 13px; cursor: pointer; }\n  .admin-tab-btn.active { background: var(--occasion-dim); border-color: var(--occasion); color: var(--occasion); }\n  .admin-fam-row { background: var(--card); border-radius: 12px; padding: 12px 14px; margin-bottom: 8px; cursor: pointer; }\n  .admin-fam-row .code { font-weight: 700; font-family: 'Cairo', sans-serif; letter-spacing: 2px; }\n  .admin-fam-row .meta { font-size: 11.5px; color: var(--muted); margin-top: 3px; }\n  .admin-back { font-size: 13px; color: var(--occasion); cursor: pointer; margin-bottom: 12px; display: inline-block; }\n  .admin-del-btn { font-size: 11px; padding: 5px 10px; border-radius: 8px; border: 1px solid var(--sos); color: var(--sos); background: none; cursor: pointer; }\n  .admin-login-box { text-align: center; padding-top: 40%; }\n  .admin-login-box input { text-align: center; letter-spacing: 2px; font-size: 16px; }\n  .admin-event-row { background: var(--card); border-radius: 12px; padding: 10px 14px; margin-bottom: 8px; font-size: 13px; }\n  .admin-event-row .code { color: var(--occasion); font-weight: 700; }\n\n  /* ---- Toasts ---- */\n  .toast-container {\n    position: fixed; top: 16px; left: 50%; transform: translateX(-50%);\n    z-index: 500; display: flex; flex-direction: column; gap: 8px;\n    width: 100%; max-width: 440px; padding: 0 16px; pointer-events: none;\n  }\n  .toast {\n    background: var(--text); color: #fff; padding: 12px 16px; border-radius: 12px;\n    font-size: 13.5px; box-shadow: 0 8px 22px rgba(0,0,0,0.18);\n    animation: toastIn 0.25s ease, toastOut 0.25s ease 2.6s forwards;\n    pointer-events: auto;\n  }\n  .toast.success { background: var(--safe); }\n  .toast.error { background: var(--sos); }\n  @keyframes toastIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }\n  @keyframes toastOut { to { opacity: 0; transform: translateY(-10px); } }\n\n  /* ---- Confirm modal danger variant ---- */\n  .btn-danger { background: var(--sos) !important; }\n\n  /* ---- App loading overlay ---- */\n  .app-loading {\n    position: fixed; inset: 0; background: var(--bg); z-index: 400;\n    display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 14px;\n  }\n  .app-loading-spinner {\n    width: 38px; height: 38px; border-radius: 50%;\n    border: 3px solid var(--line); border-top-color: var(--occasion);\n    animation: spin 0.8s linear infinite;\n  }\n  .app-loading-text { color: var(--muted); font-size: 13px; }\n  @keyframes spin { to { transform: rotate(360deg); } }\n\n  /* ---- Fade-in لعناصر الفيد والشات الجديدة ---- */\n  @keyframes fadeInUp { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }\n  .fade-in { animation: fadeInUp 0.3s ease; }\n\n  /* ---- لمسة احترافية إضافية: انتقالات ناعمة بين الشاشات ---- */\n  #loginScreen, #mainScreen, #createFamilyScreen {\n    animation: screenIn 0.25s ease;\n  }\n  @keyframes screenIn { from { opacity: 0; } to { opacity: 1; } }\n  .action-btn, .btn-primary, .btn-secondary, .tab-btn, .media-btn {\n    transition: transform 0.12s ease, opacity 0.12s ease;\n  }\n\n  /* ---- لوحة متابعة العائلة (للوالدين بس) ---- */\n  .overview-grid {\n    display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 20px;\n  }\n  .overview-card {\n    background: var(--card); border-radius: 14px; padding: 12px; display: flex; align-items: center; gap: 10px;\n    border: 1px solid var(--line);\n  }\n  .overview-card .status-icon { font-size: 20px; line-height: 1; }\n  .overview-card .ov-name { font-size: 13px; font-weight: 600; }\n  .overview-card .ov-status { font-size: 11px; color: var(--muted); margin-top: 2px; }\n  .overview-card.ov-sos { border-color: var(--sos); background: var(--sos-dim); }\n  .overview-card.ov-safe { border-color: var(--safe); background: var(--safe-dim); }\n\n  /* ---- شارة رسائل جديدة على تبويب الشات (زي واتساب) ---- */\n  .tab { position: relative; }\n  .tab-badge {\n    position: absolute; top: 4px; left: 50%; margin-left: 10px;\n    background: var(--sos); color: #fff; font-size: 9.5px; font-weight: 700;\n    min-width: 16px; height: 16px; border-radius: 8px; display: flex; align-items: center; justify-content: center;\n    padding: 0 3px;\n  }\n\n  /* ---- مفتاح تبديل الوضع الليلي ---- */\n  .dark-toggle-row {\n    display: flex; align-items: center; justify-content: space-between;\n    background: var(--card); border-radius: 14px; padding: 14px 16px; margin-bottom: 22px;\n  }\n  .switch {\n    width: 46px; height: 26px; border-radius: 20px; background: var(--line);\n    border: none; cursor: pointer; padding: 3px; position: relative; flex-shrink: 0;\n  }\n  .switch i {\n    display: block; width: 20px; height: 20px; border-radius: 50%; background: #fff;\n    box-shadow: 0 1px 3px rgba(0,0,0,0.2); transition: transform 0.2s ease;\n  }\n  .switch.on { background: var(--occasion); }\n  .switch.on i { transform: translateX(-20px); }\n</style>\n\n<script>\n// لازم تفضل مطابقة لنفس القائمة في worker.js (SECURITY_QUESTIONS)\nconst SECURITY_QUESTIONS = [\n  'ما اسم أول مدرسة التحقت بها؟',\n  'ما اسم الشارع اللي عشت فيه في طفولتك؟',\n  'ما اسم حيوانك الأليف الأول؟',\n  'ما اسم أقرب صديق ليك في المرحلة الابتدائية؟',\n  'في أي مدينة اتولدت؟',\n  'ما اسم والدتك قبل الزواج؟',\n];\nfunction fillSecurityQuestionSelect(selectEl) {\n  selectEl.innerHTML = '';\n  SECURITY_QUESTIONS.forEach(q => {\n    const opt = document.createElement('option');\n    opt.value = q; opt.textContent = q;\n    selectEl.appendChild(opt);\n  });\n}\n\nlet familyCode = null;\nlet myId = null;\nlet sessionToken = null;\nlet familyData = null;\nlet eventsData = [];\nlet chatMessages = [];\nlet selectedOccasionType = 'فرح';\nlet pollTimer = null;\n\nconst $ = id => document.getElementById(id);\nconst show = el => el.classList.remove('hidden');\nconst hide = el => el.classList.add('hidden');\n\nfunction genId() { return 'm_' + Math.random().toString(36).slice(2,10); }\nfunction initials(name) { return name.trim().split(' ').map(w=>w[0]).slice(0,2).join(''); }\nfunction timeAgo(ts) {\n  const diff = Math.floor((Date.now() - ts) / 1000);\n  if (diff < 60) return 'الآن';\n  if (diff < 3600) return Math.floor(diff/60) + ' د';\n  if (diff < 86400) return Math.floor(diff/3600) + ' س';\n  return Math.floor(diff/86400) + ' يوم';\n}\nfunction formatTime(ts) {\n  const d = new Date(ts);\n  return d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0');\n}\n\n// ---------- حماية من XSS: أي نص جاي من مستخدم (اسم، رسالة، تفاصيل...) لازم يتنضف قبل ما يتحط في الصفحة ----------\nfunction escapeHtml(str) {\n  if (str === null || str === undefined) return '';\n  return String(str)\n    .replace(/&/g, '&amp;')\n    .replace(/</g, '&lt;')\n    .replace(/>/g, '&gt;')\n    .replace(/\"/g, '&quot;')\n    .replace(/'/g, '&#39;');\n}\n\n// ---------- Toasts (بدل alert() القديمة) ----------\nfunction showToast(message, type) {\n  const container = $('toastContainer');\n  if (!container) { console.log(message); return; }\n  const el = document.createElement('div');\n  el.className = 'toast' + (type ? ' ' + type : '');\n  el.textContent = message;\n  container.appendChild(el);\n  setTimeout(() => el.remove(), 3000);\n}\n\n// ---------- Confirm مودال بدل confirm() الأصلية بتاعة المتصفح ----------\nfunction showConfirm(message, opts) {\n  opts = opts || {};\n  return new Promise(resolve => {\n    $('confirmMessage').textContent = message;\n    const okBtn = $('confirmOkBtn');\n    okBtn.textContent = opts.okText || 'تأكيد';\n    okBtn.classList.toggle('btn-danger', !!opts.danger);\n    show($('confirmModal'));\n    const cleanup = (result) => {\n      hide($('confirmModal'));\n      okBtn.onclick = null;\n      $('confirmCancelBtn').onclick = null;\n      resolve(result);\n    };\n    okBtn.onclick = () => cleanup(true);\n    $('confirmCancelBtn').onclick = () => cleanup(false);\n  });\n}\n\n// ---------- Storage (Cloudflare Worker API) ----------\n// غيّر السطر ده لرابط الـ Worker بتاعك بعد النشر (وردة عليها .workers.dev)\nconst API_BASE = 'https://amanaleilah.aktyaraty.workers.dev';\n\n// ---------- تسجيل الدخول الدائم (زي واتساب - يفضل مسجل لحد ما يعمل تسجيل خروج بنفسه) ----------\nconst SESSION_KEY = 'amanaleilah_session';\nfunction savePersistedSession() {\n  try { localStorage.setItem(SESSION_KEY, JSON.stringify({ familyCode, myId, sessionToken })); } catch(e) {}\n}\nfunction loadPersistedSession() {\n  try {\n    const raw = localStorage.getItem(SESSION_KEY);\n    if (!raw) return null;\n    return JSON.parse(raw);\n  } catch(e) { return null; }\n}\nfunction clearPersistedSession() {\n  try { localStorage.removeItem(SESSION_KEY); } catch(e) {}\n}\n\nasync function apiCall(path, options) {\n  const headers = { 'Content-Type': 'application/json' };\n  if (sessionToken) headers['x-session-token'] = sessionToken;\n  const res = await fetch(API_BASE + path, {\n    headers,\n    ...options,\n  });\n  const data = await res.json().catch(() => ({}));\n  if (!res.ok) throw new Error(data.error || 'حصل خطأ في الاتصال بالسيرفر');\n  return data;\n}\n\n// ================= تشفير الشات الخاص من طرف لطرف (E2E) =================\n// مفتاحك الخاص بيتولّد جوّه المتصفح وبيتخزن محليًا بس (localStorage) - مبيتبعتش للسيرفر خالص.\n// لو اتمسحت بيانات المتصفح، هيتولّد مفتاح جديد ومش هيقدر يفك تشفير الرسايل القديمة (تريد-أوف طبيعي في التشفير الحقيقي).\nfunction bytesToB64(bytes) {\n  let str = '';\n  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);\n  return btoa(str);\n}\nfunction b64ToBytes(b64) {\n  const bin = atob(b64);\n  const arr = new Uint8Array(bin.length);\n  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);\n  return arr;\n}\nlet _myPrivateKeyCache = null;\nasync function ensureMyKeyPair(serverKnownPublicKey) {\n  const existingJwk = localStorage.getItem('e2e_priv_' + myId);\n  const existingPub = localStorage.getItem('e2e_pub_' + myId);\n  if (existingJwk && existingPub) {\n    // لو المفتاح موجود عندنا محليًا بس السيرفر مش شايفه (يمكن أول محاولة رفع فشلت بسبب نت ضعيف)،\n    // نعيد رفعه تاني - ده بيخلي المفتاح \"يصلح نفسه\" لوحده أول ما يبقى فيه نت من غير ما نولّد مفتاح جديد\n    if (serverKnownPublicKey !== existingPub) {\n      try {\n        await apiCall('/api/member/' + familyCode + '/' + myId + '/publickey', {\n          method: 'POST', body: JSON.stringify({ publicKey: existingPub }),\n        });\n      } catch (e) { console.error('publickey re-upload failed:', e); }\n    }\n    return existingPub;\n  }\n  const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);\n  const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);\n  const pubRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);\n  const pubB64 = bytesToB64(new Uint8Array(pubRaw));\n  localStorage.setItem('e2e_priv_' + myId, JSON.stringify(privJwk));\n  localStorage.setItem('e2e_pub_' + myId, pubB64);\n  _myPrivateKeyCache = null;\n  try {\n    await apiCall('/api/member/' + familyCode + '/' + myId + '/publickey', {\n      method: 'POST', body: JSON.stringify({ publicKey: pubB64 }),\n    });\n  } catch (e) { console.error('publickey upload failed:', e); }\n  return pubB64;\n}\nasync function getMyPrivateKey() {\n  if (_myPrivateKeyCache) return _myPrivateKeyCache;\n  const jwk = JSON.parse(localStorage.getItem('e2e_priv_' + myId));\n  _myPrivateKeyCache = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);\n  return _myPrivateKeyCache;\n}\nasync function deriveSharedKey(otherPublicKeyB64) {\n  const myPriv = await getMyPrivateKey();\n  const otherPubKey = await crypto.subtle.importKey(\n    'raw', b64ToBytes(otherPublicKeyB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []\n  );\n  return crypto.subtle.deriveKey(\n    { name: 'ECDH', public: otherPubKey }, myPriv, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']\n  );\n}\nasync function encryptPrivateText(text, otherPublicKeyB64) {\n  const key = await deriveSharedKey(otherPublicKeyB64);\n  const iv = crypto.getRandomValues(new Uint8Array(12));\n  const enc = new TextEncoder().encode(text);\n  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc));\n  return { ciphertext: bytesToB64(ciphertext), iv: bytesToB64(iv) };\n}\nasync function decryptPrivateText(ciphertextB64, ivB64, otherPublicKeyB64) {\n  try {\n    const key = await deriveSharedKey(otherPublicKeyB64);\n    const iv = b64ToBytes(ivB64);\n    const ciphertext = b64ToBytes(ciphertextB64);\n    const plainBytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);\n    return new TextDecoder().decode(plainBytes);\n  } catch (e) {\n    return '⚠️ (تعذّر فك تشفير الرسالة دي - يمكن اتبعتت من جهاز/مفتاح مختلف)';\n  }\n}\n\nasync function loadFamily(code) {\n  try {\n    const data = await apiCall('/api/family/' + code, { method: 'GET' });\n    return data.family || null;\n  } catch(e) {\n    console.error('loadFamily failed:', e.message); // تسجيل في الـ Console عشان أي مشكلة تبان بدل ما تختفي بصمت\n    return null;\n  }\n}\n\nasync function saveEvent(code, evt) {\n  return await apiCall('/api/events/' + code, { method: 'POST', body: JSON.stringify(evt) });\n}\n\nasync function loadEvents(code, limit) {\n  limit = limit || 60;\n  try {\n    const data = await apiCall('/api/events/' + code + '?limit=' + limit, { method: 'GET' });\n    return data.events || [];\n  } catch(e) { return []; }\n}\n\nasync function saveChatMsg(code, msg) {\n  await apiCall('/api/chat/' + code, {\n    method: 'POST',\n    body: JSON.stringify({ senderId: msg.senderId, senderName: msg.senderName, text: msg.text }),\n  });\n}\n\nasync function loadChat(code, limit) {\n  limit = limit || 100;\n  try {\n    const data = await apiCall('/api/chat/' + code + '?limit=' + limit, { method: 'GET' });\n    return data.messages || [];\n  } catch(e) { return []; }\n}\n\n// ---------- تحديثات فورية (delta): بنجيب بس الأحداث/الرسايل الجديدة بعد آخر وقت عندنا ----------\n// (بدل ما نجيب كل الداتا تاني كل شوية، ده بيقلل الحمل على السيرفر وبيخلي التحديث أسرع)\nasync function loadEventsSince(code, sinceTs) {\n  try {\n    const data = await apiCall('/api/events/' + code + '?since=' + sinceTs, { method: 'GET' });\n    return data.events || [];\n  } catch(e) { return []; }\n}\nasync function loadChatSince(code, sinceTs) {\n  try {\n    const data = await apiCall('/api/chat/' + code + '?since=' + sinceTs, { method: 'GET' });\n    return data.messages || [];\n  } catch(e) { return []; }\n}\n\nasync function uploadChatMedia(code, payload) {\n  // payload: { senderId, senderName, mediaType, base64 (data URL), ext, contentType }\n  return apiCall('/api/chat/' + code + '/media', { method: 'POST', body: JSON.stringify(payload) });\n}\n\n// تفضيلات الصوت شخصية للجهاز - بتتخزن محليًا في المتصفح بتاع كل جهاز\n// (مش محتاجة تتشارك مع باقي العيلة، فمفيش داعي للسيرفر هنا)\nasync function loadSoundPrefs() {\n  try {\n    const raw = document.cookie.split('; ').find(r => r.startsWith('soundPrefs='));\n    if (raw) return JSON.parse(decodeURIComponent(raw.split('=')[1]));\n  } catch(e) {}\n  return { sosTone: 'siren', safeTone: 'chime', customSos: null, customSafe: null };\n}\nasync function saveSoundPrefs(prefs) {\n  try {\n    document.cookie = 'soundPrefs=' + encodeURIComponent(JSON.stringify(prefs)) + '; max-age=31536000; path=/';\n  } catch(e) {}\n}\n\nasync function pushEvent(evt) {\n  const result = await saveEvent(familyCode, evt);\n  eventsData = await loadEvents(familyCode);\n  renderFeed();\n  return result;\n}\n\nasync function pushChatMessage(msg) {\n  await saveChatMsg(familyCode, msg);\n  chatMessages = await loadChat(familyCode);\n  renderChat();\n}\n\n\n// موقع دقيق: بيطلب أعلى دقة ممكنة من الـ GPS، وبيرجع نصف قطر الخطأ بالمتر\n// (مهم وقت الطوارئ - الموقع العادي ممكن يكون غلطه مئات الأمتار، ده بيحاول يقلل الفرق)\nfunction getLocation(highAccuracy) {\n  return new Promise(resolve => {\n    if (!navigator.geolocation) return resolve(null);\n    navigator.geolocation.getCurrentPosition(\n      pos => resolve({\n        lat: pos.coords.latitude,\n        lng: pos.coords.longitude,\n        accuracy: Math.round(pos.coords.accuracy)\n      }),\n      () => resolve(null),\n      highAccuracy\n        ? { enableHighAccuracy: true, maximumAge: 0, timeout: 15000 }\n        : { enableHighAccuracy: false, maximumAge: 30000, timeout: 8000 }\n    );\n  });\n}\n\nlet soundPrefs = { sosTone: 'siren', safeTone: 'chime', customSos: null, customSafe: null };\n\n// ---------- ثيمات ألوان الشات (زي واتساب - كل شخص يختار اللي يعجبه على جهازه) ----------\nconst CHAT_THEMES = {\n  rose:     { me: '#FBD8E8', other: '#FFFFFF', accent: '#D8779C' },\n  lavender: { me: '#E7DBFB', other: '#FFFFFF', accent: '#9B6FDE' },\n  peach:    { me: '#FFE3D2', other: '#FFFFFF', accent: '#E8905E' },\n  mint:     { me: '#D9F3E4', other: '#FFFFFF', accent: '#3FAE79' },\n  sky:      { me: '#D8ECFB', other: '#FFFFFF', accent: '#3E9FE0' },\n  gold:     { me: '#FBEAC6', other: '#FFFFFF', accent: '#C99A3E' },\n};\n\nfunction applyChatTheme(themeKey) {\n  const t = CHAT_THEMES[themeKey] || CHAT_THEMES.rose;\n  document.documentElement.style.setProperty('--chat-me', t.me);\n  document.documentElement.style.setProperty('--chat-other', t.other);\n  document.documentElement.style.setProperty('--chat-accent', t.accent);\n}\n\nfunction loadChatTheme() {\n  try {\n    const raw = document.cookie.split('; ').find(r => r.startsWith('chatTheme='));\n    if (raw) return decodeURIComponent(raw.split('=')[1]);\n  } catch(e) {}\n  return 'rose';\n}\nfunction saveChatTheme(themeKey) {\n  try { document.cookie = 'chatTheme=' + encodeURIComponent(themeKey) + '; max-age=31536000; path=/'; } catch(e) {}\n}\n\n// ---------- الوضع الليلي (يتخزن على الجهاز ده بس، زي أي تطبيق كبير) ----------\nfunction loadDarkMode() {\n  try { return localStorage.getItem('amanaleilah_dark') === '1'; } catch(e) { return false; }\n}\nfunction saveDarkMode(on) {\n  try { localStorage.setItem('amanaleilah_dark', on ? '1' : '0'); } catch(e) {}\n}\nfunction applyDarkMode(on) {\n  document.body.classList.toggle('dark', on);\n  $('darkModeToggle').classList.toggle('on', on);\n  document.querySelector('meta[name=\"theme-color\"]').setAttribute('content', on ? '#14101F' : '#6d28d9');\n}\n$('darkModeToggle').onclick = () => {\n  const on = !document.body.classList.contains('dark');\n  applyDarkMode(on);\n  saveDarkMode(on);\n};\n\n// أنماط الإنذار المدمجة - مختلفة تمامًا عن بعض عشان محدش يلخبط بينهم\nconst ALERT_TONES = {\n  siren:  { freqs: [660, 880], pattern: 'wail', reps: 4, gain: 0.35 },\n  klaxon: { freqs: [440], pattern: 'pulse', reps: 6, gain: 0.35 },\n  bell:   { freqs: [1046, 784], pattern: 'ring', reps: 3, gain: 0.3 },\n  chime:  { freqs: [523, 659, 784], pattern: 'chime', reps: 1, gain: 0.2 },\n  soft:   { freqs: [392], pattern: 'soft', reps: 2, gain: 0.15 }\n};\n\nfunction playTone(ctx, freq, start, dur, gainVal, type) {\n  const osc = ctx.createOscillator();\n  const gain = ctx.createGain();\n  osc.type = type || 'sine';\n  osc.frequency.value = freq;\n  gain.gain.setValueAtTime(0.0001, start);\n  gain.gain.linearRampToValueAtTime(gainVal, start + 0.03);\n  gain.gain.exponentialRampToValueAtTime(0.001, start + dur);\n  osc.connect(gain); gain.connect(ctx.destination);\n  osc.start(start); osc.stop(start + dur + 0.02);\n}\n\nfunction playBuiltInTone(toneKey) {\n  const tone = ALERT_TONES[toneKey] || ALERT_TONES.siren;\n  try {\n    const ctx = new (window.AudioContext || window.webkitAudioContext)();\n    const now = ctx.currentTime;\n    let t = 0;\n    for (let r = 0; r < tone.reps; r++) {\n      if (tone.pattern === 'wail') {\n        playTone(ctx, tone.freqs[0], now + t, 0.35, tone.gain, 'sawtooth');\n        playTone(ctx, tone.freqs[1], now + t + 0.35, 0.35, tone.gain, 'sawtooth');\n        t += 0.75;\n      } else if (tone.pattern === 'pulse') {\n        playTone(ctx, tone.freqs[0], now + t, 0.18, tone.gain, 'square');\n        t += 0.32;\n      } else if (tone.pattern === 'ring') {\n        playTone(ctx, tone.freqs[0], now + t, 0.4, tone.gain, 'triangle');\n        playTone(ctx, tone.freqs[1], now + t + 0.15, 0.35, tone.gain*0.8, 'triangle');\n        t += 0.7;\n      } else if (tone.pattern === 'chime') {\n        tone.freqs.forEach((f, i) => playTone(ctx, f, now + t + i*0.12, 0.5, tone.gain, 'sine'));\n        t += 0.6;\n      } else {\n        playTone(ctx, tone.freqs[0], now + t, 0.5, tone.gain, 'sine');\n        t += 0.7;\n      }\n    }\n  } catch(e) {}\n}\n\n// ---------- إنذار الاستغاثة المتكرر: بانر ثابت + صوت متكرر كل 30 ثانية لحد ما حد يضغط \"تم الاطلاع\" ----------\n// (السيرفر كمان بيبعت Push متكرر كل 30 ثانية لحد 10 دقايق حتى لو التطبيق مقفول، عن طريق Durable Object)\nconst dismissedSosIds = new Set(); // بتتصفّر لو عملت refresh للصفحة - مقصود، مش عيب\nlet activeSosSoundTimer = null;\nfunction checkActiveSos() {\n  if (!eventsData || !eventsData.length) return;\n  const TEN_MIN = 10 * 60 * 1000;\n  const now = Date.now();\n  const activeSos = eventsData.find(ev =>\n    ev.type === 'sos' && ev.memberId !== myId &&\n    (now - ev.timestamp) < TEN_MIN && !dismissedSosIds.has(ev.id)\n  );\n  if (activeSos) {\n    $('activeSosText').textContent = '🆘 ' + escapeHtml(activeSos.memberName) + ' محتاج مساعدة الآن';\n    $('ackSosBtn').dataset.sosId = activeSos.id;\n    show($('activeSosBanner'));\n    if (!activeSosSoundTimer) {\n      activeSosSoundTimer = setInterval(() => { if (!document.hidden) playAlertSound('sos'); }, 30000);\n    }\n  } else {\n    hide($('activeSosBanner'));\n    if (activeSosSoundTimer) { clearInterval(activeSosSoundTimer); activeSosSoundTimer = null; }\n  }\n}\n$('ackSosBtn').onclick = async () => {\n  const sosId = $('ackSosBtn').dataset.sosId;\n  if (sosId) {\n    dismissedSosIds.add(sosId);\n    try { await apiCall('/api/events/' + familyCode + '/' + sosId + '/acknowledge', { method: 'POST' }); } catch (e) {}\n  }\n  checkActiveSos();\n  showToast('تمام، هيوقف التنبيه المتكرر', 'success');\n};\n\nfunction playAlertSound(kind) {\n  // kind: 'sos' أو 'safe' - كل واحد بياخد الصوت والاهتزاز المناسب له من تفضيلات الجهاز ده\n  const customUrl = kind === 'sos' ? soundPrefs.customSos : soundPrefs.customSafe;\n  const tone = kind === 'sos' ? soundPrefs.sosTone : soundPrefs.safeTone;\n\n  if (customUrl) {\n    try {\n      const audio = new Audio(customUrl);\n      audio.volume = 1.0;\n      if (kind === 'sos') {\n        let plays = 0;\n        audio.onended = () => { plays++; if (plays < 3) audio.play().catch(()=>{}); };\n      }\n      audio.play().catch(() => playBuiltInTone(tone));\n    } catch(e) { playBuiltInTone(tone); }\n  } else {\n    playBuiltInTone(tone);\n  }\n\n  // اهتزاز - شغال على أندرويد، آيفون مش بيدعمه في المتصفح\n  if (navigator.vibrate) {\n    navigator.vibrate(kind === 'sos' ? [400,150,400,150,400,150,400] : [120,80,120]);\n  }\n}\n\n// ---------- شروط الاستخدام ----------\ndocument.querySelectorAll('[data-open-terms]').forEach(el => {\n  el.addEventListener('click', () => show($('termsModal')));\n});\n$('termsCloseBtn').onclick = () => hide($('termsModal'));\n\n// ---------- Tabs ----------\n$('loginTabBtn').onclick = () => {\n  $('loginTabBtn').classList.add('active');\n  $('registerTabBtn').classList.remove('active');\n  show($('loginTabContent'));\n  hide($('registerTabContent'));\n};\n$('registerTabBtn').onclick = () => {\n  $('registerTabBtn').classList.add('active');\n  $('loginTabBtn').classList.remove('active');\n  hide($('loginTabContent'));\n  show($('registerTabContent'));\n};\n\n// ---------- Login (Existing Member) - كود العائلة + الاسم + كلمة السر مباشرة، من غير قايمة أسامي ----------\n$('loginSubmit').onclick = async () => {\n  const code = $('loginCode').value.trim().toUpperCase();\n  const password = $('loginPin').value;\n\n  if (!code || !password) {\n    showToast('اكتب كود العائلة وكلمة السر', 'error');\n    return;\n  }\n\n  const btn = $('loginSubmit');\n  const originalText = btn.textContent;\n  btn.disabled = true;\n  btn.textContent = 'جاري الدخول...';\n  hide($('loginError'));\n\n  try {\n    const result = await apiCall('/api/family/login', {\n      method: 'POST',\n      body: JSON.stringify({ code, password }),\n    });\n\n    familyCode = code;\n    myId = result.myId;\n    sessionToken = result.sessionToken || null;\n    familyData = result.family;\n    savePersistedSession();\n\n    hide($('loginScreen'));\n    await startApp();\n  } catch (err) {\n    console.error('loginSubmit error:', err);\n    const code2 = err && err.message;\n    const friendly = code2 === 'pending_approval'\n      ? 'لسه طلبك عند كبير العائلة محتاج موافقة، جرب تاني بعد ما يوافق عليك'\n      : (code2 || 'حصل خطأ، جرب تاني.');\n    $('loginError').textContent = '⚠️ ' + friendly;\n    show($('loginError'));\n  } finally {\n    btn.disabled = false;\n    btn.textContent = originalText;\n  }\n};\n\n// ---------- استرجاع كلمة السر بسؤال الأمان (لأي عضو) ----------\n$('openAdminRecoveryLink').onclick = () => {\n  hide($('loginTabContent'));\n  hide($('registerTabContent'));\n  document.querySelector('.tabs-row').classList.add('hidden');\n  hide($('createFamilyBtn'));\n  $('recoveryCode2').value = $('loginCode').value.trim().toUpperCase();\n  $('recoveryNameInput').value = '';\n  show($('recoveryStep1'));\n  hide($('recoveryStep3'));\n  show($('adminRecoveryBox'));\n};\n$('closeAdminRecovery').onclick = () => {\n  hide($('adminRecoveryBox'));\n  document.querySelector('.tabs-row').classList.remove('hidden');\n  show($('createFamilyBtn'));\n  show($('loginTabContent'));\n};\n\nlet recoveryCodeCache = '', recoveryNameCache = '';\n$('recoveryFindMemberBtn').onclick = async () => {\n  const code = $('recoveryCode2').value.trim().toUpperCase();\n  const name = $('recoveryNameInput').value.trim();\n  hide($('recoveryStep1Error'));\n  if (!code || !name) { $('recoveryStep1Error').textContent = 'اكتب كود العائلة واسمك'; show($('recoveryStep1Error')); return; }\n  try {\n    const result = await apiCall('/api/family/security-question?code=' + encodeURIComponent(code) + '&name=' + encodeURIComponent(name));\n    recoveryCodeCache = code; recoveryNameCache = name;\n    $('recoveryQuestionLabel').textContent = '❓ ' + result.question1;\n    $('recoveryQuestionLabel2').textContent = '❓ ' + result.question2;\n    $('recoveryAnswer').value = '';\n    $('recoveryAnswer2').value = '';\n    $('recoveryNewPin').value = '';\n    hide($('recoveryStep1'));\n    show($('recoveryStep3'));\n  } catch (e) {\n    $('recoveryStep1Error').textContent = '⚠️ ' + (e.message || 'حصل خطأ');\n    show($('recoveryStep1Error'));\n  }\n};\n$('recoveryBackToMember').onclick = () => { hide($('recoveryStep3')); show($('recoveryStep1')); };\n\n$('recoverySubmitBtn').onclick = async () => {\n  const answer1 = $('recoveryAnswer').value.trim();\n  const answer2 = $('recoveryAnswer2').value.trim();\n  const newPassword = $('recoveryNewPin').value;\n  if (!answer1 || !answer2 || !newPassword) { showToast('من فضلك اكمل كل البيانات', 'error'); return; }\n  if (newPassword.length < 6) { showToast('كلمة السر الجديدة لازم تكون 6 حروف أو أرقام على الأقل', 'error'); return; }\n  hide($('recoveryError'));\n  const btn = $('recoverySubmitBtn');\n  const originalText = btn.textContent;\n  btn.disabled = true; btn.textContent = 'جاري الاسترجاع...';\n  try {\n    await apiCall('/api/family/verify-security-answer', {\n      method: 'POST',\n      body: JSON.stringify({ code: recoveryCodeCache, name: recoveryNameCache, answer1, answer2, newPassword }),\n    });\n    showToast('تم استرجاع كلمة السر! سجّل دخول بيها دلوقتي', 'success');\n    $('closeAdminRecovery').click();\n  } catch (e) {\n    $('recoveryError').textContent = '⚠️ ' + (e.message || 'حصل خطأ');\n    show($('recoveryError'));\n  } finally {\n    btn.disabled = false; btn.textContent = originalText;\n  }\n};\n\n// ---------- Register (New Member) ----------\nfillSecurityQuestionSelect($('registerSecurityQuestion'));\nfillSecurityQuestionSelect($('registerSecurityQuestion2'));\n$('registerSubmit').onclick = async () => {\n  const code = $('registerCode').value.trim().toUpperCase();\n  const name = $('registerName').value.trim();\n  const relation = $('registerRelation').value;\n  const password = $('registerPin').value;\n  const securityQuestion1 = $('registerSecurityQuestion').value;\n  const securityAnswer1 = $('registerSecurityAnswer').value.trim();\n  const securityQuestion2 = $('registerSecurityQuestion2').value;\n  const securityAnswer2 = $('registerSecurityAnswer2').value.trim();\n\n  if (!code || !name || !password || !securityAnswer1 || !securityAnswer2) {\n    showToast('من فضلك اكمل كل البيانات', 'error');\n    return;\n  }\n  if (password.length < 6) {\n    showToast('كلمة السر لازم تكون 6 حروف أو أرقام على الأقل', 'error');\n    return;\n  }\n  if (securityQuestion1 === securityQuestion2) {\n    showToast('اختار سؤالي أمان مختلفين عن بعض', 'error');\n    return;\n  }\n  if (!$('registerAgeConfirm').checked) {\n    showToast('لازم تأكد إنك بلغت 18 سنة على الأقل عشان تنضم', 'error');\n    return;\n  }\n  if (!$('registerConsent').checked) {\n    showToast('لازم توافق على شروط استخدام بياناتك الأول', 'error');\n    return;\n  }\n\n  const btn = $('registerSubmit');\n  const originalText = btn.textContent;\n  btn.disabled = true;\n  btn.textContent = 'جاري التسجيل...';\n  hide($('registerError'));\n\n  try {\n    await apiCall('/api/family/register', {\n      method: 'POST',\n      body: JSON.stringify({ code, name, relation, consent: true, ageConfirm: true, password, securityQuestion1, securityAnswer1, securityQuestion2, securityAnswer2 }),\n    });\n\n    // العضو الجديد بيفضل \"معلّق\" لحد ما كبير العائلة يوافق عليه صراحة (مش بيدخل التطبيق فورًا)\n    hide($('registerTabContent'));\n    show($('registerPendingBox'));\n  } catch (err) {\n    console.error('registerSubmit error:', err);\n    $('registerError').textContent = '⚠️ ' + (err && err.message ? err.message : 'حصل خطأ في الاتصال، جرب تاني.');\n    show($('registerError'));\n  } finally {\n    btn.disabled = false;\n    btn.textContent = originalText;\n  }\n};\n\n$('registerPendingBackBtn').onclick = () => {\n  hide($('registerPendingBox'));\n  show($('registerTabContent'));\n  $('loginTabBtn').click();\n};\n\n// ---------- Create Family ----------\nfillSecurityQuestionSelect($('newFamilySecurityQuestion'));\nfillSecurityQuestionSelect($('newFamilySecurityQuestion2'));\n$('createFamilyBtn').onclick = () => {\n  hide($('loginScreen'));\n  show($('createFamilyScreen'));\n  $('newFamilyCode').textContent = 'هيظهر بعد الإنشاء';\n};\n\n$('backFromCreateFamily').onclick = () => {\n  hide($('createFamilyScreen'));\n  show($('loginScreen'));\n};\n\n$('createFamilySubmit').onclick = async () => {\n  const name = $('newFamilyName').value.trim();\n  const relation = $('newFamilyRelation').value;\n  const password = $('newFamilyPin').value;\n  const securityQuestion1 = $('newFamilySecurityQuestion').value;\n  const securityAnswer1 = $('newFamilySecurityAnswer').value.trim();\n  const securityQuestion2 = $('newFamilySecurityQuestion2').value;\n  const securityAnswer2 = $('newFamilySecurityAnswer2').value.trim();\n\n  if (!name || !password || !securityAnswer1 || !securityAnswer2) {\n    showToast('من فضلك اكمل كل البيانات', 'error');\n    return;\n  }\n  if (password.length < 6) {\n    showToast('كلمة السر لازم تكون 6 حروف أو أرقام على الأقل', 'error');\n    return;\n  }\n  if (securityQuestion1 === securityQuestion2) {\n    showToast('اختار سؤالي أمان مختلفين عن بعض', 'error');\n    return;\n  }\n  if (!$('createAgeConfirm').checked) {\n    showToast('لازم تأكد إنك بلغت 18 سنة على الأقل عشان تنشئ عائلة', 'error');\n    return;\n  }\n  if (!$('createConsent').checked) {\n    showToast('لازم توافق على شروط استخدام بياناتك الأول', 'error');\n    return;\n  }\n  if (!$('createResponsibility').checked) {\n    showToast('لازم تأكد إنك المسؤول عن إدارة العائلة الأول', 'error');\n    return;\n  }\n\n  const btn = $('createFamilySubmit');\n  const originalText = btn.textContent;\n  btn.disabled = true;\n  btn.textContent = 'جاري الإنشاء...';\n  hide($('createFamilyError'));\n\n  try {\n    const result = await apiCall('/api/family/create', {\n      method: 'POST',\n      body: JSON.stringify({ name, relation, consent: true, ageConfirm: true, password, securityQuestion1, securityAnswer1, securityQuestion2, securityAnswer2 }),\n    });\n\n    familyCode = result.family.code;\n    myId = result.myId;\n    sessionToken = result.sessionToken || null;\n    familyData = result.family;\n    savePersistedSession();\n    $('newFamilyCode').textContent = familyCode;\n\n    hide($('createFamilyScreen'));\n    await startApp();\n  } catch (err) {\n    console.error('createFamilySubmit error:', err);\n    $('createFamilyError').textContent = '⚠️ ' + (err && err.message ? err.message : 'حصل خطأ في الاتصال، جرب تاني كمان شوية.');\n    show($('createFamilyError'));\n  } finally {\n    btn.disabled = false;\n    btn.textContent = originalText;\n  }\n};\n\n// ---------- Main App ----------\nasync function startApp() {\n  show($('appLoadingOverlay'));\n  familyData = await loadFamily(familyCode);\n  eventsData = await loadEvents(familyCode);\n  chatMessages = await loadChat(familyCode);\n  soundPrefs = await loadSoundPrefs();\n  applyChatTheme(loadChatTheme());\n  if (!familyData) {\n    hide($('appLoadingOverlay'));\n    clearPersistedSession();\n    show($('loginScreen'));\n    showToast('حصلت مشكلة في تحميل بيانات عائلتك - جرب تحدّث الصفحة (Ctrl+Shift+R) وتدخل تاني', 'error');\n    return;\n  }\n  \n  const me = familyData.members.find(m => m.id === myId);\n  if (!me) { hide($('appLoadingOverlay')); clearPersistedSession(); familyCode = null; myId = null; show($('loginScreen')); return; }\n  $('greeting').textContent = 'أهلاً، ' + (me ? me.name.split(' ')[0] : '');\n  $('famCodeSmall').textContent = familyCode;\n  if (me && me.isAdmin) { show($('deleteFamilyBtn')); hide($('deleteMyAccountBtn')); }\n  else { hide($('deleteFamilyBtn')); show($('deleteMyAccountBtn')); }\n  ensureMyKeyPair(me ? me.publicKey : null).then(pubKey => {\n    if (me && me.publicKey !== pubKey) me.publicKey = pubKey; // متزامن محليًا لو المفتاح اتولّد لأول مرة\n  }).catch(e => console.error('key setup failed:', e));\n  \n  show($('mainScreen'));\n  hide($('appLoadingOverlay'));\n  await refreshMyBlockedIds();\n  await refreshPendingDeletionBanner();\n  renderCircle();\n  renderOverview();\n  renderFeed();\n  renderMembers();\n  renderChat();\n  setupPushNotifications();\n  loadMedicationReminders();\n  checkActiveSos();\n\n  // الكل بيوصل على الشاشة الرئيسية دلوقتي (فيها الشات والتحديثات مع بعض)\n  $('tabHomeBtn').click();\n  \n  if (pollTimer) clearInterval(pollTimer);\n  pollTimer = setInterval(refreshData, 5000);\n}\n\n// ---------- لوحة متابعة العائلة (تظهر للأب/الأم بس، عشان يشوفوا حالة كل فرد بنظرة واحدة) ----------\nfunction renderOverview() {\n  const me = familyData && familyData.members.find(m => m.id === myId);\n  const panel = $('familyOverview');\n  if (!me || me.role !== 'parent') { hide(panel); return; }\n  show(panel);\n\n  const grid = $('overviewGrid');\n  grid.innerHTML = '';\n  familyData.members.forEach(m => {\n    if (m.id === myId) return;\n    // آخر حدث خاص بالعضو ده (eventsData مرتبة من الأحدث للأقدم)\n    const lastEvent = eventsData.find(e => e.memberId === m.id);\n    let statusClass = '';\n    let icon = '⏳';\n    let statusText = 'مفيش تحديث لسه';\n    if (lastEvent) {\n      if (lastEvent.type === 'sos') { statusClass = 'ov-sos'; icon = '🚨'; statusText = 'محتاج مساعدة'; }\n      else if (lastEvent.type === 'safe') { statusClass = 'ov-safe'; icon = '✅'; statusText = 'وصل بأمان'; }\n      else if (lastEvent.type === 'join') { icon = '👋'; statusText = 'انضم للعيلة'; }\n      else { icon = '📌'; statusText = lastEvent.occasionType || 'تحديث'; }\n      statusText += ' · ' + timeAgo(lastEvent.timestamp);\n    }\n    const div = document.createElement('div');\n    div.className = 'overview-card ' + statusClass;\n    div.innerHTML = `<span class=\"status-icon\">${icon}</span><div><div class=\"ov-name\">${escapeHtml(m.name)}</div><div class=\"ov-status\">${escapeHtml(statusText)}</div></div>`;\n    grid.appendChild(div);\n  });\n}\n\n// ---------- إشعارات حقيقية (Push) ----------\nconst VAPID_PUBLIC_KEY_CLIENT = 'BHNbX9qQHUFipNqIdsarAzbwt6lHJPjWHCzqYxRYMW0S1k1b_i5uqk5sLVXtuQ0YLcRBB-aEYO79tCofa_fTqjI';\n\nfunction urlBase64ToUint8Array(base64String) {\n  const padding = '='.repeat((4 - base64String.length % 4) % 4);\n  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');\n  const rawData = atob(base64);\n  const outputArray = new Uint8Array(rawData.length);\n  for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);\n  return outputArray;\n}\n\nasync function setupPushNotifications() {\n  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {\n    console.warn('المتصفح ده مش بيدعم الإشعارات الحقيقية (Web Push).');\n    return;\n  }\n  try {\n    const reg = await navigator.serviceWorker.register('/sw.js');\n    const permission = await Notification.requestPermission();\n    if (permission !== 'granted') {\n      console.warn('إذن الإشعارات مرفوض. فعّله من إعدادات الموبايل عشان الإشعارات تشتغل.');\n      return;\n    }\n    let sub = await reg.pushManager.getSubscription();\n    if (!sub) {\n      sub = await reg.pushManager.subscribe({\n        userVisibleOnly: true,\n        applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY_CLIENT),\n      });\n    }\n    await apiCall('/api/push/subscribe', {\n      method: 'POST',\n      body: JSON.stringify({ familyCode, memberId: myId, subscription: sub.toJSON() }),\n    });\n  } catch (e) {\n    console.error('push setup failed:', e);\n  }\n}\n\nasync function refreshData() {\n  // مفيش داعي نستهلك بيانات وباتري وإحنا مسكرين التاب - نوقف التحديث ونرجع نشتغل لما نرجع نفتحه\n  if (document.hidden) return;\n\n  const newFamily = await loadFamily(familyCode);\n  familyData = newFamily || familyData;\n\n  // نجيب بس الأحداث الجديدة بعد آخر حدث عندنا بدل تحميل القايمة كلها تاني\n  const sinceEvents = eventsData.length ? eventsData[0].timestamp : 0;\n  const newEventsDelta = await loadEventsSince(familyCode, sinceEvents);\n  if (newEventsDelta.length) {\n    newEventsDelta.forEach(ev => {\n      if (ev.memberId !== myId) {\n        if (ev.type === 'sos') playAlertSound('sos');\n        else if (ev.type === 'safe') playAlertSound('safe');\n      }\n    });\n    eventsData = newEventsDelta.slice().reverse().concat(eventsData);\n    renderFeed();\n  }\n  checkActiveSos();\n\n  // نفس الفكرة بالنسبة للشات\n  const sinceChat = chatMessages.length ? chatMessages[chatMessages.length - 1].timestamp : 0;\n  const newChatDelta = await loadChatSince(familyCode, sinceChat);\n  if (newChatDelta.length) {\n    const existingIds = new Set(chatMessages.map(m => m.id));\n    const freshOnes = newChatDelta.filter(m => !existingIds.has(m.id));\n    if (freshOnes.length) {\n      chatMessages = chatMessages.concat(freshOnes);\n      renderChat();\n      const fromOthers = freshOnes.filter(m => m.senderId !== myId).length;\n      if (fromOthers && currentTab !== 'home') {\n        unreadChatCount += fromOthers;\n        updateChatBadge();\n      }\n    }\n  }\n\n  renderCircle();\n  renderOverview();\n  renderMembers();\n  $('lastUpdate').textContent = 'محدّث الآن';\n}\n\n// ---------- نرجّع نحدّث فورًا لما المستخدم يرجع للتاب بعد ما كان مقفول ----------\ndocument.addEventListener('visibilitychange', () => {\n  if (!document.hidden && familyCode) refreshData();\n});\n\nfunction renderCircle() {\n  const row = $('circleRow');\n  row.innerHTML = '';\n  if (!familyData || !familyData.members) return;\n  familyData.members.forEach(m => {\n    const div = document.createElement('div');\n    div.className = 'avatar';\n    const isMe = m.id === myId;\n    div.innerHTML = `<div class=\"bubble ${m.role==='parent'?'parent':''} ${isMe?'me':''}\">${escapeHtml(initials(m.name))}</div><div>${escapeHtml(m.name.split(' ')[0])}</div>`;\n    row.appendChild(div);\n  });\n}\n\nfunction renderFeed() {\n  const list = $('feedList');\n  if (!eventsData || !eventsData.length) {\n    list.innerHTML = '<div class=\"empty-feed\">مفيش تحديثات لسه. أول تنبيه أو رسالة هتظهر هنا لكل العائلة.</div>';\n    return;\n  }\n  list.innerHTML = '';\n  eventsData.forEach(e => {\n    const div = document.createElement('div');\n    div.className = 'feed-item fade-in ' + e.type;\n    let icon = e.type === 'sos' ? '🚨' : e.type === 'safe' ? '✅' : e.type === 'location' ? '📍' : e.type === 'join' ? '👋' : (e.occasionType==='فرح'?'🎉':e.occasionType==='عيد ميلاد'?'🎂':e.occasionType==='وفاة'?'🕊️':'📌');\n    let title = e.type === 'sos' ? 'يحتاج مساعدة' : e.type === 'safe' ? 'وصل بأمان' : e.type === 'location' ? 'شارك موقعه' : e.type === 'join' ? 'عضو جديد' : e.occasionType;\n    let locHtml = '';\n    if (e.lat) {\n      const accTxt = e.accuracy ? ` (دقة ~${e.accuracy} م)` : '';\n      locHtml = `<a class=\"loc-link\" href=\"https://maps.google.com/?q=${e.lat},${e.lng}\" target=\"_blank\">📍 عرض الموقع على الخريطة${accTxt}</a>`;\n    }\n    const deleteHtml = (e.memberId === myId) ? `<span class=\"msg-delete-btn\" data-del-event=\"${e.id}\">🗑</span>` : '';\n    div.innerHTML = `\n      <div class=\"row1\">\n        <span class=\"who\">${icon} ${escapeHtml(e.memberName)} · ${escapeHtml(title)}</span>\n        <span class=\"when\">${timeAgo(e.timestamp)}${deleteHtml}</span>\n      </div>\n      <div class=\"msg\">${escapeHtml(e.text || '')}</div>\n      ${locHtml}\n    `;\n    list.appendChild(div);\n  });\n\n  list.querySelectorAll('[data-del-event]').forEach(btn => {\n    btn.onclick = async () => {\n      const evId = btn.dataset.delEvent;\n      const ok = await showConfirm('متأكد إنك عايز تحذف التحديث ده؟', { danger: true, okText: 'حذف' });\n      if (!ok) return;\n      try {\n        await apiCall('/api/events/' + familyCode + '/' + evId, {\n          method: 'DELETE',\n          body: JSON.stringify({ memberId: myId }),\n        });\n        eventsData = eventsData.filter(e => e.id !== evId);\n        renderFeed();\n      } catch (e) {\n        showToast('حصل خطأ أثناء الحذف', 'error');\n      }\n    };\n  });\n}\n\n// حالة الحظر والشات الخاص - بنعمل refresh ليها بعد الدخول وبشكل دوري\nlet myBlockedIds = [];\nconst privateChatStatusCache = {}; // otherId -> 'approved' | 'pending' | 'none'\n\nasync function refreshMyBlockedIds() {\n  try {\n    const result = await apiCall('/api/blocks/' + familyCode + '/' + myId);\n    myBlockedIds = result.blocked || [];\n  } catch (e) { /* تجاهل */ }\n}\n\nasync function refreshPendingDeletionBanner() {\n  try {\n    const result = await apiCall('/api/account/deletion-status/' + familyCode + '/' + myId);\n    const banner = $('pendingDeletionBanner');\n    if (!result.pending) { hide(banner); return; }\n    const when = new Date(result.executeAt).toLocaleString('ar-EG');\n    $('pendingDeletionText').textContent = result.scope === 'family'\n      ? '⚠️ فيه طلب حذف للعائلة بالكامل معلّق، هيتنفذ حوالي ' + when\n      : '⚠️ فيه طلب حذف لحسابك معلّق، هيتنفذ حوالي ' + when;\n    show(banner);\n  } catch (e) { /* تجاهل */ }\n}\n$('cancelPendingDeletionBtn').onclick = async () => {\n  const ok = await showConfirm('متأكد إنك عايز تلغي طلب الحذف المعلّق؟', { okText: 'إلغاء الطلب' });\n  if (!ok) return;\n  try {\n    await apiCall('/api/account/cancel-deletion', {\n      method: 'POST',\n      body: JSON.stringify({ code: familyCode, memberId: myId }),\n    });\n    hide($('pendingDeletionBanner'));\n    showToast('تم إلغاء طلب الحذف ✓', 'success');\n  } catch (e) {\n    showToast('حصل خطأ: ' + e.message, 'error');\n  }\n};\n\nasync function refreshPendingMembers() {\n  const me = familyData.members.find(m => m.id === myId);\n  const section = $('pendingMembersSection');\n  if (!me || !me.isAdmin) { hide(section); return; }\n  const pending = familyData.members.filter(m => m.status === 'pending');\n  if (!pending.length) { hide(section); return; }\n  show(section);\n  const box = $('pendingMembersList');\n  box.innerHTML = '';\n  pending.forEach(m => {\n    const div = document.createElement('div');\n    div.className = 'member-row';\n    div.innerHTML = `\n      <div class=\"info\">\n        <div class=\"bubble\" style=\"width:36px;height:36px;font-size:12px;\">${escapeHtml(initials(m.name))}</div>\n        <div><div class=\"name\">${escapeHtml(m.name)}</div><div class=\"rel\">${escapeHtml(m.relation)}</div></div>\n      </div>\n      <div style=\"display:flex; align-items:center;\">\n        <button class=\"btn-primary\" data-approve=\"${m.id}\" style=\"width:auto; padding:6px 14px; margin:0 6px 0 0; font-size:12px;\">قبول</button>\n        <button class=\"remove-btn\" data-reject=\"${m.id}\">رفض</button>\n      </div>`;\n    box.appendChild(div);\n  });\n  box.querySelectorAll('[data-approve]').forEach(btn => {\n    btn.onclick = async () => {\n      try {\n        const result = await apiCall('/api/family/approve', {\n          method: 'POST',\n          body: JSON.stringify({ code: familyCode, memberId: btn.dataset.approve, requestedByAdminId: myId }),\n        });\n        familyData = result.family;\n        renderMembers();\n        showToast('تم قبول العضو ✓', 'success');\n      } catch (e) { showToast('حصل خطأ: ' + e.message, 'error'); }\n    };\n  });\n  box.querySelectorAll('[data-reject]').forEach(btn => {\n    btn.onclick = async () => {\n      const ok = await showConfirm('متأكد إنك عايز ترفض طلب الانضمام ده؟', { okText: 'رفض' });\n      if (!ok) return;\n      try {\n        const result = await apiCall('/api/family/remove', {\n          method: 'POST',\n          body: JSON.stringify({ code: familyCode, memberId: btn.dataset.reject, requestedByAdminId: myId }),\n        });\n        familyData = result.family;\n        renderMembers();\n      } catch (e) { showToast('حصل خطأ: ' + e.message, 'error'); }\n    };\n  });\n}\n\nasync function refreshPendingPrivateRequests() {\n  const me = familyData.members.find(m => m.id === myId);\n  const section = $('pendingPrivateSection');\n  if (!me || !me.isAdmin) { hide(section); return; }\n  try {\n    const result = await apiCall('/api/private/pending/' + familyCode + '?adminId=' + myId);\n    const requests = result.requests || [];\n    if (!requests.length) { hide(section); return; }\n    show(section);\n    const box = $('pendingPrivateList');\n    box.innerHTML = '';\n    requests.forEach(r => {\n      const div = document.createElement('div');\n      div.className = 'member-row';\n      div.innerHTML = `\n        <div class=\"info\"><div>${escapeHtml(r.nameA)} 🔒 ${escapeHtml(r.nameB)}</div></div>\n        <div style=\"display:flex; align-items:center;\">\n          <button class=\"btn-primary\" data-approve-priv style=\"width:auto; padding:6px 14px; margin:0 6px 0 0; font-size:12px;\">موافقة</button>\n          <button class=\"remove-btn\" data-reject-priv>رفض</button>\n        </div>`;\n      div.querySelector('[data-approve-priv]').onclick = async () => {\n        await apiCall('/api/private/approve', { method: 'POST', body: JSON.stringify({ familyCode, memberA: r.memberA, memberB: r.memberB, adminId: myId, approve: true }) });\n        refreshPendingPrivateRequests();\n        showToast('تمت الموافقة على الشات الخاص ✓', 'success');\n      };\n      div.querySelector('[data-reject-priv]').onclick = async () => {\n        await apiCall('/api/private/approve', { method: 'POST', body: JSON.stringify({ familyCode, memberA: r.memberA, memberB: r.memberB, adminId: myId, approve: false }) });\n        refreshPendingPrivateRequests();\n      };\n      box.appendChild(div);\n    });\n  } catch (e) { hide(section); }\n}\n\nasync function refreshPendingReports() {\n  const me = familyData.members.find(m => m.id === myId);\n  const section = $('pendingReportsSection');\n  if (!me || !me.isAdmin) { hide(section); return; }\n  try {\n    const result = await apiCall('/api/chat/' + familyCode + '/reports?adminId=' + myId);\n    const reports = result.reports || [];\n    if (!reports.length) { hide(section); return; }\n    show(section);\n    const box = $('pendingReportsList');\n    box.innerHTML = '';\n    reports.forEach(r => {\n      const div = document.createElement('div');\n      div.className = 'member-row';\n      const preview = r.text ? escapeHtml(r.text).slice(0, 80) : (r.media_type ? '📎 وسائط (' + escapeHtml(r.media_type) + ')' : 'الرسالة اتحذفت بالفعل');\n      div.innerHTML = `\n        <div class=\"info\"><div>\n          <div style=\"font-size:12.5px;\"><strong>${escapeHtml(r.sender_name || 'عضو محذوف')}</strong>: ${preview}</div>\n          <div style=\"font-size:11px; color:var(--muted); margin-top:3px;\">أبلغ عنها: ${escapeHtml(r.reporter_name || 'عضو')}${r.reason ? ' - ' + escapeHtml(r.reason) : ''}</div>\n        </div></div>\n        <div style=\"display:flex; align-items:center;\">\n          <button class=\"remove-btn\" data-delete-reported style=\"margin:0 6px 0 0;\">حذف الرسالة</button>\n          <button class=\"btn-ghost\" data-dismiss-report style=\"padding:6px 10px; font-size:12px;\">تجاهل البلاغ</button>\n        </div>`;\n      div.querySelector('[data-delete-reported]').onclick = async () => {\n        if (r.message_id) {\n          try {\n            await apiCall('/api/chat/' + familyCode + '/' + r.message_id, {\n              method: 'DELETE', body: JSON.stringify({ senderId: myId }),\n            });\n          } catch (e) {}\n        }\n        await apiCall('/api/chat/' + familyCode + '/reports/' + r.report_id + '/dismiss', {\n          method: 'POST', body: JSON.stringify({ adminId: myId }),\n        });\n        refreshPendingReports();\n        chatMessages = await loadChat(familyCode);\n        renderChat();\n        showToast('تم حذف الرسالة وتجاهل البلاغ', 'success');\n      };\n      div.querySelector('[data-dismiss-report]').onclick = async () => {\n        await apiCall('/api/chat/' + familyCode + '/reports/' + r.report_id + '/dismiss', {\n          method: 'POST', body: JSON.stringify({ adminId: myId }),\n        });\n        refreshPendingReports();\n      };\n      box.appendChild(div);\n    });\n  } catch (e) { hide(section); }\n}\n\nfunction renderMembers() {\n  const list = $('memberList');\n  list.innerHTML = '';\n  if (!familyData || !familyData.members) return;\n  const me = familyData.members.find(m => m.id === myId);\n  const iAmAdmin = me && me.isAdmin;\n  const adminCount = familyData.members.filter(m => m.isAdmin).length;\n\n  refreshPendingMembers();\n  refreshPendingPrivateRequests();\n  refreshPendingReports();\n\n  familyData.members.forEach(m => {\n    if (m.id === myId) return;\n    if (m.status === 'pending') return; // الأعضاء المعلّقين ليهم قسم منفصل فوق (لكبير العائلة بس)\n    const div = document.createElement('div');\n    div.className = 'member-row';\n    const isParent = m.role === 'parent';\n    const inCircle = me && me.circle && me.circle.includes(m.id);\n    const isBlocked = myBlockedIds.includes(m.id);\n    let rightHtml = '';\n    if (!isParent && me && me.role !== 'parent') {\n      rightHtml += `<button class=\"trust-toggle ${inCircle?'on':''}\" data-id=\"${m.id}\">${inCircle ? '✓ في دائرتي' : 'أضف لدائرتي'}</button>`;\n    } else if (isParent) {\n      rightHtml += `<span style=\"font-size:11px;color:var(--occasion);\">دائرتك دايمًا</span>`;\n    }\n    if (iAmAdmin) {\n      rightHtml += `<button class=\"remove-btn\" data-remove=\"${m.id}\" style=\"margin-right:6px;\">حذف</button>`;\n      rightHtml += `<button class=\"btn-ghost\" data-reset-pin=\"${m.id}\" style=\"margin:0 6px 0 0; padding:6px 10px; font-size:11px; width:auto;\">إعادة كلمة السر</button>`;\n      if (!m.isAdmin) {\n        rightHtml += `<button class=\"btn-ghost\" data-promote=\"${m.id}\" style=\"margin:0 6px 0 0; padding:6px 10px; font-size:11px; width:auto;\">⭐ رقّي لنائب كبير عائلة</button>`;\n      } else if (adminCount > 1) {\n        rightHtml += `<button class=\"btn-ghost\" data-demote=\"${m.id}\" style=\"margin:0 6px 0 0; padding:6px 10px; font-size:11px; width:auto;\">تنزيل من الإدارة</button>`;\n      }\n    }\n    // الشات الخاص: كبير العائلة يقدر يفتحه مباشرة مع أي حد. أي عضو عادي محتاج موافقة كبير العائلة الأول.\n    if (iAmAdmin || m.isAdmin) {\n      rightHtml += `<button class=\"btn-ghost\" data-private=\"${m.id}\" style=\"margin:0 0 0 6px; padding:6px 10px; font-size:12px;\">🔒 خاص</button>`;\n    } else {\n      rightHtml += `<button class=\"btn-ghost\" data-private-request=\"${m.id}\" style=\"margin:0 0 0 6px; padding:6px 10px; font-size:12px;\">🔒 خاص</button>`;\n    }\n    rightHtml += `<button class=\"btn-ghost ${isBlocked?'on':''}\" data-block=\"${m.id}\" style=\"margin:0 0 0 6px; padding:6px 10px; font-size:12px; ${isBlocked ? 'color:var(--sos); border-color:var(--sos);' : ''}\">${isBlocked ? '✓ محظور' : '🚫 حظر'}</button>`;\n    const badge = m.isAdmin\n      ? (m.isFounder ? '<span class=\"admin-badge\">كبير العائلة</span>' : '<span class=\"admin-badge\">نائب كبير عائلة</span>')\n      : '';\n    div.innerHTML = `\n      <div class=\"info\">\n        <div class=\"bubble\" style=\"width:36px;height:36px;font-size:12px;\">${escapeHtml(initials(m.name))}</div>\n        <div><div class=\"name\">${badge}${escapeHtml(m.name)}</div><div class=\"rel\">${escapeHtml(m.relation)}</div></div>\n      </div>\n      <div style=\"display:flex; align-items:center; flex-wrap:wrap; gap:4px;\">${rightHtml}</div>\n    `;\n    list.appendChild(div);\n  });\n\n  list.querySelectorAll('[data-promote]').forEach(btn => {\n    btn.onclick = async () => {\n      const target = familyData.members.find(x => x.id === btn.dataset.promote);\n      const ok = await showConfirm(`متأكد إنك عايز ترقّي ${target ? target.name : 'العضو'} لنائب كبير عائلة؟ هيبقى ليه نفس صلاحياتك بالظبط (موافقة أعضاء، حذف، إلخ).`, { okText: 'ترقية' });\n      if (!ok) return;\n      try {\n        const result = await apiCall('/api/family/promote-admin', {\n          method: 'POST',\n          body: JSON.stringify({ code: familyCode, memberId: btn.dataset.promote, requestedByAdminId: myId }),\n        });\n        familyData = result.family;\n        renderMembers();\n        showToast('تمت الترقية لنائب كبير عائلة ✓', 'success');\n      } catch (e) { showToast('حصل خطأ: ' + e.message, 'error'); }\n    };\n  });\n  list.querySelectorAll('[data-demote]').forEach(btn => {\n    btn.onclick = async () => {\n      const target = familyData.members.find(x => x.id === btn.dataset.demote);\n      const ok = await showConfirm(`متأكد إنك عايز تنزّل ${target ? target.name : 'العضو'} من الإدارة؟`, { okText: 'تنزيل', danger: true });\n      if (!ok) return;\n      try {\n        const result = await apiCall('/api/family/demote-admin', {\n          method: 'POST',\n          body: JSON.stringify({ code: familyCode, memberId: btn.dataset.demote, requestedByAdminId: myId }),\n        });\n        familyData = result.family;\n        renderMembers();\n        showToast('تم التنزيل من الإدارة', 'success');\n      } catch (e) { showToast('حصل خطأ: ' + e.message, 'error'); }\n    };\n  });\n\n  list.querySelectorAll('.trust-toggle').forEach(btn => {\n    btn.onclick = async () => {\n      const id = btn.dataset.id;\n      const me = familyData.members.find(m => m.id === myId);\n      if (!me.circle) me.circle = [];\n      const idx = me.circle.indexOf(id);\n      if (idx >= 0) me.circle.splice(idx,1); else me.circle.push(id);\n      try {\n        const result = await apiCall('/api/family/circle', {\n          method: 'POST',\n          body: JSON.stringify({ code: familyCode, memberId: myId, circle: me.circle }),\n        });\n        familyData = result.family;\n      } catch(e) { console.error('circle update failed:', e); }\n      renderMembers();\n    };\n  });\n\n  list.querySelectorAll('[data-private]').forEach(btn => {\n    btn.onclick = () => openPrivateChat(btn.dataset.private);\n  });\n\n  list.querySelectorAll('[data-private-request]').forEach(btn => {\n    btn.onclick = async () => {\n      const otherId = btn.dataset.privateRequest;\n      const other = familyData.members.find(x => x.id === otherId);\n      try {\n        const result = await apiCall('/api/private/status/' + familyCode + '/' + myId + '/' + otherId);\n        if (result.allowed) { openPrivateChat(otherId); return; }\n        const ok = await showConfirm('الشات الخاص مع ' + other.name + ' محتاج موافقة كبير العائلة. عايز تبعت طلب موافقة؟', { okText: 'ابعت الطلب' });\n        if (!ok) return;\n        const me = familyData.members.find(x => x.id === myId);\n        const reqResult = await apiCall('/api/private/request', {\n          method: 'POST',\n          body: JSON.stringify({ familyCode, requesterId: myId, requesterName: me.name, targetId: otherId, targetName: other.name }),\n        });\n        if (reqResult.status === 'approved') { openPrivateChat(otherId); }\n        else { showToast('اتبعت طلب الموافقة لكبير العائلة، هيوصلك إشعار لما يوافق', 'success'); }\n      } catch (e) { showToast('حصل خطأ: ' + e.message, 'error'); }\n    };\n  });\n\n  list.querySelectorAll('[data-block]').forEach(btn => {\n    btn.onclick = async () => {\n      const otherId = btn.dataset.block;\n      const already = myBlockedIds.includes(otherId);\n      try {\n        await apiCall(already ? '/api/unblock' : '/api/block', {\n          method: 'POST',\n          body: JSON.stringify({ familyCode, blockerId: myId, blockedId: otherId }),\n        });\n        await refreshMyBlockedIds();\n        renderMembers();\n        renderChat();\n      } catch (e) { showToast('حصل خطأ: ' + e.message, 'error'); }\n    };\n  });\n\n  list.querySelectorAll('[data-remove]').forEach(btn => {\n    btn.onclick = async () => {\n      const id = btn.dataset.remove;\n      const targetMember = familyData.members.find(x => x.id === id);\n      const name = targetMember ? targetMember.name : 'العضو';\n      const ok = await showConfirm(`متأكد إنك عايز تحذف ${name} من العائلة نهائيًا؟ هيتم تسجيل خروجه ومش هيقدر يدخل تاني إلا لو انضم من الأول بموافقتك.`, { okText: 'حذف', danger: true });\n      if (!ok) return;\n      try {\n        const result = await apiCall('/api/family/remove', {\n          method: 'POST',\n          body: JSON.stringify({ code: familyCode, memberId: id, requestedByAdminId: myId }),\n        });\n        familyData = result.family;\n        renderMembers();\n        showToast('تم حذف ' + name + ' من العائلة', 'success');\n      } catch (e) {\n        showToast('حصل خطأ: ' + e.message, 'error');\n      }\n    };\n  });\n\n  list.querySelectorAll('[data-reset-pin]').forEach(btn => {\n    btn.onclick = async () => {\n      const id = btn.dataset.resetPin;\n      const targetMember = familyData.members.find(x => x.id === id);\n      const name = targetMember ? targetMember.name : 'العضو';\n      const ok = await showConfirm(`متأكد إنك عايز تصفّر الـ PIN بتاع ${name}؟ هيحتاج يحدد PIN جديد أول ما يحاول يدخل تاني.`, { okText: 'تصفير' });\n      if (!ok) return;\n      try {\n        await apiCall('/api/family/reset-pin', {\n          method: 'POST',\n          body: JSON.stringify({ code: familyCode, memberId: id, requestedByAdminId: myId }),\n        });\n        showToast('تم تصفير الـ PIN، ' + name + ' هيحدد PIN جديد أول ما يحاول يدخل', 'success');\n      } catch (e) {\n        showToast('حصل خطأ: ' + e.message, 'error');\n      }\n    };\n  });\n}\n\n// ---------- الشات الخاص (E2E) ----------\nlet privateChatWith = null;\nlet privateChatMessages = [];\nlet privateChatPollTimer = null;\nlet privateChatSeenDisclosure = {};\n\nasync function openPrivateChat(otherId) {\n  const other = familyData.members.find(m => m.id === otherId);\n  if (!other) return;\n  if (!other.publicKey) {\n    showToast(other.name + ' لسه ما دخلش التطبيق من جهازه عشان يتولّد مفتاحه - جرب تاني بعد شوية', 'error');\n    return;\n  }\n  privateChatWith = other;\n  privateChatMessages = [];\n  $('privateChatTitle').textContent = '🔒 محادثة خاصة مع ' + other.name;\n  $('privateChatContainer').innerHTML = '';\n\n  if (privateChatSeenDisclosure[otherId]) {\n    hide($('privateChatDisclosure'));\n    show($('privateChatBody'));\n  } else {\n    show($('privateChatDisclosure'));\n    hide($('privateChatBody'));\n  }\n  show($('privateChatModal'));\n\n  await loadPrivateMessages();\n  clearInterval(privateChatPollTimer);\n  privateChatPollTimer = setInterval(loadPrivateMessages, 4000);\n}\n\nfunction closePrivateChat() {\n  hide($('privateChatModal'));\n  clearInterval(privateChatPollTimer);\n  privateChatPollTimer = null;\n  privateChatWith = null;\n}\n\n$('privateChatCloseBtn').onclick = closePrivateChat;\n\n$('privateChatDisclosureOk').onclick = () => {\n  if (privateChatWith) privateChatSeenDisclosure[privateChatWith.id] = true;\n  hide($('privateChatDisclosure'));\n  show($('privateChatBody'));\n};\n\nasync function loadPrivateMessages() {\n  if (!privateChatWith) return;\n  try {\n    const since = privateChatMessages.length ? privateChatMessages[privateChatMessages.length - 1].timestamp : 0;\n    const data = await apiCall('/api/private/' + familyCode + '/' + myId + '/' + privateChatWith.id + '?since=' + since, { method: 'GET' });\n    if (data.messages && data.messages.length) {\n      for (const m of data.messages) {\n        const text = await decryptPrivateText(m.ciphertext, m.iv, privateChatWith.publicKey);\n        privateChatMessages.push({ id: m.id, senderId: m.senderId, text, timestamp: m.timestamp });\n      }\n      renderPrivateChat();\n    }\n  } catch (e) { console.error('loadPrivateMessages failed:', e); }\n}\n\nfunction renderPrivateChat() {\n  const container = $('privateChatContainer');\n  container.innerHTML = '';\n  privateChatMessages.forEach(msg => {\n    const div = document.createElement('div');\n    div.className = 'chat-msg fade-in';\n    if (msg.senderId === myId) div.classList.add('me');\n    div.innerHTML = `\n      <div class=\"text\">${escapeHtml(msg.text)}</div>\n      <div class=\"time\">${formatTime(msg.timestamp)}</div>\n    `;\n    container.appendChild(div);\n  });\n  container.scrollTop = container.scrollHeight;\n}\n\n$('privateChatSendBtn').onclick = async () => {\n  const input = $('privateChatInput');\n  const text = input.value.trim();\n  if (!text || !privateChatWith) return;\n  input.value = '';\n  try {\n    const { ciphertext, iv } = await encryptPrivateText(text, privateChatWith.publicKey);\n    const me = familyData.members.find(m => m.id === myId);\n    await apiCall('/api/private/' + familyCode, {\n      method: 'POST',\n      body: JSON.stringify({\n        senderId: myId, senderName: me ? me.name : '', recipientId: privateChatWith.id,\n        ciphertext, iv,\n      }),\n    });\n    privateChatMessages.push({ id: 'local_' + Date.now(), senderId: myId, text, timestamp: Date.now() });\n    renderPrivateChat();\n  } catch (e) {\n    showToast('حصل خطأ أثناء إرسال الرسالة', 'error');\n  }\n};\n$('privateChatInput').addEventListener('keydown', (e) => {\n  if (e.key === 'Enter') $('privateChatSendBtn').click();\n});\n\n// ---------- Chat ----------\nfunction renderChat() {\n  const container = $('chatContainer');\n  if (!chatMessages || !chatMessages.length) {\n    container.innerHTML = '<div style=\"text-align:center;color:var(--muted);font-size:13px;padding:30px 0;\">💬 ابدأ المحادثة العائلية</div>';\n    return;\n  }\n  const me = familyData && familyData.members.find(m => m.id === myId);\n  const iAmAdmin = !!(me && me.isAdmin);\n  container.innerHTML = '';\n  chatMessages.filter(msg => !myBlockedIds.includes(msg.senderId)).forEach(msg => {\n    const div = document.createElement('div');\n    div.className = 'chat-msg fade-in';\n    if (msg.senderId === myId) div.classList.add('me');\n    if (msg._pending) div.style.opacity = '0.55';\n    let bodyHtml = '';\n    if (msg.mediaType === 'image') {\n      bodyHtml = `<img src=\"${msg.media}\" alt=\"صورة\">`;\n    } else if (msg.mediaType === 'audio') {\n      bodyHtml = `<audio controls src=\"${msg.media}\"></audio>`;\n    } else if (msg.mediaType === 'video') {\n      bodyHtml = `<video controls src=\"${msg.media}\"></video>`;\n    }\n    const canDelete = !msg._pending && (msg.senderId === myId || iAmAdmin);\n    const canReport = !msg._pending && msg.senderId !== myId;\n    let actionsHtml = '';\n    if (canReport) actionsHtml += `<span class=\"msg-report-btn\" data-report=\"${msg.id}\" title=\"إبلاغ\">🚩</span>`;\n    if (canDelete) actionsHtml += `<span class=\"msg-delete-btn\" data-del=\"${msg.id}\">🗑</span>`;\n    div.innerHTML = `\n      <div class=\"sender\">${escapeHtml(msg.senderName)}${actionsHtml}</div>\n      ${msg.text ? `<div class=\"text\">${escapeHtml(msg.text)}</div>` : ''}\n      ${bodyHtml}\n      <div class=\"time\">${msg._pending ? '⏳ بيترسل...' : formatTime(msg.timestamp)}</div>\n    `;\n    container.appendChild(div);\n  });\n  container.scrollTop = container.scrollHeight;\n\n  container.querySelectorAll('[data-del]').forEach(btn => {\n    btn.onclick = async () => {\n      const msgId = btn.dataset.del;\n      const ok = await showConfirm('متأكد إنك عايز تحذف الرسالة دي؟', { danger: true, okText: 'حذف' });\n      if (!ok) return;\n      try {\n        await apiCall('/api/chat/' + familyCode + '/' + msgId, {\n          method: 'DELETE',\n          body: JSON.stringify({ senderId: myId }),\n        });\n        chatMessages = chatMessages.filter(m => m.id !== msgId);\n        renderChat();\n      } catch (e) {\n        showToast('حصل خطأ أثناء الحذف', 'error');\n      }\n    };\n  });\n\n  container.querySelectorAll('[data-report]').forEach(btn => {\n    btn.onclick = async () => {\n      const msgId = btn.dataset.report;\n      const ok = await showConfirm('تبلغ كبير العائلة عن الرسالة دي عشان يراجعها ويحذفها لو لازم؟', { okText: 'إبلاغ' });\n      if (!ok) return;\n      try {\n        const meNow = familyData.members.find(m => m.id === myId);\n        await apiCall('/api/chat/' + familyCode + '/' + msgId + '/report', {\n          method: 'POST',\n          body: JSON.stringify({ reporterId: myId, reporterName: meNow ? meNow.name : '' }),\n        });\n        showToast('تم الإبلاغ، هيتراجع من كبير العائلة', 'success');\n      } catch (e) {\n        showToast('حصل خطأ أثناء الإبلاغ', 'error');\n      }\n    };\n  });\n}\n\n$('chatSendBtn').onclick = async () => {\n  const input = $('chatInput');\n  const text = input.value.trim();\n  if (!text) return;\n  input.value = '';\n\n  const me = familyData.members.find(m => m.id === myId);\n  // إرسال متفائل (optimistic): الرسالة بتظهر فورًا من غير ما ننتظر رد السيرفر، زي التطبيقات الكبيرة\n  const tempId = 'temp_' + Date.now() + '_' + Math.random().toString(36).slice(2,6);\n  const optimisticMsg = { id: tempId, senderId: myId, senderName: me.name, text: text, timestamp: Date.now(), _pending: true };\n  chatMessages.push(optimisticMsg);\n  renderChat();\n\n  try {\n    const result = await apiCall('/api/chat/' + familyCode, {\n      method: 'POST',\n      body: JSON.stringify({ senderId: myId, senderName: me.name, text: text }),\n    });\n    // نستبدل المعرف المؤقت بمعرف السيرفر الحقيقي عشان الرسالة ما تتكررش لما تيجي في التحديث الدوري\n    optimisticMsg.id = result.id;\n    delete optimisticMsg._pending;\n    renderChat();\n  } catch (err) {\n    chatMessages = chatMessages.filter(m => m.id !== tempId);\n    renderChat();\n    showToast('الرسالة ما اتبعتتش، جرب تاني', 'error');\n  }\n};\n\n$('chatInput').addEventListener('keydown', (e) => {\n  if (e.key === 'Enter') $('chatSendBtn').click();\n});\n\n// ---------- Media messages ----------\nfunction compressImage(file, maxWidth) {\n  return new Promise((resolve, reject) => {\n    const img = new Image();\n    const reader = new FileReader();\n    reader.onload = () => { img.src = reader.result; };\n    reader.onerror = reject;\n    img.onload = () => {\n      const scale = Math.min(1, maxWidth / img.width);\n      const canvas = document.createElement('canvas');\n      canvas.width = img.width * scale;\n      canvas.height = img.height * scale;\n      const ctx = canvas.getContext('2d');\n      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);\n      resolve(canvas.toDataURL('image/jpeg', 0.6));\n    };\n    img.onerror = reject;\n    reader.readAsDataURL(file);\n  });\n}\nfunction fileToDataUrlChat(file) {\n  return new Promise((resolve, reject) => {\n    const reader = new FileReader();\n    reader.onload = () => resolve(reader.result);\n    reader.onerror = reject;\n    reader.readAsDataURL(file);\n  });\n}\n\nfunction extFromMime(mime) {\n  const map = { 'image/jpeg':'jpg','image/png':'png','image/webp':'webp','audio/mpeg':'mp3','audio/mp4':'m4a','audio/webm':'webm','audio/aac':'aac','video/mp4':'mp4','video/quicktime':'mov','video/webm':'webm' };\n  return map[mime] || 'bin';\n}\n\n$('photoBtn').onclick = () => $('photoInput').click();\n$('audioBtn').onclick = () => $('audioInput').click();\n$('videoBtn').onclick = () => $('videoInput').click();\n\n$('photoInput').onchange = async (e) => {\n  const file = e.target.files[0];\n  e.target.value = '';\n  if (!file) return;\n  $('mediaUploadStatus').textContent = 'جاري ضغط ورفع الصورة...';\n  try {\n    const dataUrl = await compressImage(file, 900);\n    const me = familyData.members.find(m => m.id === myId);\n    await uploadChatMedia(familyCode, {\n      senderId: myId, senderName: me.name, mediaType: 'image',\n      base64: dataUrl, ext: 'jpg', contentType: 'image/jpeg',\n    });\n    chatMessages = await loadChat(familyCode);\n    renderChat();\n    $('mediaUploadStatus').textContent = '';\n  } catch(err) {\n    console.error(err);\n    $('mediaUploadStatus').textContent = 'حصل خطأ في رفع الصورة، جرب تاني.';\n  }\n};\n\n$('audioInput').onchange = async (e) => {\n  const file = e.target.files[0];\n  e.target.value = '';\n  if (!file) return;\n  if (file.size > 15000000) {\n    $('mediaUploadStatus').textContent = '⚠️ التسجيل كبير أوي (أكتر من 15 ميجا)، جرب تسجيل أقصر.';\n    return;\n  }\n  $('mediaUploadStatus').textContent = 'جاري رفع التسجيل...';\n  try {\n    const dataUrl = await fileToDataUrlChat(file);\n    const me = familyData.members.find(m => m.id === myId);\n    await uploadChatMedia(familyCode, {\n      senderId: myId, senderName: me.name, mediaType: 'audio',\n      base64: dataUrl, ext: extFromMime(file.type), contentType: file.type || 'audio/mpeg',\n    });\n    chatMessages = await loadChat(familyCode);\n    renderChat();\n    $('mediaUploadStatus').textContent = '';\n  } catch(err) {\n    console.error(err);\n    $('mediaUploadStatus').textContent = 'حصل خطأ في رفع التسجيل، جرب تاني.';\n  }\n};\n\n$('videoInput').onchange = async (e) => {\n  const file = e.target.files[0];\n  e.target.value = '';\n  if (!file) return;\n  if (file.size > 40000000) {\n    $('mediaUploadStatus').textContent = '⚠️ الفيديو كبير أوي (أكتر من 40 ميجا). سجل فيديو أقصر.';\n    return;\n  }\n  $('mediaUploadStatus').textContent = 'جاري رفع الفيديو... ممكن ياخد لحظات حسب حجمه';\n  try {\n    const dataUrl = await fileToDataUrlChat(file);\n    const me = familyData.members.find(m => m.id === myId);\n    await uploadChatMedia(familyCode, {\n      senderId: myId, senderName: me.name, mediaType: 'video',\n      base64: dataUrl, ext: extFromMime(file.type), contentType: file.type || 'video/mp4',\n    });\n    chatMessages = await loadChat(familyCode);\n    renderChat();\n    $('mediaUploadStatus').textContent = '';\n  } catch(err) {\n    console.error(err);\n    $('mediaUploadStatus').textContent = 'حصل خطأ في رفع الفيديو، جرب تاني.';\n  }\n};\n\n// ---------- Actions ----------\n// ملحوظة مهمة: زر الطوارئ وزر الاطمئنان بيبعتوا إشعار نصي بس، من غير أي موقع جغرافي إطلاقًا -\n// ده مقصود حسب سياسة التطبيق (\"الثقة مش المراقبة\")، ومتأكد منه كمان من جهة السيرفر.\n$('sosBtn').onclick = async () => {\n  const me = familyData.members.find(m => m.id === myId);\n  playAlertSound('sos');\n  await pushEvent({\n    id: 'e_'+Date.now(), type: 'sos', memberId: myId, memberName: me.name,\n    text: 'أحتاج إلى مساعدة الآن', timestamp: Date.now()\n  });\n  showToast('تم إرسال طلب المساعدة', 'success');\n};\n\n$('safeBtn').onclick = async () => {\n  const me = familyData.members.find(m => m.id === myId);\n  await pushEvent({\n    id: 'e_'+Date.now(), type: 'safe', memberId: myId, memberName: me.name,\n    text: 'أنا بخير', timestamp: Date.now()\n  });\n  showToast('تم إرسال طمأنتك للعائلة', 'success');\n};\n\n// ---------- مشاركة الموقع الطوعية بمدة محددة (بدون تتبع في الخلفية) ----------\n// المشاركة بتبعت نبضة موقع كل شوية بس لما التطبيق مفتوح وظاهر على الشاشة (document.hidden === false).\n// لما تقفل التطبيق أو تسكّر التاب، النبضات بتوقف تلقائيًا - مفيش أي كود بيشتغل في الخلفية.\nlet activeShareTimer = null;\nlet activeShareExpiresAt = null;\n\nfunction updateActiveShareBanner() {\n  const banner = $('activeShareBanner');\n  if (!activeShareTimer) { hide(banner); return; }\n  show(banner);\n  if (activeShareExpiresAt) {\n    const mins = Math.max(0, Math.round((activeShareExpiresAt - Date.now()) / 60000));\n    $('activeShareText').textContent = '📍 بتشارك موقعك (باقي ~' + mins + ' د)';\n  } else {\n    $('activeShareText').textContent = '📍 بتشارك موقعك لحد ما توقف';\n  }\n}\n\nasync function sendLocationPing() {\n  if (document.hidden) return; // التطبيق مقفول/مش ظاهر - مفيش إرسال، ده اللي بيمنع التتبع الخلفي\n  const me = familyData.members.find(m => m.id === myId);\n  const loc = await getLocation(true);\n  if (!loc) return;\n  try {\n    const result = await apiCall('/api/location/' + familyCode + '/ping', {\n      method: 'POST',\n      body: JSON.stringify({ memberId: myId, memberName: me.name, lat: loc.lat, lng: loc.lng, accuracy: loc.accuracy }),\n    });\n    activeShareExpiresAt = result.expiresAt || null;\n    updateActiveShareBanner();\n    eventsData = await loadEvents(familyCode);\n    renderFeed();\n  } catch (e) {\n    // المشاركة خلصت مدتها أو اتوقفت من جهاز تاني\n    stopLocationShare(false);\n  }\n}\n\nasync function startLocationShare(durationMinutes) {\n  try {\n    const result = await apiCall('/api/location/' + familyCode + '/start', {\n      method: 'POST',\n      body: JSON.stringify({ memberId: myId, durationMinutes }),\n    });\n    activeShareExpiresAt = result.expiresAt || null;\n    if (activeShareTimer) clearInterval(activeShareTimer);\n    await sendLocationPing();\n    activeShareTimer = setInterval(sendLocationPing, 120000); // نبضة كل دقيقتين بس والتطبيق ظاهر\n    updateActiveShareBanner();\n    showToast('بدأت مشاركة موقعك مع العائلة ✓', 'success');\n  } catch (e) {\n    showToast('حصل خطأ أثناء بدء المشاركة', 'error');\n  }\n}\n\nasync function stopLocationShare(notifyServer) {\n  if (activeShareTimer) { clearInterval(activeShareTimer); activeShareTimer = null; }\n  activeShareExpiresAt = null;\n  updateActiveShareBanner();\n  if (notifyServer !== false) {\n    try { await apiCall('/api/location/' + familyCode + '/stop', { method: 'POST', body: JSON.stringify({ memberId: myId }) }); } catch(e) {}\n  }\n}\n\n$('shareLocationBtn').onclick = () => {\n  if (activeShareTimer) { showToast('انت بتشارك موقعك بالفعل', 'error'); return; }\n  show($('locationShareModal'));\n};\n$('locationShareCancelBtn').onclick = () => hide($('locationShareModal'));\n$('shareLocation1HourBtn').onclick = async () => {\n  hide($('locationShareModal'));\n  await startLocationShare(60);\n};\n$('shareLocationUntilStopBtn').onclick = async () => {\n  hide($('locationShareModal'));\n  await startLocationShare(null);\n};\n$('stopShareBtn').onclick = async () => {\n  await stopLocationShare(true);\n  showToast('تم إيقاف مشاركة موقعك', 'success');\n};\n// لو المستخدم رجع للتاب وكانت المشاركة شغالة، نبعت نبضة فورًا (بدل ما ننتظر الدورة الجاية)\ndocument.addEventListener('visibilitychange', () => {\n  if (!document.hidden && activeShareTimer) sendLocationPing();\n});\n\n\n$('occasionBtn').onclick = () => show($('occasionModal'));\n$('occasionCancel').onclick = () => hide($('occasionModal'));\ndocument.querySelectorAll('.type-pick').forEach(el => {\n  el.onclick = () => {\n    document.querySelectorAll('.type-pick').forEach(x=>x.classList.remove('active'));\n    el.classList.add('active');\n    selectedOccasionType = el.dataset.type;\n  };\n});\ndocument.querySelector('.type-pick[data-type=\"فرح\"]').classList.add('active');\n\n$('occasionSubmit').onclick = async () => {\n  const name = $('occasionName').value.trim();\n  const details = $('occasionText').value.trim();\n  if (!name) { showToast('اكتب اسم المناسبة', 'error'); return; }\n  const me = familyData.members.find(m => m.id === myId);\n  const fullText = details ? (name + ' — ' + details) : name;\n\n  await pushEvent({\n    id: 'e_'+Date.now(), type: 'occasion', occasionType: selectedOccasionType,\n    memberId: myId, memberName: me.name, text: fullText, timestamp: Date.now()\n  });\n\n  const icon = selectedOccasionType === 'فرح' ? '🎉' : selectedOccasionType === 'عيد ميلاد' ? '🎂' : selectedOccasionType === 'وفاة' ? '🕊️' : '📌';\n  await pushChatMessage({\n    id: 'c_'+Date.now()+'_'+Math.random().toString(36).slice(2,6),\n    senderId: myId,\n    senderName: me.name,\n    text: icon + ' مناسبة: ' + fullText,\n    timestamp: Date.now()\n  });\n\n  $('occasionName').value = '';\n  $('occasionText').value = '';\n  hide($('occasionModal'));\n};\n\n// ---------- Tabs ----------\nlet currentTab = 'home';\nlet unreadChatCount = 0;\nfunction updateChatBadge() {\n  const badge = $('chatUnreadBadge');\n  if (unreadChatCount > 0 && currentTab !== 'home') {\n    badge.textContent = unreadChatCount > 9 ? '9+' : String(unreadChatCount);\n    show(badge);\n  } else {\n    hide(badge);\n  }\n}\n$('tabHomeBtn').onclick = () => {\n  show($('homeTab')); hide($('familyTab')); hide($('settingsTab'));\n  $('tabHomeBtn').classList.add('active');\n  $('tabFamilyBtn').classList.remove('active');\n  $('tabSettingsBtn').classList.remove('active');\n  currentTab = 'home';\n  unreadChatCount = 0;\n  updateChatBadge();\n  renderChat();\n};\n$('tabFamilyBtn').onclick = () => {\n  hide($('homeTab')); show($('familyTab')); hide($('settingsTab'));\n  $('tabHomeBtn').classList.remove('active');\n  $('tabFamilyBtn').classList.add('active');\n  $('tabSettingsBtn').classList.remove('active');\n  currentTab = 'family';\n  renderMembers();\n};\n$('tabSettingsBtn').onclick = () => {\n  hide($('homeTab')); hide($('familyTab')); show($('settingsTab'));\n  $('tabHomeBtn').classList.remove('active');\n  $('tabFamilyBtn').classList.remove('active');\n  $('tabSettingsBtn').classList.add('active');\n  currentTab = 'settings';\n  $('chatThemeSelect').value = loadChatTheme();\n  $('sosToneSelect').value = soundPrefs.sosTone;\n  $('safeToneSelect').value = soundPrefs.safeTone;\n  $('sosCustomStatus').textContent = soundPrefs.customSos ? '✓ فيه نغمة مرفوعة حاليًا' : '';\n  $('safeCustomStatus').textContent = soundPrefs.customSafe ? '✓ فيه نغمة مرفوعة حاليًا' : '';\n};\n\n// ---------- Sound settings ----------\n$('chatThemeSelect').onchange = () => {\n  const val = $('chatThemeSelect').value;\n  applyChatTheme(val);\n  saveChatTheme(val);\n};\n$('testSosTone').onclick = () => playBuiltInTone($('sosToneSelect').value);\n$('testSafeTone').onclick = () => playBuiltInTone($('safeToneSelect').value);\n\nfunction fileToDataUrl(file) {\n  return new Promise((resolve, reject) => {\n    const reader = new FileReader();\n    reader.onload = () => resolve(reader.result);\n    reader.onerror = reject;\n    reader.readAsDataURL(file);\n  });\n}\n\nlet pendingCustomSos = undefined;\nlet pendingCustomSafe = undefined;\n\n$('sosCustomFile').onchange = async (e) => {\n  const file = e.target.files[0];\n  if (!file) return;\n  if (file.size > 800000) { showToast('الملف كبير أوي، اختار ملف أصغر من 800 كيلوبايت', 'error'); e.target.value=''; return; }\n  pendingCustomSos = await fileToDataUrl(file);\n  $('sosCustomStatus').textContent = '✓ ' + file.name + ' - دوس حفظ التفضيلات';\n};\n$('safeCustomFile').onchange = async (e) => {\n  const file = e.target.files[0];\n  if (!file) return;\n  if (file.size > 800000) { showToast('الملف كبير أوي، اختار ملف أصغر من 800 كيلوبايت', 'error'); e.target.value=''; return; }\n  pendingCustomSafe = await fileToDataUrl(file);\n  $('safeCustomStatus').textContent = '✓ ' + file.name + ' - دوس حفظ التفضيلات';\n};\n\n$('saveSoundPrefs').onclick = async () => {\n  soundPrefs.sosTone = $('sosToneSelect').value;\n  soundPrefs.safeTone = $('safeToneSelect').value;\n  if (pendingCustomSos !== undefined) soundPrefs.customSos = pendingCustomSos;\n  if (pendingCustomSafe !== undefined) soundPrefs.customSafe = pendingCustomSafe;\n  await saveSoundPrefs(soundPrefs);\n  pendingCustomSos = undefined; pendingCustomSafe = undefined;\n  showToast('اتحفظت التفضيلات ✓', 'success');\n};\n\n$('changePinBtn').onclick = async () => {\n  const newPassword = $('newPinInput').value;\n  if (!newPassword || newPassword.length < 6) {\n    showToast('كلمة السر لازم تكون 6 حروف أو أرقام على الأقل', 'error');\n    return;\n  }\n  try {\n    await apiCall('/api/member/' + familyCode + '/' + myId + '/change-password', {\n      method: 'POST', body: JSON.stringify({ newPassword }),\n    });\n    $('newPinInput').value = '';\n    showToast('اتغيّرت كلمة السر بنجاح ✓', 'success');\n  } catch (e) {\n    showToast('حصل خطأ: ' + e.message, 'error');\n  }\n};\n\n// ---------- Admin panel (hidden control panel) ----------\n// يتفتح بالضغط 3 مرات متتالية بسرعة على عنوان \"أمان العيلة\" في شاشة الدخول.\n// مفيش أي زرار أو إشارة ظاهرة للزوار، والدخول محمي بمفتاح إدارة (ADMIN_KEY) بيتخزن في الـ Worker.\nlet adminClickCount = 0;\nlet adminClickTimer = null;\nlet adminKey = sessionStorage.getItem('adminKey') || '';\nlet adminActiveFamily = null;\n\n$('loginTitle').addEventListener('click', () => {\n  adminClickCount++;\n  clearTimeout(adminClickTimer);\n  adminClickTimer = setTimeout(() => { adminClickCount = 0; }, 800);\n  if (adminClickCount >= 3) {\n    adminClickCount = 0;\n    openAdminScreen();\n  }\n});\n\nasync function adminApiCall(path, options) {\n  const res = await fetch(API_BASE + path, {\n    headers: { 'Content-Type': 'application/json', 'x-admin-key': adminKey },\n    ...options,\n  });\n  const data = await res.json().catch(() => ({}));\n  if (!res.ok) throw new Error(data.error || 'حصل خطأ في الاتصال بالسيرفر');\n  return data;\n}\n\nfunction openAdminScreen() {\n  hide($('loginScreen')); hide($('mainScreen')); hide($('createFamilyScreen'));\n  show($('adminScreen'));\n  if (adminKey) {\n    tryAdminKey();\n  } else {\n    show($('adminLoginBox')); hide($('adminDashboard'));\n    $('adminKeyInput').value = '';\n    $('adminLoginError').style.display = 'none';\n    $('adminKeyInput').focus();\n  }\n}\n\nfunction closeAdminScreen() {\n  hide($('adminScreen'));\n  show($('loginScreen'));\n}\n\n$('adminCancelLogin').onclick = closeAdminScreen;\n\n$('adminKeySubmit').onclick = async () => {\n  adminKey = $('adminKeyInput').value.trim();\n  await tryAdminKey();\n};\n$('adminKeyInput').addEventListener('keydown', (e) => {\n  if (e.key === 'Enter') $('adminKeySubmit').click();\n});\n\nasync function tryAdminKey() {\n  if (!adminKey) return;\n  try {\n    await adminApiCall('/api/admin/stats', { method: 'GET' });\n    sessionStorage.setItem('adminKey', adminKey);\n    show($('adminDashboard')); hide($('adminLoginBox'));\n    showAdminFamiliesTab();\n    await loadAdminStats();\n    await loadAdminFamilies();\n  } catch (e) {\n    adminKey = '';\n    sessionStorage.removeItem('adminKey');\n    show($('adminLoginBox')); hide($('adminDashboard'));\n    $('adminLoginError').textContent = 'مفتاح غلط، حاول تاني';\n    $('adminLoginError').style.display = 'block';\n  }\n}\n\n$('logoutBtn').onclick = async () => {\n  const ok = await showConfirm('متأكد إنك عايز تسجل خروج من التطبيق؟', { danger: true, okText: 'تسجيل خروج' });\n  if (!ok) return;\n  clearPersistedSession();\n  familyCode = null; myId = null; sessionToken = null; familyData = null;\n  if (pollTimer) clearInterval(pollTimer);\n  hide($('mainScreen'));\n  show($('loginScreen'));\n};\n\n// ---------- حذف العائلة نهائيًا (لكبير العائلة بس، بتحقق ثانوي) ----------\n$('deleteFamilyBtn').onclick = () => {\n  $('deleteFamilyCodeLabel').textContent = 'اكتب كود العائلة (' + familyCode + ') للتأكيد';\n  $('deleteFamilyConfirmCode').value = '';\n  $('deleteFamilyPin').value = '';\n  hide($('deleteFamilyError'));\n  show($('deleteFamilyModal'));\n};\n$('deleteFamilyCancelBtn').onclick = () => hide($('deleteFamilyModal'));\n$('deleteFamilyConfirmBtn').onclick = async () => {\n  const confirmCode = $('deleteFamilyConfirmCode').value.trim();\n  const password = $('deleteFamilyPin').value;\n  if (!confirmCode || !password) {\n    $('deleteFamilyError').textContent = 'لازم تكتب كود العائلة وكلمة السر';\n    show($('deleteFamilyError'));\n    return;\n  }\n  const btn = $('deleteFamilyConfirmBtn');\n  btn.disabled = true;\n  const originalText = btn.textContent;\n  btn.textContent = 'جاري الحذف...';\n  try {\n    await apiCall('/api/family/delete-self', {\n      method: 'POST',\n      body: JSON.stringify({ code: familyCode, adminId: myId, password, confirmCode }),\n    });\n    hide($('deleteFamilyModal'));\n    clearPersistedSession();\n    familyCode = null; myId = null; sessionToken = null; familyData = null;\n    if (pollTimer) clearInterval(pollTimer);\n    hide($('mainScreen'));\n    show($('loginScreen'));\n    showToast('تم حذف العائلة نهائيًا', 'success');\n  } catch (e) {\n    $('deleteFamilyError').textContent = '⚠️ ' + (e.message || 'حصل خطأ، جرب تاني');\n    show($('deleteFamilyError'));\n  } finally {\n    btn.disabled = false;\n    btn.textContent = originalText;\n  }\n};\n\n// ---------- حذف حسابي أنا بس (لأي عضو عادي غير كبير العائلة) ----------\n$('deleteMyAccountBtn').onclick = () => {\n  $('deleteMyAccountPin').value = '';\n  hide($('deleteMyAccountError'));\n  show($('deleteMyAccountModal'));\n};\n$('deleteMyAccountCancelBtn').onclick = () => hide($('deleteMyAccountModal'));\n$('deleteMyAccountConfirmBtn').onclick = async () => {\n  const password = $('deleteMyAccountPin').value;\n  if (!password) {\n    $('deleteMyAccountError').textContent = 'اكتب كلمة سرك للتأكيد';\n    show($('deleteMyAccountError'));\n    return;\n  }\n  const btn = $('deleteMyAccountConfirmBtn');\n  btn.disabled = true;\n  const originalText = btn.textContent;\n  btn.textContent = 'جاري الحذف...';\n  try {\n    await apiCall('/api/member/self-delete', {\n      method: 'POST',\n      body: JSON.stringify({ code: familyCode, memberId: myId, password }),\n    });\n    hide($('deleteMyAccountModal'));\n    clearPersistedSession();\n    familyCode = null; myId = null; sessionToken = null; familyData = null;\n    if (pollTimer) clearInterval(pollTimer);\n    hide($('mainScreen'));\n    show($('loginScreen'));\n    showToast('تم حذف حسابك وبياناتك نهائيًا', 'success');\n  } catch (e) {\n    $('deleteMyAccountError').textContent = '⚠️ ' + (e.message || 'حصل خطأ، جرب تاني');\n    show($('deleteMyAccountError'));\n  } finally {\n    btn.disabled = false;\n    btn.textContent = originalText;\n  }\n};\n\n// ---------- تذكير الأدوية (أداة تذكير بس - مش أداة طبية، وبتتخزن محليًا على الجهاز بس) ----------\nfunction medicationStorageKey() { return 'amanaleilah_meds_' + myId; }\nfunction loadMedicationList() {\n  try { return JSON.parse(localStorage.getItem(medicationStorageKey()) || '[]'); } catch(e) { return []; }\n}\nfunction saveMedicationList(list) {\n  localStorage.setItem(medicationStorageKey(), JSON.stringify(list));\n}\nfunction renderMedicationList() {\n  const box = $('medicationList');\n  const list = loadMedicationList();\n  if (!list.length) {\n    box.innerHTML = '<div style=\"font-size:12px;color:var(--muted);padding:8px 0;\">مفيش تذكيرات دواء مضافة</div>';\n    return;\n  }\n  box.innerHTML = '';\n  list.forEach((med, idx) => {\n    const div = document.createElement('div');\n    div.className = 'member-row';\n    div.innerHTML = `\n      <div class=\"info\"><div><div class=\"name\">${escapeHtml(med.name)}</div><div class=\"rel\">⏰ ${escapeHtml(med.time)} يوميًا</div></div></div>\n      <button class=\"remove-btn\" data-del-med=\"${idx}\">حذف</button>`;\n    box.appendChild(div);\n  });\n  box.querySelectorAll('[data-del-med]').forEach(btn => {\n    btn.onclick = () => {\n      const list = loadMedicationList();\n      list.splice(Number(btn.dataset.delMed), 1);\n      saveMedicationList(list);\n      renderMedicationList();\n    };\n  });\n}\n$('addMedicationBtn').onclick = () => {\n  const name = $('medName').value.trim();\n  const time = $('medTime').value;\n  if (!name || !time) { showToast('اكتب اسم الدواء والمعاد', 'error'); return; }\n  const list = loadMedicationList();\n  list.push({ name, time, lastFired: null });\n  saveMedicationList(list);\n  $('medName').value = ''; $('medTime').value = '';\n  renderMedicationList();\n  showToast('تم إضافة التذكير ✓', 'success');\n};\nfunction loadMedicationReminders() {\n  renderMedicationList();\n  if (Notification && Notification.permission === 'default') {\n    Notification.requestPermission().catch(() => {});\n  }\n}\n// فحص محلي كل دقيقة لمواعيد الأدوية المستحقة - يشتغل بس والتطبيق مفتوح على الجهاز (مفيش سيرفر متضمّن)\nsetInterval(() => {\n  if (!myId) return;\n  const now = new Date();\n  const hhmm = String(now.getHours()).padStart(2,'0') + ':' + String(now.getMinutes()).padStart(2,'0');\n  const todayStr = now.toDateString();\n  const list = loadMedicationList();\n  let changed = false;\n  list.forEach(med => {\n    if (med.time === hhmm && med.lastFired !== todayStr) {\n      med.lastFired = todayStr;\n      changed = true;\n      showToast('💊 معاد ' + med.name, 'success');\n      if (Notification && Notification.permission === 'granted') {\n        try { new Notification('💊 تذكير دواء', { body: 'معاد ' + med.name + ' دلوقتي' }); } catch(e) {}\n      }\n    }\n  });\n  if (changed) saveMedicationList(list);\n}, 60000);\n\n$('adminLogoutBtn').onclick = () => {\n  adminKey = '';\n  sessionStorage.removeItem('adminKey');\n  closeAdminScreen();\n};\n\nasync function loadAdminStats() {\n  try {\n    const s = await adminApiCall('/api/admin/stats', { method: 'GET' });\n    $('adminStats').innerHTML = `\n      <div class=\"admin-stat\"><div class=\"num\">${s.families}</div><div class=\"lbl\">عائلة</div></div>\n      <div class=\"admin-stat\"><div class=\"num\">${s.members}</div><div class=\"lbl\">عضو</div></div>\n      <div class=\"admin-stat\"><div class=\"num\">${s.events}</div><div class=\"lbl\">حدث</div></div>\n      <div class=\"admin-stat\"><div class=\"num\">${s.messages}</div><div class=\"lbl\">رسالة</div></div>\n      <div class=\"admin-stat\"><div class=\"num\" style=\"color:var(--sos)\">${s.sosAlerts}</div><div class=\"lbl\">تنبيه طارئ</div></div>\n    `;\n  } catch (e) { /* ignore */ }\n}\n\n$('adminTabFamilies').onclick = showAdminFamiliesTab;\n$('adminTabEvents').onclick = showAdminEventsTab;\n\nfunction showAdminFamiliesTab() {\n  $('adminTabFamilies').classList.add('active');\n  $('adminTabEvents').classList.remove('active');\n  hide($('adminEventsList'));\n  hide($('adminFamilyDetail'));\n  show($('adminFamiliesList'));\n  loadAdminFamilies();\n}\nasync function showAdminEventsTab() {\n  $('adminTabEvents').classList.add('active');\n  $('adminTabFamilies').classList.remove('active');\n  hide($('adminFamiliesList'));\n  hide($('adminFamilyDetail'));\n  show($('adminEventsList'));\n  await loadAdminEvents();\n}\n\nasync function loadAdminFamilies() {\n  try {\n    const data = await adminApiCall('/api/admin/families', { method: 'GET' });\n    if (!data.families.length) {\n      $('adminFamiliesList').innerHTML = '<div class=\"empty-feed\">مفيش عائلات لسه</div>';\n      return;\n    }\n    $('adminFamiliesList').innerHTML = data.families.map(f => `\n      <div class=\"admin-fam-row\" data-code=\"${f.code}\">\n        <div class=\"code\">${f.code}</div>\n        <div class=\"meta\">${f.admin_name || 'بدون كبير عائلة'} · ${f.member_count} عضو · ${new Date(f.created_at).toLocaleDateString('ar-EG')}</div>\n      </div>\n    `).join('');\n    $('adminFamiliesList').querySelectorAll('.admin-fam-row').forEach(row => {\n      row.onclick = () => openAdminFamilyDetail(row.dataset.code);\n    });\n  } catch (e) { $('adminFamiliesList').innerHTML = '<div class=\"empty-feed\">حصل خطأ</div>'; }\n}\n\nasync function openAdminFamilyDetail(code) {\n  adminActiveFamily = code;\n  hide($('adminFamiliesList'));\n  show($('adminFamilyDetail'));\n  $('adminFamilyDetailContent').innerHTML = 'جارِ التحميل...';\n  try {\n    const data = await adminApiCall('/api/admin/family/' + code, { method: 'GET' });\n    const f = data.family;\n    $('adminFamilyDetailContent').innerHTML = `\n      <h3 style=\"margin-bottom:4px;\">كود العائلة: ${f.code}</h3>\n      <div style=\"color:var(--muted); font-size:12.5px; margin-bottom:14px;\">\n        ${data.eventCount} حدث · ${data.messageCount} رسالة · اتعملت في ${new Date(f.createdAt).toLocaleDateString('ar-EG')}\n      </div>\n      <button class=\"admin-del-btn\" id=\"adminDeleteFamilyBtn\" style=\"margin-bottom:16px;\">🗑 حذف العائلة بالكامل</button>\n      <div class=\"section-title\">الأعضاء</div>\n      ${f.members.map(m => `\n        <div class=\"member-row\">\n          <div class=\"info\">\n            <div><div class=\"name\">${m.isAdmin ? '<span class=\"admin-badge\">كبير العائلة</span>' : ''}${m.name}</div><div class=\"rel\">${m.relation} · ${m.status === 'pending' ? 'معلّق' : 'مفعّل'}</div></div>\n          </div>\n          <button class=\"admin-del-btn\" data-mid=\"${m.id}\">حذف</button>\n        </div>\n      `).join('')}\n    `;\n    $('adminDeleteFamilyBtn').onclick = async () => {\n      if (!confirm('متأكد إنك عاوز تمسح العائلة دي بكل بياناتها؟ الإجراء ده مش هيترجع.')) return;\n      await adminApiCall('/api/admin/family/' + code, { method: 'DELETE' });\n      showAdminFamiliesTab();\n      loadAdminStats();\n    };\n    $('adminFamilyDetailContent').querySelectorAll('button[data-mid]').forEach(btn => {\n      btn.onclick = async () => {\n        if (!confirm('متأكد إنك عاوز تمسح العضو ده؟')) return;\n        await adminApiCall('/api/admin/member/' + btn.dataset.mid, { method: 'DELETE' });\n        openAdminFamilyDetail(code);\n        loadAdminStats();\n      };\n    });\n  } catch (e) {\n    $('adminFamilyDetailContent').innerHTML = '<div class=\"empty-feed\">حصل خطأ في التحميل</div>';\n  }\n}\n\n$('adminBackToFamilies').onclick = showAdminFamiliesTab;\n\nasync function loadAdminEvents() {\n  $('adminEventsList').innerHTML = 'جارِ التحميل...';\n  try {\n    const data = await adminApiCall('/api/admin/events?limit=80', { method: 'GET' });\n    if (!data.events.length) {\n      $('adminEventsList').innerHTML = '<div class=\"empty-feed\">مفيش أحداث لسه</div>';\n      return;\n    }\n    $('adminEventsList').innerHTML = data.events.map(e => `\n      <div class=\"admin-event-row\">\n        <span class=\"code\">${e.familyCode}</span> — ${e.memberName}\n        (${e.type === 'sos' ? '🔴 طارئ' : e.type === 'safe' ? '🟢 اطمئنان' : '🟡 ' + (e.occasionType || 'مناسبة')})\n        ${e.text ? ' — ' + e.text : ''}\n        <div class=\"admin-event-row\" style=\"background:none;padding:2px 0;color:var(--muted);font-size:11px;\">${new Date(e.timestamp).toLocaleString('ar-EG')}</div>\n      </div>\n    `).join('');\n  } catch (e) { $('adminEventsList').innerHTML = '<div class=\"empty-feed\">حصل خطأ</div>'; }\n}\n\n// ---------- تثبيت التطبيق على الشاشة الرئيسية (يشتغل تلقائيًا حسب نوع المتصفح) ----------\nlet deferredInstallPrompt = null;\nwindow.addEventListener('beforeinstallprompt', (e) => {\n  e.preventDefault();\n  deferredInstallPrompt = e;\n  show($('installAppBtn'));\n  $('installBanner').textContent = '📲 التطبيق جاهز للتثبيت! دوس على الزرار تحت.';\n});\n\n$('installAppBtn').onclick = async () => {\n  if (!deferredInstallPrompt) return;\n  deferredInstallPrompt.prompt();\n  await deferredInstallPrompt.userChoice;\n  deferredInstallPrompt = null;\n  hide($('installAppBtn'));\n};\n\nfunction setupInstallBanner() {\n  const isStandalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;\n  if (isStandalone) {\n    $('installBanner').textContent = '✅ التطبيق مثبّت بالفعل على جهازك.';\n    return;\n  }\n  const ua = navigator.userAgent;\n  const isIOS = /iPad|iPhone|iPod/.test(ua) && !window.MSStream;\n  const isAndroid = /Android/.test(ua);\n  if (isIOS) {\n    $('installBanner').textContent = 'لتثبيت التطبيق على آيفون: دوس على زرار المشاركة 📤 تحت في Safari، وبعدين اختار \\\"Add to Home Screen\\\".';\n  } else if (isAndroid) {\n    $('installBanner').textContent = 'لو زرار التثبيت مش ظاهر تحت، افتح قائمة المتصفح (⋮) واختار \\\"تثبيت التطبيق\\\" أو \\\"Add to Home screen\\\".';\n  } else {\n    $('installBanner').textContent = 'افتح الموقع من موبايلك (Chrome أو Safari) عشان تقدر تثبته على الشاشة الرئيسية زي أي تطبيق عادي.';\n  }\n}\n\n(function initApp() {\n  applyDarkMode(loadDarkMode());\n  setupInstallBanner();\n\n  // تسجيل الـ Service Worker بدري عشان التطبيق يفتح حتى لو النت ضعيف أو مقطوع (PWA حقيقي)\n  if ('serviceWorker' in navigator) {\n    navigator.serviceWorker.register('/sw.js').catch(() => {});\n  }\n\n  const saved = loadPersistedSession();\n  if (saved && saved.familyCode && saved.myId) {\n    familyCode = saved.familyCode;\n    myId = saved.myId;\n    sessionToken = saved.sessionToken || null;\n    startApp();\n  } else {\n    show($('loginScreen'));\n  }\n})();\n</script>\n</body>\n</html>";

// صفحة عامة (متاحة لأي حد من غير تسجيل دخول أو تثبيت التطبيق) لطلب حذف الحساب أو العائلة نهائيًا.
// مطلوبة عشان تستوفي شرط "طريقة حذف الحساب من غير الحاجة لتثبيت التطبيق" في Google Play.
// صفحة سياسة الخصوصية - حية على رابط ثابت من غير أي استضافة منفصلة (/privacy-policy).
// ده الرابط اللي تحطه في نموذج "أمان البيانات" على Google Play Console.
const PRIVACY_POLICY_HTML = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>سياسة الخصوصية - أمان العيلة</title>
<style>
  body { font-family: 'IBM Plex Sans Arabic', Tahoma, sans-serif; background:#F6F2FE; color:#241D33; max-width:640px; margin:0 auto; padding:32px 20px 70px; line-height:1.8; }
  h1 { font-size:24px; margin-bottom:4px; }
  .updated { font-size:12.5px; color:#8a7fa8; margin-bottom:28px; }
  h2 { font-size:17px; color:#7C3AED; margin:30px 0 10px; border-right:3px solid #7C3AED; padding-right:10px; }
  p, li { font-size:14.5px; color:#4a4458; }
  table { width:100%; border-collapse:collapse; margin:12px 0; font-size:13.5px; }
  th, td { border:1px solid #E4D9FA; padding:8px 10px; text-align:right; }
  th { background:#EEF2FF; }
  ul { padding-right:20px; }
  strong { color:#241D33; }
  .box { background:#EEF2FF; border:1px solid #7C3AED; border-radius:10px; padding:14px 16px; margin:14px 0; font-size:13.5px; }
  a { color:#7C3AED; }
  hr { border:none; border-top:1px solid #E4D9FA; margin:26px 0; }
  footer { font-size:12px; color:#8a7fa8; margin-top:30px; text-align:center; }
</style>
</head>
<body>
  <h1>سياسة الخصوصية - تطبيق "أمان العيلة"</h1>
  <div class="updated">آخر تحديث: PRIVACY_POLICY_DATE_PLACEHOLDER</div>

  <h2>1. من يستخدم هذا التطبيق</h2>
  <p>تطبيق "أمان العيلة" مخصص <strong>للبالغين فقط (18 سنة فأكثر)</strong>. لا يتم استهداف الأطفال أو القاصرين، ولا يجوز لأي شخص أقل من 18 سنة استخدام التطبيق أو الانضمام إليه. لا نجمع عن قصد أي بيانات من أشخاص أقل من 18 سنة.</p>

  <h2>2. البيانات التي نجمعها</h2>
  <table>
    <tr><th>البيانات</th><th>متى تُجمع</th><th>الغرض</th></tr>
    <tr><td>الاسم (أو اسم مستعار من اختيارك)</td><td>عند إنشاء عائلة أو الانضمام لها</td><td>تعريف العضو لعائلته، واسترجاع كلمة السر عند الحاجة</td></tr>
    <tr><td>صلة القرابة</td><td>عند التسجيل</td><td>عرضها لباقي أفراد العائلة</td></tr>
    <tr><td>كلمة سر</td><td>عند التسجيل</td><td>حماية الدخول (تُخزَّن مشفّرة)</td></tr>
    <tr><td>سؤالا أمان وإجابتاهما</td><td>عند التسجيل</td><td>استرجاع كلمة السر ذاتيًا (الإجابات مشفّرة)</td></tr>
    <tr><td>الموقع الجغرافي</td><td>فقط عند ضغطك على "شارك موقعي"</td><td>إعلام عائلتك طوعيًا</td></tr>
    <tr><td>محتوى الشات</td><td>عند إرسال رسالة</td><td>التواصل بين أفراد العائلة</td></tr>
    <tr><td>تذكير الأدوية</td><td>عند إضافة تذكير</td><td>يُخزَّن على جهازك فقط، ولا يُرسَل لسيرفراتنا إطلاقًا</td></tr>
  </table>
  <div class="box">لا يتم جمع رقم هاتفك أو بريدك الإلكتروني في أي مرحلة. تسجيل الدخول اليومي يتم بكود العائلة + كلمة السر فقط.<br><br><strong>التطبيق لا يشترط اسمك الحقيقي إطلاقًا</strong> - تقدر تسجّل بأي اسم مستعار تحب تظهر بيه لعائلتك. الاسم بيُستخدم لعرضك لباقي أفراد عائلتك، ولاسترجاع كلمة السر عن طريق سؤالي الأمان لو نسيتها يومًا.</div>

  <h2>3. البيانات التي لا نجمعها أبدًا</h2>
  <ul>
    <li>لا تتبع مستمر أو تلقائي لموقعك، ولا تحديث للموقع في الخلفية</li>
    <li>لا سجل مسارات أو تاريخ تحركات، ولا مراقبة لنشاطك</li>
    <li>لا تسجيل صوت أو فيديو تلقائي</li>
    <li>لا موقع مع زر الطوارئ أو زر الاطمئنان (نص فقط)</li>
    <li>لا بيانات من أي شخص أقل من 18 سنة</li>
  </ul>

  <h2>4. كيف نستخدم بياناتك</h2>
  <p>بياناتك تُستخدم <strong>حصريًا</strong> داخل مجموعة عائلتك المغلقة، لتعريفك لأفراد عائلتك وتفعيل ميزات التواصل والاطمئنان وتسجيل دخولك بأمان. لا نستخدم بياناتك لأي غرض إعلاني أو تسويقي، ولا نُجري أي تحليل لمحتوى محادثاتك.</p>

  <h2>5. مشاركة البيانات مع أطراف ثالثة</h2>
  <p><strong>لا نبيع بياناتك لأي طرف ثالث تحت أي ظرف.</strong> لا نشارك بياناتك مع أي جهة خارج التطبيق، باستثناء ما يلزم تقنيًا لتشغيل الخدمة (مزوّد الاستضافة السحابية Cloudflare)، والذي لا يستخدم بياناتك لأي غرض خاص به.</p>

  <h2>6. التشفير وحماية البيانات</h2>
  <ul>
    <li><strong>الموقع الجغرافي</strong> يُشفَّر (AES-GCM) قبل التخزين</li>
    <li><strong>الشات الخاص</strong> مشفّر من طرف لطرف - حتى فريقنا لا يقدر يقرأه</li>
    <li><strong>كلمة السر وإجابات سؤالي الأمان</strong> تُخزَّن بصيغة مُجزَّأة (hashed) ولا نستطيع الاطلاع عليها</li>
  </ul>

  <h2>7. مدة الاحتفاظ بالبيانات</h2>
  <p>رسائل الشات وأحداث الحالة (طوارئ/اطمئنان/موقع/مناسبات) تُحذف تلقائيًا بعد <strong>30 يومًا</strong> من تاريخها. بيانات العائلة والأعضاء الأساسية تبقى محفوظة طالما الحساب نشطًا، ويمكن حذفها بالكامل في أي وقت.</p>

  <h2>8. حقوق المستخدم</h2>
  <ul>
    <li>طلب الاطلاع على نسخة من بياناتك (بالتواصل معنا على البريد أدناه)</li>
    <li>طلب تصحيح أي بيانات غير دقيقة</li>
    <li>سحب موافقتك على جمع بياناتك</li>
    <li>طلب حذف حسابك أو بيانات عائلتك بالكامل، ذاتيًا وفوريًا من داخل التطبيق</li>
  </ul>

  <h2>9. حذف الحساب أو العائلة بالكامل</h2>
  <p>أي عضو يقدر يحذف حسابه فورًا من داخل التطبيق (الإعدادات ← "احذف حسابي نهائيًا")، أو من رابط عام بدون تثبيت التطبيق: <a href="/account-deletion">/account-deletion</a>. الطلب من الرابط العام بينفّذ بعد 24 ساعة وممكن إلغاؤه خلالها. كبير العائلة (أو نائبه) يقدر يحذف العائلة بالكامل فورًا من داخل التطبيق بتحقق ثانوي. الحذف الفعلي كامل ولا يمكن التراجع عنه.</p>

  <h2>10. الأطفال والقاصرين</h2>
  <p>هذا التطبيق غير موجّه للأطفال أو القاصرين إطلاقًا. لا نجمع بيانات أي شخص نعلم أنه أقل من 18 سنة. إذا علمنا بوجود بيانات لشخص قاصر، سنقوم بحذفها فورًا.</p>

  <h2>11. التبليغ عن اختراق البيانات</h2>
  <p>في حال وقوع أي اختراق لبياناتك، سيتم إخطار الجهة المختصة بحماية البيانات خلال 72 ساعة، وإخطارك خلال 3 أيام عمل من اكتشاف الاختراق.</p>

  <h2>12. التغييرات على هذه السياسة</h2>
  <p>قد نقوم بتحديث هذه السياسة من وقت لآخر لتحسين الخدمة أو الالتزام بمتطلبات قانونية جديدة. سيتم إخطارك بأي تغيير جوهري داخل التطبيق.</p>

  <h2>13. تواصل معنا</h2>
  <p>البريد الإلكتروني: <strong>PRIVACY_CONTACT_EMAIL_PLACEHOLDER</strong><br>الجهة المسؤولة: <strong>PRIVACY_DEVELOPER_NAME_PLACEHOLDER</strong></p>

  <hr>
  <footer>هذه السياسة تخضع لأحكام قانون حماية البيانات الشخصية المصري (القانون رقم 151 لسنة 2020) والتشريعات ذات الصلة.</footer>
</body>
</html>`;

const ACCOUNT_DELETION_HTML = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>حذف الحساب - أمان العيلة</title>
<style>
  body { font-family: 'IBM Plex Sans Arabic', Tahoma, sans-serif; background:#F6F2FE; color:#241D33; max-width:480px; margin:0 auto; padding:24px 18px 60px; }
  h1 { font-size:22px; margin-bottom:6px; }
  h2 { font-size:16px; margin-top:32px; }
  p { line-height:1.8; font-size:14px; color:#4a4458; }
  .field { margin:14px 0; }
  label { display:block; font-size:13px; margin-bottom:6px; color:#4a4458; }
  input, select { width:100%; padding:12px 14px; border-radius:10px; border:1px solid #E4D9FA; font-size:16px; box-sizing:border-box; }
  button { width:100%; padding:14px; border:none; border-radius:12px; background:#7C3AED; color:#fff; font-weight:700; font-size:15px; cursor:pointer; margin-top:10px; }
  button.secondary { background:#fff; color:#7C3AED; border:1px solid #7C3AED; }
  .note { background:#FDEAEA; border:1px solid #EF4444; border-radius:10px; padding:12px 14px; font-size:13px; color:#7a1f1f; margin:16px 0; }
  .info-note { background:#EEF2FF; border:1px solid #7C3AED; border-radius:10px; padding:12px 14px; font-size:13px; color:#3d2a80; margin:16px 0; }
  #result, #cancelResult { margin-top:14px; font-size:14px; white-space:pre-line; }
  .ok { color:#0f7a4d; }
  .err { color:#EF4444; }
  hr { border:none; border-top:1px solid #E4D9FA; margin:30px 0; }
</style>
</head>
<body>
  <h1>🗑️ حذف الحساب أو بيانات العائلة</h1>
  <p>تقدر تستخدم الصفحة دي لطلب حذف حسابك (أو العائلة بالكامل لو انت كبير العائلة) نهائيًا من "أمان العيلة"، حتى لو مش عندك التطبيق مثبّت.</p>
  <div class="info-note">⏱️ الطلب مش بينفّذ فورًا - بيتنفذ تلقائيًا بعد <strong>24 ساعة</strong> من تقديمه. تقدر تلغي الطلب خلال المهلة دي من نفس الصفحة (تحت) أو من داخل التطبيق لو دخلت بحسابك.</div>
  <div class="note">لو انت عضو عادي: هيتم حذف بياناتك الشخصية بس (رسايلك، أحداثك، محادثاتك الخاصة). لو انت كبير العائلة: هيتم حذف العائلة بالكامل لكل الأعضاء، لأنك المسؤول الوحيد عنها.</div>
  <div class="field">
    <label>كود العائلة</label>
    <input type="text" id="code" placeholder="مثال: ABC123" style="text-transform:uppercase;">
  </div>
  <button class="secondary" id="loadMembersBtn" style="margin-top:0;">تحميل قائمة الأعضاء</button>
  <div class="field hidden-field" id="memberFieldWrap" style="display:none;">
    <label>مين حضرتك؟</label>
    <select id="memberSelect"></select>
  </div>
  <div class="field hidden-field" id="passwordFieldWrap" style="display:none;">
    <label>كلمة السر</label>
    <input type="password" id="password">
  </div>
  <button id="submitBtn" style="display:none;">تقديم طلب الحذف</button>
  <div id="result"></div>

  <hr>
  <h2>لغيت رأيك؟ إلغِ طلب حذف قدّمته قبل كده</h2>
  <p>اختار اسمك من القائمة فوق (بعد تحميلها بكود العائلة)، ثم اضغط إلغاء - من غير ما تحتاج تكتب كلمة السر تاني.</p>
  <button class="secondary" id="cancelBtn" style="display:none;">إلغاء طلب الحذف المعلّق</button>
  <div id="cancelResult"></div>

<script>
var loadedMembers = [];
document.getElementById('loadMembersBtn').onclick = async function() {
  var code = document.getElementById('code').value.trim().toUpperCase();
  var resultBox = document.getElementById('result');
  if (!code) { resultBox.className = 'err'; resultBox.textContent = 'اكتب كود العائلة الأول.'; return; }
  var btn = document.getElementById('loadMembersBtn');
  btn.disabled = true; btn.textContent = 'جاري التحميل...';
  try {
    var res = await fetch('/api/family/' + code + '/members-lite');
    var data = await res.json();
    if (!res.ok) throw new Error(data.error || 'كود العائلة غير صحيح');
    loadedMembers = data.members || [];
    var select = document.getElementById('memberSelect');
    select.innerHTML = '';
    loadedMembers.forEach(function(m) {
      var opt = document.createElement('option');
      opt.value = m.id;
      opt.textContent = m.name + ' (' + m.relation + ')';
      select.appendChild(opt);
    });
    document.getElementById('memberFieldWrap').style.display = 'block';
    document.getElementById('passwordFieldWrap').style.display = 'block';
    document.getElementById('submitBtn').style.display = 'block';
    document.getElementById('cancelBtn').style.display = 'block';
    resultBox.className = 'ok'; resultBox.textContent = '✓ تم تحميل الأعضاء، اختار اسمك تحت.';
  } catch (e) {
    resultBox.className = 'err'; resultBox.textContent = '⚠️ ' + e.message;
  } finally {
    btn.disabled = false; btn.textContent = 'تحميل قائمة الأعضاء';
  }
};

document.getElementById('submitBtn').onclick = async function() {
  var code = document.getElementById('code').value.trim().toUpperCase();
  var memberId = document.getElementById('memberSelect').value;
  var password = document.getElementById('password').value;
  var resultBox = document.getElementById('result');
  if (!code || !memberId || !password) {
    resultBox.className = 'err'; resultBox.textContent = 'من فضلك اكمل كل الحقول.';
    return;
  }
  if (!confirm('متأكد إنك عايز تقدّم طلب حذف بياناتك؟ هيتنفذ خلال 24 ساعة إلا لو ألغيته.')) return;
  var btn = document.getElementById('submitBtn');
  btn.disabled = true; btn.textContent = 'جاري تقديم الطلب...';
  try {
    var res = await fetch('/api/account/delete-request', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: code, memberId: memberId, password: password })
    });
    var data = await res.json();
    if (!res.ok) throw new Error(data.error || 'حصل خطأ');
    var when = data.executeAt ? new Date(data.executeAt).toLocaleString('ar-EG') : '';
    resultBox.className = 'ok';
    resultBox.textContent = data.alreadyPending
      ? '✓ عندك طلب حذف معلّق بالفعل، هيتنفذ حوالي ' + when
      : '✓ تم تقديم طلب الحذف. هيتنفذ تلقائيًا حوالي ' + when + '. تقدر تلغيه في أي وقت قبل كده من تحت.';
  } catch (e) {
    resultBox.className = 'err';
    resultBox.textContent = '⚠️ ' + e.message;
  } finally {
    btn.disabled = false; btn.textContent = 'تقديم طلب الحذف';
  }
};

document.getElementById('cancelBtn').onclick = async function() {
  var code = document.getElementById('code').value.trim().toUpperCase();
  var memberId = document.getElementById('memberSelect').value;
  var resultBox = document.getElementById('cancelResult');
  if (!code || !memberId) {
    resultBox.className = 'err'; resultBox.textContent = 'حمّل قائمة الأعضاء واختار اسمك فوق الأول.';
    return;
  }
  var btn = document.getElementById('cancelBtn');
  btn.disabled = true; btn.textContent = 'جاري الإلغاء...';
  try {
    var res = await fetch('/api/account/cancel-deletion', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: code, memberId: memberId })
    });
    var data = await res.json();
    if (!res.ok) throw new Error(data.error || 'حصل خطأ');
    resultBox.className = 'ok';
    resultBox.textContent = '✓ تم إلغاء طلب الحذف (لو كان فيه طلب معلّق أصلاً).';
  } catch (e) {
    resultBox.className = 'err';
    resultBox.textContent = '⚠️ ' + e.message;
  } finally {
    btn.disabled = false; btn.textContent = 'إلغاء طلب الحذف المعلّق';
  }
};
</script>
</body>
</html>`;

// ================= تكرار إنذار الاستغاثة كل 30 ثانية لحد ما حد من العائلة يشوفه =================
// الـ Workers العادية مالهاش "مؤقّت" بيفضل شغال من غير طلب جديد، فبنستخدم Durable Object
// مع alarm() اللي بتقدر تجدول نفسها كل 30 ثانية بدقة، وتوقف نفسها لما حد يأكد إنه شاف النداء.
export class SosAlarm {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/start' && request.method === 'POST') {
      const data = await request.json(); // { familyCode, memberName, excludeMemberId }
      await this.state.storage.put('data', data);
      await this.state.storage.put('attempts', 0);
      await this.state.storage.put('acknowledged', false);
      await this.state.storage.setAlarm(Date.now() + 30000);
      return new Response('ok');
    }
    if (url.pathname === '/acknowledge' && request.method === 'POST') {
      await this.state.storage.put('acknowledged', true);
      return new Response('ok');
    }
    return new Response('not found', { status: 404 });
  }
  async alarm() {
    const acknowledged = await this.state.storage.get('acknowledged');
    if (acknowledged) return; // حد شاف النداء بالفعل - نوقف التكرار
    const attempts = (await this.state.storage.get('attempts')) || 0;
    const MAX_ATTEMPTS = 20; // 20 مرة × 30 ثانية = 10 دقايق كحد أقصى، عشان منزعجش الناس للأبد لو محدش شاف الإشعار خالص
    if (attempts >= MAX_ATTEMPTS) return;
    const data = await this.state.storage.get('data');
    if (!data) return;
    try {
      const { results } = await this.env.DB.prepare(
        'SELECT * FROM push_subscriptions WHERE family_code = ? AND member_id != ?'
      ).bind(data.familyCode, data.excludeMemberId || '').all();
      const payload = {
        title: '🆘 لسه محتاج مساعدة!',
        body: data.memberName + ' لسه مستني حد يشوف طلب المساعدة',
        url: '/',
      };
      await Promise.all(results.map(row => sendWebPush(this.env, {
        endpoint: row.endpoint,
        keys: { p256dh: row.p256dh, auth: row.auth },
      }, payload).catch(() => {})));
    } catch (e) { /* لو حصل خطأ، لسه هنحاول تاني بعد 30 ثانية */ }
    await this.state.storage.put('attempts', attempts + 1);
    await this.state.storage.setAlarm(Date.now() + 30000);
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    // ---------- عرض صفحة الموقع نفسها ----------
    // Cache-Control: no-store مهم جدًا هنا - من غيره المتصفح ممكن "يقصّر" ويورّي نسخة قديمة
    // من الصفحة (بكود جافاسكريبت قديم فيه باجات) حتى بعد ما تعمل deploy لنسخة جديدة تمامًا.
    if (path === '/' && method === 'GET') {
      return new Response(INDEX_HTML, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }

    // ---------- ملف الـ Service Worker (لازم للإشعارات الحقيقية) ----------
    if (path === '/manifest.json' && method === 'GET') {
      return new Response(MANIFEST_JSON, {
        status: 200,
        headers: { 'Content-Type': 'application/manifest+json; charset=utf-8', 'Cache-Control': 'public, max-age=86400' },
      });
    }
    if (path === '/icon-192.png' && method === 'GET') {
      return new Response(base64ToBytes(ICON_192_B64), { status: 200, headers: { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=604800' } });
    }
    if (path === '/icon-512.png' && method === 'GET') {
      return new Response(base64ToBytes(ICON_512_B64), { status: 200, headers: { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=604800' } });
    }
    if (path === '/icon-512-maskable.png' && method === 'GET') {
      return new Response(base64ToBytes(ICON_512_MASKABLE_B64), { status: 200, headers: { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=604800' } });
    }

    if (path === '/sw.js' && method === 'GET') {
      return new Response(SERVICE_WORKER_JS, {
        status: 200,
        headers: { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }

    try {
      // ---------- لوحة التحكم (Admin) ----------
      if (path.startsWith('/api/admin/')) {
        if (!checkAdminAuth(request, env)) {
          return json({ error: 'مفتاح الإدارة غلط أو مفقود' }, 401);
        }

        // إحصائيات عامة
        if (path === '/api/admin/stats' && method === 'GET') {
          const famCount = await env.DB.prepare('SELECT COUNT(*) as c FROM families').first();
          const memCount = await env.DB.prepare('SELECT COUNT(*) as c FROM members').first();
          const evtCount = await env.DB.prepare('SELECT COUNT(*) as c FROM events').first();
          const msgCount = await env.DB.prepare('SELECT COUNT(*) as c FROM chat_messages').first();
          const sosCount = await env.DB.prepare("SELECT COUNT(*) as c FROM events WHERE type = 'sos'").first();
          return json({
            families: famCount.c, members: memCount.c, events: evtCount.c,
            messages: msgCount.c, sosAlerts: sosCount.c,
          });
        }

        // قائمة كل العائلات + عدد الأعضاء
        if (path === '/api/admin/families' && method === 'GET') {
          const { results } = await env.DB.prepare(`
            SELECT f.code, f.created_at,
              (SELECT COUNT(*) FROM members m WHERE m.family_code = f.code) as member_count,
              (SELECT name FROM members m WHERE m.family_code = f.code AND m.is_admin = 1 LIMIT 1) as admin_name
            FROM families f ORDER BY f.created_at DESC
          `).all();
          return json({ families: results });
        }

        // تفاصيل عائلة واحدة (أعضاء + عدد أحداث/رسائل)
        const famDetailMatch = path.match(/^\/api\/admin\/family\/([A-Z0-9]+)$/);
        if (famDetailMatch && method === 'GET') {
          const code = famDetailMatch[1];
          const family = await getFamilyWithMembers(env.DB, code);
          if (!family) return json({ error: 'مش موجودة' }, 404);
          const evtCount = await env.DB.prepare('SELECT COUNT(*) as c FROM events WHERE family_code = ?').bind(code).first();
          const msgCount = await env.DB.prepare('SELECT COUNT(*) as c FROM chat_messages WHERE family_code = ?').bind(code).first();
          return json({ family, eventCount: evtCount.c, messageCount: msgCount.c });
        }

        // حذف عائلة بالكامل
        if (famDetailMatch && method === 'DELETE') {
          const code = famDetailMatch[1];
          // نمسح ملفات الوسائط من R2 الأول
          const { results: mediaRows } = await env.DB.prepare(
            "SELECT media_key FROM chat_messages WHERE family_code = ? AND media_key IS NOT NULL"
          ).bind(code).all();
          for (const row of mediaRows) {
            await env.MEDIA.delete(row.media_key).catch(() => {});
          }
          await env.DB.prepare('DELETE FROM chat_messages WHERE family_code = ?').bind(code).run();
          await env.DB.prepare('DELETE FROM events WHERE family_code = ?').bind(code).run();
          await env.DB.prepare('DELETE FROM members WHERE family_code = ?').bind(code).run();
          await env.DB.prepare('DELETE FROM families WHERE code = ?').bind(code).run();
          return json({ deleted: true });
        }

        // حذف عضو واحد من أي عائلة (بدون شرط كبير العائلة - ده مفتاح إدارة عام)
        const memberDeleteMatch = path.match(/^\/api\/admin\/member\/([^/]+)$/);
        if (memberDeleteMatch && method === 'DELETE') {
          await env.DB.prepare('DELETE FROM members WHERE id = ?').bind(memberDeleteMatch[1]).run();
          return json({ deleted: true });
        }

        // آخر الأحداث في كل العائلات (لمراقبة عامة، مفيد لتنبيهات SOS)
        if (path === '/api/admin/events' && method === 'GET') {
          const limit = parseInt(url.searchParams.get('limit') || '50', 10);
          const { results } = await env.DB.prepare(
            'SELECT * FROM events ORDER BY timestamp DESC LIMIT ?'
          ).bind(limit).all();
          const decryptedEvents = await Promise.all(results.map(async e => ({
            id: e.id, familyCode: e.family_code, type: e.type, occasionType: e.occasion_type,
            memberName: e.member_name, text: e.text, lat: await decryptGeo(env, e.lat), lng: await decryptGeo(env, e.lng),
            accuracy: e.accuracy, timestamp: e.timestamp,
          })));
          return json({ events: decryptedEvents });
        }

        // تشغيل يدوي لحذف البيانات القديمة (نفس اللي بيحصل تلقائيًا كل يوم - مفيد للتجربة أو التشغيل الفوري)
        if (path === '/api/admin/cleanup' && method === 'POST') {
          const result = await cleanupOldData(env);
          return json({ ok: true, ...result });
        }

        return json({ error: 'not found' }, 404);
      }

      // ---------- إنشاء عائلة جديدة ----------
      if (path === '/api/family/create' && method === 'POST') {
        if (!(await checkAuthRateLimit(request, env))) {
          return json({ error: 'محاولات كتير أوي، حاول تاني بعد شوية' }, 429);
        }
        const body = await request.json();
        const { name, relation, consent, ageConfirm, password, securityQuestion1, securityAnswer1, securityQuestion2, securityAnswer2 } = body;
        if (!name) return json({ error: 'الاسم مطلوب' }, 400);
        if (consent !== true) return json({ error: 'يجب الموافقة على شروط استخدام البيانات أولاً' }, 400);
        if (ageConfirm !== true) return json({ error: 'لازم تأكد إنك بلغت 18 سنة على الأقل عشان تنشئ عائلة' }, 400);
        if (!password || password.length < 6) return json({ error: 'كلمة السر لازم تكون 6 حروف أو أرقام على الأقل' }, 400);
        if (!SECURITY_QUESTIONS.includes(securityQuestion1) || !SECURITY_QUESTIONS.includes(securityQuestion2)) {
          return json({ error: 'اختار سؤالي أمان من القائمة' }, 400);
        }
        if (securityQuestion1 === securityQuestion2) return json({ error: 'اختار سؤالين مختلفين عن بعض' }, 400);
        if (!securityAnswer1 || !securityAnswer1.trim() || !securityAnswer2 || !securityAnswer2.trim()) {
          return json({ error: 'لازم تكتب إجابة السؤالين الاتنين' }, 400);
        }

        let code = genCode();
        for (let i = 0; i < 8; i++) {
          const exists = await env.DB.prepare('SELECT code FROM families WHERE code = ?').bind(code).first();
          if (!exists) break;
          code = genCode();
        }

        const now = Date.now();
        await env.DB.prepare('INSERT INTO families (code, created_at) VALUES (?, ?)').bind(code, now).run();

        const id = genId('m');
        const passwordHash = await hashSecret(password);
        const answerHash1 = await hashSecret(normalizeSecurityAnswer(securityAnswer1));
        const answerHash2 = await hashSecret(normalizeSecurityAnswer(securityAnswer2));
        await env.DB.prepare(
          `INSERT INTO members (id, family_code, name, phone, relation, role, is_admin, is_founder, status, circle, pin_hash, security_question, security_answer_hash, security_question_2, security_answer_hash_2, age_confirmed, consent_at, created_at)
           VALUES (?, ?, ?, '', ?, 'parent', 1, 1, 'approved', '[]', ?, ?, ?, ?, ?, 1, ?, ?)`
        ).bind(id, code, name, relation, passwordHash, securityQuestion1, answerHash1, securityQuestion2, answerHash2, now, now).run();

        const family = await getFamilyWithMembers(env.DB, code);
        const sessionToken = await createSessionToken(env, code, id);
        return json({ family, myId: id, sessionToken });
      }

      // ---------- قايمة أسماء أفراد عائلة (بدون بيانات حساسة) عشان تختار مين هيدخل قبل ما تكتب الـ PIN ----------
      const membersLiteMatch = path.match(/^\/api\/family\/([A-Z0-9]+)\/members-lite$/);
      if (membersLiteMatch && method === 'GET') {
        const { results } = await env.DB.prepare(
          'SELECT id, name, relation, is_admin, pin_hash, status FROM members WHERE family_code = ?'
        ).bind(membersLiteMatch[1]).all();
        if (!results.length) return json({ error: 'كود العائلة غير صحيح' }, 404);
        return json({ members: results.filter(m => m.status !== 'pending').map(m => ({
          id: m.id, name: m.name, relation: m.relation, isAdmin: !!m.is_admin, hasPin: !!m.pin_hash,
        })) });
      }

      // ---------- تسجيل دخول (عضو موجود) - بكلمة السر ----------
      // تسجيل الدخول بكود العائلة وكلمة السر بس - من غير اسم، عشان نتفادى مشاكل عدم تطابق كتابة
      // الاسم بالظبط (مسافات زيادة، شكل حروف عربي مختلف شكليًا، إلخ). بندوّر على العضو اللي
      // كلمة السر دي بتاعته من بين كل أعضاء العائلة المعتمدين.
      if (path === '/api/family/login' && method === 'POST') {
        if (!(await checkAuthRateLimit(request, env))) {
          return json({ error: 'محاولات كتير أوي، حاول تاني بعد شوية' }, 429);
        }
        const { code, password } = await request.json();
        const upperCode = (code || '').toUpperCase();
        if (!password) return json({ error: 'اكتب كلمة السر' }, 400);
        const { results: members } = await env.DB.prepare(
          "SELECT * FROM members WHERE family_code = ? AND status != 'pending' AND pin_hash IS NOT NULL"
        ).bind(upperCode).all();
        if (!members.length) return json({ error: 'كود العائلة أو كلمة السر غلط' }, 404);
        let matched = null;
        for (const m of members) {
          if (await verifySecret(password, m.pin_hash)) { matched = m; break; }
        }
        if (!matched) return json({ error: 'كود العائلة أو كلمة السر غلط' }, 401);
        const family = await getFamilyWithMembers(env.DB, upperCode);
        const sessionToken = await createSessionToken(env, upperCode, matched.id);
        return json({ family, myId: matched.id, sessionToken });
      }

      // ---------- تحديد كلمة سر لأول مرة (مسار قديم، الدخول العادي بقى بيغطي الحالة دي تلقائيًا) ----------
      if (path === '/api/family/set-initial-password' && method === 'POST') {
        if (!(await checkAuthRateLimit(request, env))) {
          return json({ error: 'محاولات كتير أوي، حاول تاني بعد شوية' }, 429);
        }
        const { code, memberId, password } = await request.json();
        const upperCode = (code || '').toUpperCase();
        if (!password || password.length < 6) return json({ error: 'كلمة السر لازم تكون 6 حروف أو أرقام على الأقل' }, 400);
        const memberRow = await env.DB.prepare(
          'SELECT * FROM members WHERE id = ? AND family_code = ?'
        ).bind(memberId, upperCode).first();
        if (!memberRow) return json({ error: 'العضو مش موجود' }, 404);
        if (memberRow.status === 'pending') return json({ error: 'pending_approval' }, 403);
        if (memberRow.pin_hash) return json({ error: 'already_has_pin' }, 409);
        const passwordHash = await hashSecret(password);
        await env.DB.prepare('UPDATE members SET pin_hash = ? WHERE id = ?').bind(passwordHash, memberId).run();
        const family = await getFamilyWithMembers(env.DB, upperCode);
        const sessionToken = await createSessionToken(env, upperCode, memberId);
        return json({ family, myId: memberId, sessionToken });
      }

      // ---------- تغيير كلمة السر وانت داخل حسابك بالفعل (من غير ما تحتاج تكتب القديمة) ----------
      const changePinMatch = path.match(/^\/api\/member\/([A-Z0-9]+)\/([a-zA-Z0-9_]+)\/change-password$/);
      if (changePinMatch && method === 'POST') {
        if (!(await requireSession(request, env, changePinMatch[1], changePinMatch[2]))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        const { newPassword } = await request.json();
        if (!newPassword || newPassword.length < 6) return json({ error: 'كلمة السر لازم تكون 6 حروف أو أرقام على الأقل' }, 400);
        const memberRow = await env.DB.prepare(
          'SELECT id FROM members WHERE id = ? AND family_code = ?'
        ).bind(changePinMatch[2], changePinMatch[1]).first();
        if (!memberRow) return json({ error: 'العضو مش موجود' }, 404);
        await env.DB.prepare('UPDATE members SET pin_hash = ? WHERE id = ?').bind(await hashSecret(newPassword), memberRow.id).run();
        return json({ ok: true });
      }

      // ================= نائب كبير عائلة (Co-admin) - حل مشكلة "لو كبير العائلة اختفى، العائلة تتجمد" =================
      // أي كبير عائلة حالي يقدر يرقّي عضو معتمد (مش معلّق) لنائب كبير عائلة - وله نفس الصلاحيات بالظبط
      if (path === '/api/family/promote-admin' && method === 'POST') {
        const { code, memberId, requestedByAdminId } = await request.json();
        const upperCode = (code || '').toUpperCase();
        if (!(await requireSession(request, env, upperCode, requestedByAdminId))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        const requester = await env.DB.prepare(
          'SELECT is_admin FROM members WHERE id = ? AND family_code = ?'
        ).bind(requestedByAdminId, upperCode).first();
        if (!requester || !requester.is_admin) return json({ error: 'كبير العائلة بس اللي يقدر يعمل كده' }, 403);
        const target = await env.DB.prepare(
          'SELECT status FROM members WHERE id = ? AND family_code = ?'
        ).bind(memberId, upperCode).first();
        if (!target) return json({ error: 'العضو مش موجود' }, 404);
        if (target.status === 'pending') return json({ error: 'لازم توافق على العضو الأول قبل ما ترقّيه' }, 400);
        await env.DB.prepare('UPDATE members SET is_admin = 1 WHERE id = ? AND family_code = ?').bind(memberId, upperCode).run();
        const family = await getFamilyWithMembers(env.DB, upperCode);
        return json({ family });
      }
      // تنزيل نائب كبير عائلة (مش المؤسس نفسه إلزاميًا - أي أدمن يقدر ينزّل أي أدمن تاني غيره)،
      // بشرط إن يفضل أدمن واحد على الأقل في العائلة عشان محدش يقفل الباب على الكل
      if (path === '/api/family/demote-admin' && method === 'POST') {
        const { code, memberId, requestedByAdminId } = await request.json();
        const upperCode = (code || '').toUpperCase();
        if (!(await requireSession(request, env, upperCode, requestedByAdminId))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        const requester = await env.DB.prepare(
          'SELECT is_admin FROM members WHERE id = ? AND family_code = ?'
        ).bind(requestedByAdminId, upperCode).first();
        if (!requester || !requester.is_admin) return json({ error: 'كبير العائلة بس اللي يقدر يعمل كده' }, 403);
        if (memberId === requestedByAdminId) return json({ error: 'مينفعش تنزّل نفسك - لازم أدمن تاني يعمل كده' }, 400);
        const { results: admins } = await env.DB.prepare(
          'SELECT id FROM members WHERE family_code = ? AND is_admin = 1'
        ).bind(upperCode).all();
        if (admins.length <= 1) return json({ error: 'مينفعش تسيب العائلة من غير أي كبير عائلة خالص' }, 400);
        await env.DB.prepare('UPDATE members SET is_admin = 0 WHERE id = ? AND family_code = ?').bind(memberId, upperCode).run();
        const family = await getFamilyWithMembers(env.DB, upperCode);
        return json({ family });
      }

      // ---------- كبير العائلة يصفّر كلمة سر عضو نسيها، بس لو العضو طلب منه كده (سياسة استخدام، مش تقنية) ----------
      // كبير العائلة مينفعش يستخدم المسار ده لتصفير كلمة سره هو - لازم يستخدم سؤال الأمان بتاعه (الخطوة أعلاه)
      if (path === '/api/family/reset-pin' && method === 'POST') {
        const { code, memberId, requestedByAdminId } = await request.json();
        const upperCode = (code || '').toUpperCase();
        if (!(await requireSession(request, env, upperCode, requestedByAdminId))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        const requester = await env.DB.prepare(
          'SELECT is_admin FROM members WHERE id = ? AND family_code = ?'
        ).bind(requestedByAdminId, upperCode).first();
        if (!requester || !requester.is_admin) return json({ error: 'كبير العائلة بس اللي يقدر يعمل كده' }, 403);
        if (memberId === requestedByAdminId) return json({ error: 'مينفعش تصفّر كلمة سرك انت بنفس الطريقة دي - استخدم سؤال الأمان بتاعك' }, 400);
        await env.DB.prepare('UPDATE members SET pin_hash = NULL WHERE id = ? AND family_code = ?').bind(memberId, upperCode).run();
        return json({ ok: true });
      }

      // ---------- حذف حساب فردي (لأي عضو عادي، بيحذف بياناته هو بس - مش العائلة كلها) ----------
      // ده بيلبي حق "حذف البيانات" اللي بيتطلبه جوجل بلاي وقانون حماية البيانات: أي عضو غير الأدمن
      // يقدر يحذف حسابه وكل بياناته الشخصية بنفسه، من غير ما يستنى موافقة حد.
      // كبير العائلة (الأدمن) مينفعش يستخدم الطريقة دي لوحده لأنه مسؤول عن العائلة كلها -
      // لو عايز يمسح بياناته، لازم يمسح العائلة بالكامل من مسار /api/family/delete-self.
      if (path === '/api/member/self-delete' && method === 'POST') {
        const { code, memberId, password } = await request.json();
        const upperCode = (code || '').toUpperCase();
        const member = await env.DB.prepare(
          'SELECT * FROM members WHERE id = ? AND family_code = ?'
        ).bind(memberId, upperCode).first();
        if (!member) return json({ error: 'العضو مش موجود' }, 404);
        if (member.is_admin) {
          return json({ error: 'انت كبير العائلة - لازم تحذف العائلة بالكامل من إعدادات "حذف العائلة نهائيًا"، مينفعش تحذف حسابك لوحده' }, 400);
        }
        const validPassword = await verifySecret(password, member.pin_hash);
        if (!validPassword) return json({ error: 'كلمة السر غلط' }, 401);

        await performMemberDeletion(env, upperCode, member, 'حذف ذاتي فوري بواسطة العضو نفسه من داخل التطبيق');

        return json({ ok: true });
      }

      // ================= طلب حذف حساب من برّه التطبيق (صفحة ويب عامة - Google Play Account Deletion) =================
      // بيسمح لأي حد يطلب حذف بياناته حتى لو مش فاتح التطبيق، عن طريق اختيار اسمه وكتابة كلمة سره.
      // الطلب مش بينفّذ فورًا - بيتنفذ تلقائيًا بعد 24 ساعة، وممكن إلغاؤه خلال المهلة دي (حماية من إساءة الاستخدام
      // لو حد عرف كود العائلة واسم عضو فيها وخمّن كلمة سره - الإجراء الخطير ده بقاله فرصة تراجع حقيقية).
      if (path === '/api/account/delete-request' && method === 'POST') {
        if (!(await checkAuthRateLimit(request, env))) {
          return json({ error: 'محاولات كتير أوي، حاول تاني بعد شوية' }, 429);
        }
        const { code, memberId, password } = await request.json();
        const upperCode = (code || '').toUpperCase();
        const member = await env.DB.prepare(
          'SELECT * FROM members WHERE id = ? AND family_code = ?'
        ).bind(memberId, upperCode).first();
        if (!member) return json({ error: 'مفيش عضو بالبيانات دي' }, 404);
        const validPassword = await verifySecret(password, member.pin_hash);
        if (!validPassword) return json({ error: 'كلمة السر غلط' }, 401);

        const existing = await env.DB.prepare(
          'SELECT * FROM deletion_requests WHERE member_id = ? AND status = ?'
        ).bind(member.id, 'pending').first();
        if (existing) {
          return json({ ok: true, scope: existing.scope, executeAt: existing.execute_at, alreadyPending: true });
        }

        const now = Date.now();
        const executeAt = now + 24 * 60 * 60 * 1000;
        const scope = member.is_admin ? 'family' : 'member';
        await env.DB.prepare(
          'INSERT INTO deletion_requests (id, family_code, member_id, scope, requested_at, execute_at, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).bind(genId('dreq'), upperCode, member.id, scope, now, executeAt, 'pending').run();

        // نبلغ باقي أفراد العائلة بإن فيه طلب حذف معلّق، عشان لو مكانش هو اللي طلبه يقدر يبلّغ كبير العائلة أو يلغيه من جوّه التطبيق
        ctx.waitUntil((async () => {
          try {
            const { results } = await env.DB.prepare(
              'SELECT * FROM push_subscriptions WHERE family_code = ?'
            ).bind(upperCode).all();
            const payload = {
              title: '⚠️ طلب حذف بيانات معلّق',
              body: scope === 'family'
                ? 'اتقدّم طلب لحذف العائلة بالكامل، هيتنفذ خلال 24 ساعة إلا لو اتلغى'
                : (member.name + ' اتقدّم طلب لحذف حسابه، هيتنفذ خلال 24 ساعة إلا لو اتلغى'),
              url: '/',
            };
            await Promise.all(results.map(row => sendWebPush(env, {
              endpoint: row.endpoint,
              keys: { p256dh: row.p256dh, auth: row.auth },
            }, payload)));
          } catch (e) {}
        })());

        return json({ ok: true, scope, executeAt, alreadyPending: false });
      }

      // إلغاء طلب حذف معلّق - بمعرّف العضو (من الصفحة العامة بعد ما يختار اسمه، أو من جوّه التطبيق مباشرة)
      if (path === '/api/account/cancel-deletion' && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const upperCode = (body.code || '').toUpperCase();
        const memberId = body.memberId;
        if (!memberId) return json({ error: 'بيانات ناقصة' }, 400);
        await env.DB.prepare(
          "UPDATE deletion_requests SET status = 'cancelled' WHERE member_id = ? AND family_code = ? AND status = 'pending'"
        ).bind(memberId, upperCode).run();
        return json({ ok: true });
      }

      // فحص وجود طلب حذف معلّق لعضو معيّن (تستخدمها الواجهة عشان تعرض بانر إلغاء لو فيه طلب شغّال)
      const delStatusMatch = path.match(/^\/api\/account\/deletion-status\/([A-Z0-9]+)\/([a-zA-Z0-9_]+)$/);
      if (delStatusMatch && method === 'GET') {
        const row = await env.DB.prepare(
          "SELECT scope, execute_at FROM deletion_requests WHERE family_code = ? AND member_id = ? AND status = 'pending'"
        ).bind(delStatusMatch[1], delStatusMatch[2]).first();
        return json({ pending: !!row, scope: row ? row.scope : null, executeAt: row ? row.execute_at : null });
      }

      // صفحة عامة (بدون تسجيل دخول) بتشرح إزاي تحذف بياناتك، ومعاها نموذج فعلي بيقدّم طلب الحذف
      // صفحة سياسة الخصوصية - حية على الدومين بتاعك مباشرة، من غير أي استضافة منفصلة
      if (path === '/privacy-policy' && method === 'GET') {
        const html = PRIVACY_POLICY_HTML
          .replace('PRIVACY_POLICY_DATE_PLACEHOLDER', (env.PRIVACY_POLICY_DATE || new Date().toISOString().slice(0, 10)))
          .replace('PRIVACY_CONTACT_EMAIL_PLACEHOLDER', (env.PRIVACY_CONTACT_EMAIL || '[لسه محتاج تحط بريد التواصل - راجع الـ README]'))
          .replace('PRIVACY_DEVELOPER_NAME_PLACEHOLDER', (env.PRIVACY_DEVELOPER_NAME || '[لسه محتاج تحط اسم الجهة المسؤولة - راجع الـ README]'));
        return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }

      if (path === '/account-deletion' && method === 'GET') {
        return new Response(ACCOUNT_DELETION_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }

      // ---------- استرجاع كلمة السر بسؤالي أمان (متاح لأي عضو، مش بس كبير العائلة) ----------
      // 1) الواجهة بتجيب السؤالين بالاسم (من غير ما تكشف الإجابات، ومن غير ما تحتاج قايمة أسامي عامة)
      if (path === '/api/family/security-question' && method === 'GET') {
        const code = (url.searchParams.get('code') || '').toUpperCase();
        const name = (url.searchParams.get('name') || '').trim();
        const memberRow = await env.DB.prepare(
          'SELECT security_question, security_question_2 FROM members WHERE family_code = ? AND name = ?'
        ).bind(code, name).first();
        if (!memberRow || !memberRow.security_question || !memberRow.security_question_2) {
          return json({ error: 'مفيش سؤالي أمان محددين للعضو ده، أو الاسم غلط' }, 404);
        }
        return json({ question1: memberRow.security_question, question2: memberRow.security_question_2 });
      }
      // 2) الواجهة بتبعت الإجابتين + كلمة السر الجديدة، ولو الإجابتين صح بيتغيّر كلمة السر فورًا
      if (path === '/api/family/verify-security-answer' && method === 'POST') {
        if (!(await checkAuthRateLimit(request, env))) {
          return json({ error: 'محاولات كتير أوي، حاول تاني بعد شوية' }, 429);
        }
        const { code, name, answer1, answer2, newPassword } = await request.json();
        const upperCode = (code || '').toUpperCase();
        const trimmedName = (name || '').trim();
        if (!newPassword || newPassword.length < 6) return json({ error: 'كلمة السر الجديدة لازم تكون 6 حروف أو أرقام على الأقل' }, 400);
        const memberRow = await env.DB.prepare(
          'SELECT * FROM members WHERE family_code = ? AND name = ?'
        ).bind(upperCode, trimmedName).first();
        if (!memberRow || !memberRow.security_answer_hash || !memberRow.security_answer_hash_2) {
          return json({ error: 'مفيش سؤالي أمان محددين للعضو ده' }, 404);
        }
        const valid1 = await verifySecret(normalizeSecurityAnswer(answer1), memberRow.security_answer_hash);
        const valid2 = await verifySecret(normalizeSecurityAnswer(answer2), memberRow.security_answer_hash_2);
        if (!valid1 || !valid2) return json({ error: 'إجابة واحدة أو الاتنين مش صح' }, 401);
        await env.DB.prepare('UPDATE members SET pin_hash = ? WHERE id = ?').bind(await hashSecret(newPassword), memberRow.id).run();
        return json({ ok: true });
      }

      // ---------- الانضمام لعائلة (طلب معلّق) ----------
      if (path === '/api/family/register' && method === 'POST') {
        if (!(await checkAuthRateLimit(request, env))) {
          return json({ error: 'محاولات كتير أوي، حاول تاني بعد شوية' }, 429);
        }
        const { code, name, relation, consent, ageConfirm, password, securityQuestion1, securityAnswer1, securityQuestion2, securityAnswer2 } = await request.json();
        if (consent !== true) return json({ error: 'يجب الموافقة على شروط استخدام البيانات أولاً' }, 400);
        if (ageConfirm !== true) return json({ error: 'لازم تأكد إنك بلغت 18 سنة على الأقل عشان تنضم للتطبيق' }, 400);
        if (!password || password.length < 6) return json({ error: 'كلمة السر لازم تكون 6 حروف أو أرقام على الأقل' }, 400);
        if (!SECURITY_QUESTIONS.includes(securityQuestion1) || !SECURITY_QUESTIONS.includes(securityQuestion2)) {
          return json({ error: 'اختار سؤالي أمان من القائمة' }, 400);
        }
        if (securityQuestion1 === securityQuestion2) return json({ error: 'اختار سؤالين مختلفين عن بعض' }, 400);
        if (!securityAnswer1 || !securityAnswer1.trim() || !securityAnswer2 || !securityAnswer2.trim()) {
          return json({ error: 'لازم تكتب إجابة السؤالين الاتنين' }, 400);
        }
        const upperCode = (code || '').toUpperCase();
        const fam = await env.DB.prepare('SELECT code FROM families WHERE code = ?').bind(upperCode).first();
        if (!fam) return json({ error: 'كود العائلة غير صحيح' }, 404);

        const trimmedName = (name || '').trim();
        if (!trimmedName) return json({ error: 'الاسم مطلوب' }, 400);
        const existingName = await env.DB.prepare(
          'SELECT id FROM members WHERE family_code = ? AND name = ?'
        ).bind(upperCode, trimmedName).first();
        if (existingName) {
          return json({ error: 'الاسم ده مستخدم بالفعل في العائلة دي - اكتب اسمك مع لقب أو حاجة تميّزك (مثلاً "أحمد الصغير")، لأن الاسم بيُستخدم للدخول' }, 409);
        }

        const id = genId('m');
        const role = (relation === 'أب' || relation === 'أم') ? 'parent' : 'child';
        const now = Date.now();
        const passwordHash = await hashSecret(password);
        const answerHash1 = await hashSecret(normalizeSecurityAnswer(securityAnswer1));
        const answerHash2 = await hashSecret(normalizeSecurityAnswer(securityAnswer2));
        // الانضمام بيفضل "معلّق" (pending) لحد ما كبير العائلة يوافق عليه صراحة من داخل التطبيق
        await env.DB.prepare(
          `INSERT INTO members (id, family_code, name, phone, relation, role, is_admin, status, circle, pin_hash, security_question, security_answer_hash, security_question_2, security_answer_hash_2, age_confirmed, consent_at, created_at)
           VALUES (?, ?, ?, '', ?, ?, 0, 'pending', '[]', ?, ?, ?, ?, ?, 1, ?, ?)`
        ).bind(id, upperCode, trimmedName, relation, role, passwordHash, securityQuestion1, answerHash1, securityQuestion2, answerHash2, now, now).run();

        ctx.waitUntil(notifyFamilyNewJoinRequest(env, upperCode, trimmedName));
        return json({ myId: id, pending: true });
      }

      // ---------- جلب بيانات عائلة ----------
      const familyMatch = path.match(/^\/api\/family\/([A-Z0-9]+)$/);
      if (familyMatch && method === 'GET') {
        const family = await getFamilyWithMembers(env.DB, familyMatch[1]);
        if (!family) return json({ error: 'not found' }, 404);
        return json({ family });
      }

      // ---------- موافقة على عضو ----------
      if (path === '/api/family/approve' && method === 'POST') {
        const { code, memberId, approvedByAdminId } = await request.json();
        if (!(await requireSession(request, env, code, approvedByAdminId))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        const admin = await env.DB.prepare('SELECT is_admin FROM members WHERE id = ?').bind(approvedByAdminId).first();
        if (!admin || !admin.is_admin) return json({ error: 'مسموح لكبير العائلة بس' }, 403);
        await env.DB.prepare('UPDATE members SET status = ? WHERE id = ? AND family_code = ?')
          .bind('approved', memberId, code).run();
        const family = await getFamilyWithMembers(env.DB, code);
        return json({ family });
      }

      // ---------- رفض / حذف عضو ----------
      if (path === '/api/family/remove' && method === 'POST') {
        const { code, memberId, requestedByAdminId } = await request.json();
        if (!(await requireSession(request, env, code, requestedByAdminId))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        const admin = await env.DB.prepare('SELECT is_admin FROM members WHERE id = ?').bind(requestedByAdminId).first();
        if (!admin || !admin.is_admin) return json({ error: 'مسموح لكبير العائلة بس' }, 403);
        if (memberId === requestedByAdminId) return json({ error: 'مينفعش تحذف نفسك بالطريقة دي - استخدم "حذف حسابي" أو "حذف العائلة" من الإعدادات' }, 400);
        // بننضّف بياناته المرتبطة (إشعارات، حظر، صلاحيات شات خاص، مشاركة موقع نشطة) - رسايله القديمة في
        // الشات العام بتفضل زي ما هي عشان سياق المحادثة يفضل مفهوم لباقي العائلة
        await env.DB.prepare('DELETE FROM push_subscriptions WHERE member_id = ?').bind(memberId).run().catch(() => {});
        await env.DB.prepare('DELETE FROM blocks WHERE family_code = ? AND (blocker_id = ? OR blocked_id = ?)').bind(code, memberId, memberId).run().catch(() => {});
        await env.DB.prepare('DELETE FROM private_chat_permissions WHERE family_code = ? AND (member_a = ? OR member_b = ?)').bind(code, memberId, memberId).run().catch(() => {});
        await env.DB.prepare('DELETE FROM location_shares WHERE member_id = ?').bind(memberId).run().catch(() => {});
        await env.DB.prepare('DELETE FROM members WHERE id = ? AND family_code = ?').bind(memberId, code).run();
        const family = await getFamilyWithMembers(env.DB, code);
        return json({ family });
      }

      // ---------- تأكيد إن حد من العائلة شاف نداء الاستغاثة - بيوقف التكرار لكل الأجهزة ----------
      const sosAckMatch = path.match(/^\/api\/events\/([A-Z0-9]+)\/([a-zA-Z0-9_]+)\/acknowledge$/);
      if (sosAckMatch && method === 'POST' && env.SOS_ALARM) {
        try {
          const doId = env.SOS_ALARM.idFromName(sosAckMatch[2]);
          const stub = env.SOS_ALARM.get(doId);
          await stub.fetch('https://sos-alarm/acknowledge', { method: 'POST' });
        } catch (e) { /* تجاهل */ }
        return json({ ok: true });
      }

      // ---------- تحديث دائرة الثقة الشخصية ----------
      if (path === '/api/family/circle' && method === 'POST') {
        const { code, memberId, circle } = await request.json();
        if (!(await requireSession(request, env, code, memberId))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        await env.DB.prepare('UPDATE members SET circle = ? WHERE id = ? AND family_code = ?')
          .bind(JSON.stringify(circle), memberId, code).run();
        const family = await getFamilyWithMembers(env.DB, code);
        return json({ family });
      }

      // ---------- تسجيل اشتراك الإشعارات (Push) ----------
      if (path === '/api/push/subscribe' && method === 'POST') {
        const body = await request.json();
        const { familyCode: fc, memberId, subscription } = body;
        if (!fc || !memberId || !subscription || !subscription.endpoint) {
          return json({ error: 'بيانات الاشتراك ناقصة' }, 400);
        }
        await env.DB.prepare(
          `INSERT INTO push_subscriptions (member_id, family_code, endpoint, p256dh, auth, created_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(member_id) DO UPDATE SET
             endpoint = excluded.endpoint, p256dh = excluded.p256dh, auth = excluded.auth`
        ).bind(
          memberId, fc, subscription.endpoint,
          subscription.keys.p256dh, subscription.keys.auth, Date.now()
        ).run();
        return json({ ok: true });
      }

      // ---------- الأحداث (SOS / اطمئنان / مناسبات) ----------
      const eventsMatch = path.match(/^\/api\/events\/([A-Z0-9]+)$/);
      if (eventsMatch && method === 'GET') {
        const sinceParam = url.searchParams.get('since');
        let results;
        if (sinceParam !== null) {
          // تحديث تدريجي (delta): بس الأحداث الأحدث من آخر وقت عند العميل
          const since = parseInt(sinceParam, 10) || 0;
          ({ results } = await env.DB.prepare(
            'SELECT * FROM events WHERE family_code = ? AND timestamp > ? ORDER BY timestamp ASC LIMIT 100'
          ).bind(eventsMatch[1], since).all());
        } else {
          const limit = parseInt(url.searchParams.get('limit') || '60', 10);
          ({ results } = await env.DB.prepare(
            'SELECT * FROM events WHERE family_code = ? ORDER BY timestamp DESC LIMIT ?'
          ).bind(eventsMatch[1], limit).all());
        }
        const events = await Promise.all(results.map(e => decryptEventRow(env, e)));
        return json({ events });
      }
      if (eventsMatch && method === 'POST') {
        const body = await request.json();
        const id = genId('e');
        // زر الطوارئ وزر الاطمئنان بحسب البرومت "لا يُرسل الموقع" أبدًا معاهم -
        // بنمنع ده من جهة السيرفر كمان (مش بس الفرونت إند) عشان محدش يقدر يلف على القيد ده
        const noLocationTypes = (body.type === 'sos' || body.type === 'safe');
        let encLat, encLng;
        try {
          encLat = noLocationTypes ? null : await encryptGeo(env, body.lat ?? null);
          encLng = noLocationTypes ? null : await encryptGeo(env, body.lng ?? null);
        } catch (e) {
          return json({ error: 'التطبيق لسه مش جاهز يخزّن مواقع جغرافية بأمان - كلّم مطوّر التطبيق (ENCRYPTION_KEY مش متسجل)' }, 503);
        }
        await env.DB.prepare(
          `INSERT INTO events (id, family_code, type, occasion_type, member_id, member_name, text, lat, lng, accuracy, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          id, eventsMatch[1], body.type, body.occasionType || null, body.memberId, body.memberName,
          body.text || null, encLat, encLng, noLocationTypes ? null : (body.accuracy ?? null), Date.now()
        ).run();
        if (body.type === 'sos') {
          ctx.waitUntil(notifyFamilySOS(env, eventsMatch[1], body.memberId, body.memberName));
          // بدء التكرار كل 30 ثانية لحد ما حد يشوف النداء (أو 10 دقايق كحد أقصى)
          if (env.SOS_ALARM) {
            ctx.waitUntil((async () => {
              try {
                const doId = env.SOS_ALARM.idFromName(id);
                const stub = env.SOS_ALARM.get(doId);
                await stub.fetch('https://sos-alarm/start', {
                  method: 'POST',
                  body: JSON.stringify({ familyCode: eventsMatch[1], memberName: body.memberName, excludeMemberId: body.memberId }),
                });
              } catch (e) { /* لو الـ Durable Object مش شغال لأي سبب، التنبيه الأول لسه بيتبعت عادي */ }
            })());
          }
        }
        return json({ id, sosEventId: body.type === 'sos' ? id : undefined });
      }

      // ---------- حذف حدث من آخر التحديثات (المرسل بس اللي يقدر يحذف حدثه) ----------
      const eventDeleteMatch = path.match(/^\/api\/events\/([A-Z0-9]+)\/([a-zA-Z0-9_]+)$/);
      if (eventDeleteMatch && method === 'DELETE') {
        const body = await request.json().catch(() => ({}));
        const eventId = eventDeleteMatch[2];
        const requesterId = body.memberId;
        if (!(await requireSession(request, env, eventDeleteMatch[1], requesterId))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        const { results } = await env.DB.prepare(
          'SELECT * FROM events WHERE id = ? AND family_code = ?'
        ).bind(eventId, eventDeleteMatch[1]).all();
        const ev = results[0];
        if (!ev) return json({ error: 'الحدث مش موجود' }, 404);
        if (ev.member_id !== requesterId) return json({ error: 'مينفعش تحذف حدث مش بتاعك' }, 403);
        await env.DB.prepare('DELETE FROM events WHERE id = ?').bind(eventId).run();
        return json({ ok: true });
      }

      // ---------- الشات (نصوص) ----------
      const chatMatch = path.match(/^\/api\/chat\/([A-Z0-9]+)$/);
      if (chatMatch && method === 'GET') {
        const sinceParam = url.searchParams.get('since');
        let results;
        if (sinceParam !== null) {
          // تحديث تدريجي (delta): بس الرسايل الأحدث من آخر وقت عند العميل
          const since = parseInt(sinceParam, 10) || 0;
          ({ results } = await env.DB.prepare(
            'SELECT * FROM chat_messages WHERE family_code = ? AND timestamp > ? ORDER BY timestamp ASC LIMIT 100'
          ).bind(chatMatch[1], since).all());
        } else {
          const limit = parseInt(url.searchParams.get('limit') || '100', 10);
          ({ results } = await env.DB.prepare(
            'SELECT * FROM chat_messages WHERE family_code = ? ORDER BY timestamp ASC LIMIT ?'
          ).bind(chatMatch[1], limit).all());
        }
        return json({ messages: results.map(m => ({
          id: m.id, senderId: m.sender_id, senderName: m.sender_name, text: m.text,
          mediaType: m.media_type,
          media: m.media_key ? `/api/media/${m.media_key}` : null,
          timestamp: m.timestamp,
        })) });
      }
      if (chatMatch && method === 'POST') {
        const body = await request.json();
        const id = genId('c');
        await env.DB.prepare(
          `INSERT INTO chat_messages (id, family_code, sender_id, sender_name, text, media_type, media_key, timestamp)
           VALUES (?, ?, ?, ?, ?, NULL, NULL, ?)`
        ).bind(id, chatMatch[1], body.senderId, body.senderName, body.text, Date.now()).run();
        ctx.waitUntil(notifyFamilyChatMessage(env, chatMatch[1], body.senderId, body.senderName, body.text));
        return json({ id });
      }

      // ---------- حذف رسالة من الشات (المرسل، أو كبير العائلة لأي رسالة - مهم لحذف محتوى مُبلَّغ عنه) ----------
      const chatDeleteMatch = path.match(/^\/api\/chat\/([A-Z0-9]+)\/([a-zA-Z0-9_]+)$/);
      if (chatDeleteMatch && method === 'DELETE') {
        const body = await request.json().catch(() => ({}));
        const messageId = chatDeleteMatch[2];
        const requesterId = body.senderId;
        if (!(await requireSession(request, env, chatDeleteMatch[1], requesterId))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        const { results } = await env.DB.prepare(
          'SELECT * FROM chat_messages WHERE id = ? AND family_code = ?'
        ).bind(messageId, chatDeleteMatch[1]).all();
        const msg = results[0];
        if (!msg) return json({ error: 'الرسالة مش موجودة' }, 404);
        if (msg.sender_id !== requesterId) {
          const requester = await env.DB.prepare(
            'SELECT is_admin FROM members WHERE id = ? AND family_code = ?'
          ).bind(requesterId, chatDeleteMatch[1]).first();
          if (!requester || !requester.is_admin) {
            return json({ error: 'مينفعش تحذف رسالة مش بتاعتك' }, 403);
          }
        }
        if (msg.media_key) {
          await env.MEDIA.delete(msg.media_key).catch(() => {});
        }
        await env.DB.prepare('DELETE FROM chat_messages WHERE id = ?').bind(messageId).run();
        await env.DB.prepare('DELETE FROM chat_reports WHERE message_id = ?').bind(messageId).run().catch(() => {});
        return json({ ok: true });
      }

      // ---------- الإبلاغ عن رسالة مخالفة (أي عضو يقدر يبلغ، وكبير العائلة بيتنبّه فورًا) ----------
      const chatReportMatch = path.match(/^\/api\/chat\/([A-Z0-9]+)\/([a-zA-Z0-9_]+)\/report$/);
      if (chatReportMatch && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const familyCode = chatReportMatch[1];
        const messageId = chatReportMatch[2];
        const msg = await env.DB.prepare(
          'SELECT * FROM chat_messages WHERE id = ? AND family_code = ?'
        ).bind(messageId, familyCode).first();
        if (!msg) return json({ error: 'الرسالة مش موجودة (يمكن اتحذفت بالفعل)' }, 404);
        const reportId = genId('rep');
        await env.DB.prepare(
          `INSERT INTO chat_reports (id, message_id, family_code, reporter_id, reason, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(reportId, messageId, familyCode, body.reporterId || null, body.reason || null, Date.now()).run();
        ctx.waitUntil(notifyFamilyReport(env, familyCode, body.reporterName || 'أحد أفراد العائلة'));
        return json({ ok: true });
      }

      // ---------- كبير العائلة يشوف البلاغات المعلّقة على رسايل الشات العام ويتصرف فيها ----------
      const reportsListMatch = path.match(/^\/api\/chat\/([A-Z0-9]+)\/reports$/);
      if (reportsListMatch && method === 'GET') {
        const adminId = url.searchParams.get('adminId');
        if (!(await isAdminMember(env.DB, reportsListMatch[1], adminId))) {
          return json({ error: 'مسموح لكبير العائلة بس' }, 403);
        }
        const { results } = await env.DB.prepare(
          `SELECT r.id as report_id, r.reason, r.created_at as reported_at, r.reporter_id,
                  m.text, m.sender_name, m.media_type, m.timestamp as message_time, m.id as message_id,
                  rep.name as reporter_name
           FROM chat_reports r
           LEFT JOIN chat_messages m ON m.id = r.message_id
           LEFT JOIN members rep ON rep.id = r.reporter_id
           WHERE r.family_code = ?
           ORDER BY r.created_at DESC`
        ).bind(reportsListMatch[1]).all();
        return json({ reports: results });
      }
      // تجاهل بلاغ (من غير ما يحذف الرسالة نفسها - لو كبير العائلة شافها وقرر إنها مش مخالفة)
      const dismissReportMatch = path.match(/^\/api\/chat\/([A-Z0-9]+)\/reports\/([a-zA-Z0-9_]+)\/dismiss$/);
      if (dismissReportMatch && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        if (!(await requireSession(request, env, dismissReportMatch[1], body.adminId))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        if (!(await isAdminMember(env.DB, dismissReportMatch[1], body.adminId))) {
          return json({ error: 'مسموح لكبير العائلة بس' }, 403);
        }
        await env.DB.prepare('DELETE FROM chat_reports WHERE id = ? AND family_code = ?')
          .bind(dismissReportMatch[2], dismissReportMatch[1]).run();
        return json({ ok: true });
      }

      // ---------- تسجيل المفتاح العام لعضو (للشات الخاص المشفر E2E - المفتاح الخاص مبيتبعتش خالص) ----------
      const publicKeyMatch = path.match(/^\/api\/member\/([A-Z0-9]+)\/([a-zA-Z0-9_]+)\/publickey$/);
      if (publicKeyMatch && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        if (!body.publicKey) return json({ error: 'المفتاح العام مطلوب' }, 400);
        const familyCode = publicKeyMatch[1];
        const memberId = publicKeyMatch[2];
        const member = await env.DB.prepare(
          'SELECT id FROM members WHERE id = ? AND family_code = ?'
        ).bind(memberId, familyCode).first();
        if (!member) return json({ error: 'العضو مش موجود' }, 404);
        await env.DB.prepare('UPDATE members SET public_key = ? WHERE id = ?').bind(body.publicKey, memberId).run();
        return json({ ok: true });
      }

      // ---------- إرسال رسالة خاصة مشفرة (السيرفر بيخزن نص مشفر بس، ومش قادر يفكه) ----------
      const privateSendMatch = path.match(/^\/api\/private\/([A-Z0-9]+)$/);
      if (privateSendMatch && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const familyCode = privateSendMatch[1];
        if (!body.senderId || !body.recipientId || !body.ciphertext || !body.iv) {
          return json({ error: 'بيانات ناقصة' }, 400);
        }
        if (await isBlockedEitherWay(env.DB, body.senderId, body.recipientId)) {
          return json({ error: 'مينفعش تتواصل مع الشخص ده' }, 403);
        }
        if (!(await isPrivateChatAllowed(env.DB, familyCode, body.senderId, body.recipientId))) {
          return json({ error: 'private_not_allowed' }, 403);
        }
        const id = genId('pm');
        await env.DB.prepare(
          `INSERT INTO private_messages (id, family_code, sender_id, recipient_id, ciphertext, iv, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).bind(id, familyCode, body.senderId, body.recipientId, body.ciphertext, body.iv, Date.now()).run();
        ctx.waitUntil(notifyPrivateMessage(env, familyCode, body.recipientId, body.senderName || 'أحد أفراد العائلة'));
        return json({ ok: true, id, timestamp: Date.now() });
      }

      // ---------- جلب محادثة خاصة بين عضوين (كل الرسايل في الاتجاهين) ----------
      const privateGetMatch = path.match(/^\/api\/private\/([A-Z0-9]+)\/([a-zA-Z0-9_]+)\/([a-zA-Z0-9_]+)$/);
      if (privateGetMatch && method === 'GET') {
        const familyCode = privateGetMatch[1];
        const meId = privateGetMatch[2];
        const otherId = privateGetMatch[3];
        const since = Number(url.searchParams.get('since') || 0);
        const { results } = await env.DB.prepare(
          `SELECT * FROM private_messages
           WHERE family_code = ? AND timestamp > ?
             AND ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?))
           ORDER BY timestamp ASC`
        ).bind(familyCode, since, meId, otherId, otherId, meId).all();
        return json({ messages: results.map(r => ({
          id: r.id, senderId: r.sender_id, recipientId: r.recipient_id,
          ciphertext: r.ciphertext, iv: r.iv, timestamp: r.timestamp,
        })) });
      }

      // ================= مشاركة الموقع الطوعية بمدة محددة (بدون تتبع خلفي) =================
      // بدء مشاركة: المستخدم يختار "ساعة" أو "لحد ما يوقف"
      const locStartMatch = path.match(/^\/api\/location\/([A-Z0-9]+)\/start$/);
      if (locStartMatch && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        if (!body.memberId) return json({ error: 'بيانات ناقصة' }, 400);
        const now = Date.now();
        const durationMinutes = body.durationMinutes ? Number(body.durationMinutes) : null;
        const expiresAt = durationMinutes ? now + durationMinutes * 60 * 1000 : null;
        await env.DB.prepare(
          `INSERT INTO location_shares (member_id, family_code, expires_at, started_at) VALUES (?, ?, ?, ?)
           ON CONFLICT(member_id) DO UPDATE SET family_code = excluded.family_code, expires_at = excluded.expires_at, started_at = excluded.started_at`
        ).bind(body.memberId, locStartMatch[1], expiresAt, now).run();
        return json({ ok: true, expiresAt });
      }
      // تحديث نبضة الموقع أثناء وجود التطبيق مفتوح بس (الفرونت إند هو اللي بيوقف الإرسال لو التطبيق مقفول/مش ظاهر - مفيش تتبع خلفي)
      const locPingMatch = path.match(/^\/api\/location\/([A-Z0-9]+)\/ping$/);
      if (locPingMatch && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        if (!body.memberId) return json({ error: 'بيانات ناقصة' }, 400);
        const share = await env.DB.prepare(
          'SELECT * FROM location_shares WHERE member_id = ? AND family_code = ?'
        ).bind(body.memberId, locPingMatch[1]).first();
        if (!share) return json({ error: 'share_ended' }, 409);
        if (share.expires_at && share.expires_at <= Date.now()) {
          await env.DB.prepare('DELETE FROM location_shares WHERE member_id = ?').bind(body.memberId).run();
          return json({ error: 'share_ended' }, 409);
        }
        const id = genId('e');
        let encLat, encLng;
        try {
          encLat = await encryptGeo(env, body.lat ?? null);
          encLng = await encryptGeo(env, body.lng ?? null);
        } catch (e) {
          return json({ error: 'التطبيق لسه مش جاهز يخزّن مواقع جغرافية بأمان - كلّم مطوّر التطبيق (ENCRYPTION_KEY مش متسجل)' }, 503);
        }
        await env.DB.prepare(
          `INSERT INTO events (id, family_code, type, occasion_type, member_id, member_name, text, lat, lng, accuracy, timestamp)
           VALUES (?, ?, 'location', NULL, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(id, locPingMatch[1], body.memberId, body.memberName || '', 'شارك موقعه مع العائلة', encLat, encLng, body.accuracy ?? null, Date.now()).run();
        return json({ id, expiresAt: share.expires_at });
      }
      // إيقاف المشاركة يدويًا
      const locStopMatch = path.match(/^\/api\/location\/([A-Z0-9]+)\/stop$/);
      if (locStopMatch && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        await env.DB.prepare('DELETE FROM location_shares WHERE member_id = ? AND family_code = ?')
          .bind(body.memberId, locStopMatch[1]).run();
        return json({ ok: true });
      }
      // مين شغال مشاركة موقعه دلوقتي في العائلة (عشان الواجهة تعرض "بيشارك موقعه لحد الساعة كذا")
      const locActiveMatch = path.match(/^\/api\/location\/([A-Z0-9]+)\/active$/);
      if (locActiveMatch && method === 'GET') {
        const { results } = await env.DB.prepare(
          'SELECT member_id, expires_at FROM location_shares WHERE family_code = ?'
        ).bind(locActiveMatch[1]).all();
        const now = Date.now();
        const active = results.filter(r => !r.expires_at || r.expires_at > now);
        // ننضف أي مشاركة خلصت مدتها لوحدها
        const expired = results.filter(r => r.expires_at && r.expires_at <= now);
        for (const r of expired) {
          await env.DB.prepare('DELETE FROM location_shares WHERE member_id = ?').bind(r.member_id).run();
        }
        return json({ active: active.map(r => ({ memberId: r.member_id, expiresAt: r.expires_at })) });
      }

      // ================= الحظر (منع عضو من التواصل معاك) =================
      if (path === '/api/block' && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        if (!body.blockerId || !body.blockedId || !body.familyCode) return json({ error: 'بيانات ناقصة' }, 400);
        if (!(await requireSession(request, env, body.familyCode, body.blockerId))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        await env.DB.prepare(
          'INSERT OR IGNORE INTO blocks (blocker_id, blocked_id, family_code, created_at) VALUES (?, ?, ?, ?)'
        ).bind(body.blockerId, body.blockedId, body.familyCode, Date.now()).run();
        return json({ ok: true });
      }
      if (path === '/api/unblock' && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        if (!(await requireSession(request, env, body.familyCode, body.blockerId))) {
          return json({ error: 'الجلسة منتهية أو غير صالحة، سجّل دخول تاني' }, 401);
        }
        await env.DB.prepare('DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?')
          .bind(body.blockerId, body.blockedId).run();
        return json({ ok: true });
      }
      // قائمة اللي أنا حاظرهم بس (خصوصية - كل عضو يشوف قايمته هو بس)
      const blocksMatch = path.match(/^\/api\/blocks\/([A-Z0-9]+)\/([a-zA-Z0-9_]+)$/);
      if (blocksMatch && method === 'GET') {
        const { results } = await env.DB.prepare(
          'SELECT blocked_id FROM blocks WHERE family_code = ? AND blocker_id = ?'
        ).bind(blocksMatch[1], blocksMatch[2]).all();
        return json({ blocked: results.map(r => r.blocked_id) });
      }

      // ================= الشات الخاص المقيّد (يحتاج موافقة كبير العائلة بين عضوين عاديين) =================
      // طلب فتح شات خاص - لو حد الطرفين كبير العائلة بيتوافق عليه أوتوماتيك
      if (path === '/api/private/request' && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const { familyCode, requesterId, requesterName, targetId, targetName } = body;
        if (!familyCode || !requesterId || !targetId) return json({ error: 'بيانات ناقصة' }, 400);
        if (await isAdminMember(env.DB, familyCode, requesterId) || await isAdminMember(env.DB, familyCode, targetId)) {
          return json({ status: 'approved' });
        }
        const [a, b] = sortPair(requesterId, targetId);
        const now = Date.now();
        await env.DB.prepare(
          `INSERT INTO private_chat_permissions (family_code, member_a, member_b, status, requested_by, created_at, updated_at)
           VALUES (?, ?, ?, 'pending', ?, ?, ?)
           ON CONFLICT(family_code, member_a, member_b) DO UPDATE SET
             status = CASE WHEN private_chat_permissions.status = 'approved' THEN 'approved' ELSE 'pending' END,
             requested_by = excluded.requested_by, updated_at = excluded.updated_at`
        ).bind(familyCode, a, b, requesterId, now, now).run();
        ctx.waitUntil(notifyAdminPrivateRequest(env, familyCode, requesterName || 'عضو', targetName || 'عضو'));
        const finalStatus = await isPrivateChatAllowed(env.DB, familyCode, requesterId, targetId);
        return json({ status: finalStatus ? 'approved' : 'pending' });
      }
      // فحص حالة الإذن بين عضوين (تستخدمها الواجهة قبل ما تفتح شاشة الشات الخاص)
      const privStatusMatch = path.match(/^\/api\/private\/status\/([A-Z0-9]+)\/([a-zA-Z0-9_]+)\/([a-zA-Z0-9_]+)$/);
      if (privStatusMatch && method === 'GET') {
        const allowed = await isPrivateChatAllowed(env.DB, privStatusMatch[1], privStatusMatch[2], privStatusMatch[3]);
        return json({ allowed });
      }
      // قائمة الطلبات المعلّقة (لكبير العائلة بس)
      const privPendingMatch = path.match(/^\/api\/private\/pending\/([A-Z0-9]+)$/);
      if (privPendingMatch && method === 'GET') {
        const adminId = url.searchParams.get('adminId');
        if (!(await isAdminMember(env.DB, privPendingMatch[1], adminId))) {
          return json({ error: 'مسموح لكبير العائلة بس' }, 403);
        }
        const { results } = await env.DB.prepare(
          `SELECT p.*, ma.name as name_a, mb.name as name_b FROM private_chat_permissions p
           LEFT JOIN members ma ON ma.id = p.member_a
           LEFT JOIN members mb ON mb.id = p.member_b
           WHERE p.family_code = ? AND p.status = 'pending'`
        ).bind(privPendingMatch[1]).all();
        return json({ requests: results.map(r => ({
          memberA: r.member_a, memberB: r.member_b, nameA: r.name_a, nameB: r.name_b,
          requestedBy: r.requested_by, createdAt: r.created_at,
        })) });
      }
      // موافقة/رفض كبير العائلة على طلب شات خاص
      if (path === '/api/private/approve' && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const { familyCode, memberA, memberB, adminId, approve } = body;
        if (!(await isAdminMember(env.DB, familyCode, adminId))) return json({ error: 'مسموح لكبير العائلة بس' }, 403);
        const [a, b] = sortPair(memberA, memberB);
        await env.DB.prepare(
          'UPDATE private_chat_permissions SET status = ?, approved_by = ?, updated_at = ? WHERE family_code = ? AND member_a = ? AND member_b = ?'
        ).bind(approve ? 'approved' : 'rejected', adminId, Date.now(), familyCode, a, b).run();
        return json({ ok: true });
      }

      // ================= حذف العائلة نهائيًا بواسطة كبير العائلة نفسه (من داخل التطبيق) =================
      // تحقق ثانوي: لازم يكتب كلمة سره + يكتب كود العائلة تاني تأكيدًا (مش مجرد ضغطة زرار)
      if (path === '/api/family/delete-self' && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const { code, adminId, password, confirmCode } = body;
        const upperCode = (code || '').toUpperCase();
        const admin = await env.DB.prepare(
          'SELECT * FROM members WHERE id = ? AND family_code = ? AND is_admin = 1'
        ).bind(adminId, upperCode).first();
        if (!admin) return json({ error: 'مسموح لكبير العائلة بس' }, 403);
        if ((confirmCode || '').toUpperCase() !== upperCode) {
          return json({ error: 'لازم تكتب كود العائلة بالظبط للتأكيد' }, 400);
        }
        const validPassword = await verifySecret(password, admin.pin_hash);
        if (!validPassword) return json({ error: 'كلمة السر غلط' }, 401);

        await performFamilyDeletion(env, ctx, upperCode, adminId, admin.name, 'حذف فوري بواسطة كبير العائلة من داخل التطبيق');

        return json({ ok: true });
      }

      // ---------- رفع وسائط (صور/صوت/فيديو) إلى R2 ----------
      const mediaUploadMatch = path.match(/^\/api\/chat\/([A-Z0-9]+)\/media$/);
      if (mediaUploadMatch && method === 'POST') {
        const familyCodeVal = mediaUploadMatch[1];
        const body = await request.json(); // { senderId, senderName, mediaType, base64, ext, contentType }
        // نوع الملف لازم يكون من قائمة معروفة وآمنة بس - مش أي حاجة تتبعت
        const ALLOWED_CONTENT_TYPES = [
          'image/jpeg', 'image/png', 'image/webp', 'image/gif',
          'audio/webm', 'audio/mpeg', 'audio/ogg', 'audio/mp4', 'audio/aac', 'audio/wav', 'audio/x-m4a', 'audio/m4a',
          'video/mp4', 'video/webm', 'video/quicktime',
        ];
        if (!ALLOWED_CONTENT_TYPES.includes(body.contentType)) {
          return json({ error: 'نوع الملف ده مش مسموح بيه' }, 400);
        }
        const base64Data = (body.base64 || '').split(',').pop();
        // حد أقصى 15 ميجا للملف الأصلي (base64 بيكبر الحجم ~33%، فبنحسب الحد بناءً على طول النص المشفّر)
        const MAX_FILE_BYTES = 15 * 1024 * 1024;
        if (!base64Data || base64Data.length > MAX_FILE_BYTES * 1.4) {
          return json({ error: 'حجم الملف أكبر من المسموح (15 ميجا كحد أقصى)' }, 400);
        }
        const key = `${familyCodeVal}/${genId('media')}.${body.ext || 'bin'}`;
        const binary = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));
        if (binary.length > MAX_FILE_BYTES) {
          return json({ error: 'حجم الملف أكبر من المسموح (15 ميجا كحد أقصى)' }, 400);
        }
        await env.MEDIA.put(key, binary, { httpMetadata: { contentType: body.contentType } });

        const id = genId('c');
        await env.DB.prepare(
          `INSERT INTO chat_messages (id, family_code, sender_id, sender_name, text, media_type, media_key, timestamp)
           VALUES (?, ?, ?, ?, NULL, ?, ?, ?)`
        ).bind(id, familyCodeVal, body.senderId, body.senderName, body.mediaType, key, Date.now()).run();

        const mediaLabel = body.mediaType === 'image' ? 'صورة' : body.mediaType === 'video' ? 'فيديو' : 'تسجيل صوتي';
        ctx.waitUntil(notifyFamilyChatMessage(env, familyCodeVal, body.senderId, body.senderName, '📎 أرسل ' + mediaLabel));

        return json({ id, mediaUrl: `/api/media/${key}` });
      }

      // ---------- تحميل ملف وسائط من R2 ----------
      const mediaGetMatch = path.match(/^\/api\/media\/(.+)$/);
      if (mediaGetMatch && method === 'GET') {
        const obj = await env.MEDIA.get(mediaGetMatch[1]);
        if (!obj) return new Response('Not found', { status: 404, headers: corsHeaders() });
        return new Response(obj.body, {
          headers: {
            'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
            'Cache-Control': 'public, max-age=31536000',
            ...corsHeaders(),
          },
        });
      }

      return json({ error: 'not found' }, 404);
    } catch (err) {
      return json({ error: 'Server error: ' + err.message }, 500);
    }
  },

  // ---------- تشغيل تلقائي كل ساعة (Cron Trigger) لحذف البيانات القديمة وتنفيذ طلبات الحذف المؤجلة ----------
  // مواعيد التشغيل متسجلة في wrangler.toml تحت [triggers]. محتاج تفعيله بعد النشر:
  //   wrangler deploy   (الكرون بيتفعل تلقائيًا مع النشر لو معرّف في wrangler.toml)
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanupOldData(env));
    ctx.waitUntil(processDueDeletionRequests(env, ctx));
  },
};
