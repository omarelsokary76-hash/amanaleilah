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
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
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

async function getFamilyWithMembers(db, code) {
  const fam = await db.prepare('SELECT * FROM families WHERE code = ?').bind(code).first();
  if (!fam) return null;
  const { results: members } = await db.prepare('SELECT * FROM members WHERE family_code = ?').bind(code).all();
  return {
    code: fam.code,
    createdAt: fam.created_at,
    members: members.map(m => ({
      id: m.id, name: m.name, phone: m.phone, relation: m.relation,
      role: m.role, isAdmin: !!m.is_admin, status: m.status,
      circle: JSON.parse(m.circle || '[]'),
    })),
  };
}

function checkAdminAuth(request, env) {
  const key = request.headers.get('x-admin-key');
  return key && env.ADMIN_KEY && key === env.ADMIN_KEY;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
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
          return json({ events: results.map(e => ({
            id: e.id, familyCode: e.family_code, type: e.type, occasionType: e.occasion_type,
            memberName: e.member_name, text: e.text, lat: e.lat, lng: e.lng,
            accuracy: e.accuracy, timestamp: e.timestamp,
          })) });
        }

        return json({ error: 'not found' }, 404);
      }

      // ---------- إنشاء عائلة جديدة ----------
      if (path === '/api/family/create' && method === 'POST') {
        const body = await request.json();
        const { name, phone, relation } = body;
        if (!name || !phone) return json({ error: 'الاسم والهاتف مطلوبين' }, 400);

        let code = genCode();
        for (let i = 0; i < 8; i++) {
          const exists = await env.DB.prepare('SELECT code FROM families WHERE code = ?').bind(code).first();
          if (!exists) break;
          code = genCode();
        }

        const now = Date.now();
        await env.DB.prepare('INSERT INTO families (code, created_at) VALUES (?, ?)').bind(code, now).run();

        const id = genId('m');
        await env.DB.prepare(
          `INSERT INTO members (id, family_code, name, phone, relation, role, is_admin, status, circle, created_at)
           VALUES (?, ?, ?, ?, ?, 'parent', 1, 'approved', '[]', ?)`
        ).bind(id, code, name, phone, relation, now).run();

        const family = await getFamilyWithMembers(env.DB, code);
        return json({ family, myId: id });
      }

      // ---------- تسجيل دخول (عضو موجود) ----------
      if (path === '/api/family/login' && method === 'POST') {
        const { code, phone } = await request.json();
        const family = await getFamilyWithMembers(env.DB, (code || '').toUpperCase());
        if (!family) return json({ error: 'كود العائلة غير صحيح' }, 404);
        const member = family.members.find(m => m.phone === phone);
        if (!member) return json({ error: 'رقم الهاتف غير مسجل في العائلة دي' }, 404);
        return json({ family, myId: member.id });
      }

      // ---------- الانضمام لعائلة (طلب معلّق) ----------
      if (path === '/api/family/register' && method === 'POST') {
        const { code, name, phone, relation } = await request.json();
        const upperCode = (code || '').toUpperCase();
        const fam = await env.DB.prepare('SELECT code FROM families WHERE code = ?').bind(upperCode).first();
        if (!fam) return json({ error: 'كود العائلة غير صحيح' }, 404);

        const existingPhone = await env.DB.prepare(
          'SELECT id FROM members WHERE family_code = ? AND phone = ?'
        ).bind(upperCode, phone).first();
        if (existingPhone) return json({ error: 'رقم الهاتف ده مسجل بالفعل، استخدم تسجيل الدخول' }, 409);

        const id = genId('m');
        const role = (relation === 'أب' || relation === 'أم') ? 'parent' : 'child';
        const now = Date.now();
        await env.DB.prepare(
          `INSERT INTO members (id, family_code, name, phone, relation, role, is_admin, status, circle, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 0, 'approved', '[]', ?)`
        ).bind(id, upperCode, name, phone, relation, role, now).run();

        const family = await getFamilyWithMembers(env.DB, upperCode);
        return json({ family, myId: id });
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
        const admin = await env.DB.prepare('SELECT is_admin FROM members WHERE id = ?').bind(requestedByAdminId).first();
        if (!admin || !admin.is_admin) return json({ error: 'مسموح لكبير العائلة بس' }, 403);
        await env.DB.prepare('DELETE FROM members WHERE id = ? AND family_code = ?').bind(memberId, code).run();
        const family = await getFamilyWithMembers(env.DB, code);
        return json({ family });
      }

      // ---------- تحديث دائرة الثقة الشخصية ----------
      if (path === '/api/family/circle' && method === 'POST') {
        const { code, memberId, circle } = await request.json();
        await env.DB.prepare('UPDATE members SET circle = ? WHERE id = ? AND family_code = ?')
          .bind(JSON.stringify(circle), memberId, code).run();
        const family = await getFamilyWithMembers(env.DB, code);
        return json({ family });
      }

      // ---------- الأحداث (SOS / اطمئنان / مناسبات) ----------
      const eventsMatch = path.match(/^\/api\/events\/([A-Z0-9]+)$/);
      if (eventsMatch && method === 'GET') {
        const limit = parseInt(url.searchParams.get('limit') || '60', 10);
        const { results } = await env.DB.prepare(
          'SELECT * FROM events WHERE family_code = ? ORDER BY timestamp DESC LIMIT ?'
        ).bind(eventsMatch[1], limit).all();
        return json({ events: results.map(e => ({
          id: e.id, type: e.type, occasionType: e.occasion_type, memberId: e.member_id,
          memberName: e.member_name, text: e.text, lat: e.lat, lng: e.lng,
          accuracy: e.accuracy, timestamp: e.timestamp,
        })) });
      }
      if (eventsMatch && method === 'POST') {
        const body = await request.json();
        const id = genId('e');
        await env.DB.prepare(
          `INSERT INTO events (id, family_code, type, occasion_type, member_id, member_name, text, lat, lng, accuracy, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          id, eventsMatch[1], body.type, body.occasionType || null, body.memberId, body.memberName,
          body.text || null, body.lat ?? null, body.lng ?? null, body.accuracy ?? null, Date.now()
        ).run();
        return json({ id });
      }

      // ---------- الشات (نصوص) ----------
      const chatMatch = path.match(/^\/api\/chat\/([A-Z0-9]+)$/);
      if (chatMatch && method === 'GET') {
        const limit = parseInt(url.searchParams.get('limit') || '100', 10);
        const { results } = await env.DB.prepare(
          'SELECT * FROM chat_messages WHERE family_code = ? ORDER BY timestamp ASC LIMIT ?'
        ).bind(chatMatch[1], limit).all();
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
        return json({ id });
      }

      // ---------- رفع وسائط (صور/صوت/فيديو) إلى R2 ----------
      const mediaUploadMatch = path.match(/^\/api\/chat\/([A-Z0-9]+)\/media$/);
      if (mediaUploadMatch && method === 'POST') {
        const familyCodeVal = mediaUploadMatch[1];
        const body = await request.json(); // { senderId, senderName, mediaType, base64, ext }
        const key = `${familyCodeVal}/${genId('media')}.${body.ext || 'bin'}`;
        const binary = Uint8Array.from(atob(body.base64.split(',').pop()), c => c.charCodeAt(0));
        await env.MEDIA.put(key, binary, { httpMetadata: { contentType: body.contentType || 'application/octet-stream' } });

        const id = genId('c');
        await env.DB.prepare(
          `INSERT INTO chat_messages (id, family_code, sender_id, sender_name, text, media_type, media_key, timestamp)
           VALUES (?, ?, ?, ?, NULL, ?, ?, ?)`
        ).bind(id, familyCodeVal, body.senderId, body.senderName, body.mediaType, key, Date.now()).run();

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
};
