const LINE_API = "https://api.line.me";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return json({
        ok: true,
        service: "customer-liff-webhook",
        configured: {
          database: Boolean(env.DB),
          channelSecret: Boolean(env.LINE_CHANNEL_SECRET),
          channelAccessToken: Boolean(env.LINE_CHANNEL_ACCESS_TOKEN),
          lineLoginChannelId: Boolean(env.LINE_LOGIN_CHANNEL_ID),
        },
      });
    }

    if (url.pathname === "/webhook" && request.method === "POST") {
      return handleWebhook(request, env, ctx);
    }

    if (url.pathname.startsWith("/api/")) {
      return handleApi(request, env, url);
    }

    return json({ ok: false, message: "Not found" }, 404);
  },
};

async function handleWebhook(request, env, ctx) {
  const body = await request.text();
  const signature = request.headers.get("x-line-signature") || "";

  if (!await verifyWebhookSignature(body, signature, env.LINE_CHANNEL_SECRET)) {
    return json({ ok: false, error: "invalid_signature" }, 401);
  }

  let payload;
  try {
    payload = JSON.parse(body);
  } catch {
    return json({ ok: false, error: "invalid_json" }, 400);
  }

  ctx.waitUntil(processEvents(payload.events || [], env));
  return json({ ok: true });
}

async function processEvents(events, env) {
  for (const event of events) {
    if (event.type !== "message") continue;

    const sourceType = event.source?.type;
    if (sourceType !== "user" && sourceType !== "group") continue;

    const userId = event.source?.userId || null;
    const groupId = sourceType === "group" ? event.source?.groupId || null : null;
    const conversationId = sourceType === "group" ? groupId : userId;
    if (!conversationId) continue;

    try {
      if (sourceType === "group") {
        await cacheGroup(groupId, env);
        if (userId) await cacheGroupMember(groupId, userId, env);
      } else if (userId) {
        await cacheUser(userId, env);
      }
    } catch (error) {
      console.warn("Unable to refresh LINE profile", String(error));
    }

    const message = event.message || {};
    await env.DB.prepare(`
      INSERT OR IGNORE INTO messages (
        webhook_event_id,
        conversation_type,
        conversation_id,
        group_id,
        user_id,
        message_id,
        message_type,
        message_text,
        sent_at,
        raw_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      event.webhookEventId || `${message.id || "unknown"}:${event.timestamp || Date.now()}`,
      sourceType,
      conversationId,
      groupId,
      userId,
      message.id || null,
      message.type || "unknown",
      message.type === "text" ? message.text || "" : null,
      Number(event.timestamp || Date.now()),
      JSON.stringify(event)
    ).run();
  }
}

async function cacheUser(userId, env) {
  const profile = await lineGet(`/v2/bot/profile/${encodeURIComponent(userId)}`, env);
  await env.DB.prepare(`
    INSERT INTO users (user_id, display_name, picture_url, updated_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(user_id) DO UPDATE SET
      display_name = excluded.display_name,
      picture_url = excluded.picture_url,
      updated_at = CURRENT_TIMESTAMP
  `).bind(userId, profile.displayName || null, profile.pictureUrl || null).run();
}

async function cacheGroup(groupId, env) {
  const group = await lineGet(`/v2/bot/group/${encodeURIComponent(groupId)}/summary`, env);
  await env.DB.prepare(`
    INSERT INTO groups (group_id, group_name, picture_url, updated_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(group_id) DO UPDATE SET
      group_name = excluded.group_name,
      picture_url = excluded.picture_url,
      updated_at = CURRENT_TIMESTAMP
  `).bind(groupId, group.groupName || null, group.pictureUrl || null).run();
}

async function cacheGroupMember(groupId, userId, env) {
  const profile = await lineGet(
    `/v2/bot/group/${encodeURIComponent(groupId)}/member/${encodeURIComponent(userId)}`,
    env
  );
  await env.DB.prepare(`
    INSERT INTO members (group_id, user_id, display_name, picture_url, updated_at)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(group_id, user_id) DO UPDATE SET
      display_name = excluded.display_name,
      picture_url = excluded.picture_url,
      updated_at = CURRENT_TIMESTAMP
  `).bind(groupId, userId, profile.displayName || null, profile.pictureUrl || null).run();
}

async function lineGet(path, env) {
  const response = await fetch(`${LINE_API}${path}`, {
    headers: { Authorization: `Bearer ${env.LINE_CHANNEL_ACCESS_TOKEN}` },
  });
  if (!response.ok) throw new Error(`LINE API ${response.status}`);
  return response.json();
}

async function handleApi(request, env, url) {
  const cors = getCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return cors
      ? new Response(null, { status: 204, headers: cors })
      : new Response(null, { status: 403 });
  }

  if (!cors) return json({ ok: false, error: "origin_not_allowed" }, 403);
  if (!["GET", "POST", "DELETE"].includes(request.method)) {
  if (request.method !== "GET") return apiJson({ ok: false, error: "method_not_allowed" }, 405, cors);
    return apiJson({ ok: false, error: "method_not_allowed" }, 405, cors);
  }

  const viewer = await authenticateLiff(request, env);
  if (!viewer) return apiJson({ ok: false, error: "invalid_token" }, 401, cors);

  const admin = await env.DB.prepare(
    "SELECT user_id, display_name FROM admins WHERE user_id = ? LIMIT 1"
  ).bind(viewer.sub).first();

  if (url.pathname === "/api/me") {
  if (url.pathname === "/api/me" && request.method === "GET") {
    return apiJson({
      ok: true,
      isAdmin: Boolean(admin),
      viewer: {
        userId: viewer.sub,
        displayName: viewer.name || admin?.display_name || null,
        pictureUrl: viewer.picture || null,
      },
    }, 200, cors);
  }

  if (!admin) return apiJson({ ok: false, error: "forbidden" }, 403, cors);

  if (url.pathname === "/api/messages") {
  if (url.pathname === "/api/messages" && request.method === "GET") {
    return getMessages(url, env, viewer, admin, cors);
  }

  if (url.pathname === "/api/admins" && request.method === "GET") {
    return getAdmins(env, viewer, cors);
  }

  if (url.pathname === "/api/admins" && request.method === "POST") {
    return addAdmin(request, env, cors);
  }

  if (url.pathname.startsWith("/api/admins/") && request.method === "DELETE") {
    const userId = decodeURIComponent(url.pathname.slice("/api/admins/".length));
    return removeAdmin(userId, env, viewer, cors);
  }

  return apiJson({ ok: false, error: "not_found" }, 404, cors);
}

async function getAdmins(env, viewer, cors) {
  const result = await env.DB.prepare(`
    SELECT
      known.user_id,
      MAX(known.display_name) AS display_name,
      MAX(known.picture_url) AS picture_url,
      MAX(known.last_seen) AS last_seen,
      CASE WHEN a.user_id IS NULL THEN 0 ELSE 1 END AS is_admin,
      MAX(a.created_at) AS admin_since
    FROM (
      SELECT user_id, display_name, picture_url, updated_at AS last_seen FROM users
      UNION ALL
      SELECT user_id, display_name, picture_url, updated_at AS last_seen FROM members
      UNION ALL
      SELECT user_id, display_name, NULL AS picture_url, created_at AS last_seen FROM admins
    ) AS known
    LEFT JOIN admins a ON a.user_id = known.user_id
    WHERE known.user_id IS NOT NULL
    GROUP BY known.user_id, a.user_id
    ORDER BY is_admin DESC, display_name COLLATE NOCASE, known.user_id
    LIMIT 500
  `).all();

  const people = result.results || [];
  return apiJson({
    ok: true,
    viewerUserId: viewer.sub,
    admins: people.filter((person) => Number(person.is_admin) === 1),
    candidates: people.filter((person) => Number(person.is_admin) !== 1),
  }, 200, cors);
}

async function addAdmin(request, env, cors) {
  let body;
  try {
    body = await request.json();
  } catch {
    return apiJson({ ok: false, error: "invalid_json" }, 400, cors);
  }

  const userId = String(body?.userId || "").trim();
  if (!/^U[0-9a-f]{32}$/i.test(userId)) {
    return apiJson({ ok: false, error: "invalid_user_id" }, 400, cors);
  }

  const known = await env.DB.prepare(`
    SELECT display_name FROM users WHERE user_id = ?
    UNION ALL
    SELECT display_name FROM members WHERE user_id = ?
    LIMIT 1
  `).bind(userId, userId).first();
  const displayName = String(body?.displayName || known?.display_name || "未命名管理員").trim();

  const result = await env.DB.prepare(`
    INSERT OR IGNORE INTO admins (user_id, display_name)
    VALUES (?, ?)
  `).bind(userId, displayName).run();

  return apiJson({
    ok: true,
    created: Number(result.meta?.changes || 0) > 0,
  }, 200, cors);
}

async function removeAdmin(userId, env, viewer, cors) {
  if (!/^U[0-9a-f]{32}$/i.test(userId)) {
    return apiJson({ ok: false, error: "invalid_user_id" }, 400, cors);
  }
  if (userId === viewer.sub) {
    return apiJson({ ok: false, error: "self_removal_not_allowed" }, 400, cors);
  }

  const countRow = await env.DB.prepare("SELECT COUNT(*) AS total FROM admins").first();
  if (Number(countRow?.total || 0) <= 1) {
    return apiJson({ ok: false, error: "last_admin" }, 409, cors);
  }

  const result = await env.DB.prepare("DELETE FROM admins WHERE user_id = ?")
    .bind(userId)
    .run();
  if (Number(result.meta?.changes || 0) === 0) {
    return apiJson({ ok: false, error: "admin_not_found" }, 404, cors);
  }

  return apiJson({ ok: true }, 200, cors);
}

async function getMessages(url, env, viewer, admin, cors) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit")) || 100, 1), 100);
  const before = Number(url.searchParams.get("before")) || null;

  let sql = `
    SELECT
      m.id,
      m.conversation_type,
      m.conversation_id,
      m.group_id,
      m.user_id,
      m.message_id,
      m.message_type,
      m.message_text,
      m.sent_at,
      CASE
        WHEN m.conversation_type = 'group' THEN COALESCE(g.group_name, '未知群組')
        ELSE '私訊'
      END AS conversation_name,
      COALESCE(g.group_name, CASE WHEN m.conversation_type = 'user' THEN '私訊' END) AS group_name,
      COALESCE(mem.display_name, u.display_name, '未知使用者') AS sender_name,
      COALESCE(mem.picture_url, u.picture_url) AS sender_picture_url
    FROM messages m
    LEFT JOIN groups g ON g.group_id = m.group_id
    LEFT JOIN members mem ON mem.group_id = m.group_id AND mem.user_id = m.user_id
    LEFT JOIN users u ON u.user_id = m.user_id
  `;
  const bindings = [];

  if (before) {
    sql += " WHERE m.id < ?";
    bindings.push(before);
  }
  sql += " ORDER BY m.id DESC LIMIT ?";
  bindings.push(limit + 1);

  const result = await env.DB.prepare(sql).bind(...bindings).all();
  const rows = result.results || [];
  const hasMore = rows.length > limit;
  const items = hasMore ? rows.slice(0, limit) : rows;

  return apiJson({
    ok: true,
    items,
    nextBefore: hasMore ? items[items.length - 1].id : null,
    viewer: {
      userId: viewer.sub,
      displayName: viewer.name || admin.display_name || null,
      pictureUrl: viewer.picture || null,
    },
  }, 200, cors);
}

async function authenticateLiff(request, env) {
  const authorization = request.headers.get("authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;

  const form = new URLSearchParams({
    id_token: match[1],
    client_id: String(env.LINE_LOGIN_CHANNEL_ID || ""),
  });
  const response = await fetch(`${LINE_API}/oauth2/v2.1/verify`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });

  if (!response.ok) return null;
  const payload = await response.json();
  return payload.aud === String(env.LINE_LOGIN_CHANNEL_ID) ? payload : null;
}

function getCorsHeaders(request, env) {
  const origin = request.headers.get("origin");
  const allowed = String(env.ALLOWED_ORIGIN || "")
    .split(",")
    .map((value) => value.trim().replace(/\/+$/, ""))
    .filter(Boolean);
  const normalized = String(origin || "").replace(/\/+$/, "");
  if (!origin || !allowed.includes(normalized)) return null;

  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, OPTIONS",
    "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
    "access-control-allow-headers": "Authorization, Content-Type",
    "access-control-max-age": "86400",
    "vary": "Origin",
  };
}

async function verifyWebhookSignature(body, signature, secret) {
  if (!signature || !secret) return false;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const digest = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
  const expected = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return timingSafeEqual(expected, signature);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let index = 0; index < a.length; index += 1) {
    result |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return result === 0;
}

function apiJson(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...cors,
    },
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}
