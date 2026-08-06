/**
 * coin-ticker API (Cloudflare Workers + D1)
 *
 * 두 가지를 한다.
 *  1) 업비트 REST 프록시 — 브라우저가 직접 부르면 Origin 단위로 묶여 분당 약 10회지만
 *     서버에서 Origin 없이 부르면 group=ticker 로 분당 600회다. 여기서 대신 불러 캐시까지
 *     얹으므로 사용자가 몇 명이든 업비트로 나가는 요청은 TTL당 한 번이다.
 *  2) 계정 + 트레이드 히스토리 — 비밀번호는 PBKDF2 해시로만 저장하고 세션은 Bearer 토큰.
 *     프론트가 다른 출처(GitHub Pages)에 있어 크로스 오리진 쿠키를 피하려 토큰 방식을 쓴다.
 */

const SESSION_TTL = 30 * 24 * 3600 * 1000;   // 30일
const PBKDF2_ITER = 100000;

/* ---------- 공통 ---------- */
const enc = new TextEncoder();
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = s => new Uint8Array(s.match(/.{2}/g).map(b => parseInt(b, 16)));

function corsHeaders(env, origin) {
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const ok = origin && allowed.includes(origin);
  return {
    'Access-Control-Allow-Origin': ok ? origin : (allowed[0] || '*'),
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,PATCH,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}
const json = (data, status, env, origin) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...corsHeaders(env, origin) },
  });

/* ---------- 비밀번호 / 세션 ---------- */
async function derive(password, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, key, 256);
  return hex(bits);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { hash: await derive(password, salt), salt: hex(salt) };
}
async function verifyPassword(password, saltHex, expected) {
  const got = await derive(password, unhex(saltHex));
  // 길이가 같은 hex 문자열끼리 상수시간 비교 — 조기 반환으로 정보가 새지 않게
  if (got.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}
const newToken = () => hex(crypto.getRandomValues(new Uint8Array(32)));

async function authenticate(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT s.user_id, s.expires_at, u.username, u.is_admin, u.must_change_pw
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token = ?`).bind(token).first();
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  return { userId: row.user_id, username: row.username, token,
           isAdmin: !!row.is_admin, mustChangePw: !!row.must_change_pw };
}

/* ---------- 업비트 프록시 ---------- */
function ttlFor(path) {
  if (path.startsWith('market/all')) return 3600;   // 상장 목록은 거의 안 변한다
  if (path.startsWith('candles/'))   return 30;
  if (path.startsWith('ticker'))     return 2;      // 실시간은 WebSocket이 담당
  return 5;
}
async function proxyUpbit(url, env, ctx, origin) {
  const path = url.pathname.replace(/^\/api\/upbit\//, '');
  if (!/^[a-z0-9/_-]+$/i.test(path)) return json({ error: 'bad path' }, 400, env, origin);

  const target = `https://api.upbit.com/v1/${path}${url.search}`;
  const cache = caches.default;
  const cacheKey = new Request(target);
  let hit = await cache.match(cacheKey);

  if (!hit) {
    // Origin 헤더를 붙이지 않는 것이 핵심 — 붙는 순간 분당 10회 그룹으로 떨어진다
    const upstream = await fetch(target, { headers: { Accept: 'application/json' } });
    const body = await upstream.text();
    hit = new Response(body, {
      status: upstream.status,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': `public, max-age=${ttlFor(path)}`,
      },
    });
    if (upstream.ok) ctx.waitUntil(cache.put(cacheKey, hit.clone()));
  }
  const out = new Response(hit.body, hit);
  Object.entries(corsHeaders(env, origin)).forEach(([k, v]) => out.headers.set(k, v));
  return out;
}

/* ---------- 계정 ---------- */
function checkCredentials(username, password) {
  if (typeof username !== 'string' || typeof password !== 'string') return '아이디와 비밀번호를 입력해 주세요.';
  if (!/^[A-Za-z0-9가-힣_-]{3,20}$/.test(username)) return '아이디는 3~20자의 한글·영문·숫자·_- 만 가능합니다.';
  if (password.length < 8) return '비밀번호는 8자 이상이어야 합니다.';
  if (password.length > 200) return '비밀번호가 너무 깁니다.';
  return null;
}
async function issueSession(env, userId) {
  const token = newToken(), now = Date.now();
  await env.DB.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)')
    .bind(token, userId, now, now + SESSION_TTL).run();
  return token;
}

async function userCount(env) {
  const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
  return r ? r.n : 0;
}

/* 공개 회원가입은 없다. 계정은 관리자가 발급한다.
   다만 최초의 관리자 하나는 어딘가에서 생겨야 하므로, 계정이 0개일 때만
   이 경로가 열린다. 첫 계정이 만들어지는 순간 영구히 닫힌다. */
async function handleBootstrap(request, env, origin) {
  if (await userCount(env) > 0)
    return json({ error: '가입은 닫혀 있습니다. 관리자에게 계정 발급을 요청하세요.' }, 403, env, origin);

  const { username, password } = await request.json().catch(() => ({}));
  const bad = checkCredentials(username, password);
  if (bad) return json({ error: bad }, 400, env, origin);

  const { hash, salt } = await hashPassword(password);
  const res = await env.DB.prepare(
    'INSERT INTO users (username, pw_hash, pw_salt, created_at, is_admin) VALUES (?,?,?,?,1)')
    .bind(username, hash, salt, Date.now()).run();
  return json({ token: await issueSession(env, res.meta.last_row_id), username, isAdmin: true }, 200, env, origin);
}

/* 관리자의 계정 발급 — 비밀번호는 서버가 만들어 응답에서 한 번만 보여 준다.
   받는 사람은 임시 비밀번호로 첫 로그인한 뒤 반드시 자기 것으로 바꾸게 된다. */
async function createUser(request, env, origin) {
  const { username, is_admin } = await request.json().catch(() => ({}));
  if (typeof username !== 'string' || !/^[A-Za-z0-9가-힣_-]{3,20}$/.test(username))
    return json({ error: '아이디는 3~20자의 한글·영문·숫자·_- 만 가능합니다.' }, 400, env, origin);

  const dup = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (dup) return json({ error: '이미 사용 중인 아이디입니다.' }, 409, env, origin);

  const pw = tempPassword();
  const { hash, salt } = await hashPassword(pw);
  await env.DB.prepare(
    `INSERT INTO users (username, pw_hash, pw_salt, created_at, is_admin, must_change_pw)
     VALUES (?,?,?,?,?,1)`)
    .bind(username, hash, salt, Date.now(), is_admin ? 1 : 0).run();
  return json({ username, password: pw, isAdmin: !!is_admin }, 200, env, origin);
}

/* ---------- 비밀번호 변경 / 관리자 재설정 ---------- */
async function changePassword(request, env, origin, me) {
  const { current, next } = await request.json().catch(() => ({}));
  if (typeof next !== 'string' || next.length < 8) return json({ error: '새 비밀번호는 8자 이상이어야 합니다.' }, 400, env, origin);
  if (next.length > 200) return json({ error: '비밀번호가 너무 깁니다.' }, 400, env, origin);

  const u = await env.DB.prepare('SELECT pw_hash, pw_salt FROM users WHERE id = ?').bind(me.userId).first();
  if (!u || !await verifyPassword(String(current || ''), u.pw_salt, u.pw_hash))
    return json({ error: '현재 비밀번호가 올바르지 않습니다.' }, 401, env, origin);

  const { hash, salt } = await hashPassword(next);
  await env.DB.prepare('UPDATE users SET pw_hash = ?, pw_salt = ?, must_change_pw = 0 WHERE id = ?')
    .bind(hash, salt, me.userId).run();
  // 비밀번호를 바꿨으면 다른 기기의 세션은 끊는다 (지금 쓰는 세션만 남김)
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?').bind(me.userId, me.token).run();
  return json({ ok: true }, 200, env, origin);
}

// 사람이 받아 적기 쉬운 임시 비밀번호 (혼동되는 O0Il1 제외)
function tempPassword() {
  const CS = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const buf = crypto.getRandomValues(new Uint8Array(12));
  return [...buf].map(b => CS[b % CS.length]).join('');
}
async function listUsers(env, origin) {
  const { results } = await env.DB.prepare(
    `SELECT u.id, u.username, u.created_at, u.is_admin, u.must_change_pw,
            (SELECT COUNT(*) FROM trades t WHERE t.user_id = u.id) AS trade_count
       FROM users u ORDER BY u.id`).all();
  return json({ users: results || [] }, 200, env, origin);
}
async function resetPassword(request, env, origin, me) {
  const { user_id } = await request.json().catch(() => ({}));
  const target = await env.DB.prepare('SELECT id, username, is_admin FROM users WHERE id = ?').bind(user_id).first();
  if (!target) return json({ error: '없는 계정입니다.' }, 404, env, origin);
  if (target.id === me.userId) return json({ error: '본인 비밀번호는 비밀번호 변경에서 바꿔 주세요.' }, 400, env, origin);

  const pw = tempPassword();
  const { hash, salt } = await hashPassword(pw);
  await env.DB.prepare('UPDATE users SET pw_hash = ?, pw_salt = ?, must_change_pw = 1 WHERE id = ?')
    .bind(hash, salt, target.id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(target.id).run();  // 기존 세션 전부 무효화
  // 임시 비밀번호는 저장하지 않고 이 응답에서 한 번만 보여 준다
  return json({ username: target.username, password: pw }, 200, env, origin);
}
async function deleteUser(env, origin, me, id) {
  if (id === me.userId) return json({ error: '본인 계정은 삭제할 수 없습니다.' }, 400, env, origin);
  const t = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(id).first();
  if (!t) return json({ error: '없는 계정입니다.' }, 404, env, origin);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM trades   WHERE user_id = ?').bind(id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id),
    env.DB.prepare('DELETE FROM users    WHERE id = ?').bind(id),
  ]);
  return json({ ok: true }, 200, env, origin);
}

async function handleLogin(request, env, origin) {
  const { username, password } = await request.json().catch(() => ({}));
  if (!username || !password) return json({ error: '아이디와 비밀번호를 입력해 주세요.' }, 400, env, origin);

  const user = await env.DB.prepare(
    'SELECT id, username, pw_hash, pw_salt, is_admin, must_change_pw FROM users WHERE username = ?')
    .bind(username).first();
  // 아이디 존재 여부를 응답으로 구분할 수 없게 메시지를 하나로 통일한다
  const fail = () => json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' }, 401, env, origin);
  if (!user) { await derive(password, new Uint8Array(16)); return fail(); }   // 타이밍 평탄화
  if (!await verifyPassword(password, user.pw_salt, user.pw_hash)) return fail();

  return json({ token: await issueSession(env, user.id), username: user.username,
                isAdmin: !!user.is_admin, mustChangePw: !!user.must_change_pw }, 200, env, origin);
}

/* ---------- 트레이드 히스토리 ---------- */
const num = v => (typeof v === 'number' && isFinite(v) ? v : null);

async function listTrades(env, origin, me) {
  const { results } = await env.DB.prepare(
    `SELECT id, traded_at, from_market, to_market, from_qty, to_qty, ratio,
            from_price, to_price, quote, fee_applied, memo
       FROM trades WHERE user_id = ? ORDER BY traded_at DESC, id DESC LIMIT 500`)
    .bind(me.userId).all();
  // 기록은 계정에 계속 쌓이지만 화면에는 500건까지만 내려간다.
  // 전체 건수를 함께 주어 "잘렸다"는 사실이 조용히 묻히지 않게 한다.
  const cnt = await env.DB.prepare('SELECT COUNT(*) AS n FROM trades WHERE user_id = ?')
    .bind(me.userId).first();
  return json({ trades: results || [], total: cnt ? cnt.n : (results || []).length }, 200, env, origin);
}

async function createTrade(request, env, origin, me) {
  const b = await request.json().catch(() => ({}));
  const fromQty = num(b.from_qty), toQty = num(b.to_qty), ratio = num(b.ratio);
  if (!b.from_market || !b.to_market) return json({ error: '교환한 코인 정보가 없습니다.' }, 400, env, origin);
  if (!(fromQty > 0) || !(toQty > 0) || !(ratio > 0)) return json({ error: '수량과 교환비는 0보다 커야 합니다.' }, 400, env, origin);

  const now = Date.now();
  const tradedAt = num(b.traded_at) || now;
  const memo = typeof b.memo === 'string' ? b.memo.slice(0, 200) : null;
  const res = await env.DB.prepare(
    `INSERT INTO trades (user_id, traded_at, from_market, to_market, from_qty, to_qty, ratio,
                         from_price, to_price, quote, fee_applied, memo, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .bind(me.userId, tradedAt, String(b.from_market), String(b.to_market), fromQty, toQty, ratio,
          num(b.from_price) || 0, num(b.to_price) || 0, String(b.quote || 'KRW'),
          b.fee_applied ? 1 : 0, memo, now).run();
  return json({ id: res.meta.last_row_id }, 200, env, origin);
}

async function deleteTrade(env, origin, me, id) {
  // user_id 조건을 함께 걸어 남의 기록은 지울 수 없게 한다
  const res = await env.DB.prepare('DELETE FROM trades WHERE id = ? AND user_id = ?')
    .bind(id, me.userId).run();
  if (!res.meta.changes) return json({ error: '없는 기록입니다.' }, 404, env, origin);
  return json({ ok: true }, 200, env, origin);
}

/* ---------- 라우팅 ---------- */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    const p = url.pathname;

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(env, origin) });

    try {
      if (p.startsWith('/api/upbit/')) {
        if (request.method !== 'GET') return json({ error: 'method' }, 405, env, origin);
        return await proxyUpbit(url, env, ctx, origin);
      }
      // 계정이 하나도 없을 때만 최초 관리자를 만들 수 있다 (프론트가 화면을 가르는 근거)
      if (p === '/api/auth/bootstrap' && request.method === 'GET')
        return json({ needed: await userCount(env) === 0 }, 200, env, origin);
      if (p === '/api/auth/register' && request.method === 'POST') return await handleBootstrap(request, env, origin);
      if (p === '/api/auth/login'    && request.method === 'POST') return await handleLogin(request, env, origin);

      // 이하 로그인 필요
      const me = await authenticate(request, env);

      if (p === '/api/auth/logout' && request.method === 'POST') {
        if (me) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(me.token).run();
        return json({ ok: true }, 200, env, origin);
      }
      if (p === '/api/auth/me') {
        return me ? json({ username: me.username, isAdmin: me.isAdmin, mustChangePw: me.mustChangePw }, 200, env, origin)
                  : json({ error: '로그인이 필요합니다.' }, 401, env, origin);
      }
      if (p === '/api/auth/change-password' && request.method === 'POST') {
        if (!me) return json({ error: '로그인이 필요합니다.' }, 401, env, origin);
        return await changePassword(request, env, origin, me);
      }
      if (p.startsWith('/api/admin/')) {
        if (!me) return json({ error: '로그인이 필요합니다.' }, 401, env, origin);
        if (!me.isAdmin) return json({ error: '관리자만 사용할 수 있습니다.' }, 403, env, origin);
        if (p === '/api/admin/users' && request.method === 'GET')  return await listUsers(env, origin);
        if (p === '/api/admin/users' && request.method === 'POST') return await createUser(request, env, origin);
        if (p === '/api/admin/reset-password' && request.method === 'POST') return await resetPassword(request, env, origin, me);
        const du = p.match(/^\/api\/admin\/users\/(\d+)$/);
        if (du && request.method === 'DELETE') return await deleteUser(env, origin, me, +du[1]);
      }
      if (p.startsWith('/api/trades')) {
        if (!me) return json({ error: '로그인이 필요합니다.' }, 401, env, origin);
        if (p === '/api/trades' && request.method === 'GET')  return await listTrades(env, origin, me);
        if (p === '/api/trades' && request.method === 'POST') return await createTrade(request, env, origin, me);
        const m = p.match(/^\/api\/trades\/(\d+)$/);
        if (m && request.method === 'DELETE') return await deleteTrade(env, origin, me, +m[1]);
      }
      return json({ error: 'not found' }, 404, env, origin);
    } catch (err) {
      return json({ error: '서버 오류', detail: String(err && err.message || err) }, 500, env, origin);
    }
  },

  // 만료 세션 정리 (wrangler.toml 에 [triggers] crons 를 추가하면 동작)
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(Date.now()).run());
  },
};
