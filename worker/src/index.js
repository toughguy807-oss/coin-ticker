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
    `SELECT s.user_id, s.expires_at, u.username
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token = ?`).bind(token).first();
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  return { userId: row.user_id, username: row.username, token };
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

async function handleRegister(request, env, origin) {
  const { username, password } = await request.json().catch(() => ({}));
  const bad = checkCredentials(username, password);
  if (bad) return json({ error: bad }, 400, env, origin);

  const dup = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (dup) return json({ error: '이미 사용 중인 아이디입니다.' }, 409, env, origin);

  const { hash, salt } = await hashPassword(password);
  const res = await env.DB.prepare(
    'INSERT INTO users (username, pw_hash, pw_salt, created_at) VALUES (?,?,?,?)')
    .bind(username, hash, salt, Date.now()).run();
  const userId = res.meta.last_row_id;
  return json({ token: await issueSession(env, userId), username }, 200, env, origin);
}

async function handleLogin(request, env, origin) {
  const { username, password } = await request.json().catch(() => ({}));
  if (!username || !password) return json({ error: '아이디와 비밀번호를 입력해 주세요.' }, 400, env, origin);

  const user = await env.DB.prepare('SELECT id, username, pw_hash, pw_salt FROM users WHERE username = ?')
    .bind(username).first();
  // 아이디 존재 여부를 응답으로 구분할 수 없게 메시지를 하나로 통일한다
  const fail = () => json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' }, 401, env, origin);
  if (!user) { await derive(password, new Uint8Array(16)); return fail(); }   // 타이밍 평탄화
  if (!await verifyPassword(password, user.pw_salt, user.pw_hash)) return fail();

  return json({ token: await issueSession(env, user.id), username: user.username }, 200, env, origin);
}

/* ---------- 트레이드 히스토리 ---------- */
const num = v => (typeof v === 'number' && isFinite(v) ? v : null);

async function listTrades(env, origin, me) {
  const { results } = await env.DB.prepare(
    `SELECT id, traded_at, from_market, to_market, from_qty, to_qty, ratio,
            from_price, to_price, quote, fee_applied, memo
       FROM trades WHERE user_id = ? ORDER BY traded_at DESC, id DESC LIMIT 500`)
    .bind(me.userId).all();
  return json({ trades: results || [] }, 200, env, origin);
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
      if (p === '/api/auth/register' && request.method === 'POST') return await handleRegister(request, env, origin);
      if (p === '/api/auth/login'    && request.method === 'POST') return await handleLogin(request, env, origin);

      // 이하 로그인 필요
      const me = await authenticate(request, env);

      if (p === '/api/auth/logout' && request.method === 'POST') {
        if (me) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(me.token).run();
        return json({ ok: true }, 200, env, origin);
      }
      if (p === '/api/auth/me') {
        return me ? json({ username: me.username }, 200, env, origin)
                  : json({ error: '로그인이 필요합니다.' }, 401, env, origin);
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
