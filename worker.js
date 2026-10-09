/**
 * 쿠팡 파트너스 인기상품 프록시 (Cloudflare Workers)
 *
 * 설치 순서
 *  1) npm i -g wrangler && wrangler login
 *  2) wrangler kv namespace create CACHE  → 출력된 id를 wrangler.toml 에 붙여넣기
 *  3) wrangler secret put COUPANG_ACCESS_KEY
 *     wrangler secret put COUPANG_SECRET_KEY
 *  4) wrangler.toml 의 ALLOWED_ORIGINS 에 블로그 주소 입력
 *  5) wrangler deploy → 나온 주소를 테마의 CFG.api 에 입력
 *
 * 동작
 *  - /best?cat=1016&limit=20 → 해당 카테고리 베스트 상품 JSON
 *  - KV에 1시간(TTL) 저장, 만료 전에는 쿠팡 API를 호출하지 않음
 *  - 쿠팡 API 장애 시 만료된 캐시라도 있으면 그걸로 응답(stale)
 */

const HOST = 'https://api-gateway.coupang.com';
const BASE = '/v2/providers/affiliate_open_api/apis/openapi/v1';
const TTL_MS = 60 * 60 * 1000;

// 쿠팡 베스트 카테고리 ID (테마의 탭과 맞출 것)
const CATS = new Set([
  '1001', '1002', '1010', '1011', '1012', '1013', '1014', '1015', '1016',
  '1017', '1018', '1019', '1020', '1021', '1024', '1025', '1026', '1029',
]);

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const cors = corsHeaders(req, env);

    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (req.method !== 'GET') return json({ error: 'method_not_allowed' }, 405, cors);
    if (url.pathname !== '/best') return json({ error: 'not_found' }, 404, cors);

    const cat = url.searchParams.get('cat') || '1014';
    if (!CATS.has(cat)) return json({ error: 'bad_category' }, 400, cors);

    let limit = parseInt(url.searchParams.get('limit') || '20', 10);
    if (!(limit >= 1)) limit = 20;
    limit = Math.min(limit, 50);

    // limit 값과 무관하게 카테고리당 한 번만 호출하도록 항상 50개를 받아 저장
    const key = 'best:' + cat;
    const cached = await env.CACHE.get(key, 'json');

    if (cached && Date.now() - cached.t < TTL_MS) {
      return json(slice(cached, limit), 200, cors);
    }

    try {
      const fresh = await fetchBest(cat, env);
      await env.CACHE.put(key, JSON.stringify(fresh), { expirationTtl: 60 * 60 * 24 });
      return json(slice(fresh, limit), 200, cors);
    } catch (e) {
      console.error('fetchBest failed:', e && e.message);
      if (cached) return json(slice(cached, limit, true), 200, cors);
      return json({ error: 'upstream_failed', reason: String((e && e.message) || e) }, 502, cors);
    }
  },
};

async function fetchBest(cat, env) {
  if (!env.COUPANG_ACCESS_KEY || !env.COUPANG_SECRET_KEY) throw new Error('missing_secret');
  const path = `${BASE}/products/bestcategories/${cat}`;
  const query = 'limit=50';
  const auth = await authorization('GET', path, query, env);

  const res = await fetch(`${HOST}${path}?${query}`, {
    headers: { Authorization: auth, 'Content-Type': 'application/json;charset=UTF-8' },
  });
  if (!res.ok) throw new Error('http_' + res.status);

  const body = await res.json();
  if (String(body.rCode) !== '0' || !Array.isArray(body.data)) throw new Error('api_' + body.rCode);

  return {
    t: Date.now(),
    cat,
    items: body.data.map((p, i) => ({
      rank: p.rank || i + 1,
      id: p.productId,
      name: p.productName,
      price: p.productPrice,
      image: p.productImage,
      url: p.productUrl,
      rocket: !!p.isRocket,
      free: !!p.isFreeShipping,
    })),
  };
}

function slice(data, limit, stale) {
  const out = { t: data.t, cat: data.cat, items: data.items.slice(0, limit) };
  if (stale) out.stale = true;
  return out;
}

// 쿠팡 HMAC: message = signedDate + METHOD + path + query(물음표 제외)
async function authorization(method, path, query, env) {
  const signedDate = coupangDate();
  const message = signedDate + method + path + query;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(env.COUPANG_SECRET_KEY),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `CEA algorithm=HmacSHA256, access-key=${env.COUPANG_ACCESS_KEY}, signed-date=${signedDate}, signature=${hex}`;
}

function coupangDate() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return (
    String(d.getUTCFullYear()).slice(2) + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) +
    'T' + p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + 'Z'
  );
}

// Origin 비교용 정규화: "http://a.com/" , "HTTP://A.com" → "http://a.com"
function normOrigin(v) {
  try { return new URL(v.trim()).origin.toLowerCase(); }
  catch { return v.trim().replace(/\/+$/, '').toLowerCase(); }
}

function corsHeaders(req, env) {
  const origin = req.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean).map(normOrigin);
  const h = {
    Vary: 'Origin',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
  if (!allowed.length) h['Access-Control-Allow-Origin'] = '*';
  else if (origin && allowed.includes(normOrigin(origin))) h['Access-Control-Allow-Origin'] = origin;
  return h;
}

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json;charset=UTF-8',
      'Cache-Control': 'public, max-age=60',
      ...cors,
    },
  });
}
