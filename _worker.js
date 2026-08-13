// _worker.js  -  Cloudflare Pages advanced mode.
//   /api/balance : public guest balance lookup (rate limited, secret-gated)
//   /api/blaze   : staff-only proxy to the Blaze Partner API
//
// REQUIRED binding (Pages > Settings > Variables and Secrets):
//   LOOKUP_SECRET  (encrypted)  - must match app_secrets.balance_lookup_token
//                                 in Supabase, or balance lookups will fail.
//
// OPTIONAL binding (Pages > Settings > Bindings > KV namespace):
//   RATELIMIT_KV                - shared rate-limit counters across isolates.
//                                 Without it the limiter falls back to
//                                 per-isolate memory, which is much leakier.
//                                 Several other binding spellings are accepted
//                                 too - see pickKv(). The namespace's *title*
//                                 is irrelevant; only the binding variable
//                                 name is read.
//
// Every /api/balance response carries `x-rl: kv | mem | mem-fallback` so the
// live limiter can be confirmed with one curl instead of guessing at whether a
// binding took effect. Bindings and secrets only apply to deployments created
// AFTER they are saved.

const BLAZE_BASE = "https://api.partners.blaze.me";
const SUPABASE_URL = "https://cskmqqjvjqreldiwgizb.supabase.co";
// Public by design - the anon key is safe to ship. It is NOT what protects
// customer data; row-level security and LOOKUP_SECRET are.
const SUPABASE_ANON = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNza21xcWp2anFyZWxkaXdnaXpiIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQ4MzE4NDgsImV4cCI6MjEwMDQwNzg0OH0.4q_twc3Lig6mq9mdHDWlHt9wNw5YhdS2mfAA17USGR8";

const RL_MAX = 15;      // lookups allowed per window, per IP
const RL_WINDOW = 60;   // window length in seconds

// Security response headers, applied to every response below because a _headers
// file is ignored in advanced (_worker.js) mode.
//   strict-transport-security : force HTTPS for a year. The site is already
//     HTTPS-only behind Cloudflare, so this only closes the first-visit
//     SSL-strip window. includeSubDomains scopes to the cash.* subtree only, not
//     the apex, so it is safe here. `preload` is deliberately omitted — hard to reverse.
//   x-content-type-options    : nosniff — stop MIME-type guessing on responses.
//   x-frame-options           : DENY — no framing, blocks clickjacking of the
//     staff login / PII pages. (No CSP frame-ancestors yet — separate tested pass.)
//   referrer-policy           : no-referrer — never leak the URL to third parties.
const SEC_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer"
};

function json(o, s, extra) {
  const headers = {
    "content-type": "application/json",
    "cache-control": "no-store",
    ...SEC_HEADERS
  };
  if (extra) { for (const k in extra) { if (extra[k] != null) headers[k] = String(extra[k]); } }
  return new Response(JSON.stringify(o), { status: s || 200, headers: headers });
}

async function verifyStaff(request) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) return false;
  try {
    const r = await fetch(SUPABASE_URL + "/auth/v1/user", {
      headers: { apikey: SUPABASE_ANON, Authorization: "Bearer " + token }
    });
    return r.status === 200;
  } catch (e) { return false; }
}

function pickEnv(env, names) {
  for (var i = 0; i < names.length; i++) { var v = env[names[i]]; if (v) return v; }
  return "";
}

// ---- Rate limiting -------------------------------------------------------
// Preferred path is KV so the count is shared across isolates and colos.
// KV is eventually consistent and this is a read-then-write, so a determined
// attacker can squeeze through a few extra requests. That is acceptable: the
// LOOKUP_SECRET gate is what actually prevents bulk scraping, and this is
// defence in depth on top of it.
const MEM = new Map();

function memLimited(ip) {
  const now = Date.now(), win = RL_WINDOW * 1000;
  const hits = (MEM.get(ip) || []).filter(function (t) { return now - t < win; });
  hits.push(now);
  MEM.set(ip, hits);
  if (MEM.size > 5000) MEM.clear();
  return hits.length > RL_MAX;
}

// The KV namespace is looked up under several plausible binding names rather
// than one exact spelling. A mis-named binding used to fall back to per-isolate
// memory silently, which is indistinguishable from working. Same tolerance
// pattern as pickEnv() does for the Blaze credentials.
//
// Duck-typed on get/put so a same-named string variable can never be mistaken
// for a namespace.
function pickKv(env) {
  const names = [
    "RATELIMIT_KV", "RATE_LIMIT_KV", "RATELIMITKV", "ratelimit_kv",
    "RATELIMIT", "RATE_LIMIT", "CANNA_CASH_RATELIMIT", "CANNACASH_RATELIMIT",
    "canna_cash_ratelimit", "cannacash_ratelimit", "KV"
  ];
  for (let i = 0; i < names.length; i++) {
    const v = env[names[i]];
    if (v && typeof v.get === "function" && typeof v.put === "function") return v;
  }
  return null;
}

// Returns { limited, backend } — backend is surfaced as the x-rl response
// header so which limiter is actually live can be checked from outside without
// reading logs. Silent config drift is what made this class of bug expensive.
async function checkRateLimit(env, ip) {
  const kv = pickKv(env);
  if (!kv) return { limited: memLimited(ip), backend: "mem" };
  try {
    const bucket = Math.floor(Date.now() / (RL_WINDOW * 1000));
    const key = "rl:" + ip + ":" + bucket;
    const current = parseInt((await kv.get(key)) || "0", 10);
    if (current >= RL_MAX) return { limited: true, backend: "kv" };
    // TTL floor in Workers KV is 60s.
    await kv.put(key, String(current + 1), { expirationTtl: Math.max(60, RL_WINDOW) });
    return { limited: false, backend: "kv" };
  } catch (e) {
    // Never let a KV hiccup take the balance page down.
    return { limited: memLimited(ip), backend: "mem-fallback" };
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ---- PUBLIC: guest balance lookup (no login) ----
    if (url.pathname === "/api/balance") {
      const ip = request.headers.get("cf-connecting-ip") || "0.0.0.0";
      const rl = await checkRateLimit(env, ip);
      // Stamped on every response from this route, including errors.
      const diag = { "x-rl": rl.backend };
      if (rl.limited) return json({ error: "rate_limited" }, 429, diag);

      const secret = env.LOOKUP_SECRET || "";
      if (!secret) {
        // Fail loudly rather than silently returning "no match" for every
        // customer, which would look like data loss rather than misconfig.
        return json({ error: "server_misconfigured" }, 500, diag);
      }

      let q = "";
      if (request.method === "POST") {
        try { const b = await request.json(); q = (b && b.q != null) ? String(b.q) : ""; } catch (e) {}
      } else {
        q = url.searchParams.get("q") || "";
      }
      q = q.trim();
      if (q.length < 2) return json({ found: false }, 200, diag);

      try {
        const r = await fetch(SUPABASE_URL + "/rest/v1/rpc/guest_balance", {
          method: "POST",
          headers: {
            "apikey": SUPABASE_ANON,
            "Authorization": "Bearer " + SUPABASE_ANON,
            "content-type": "application/json"
          },
          body: JSON.stringify({ p_query: q, p_token: secret })
        });
        // A non-2xx from PostgREST is a fault on our side, not a missing member.
        // Returning { found:false } here would have looked like data loss.
        if (!r.ok) return json({ error: "lookup_upstream_" + r.status }, 502, diag);
        const rows = await r.json();
        const row = Array.isArray(rows) ? rows[0] : rows;
        if (!row || !row.match_count) return json({ found: false }, 200, diag);
        if (row.match_count > 1) return json({ found: false, multiple: true }, 200, diag);
        return json({
          found: true,
          name: row.display_name,
          balance: Number(row.balance),
          code: row.referral_code || ""
        }, 200, diag);
      } catch (e) {
        return json({ error: "lookup_failed" }, 502, diag);
      }
    }

    // ---- STAFF ONLY: Blaze Partner API proxy ----
    if (url.pathname === "/api/blaze") {
      if (!(await verifyStaff(request))) return json({ error: "unauthorized" }, 401);

      const KEY = pickEnv(env, ["BLAZE_KEY","Blaze Key","BLAZE KEY","blaze_key","BlazeKey","blazeKey"]);
      const SECRET = pickEnv(env, ["BLAZE_SECRET","Blaze Secret","BLAZE SECRET","blaze_secret","BlazeSecret","blazeSecret"]);
      // Do not echo Object.keys(env) here - that discloses the names of every
      // binding on the project, including unrelated secrets.
      if (!KEY || !SECRET) return json({ error: "missing_secrets" }, 500);

      let path = url.searchParams.get("path") || "/api/v1/partner/store";
      if (!path.startsWith("/")) path = "/" + path;

      // Auth probing knobs, kept while the Blaze partner integration is still
      // being scoped:
      //   akey  = which credential goes in Authorization: "key" | "secret"
      //   extra = header carrying the other one: partner_key | x-api-key | apikey | none
      const akey = (url.searchParams.get("akey") || "secret").toLowerCase();
      const extra = (url.searchParams.get("extra") || "partner_key").toLowerCase();
      const authVal = akey === "key" ? KEY : SECRET;
      const otherVal = akey === "key" ? SECRET : KEY;
      const headers = { "Authorization": authVal, "Accept": "application/json" };
      if (extra && extra !== "none") {
        const map = { "partner_key": "partner_key", "x-api-key": "x-api-key", "apikey": "apikey" };
        headers[map[extra] || "partner_key"] = otherVal;
      }

      // Pin the host so a crafted ?path= cannot redirect the credentials
      // somewhere else.
      let target;
      try {
        target = new URL(BLAZE_BASE + path);
        if (target.host !== new URL(BLAZE_BASE).host) return json({ error: "bad_path" }, 400);
      } catch (e) { return json({ error: "bad_path" }, 400); }

      let r, body;
      try { r = await fetch(target.toString(), { headers, redirect: "manual" }); body = await r.text(); }
      catch (e) { return json({ error: "fetch_failed", detail: String(e) }, 502); }

      return new Response(body, {
        status: r.status,
        headers: {
          "content-type": "application/json",
          "cache-control": "no-store",
          ...SEC_HEADERS,
          "x-blaze-status": String(r.status)
        }
      });
    }

    // Static assets. Asset responses can be immutable, so copy before mutating.
    // A _headers file would be ignored in advanced mode, so the security
    // headers are layered on the HTML page here.
    const assetResp = await env.ASSETS.fetch(request);
    const out = new Response(assetResp.body, assetResp);
    for (const k in SEC_HEADERS) out.headers.set(k, SEC_HEADERS[k]);
    return out;
  }
};
