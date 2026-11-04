// Dogs Life : relais vers Claude pour les conseils du jour.
// La clé Anthropic reste ici, en secret Cloudflare (ANTHROPIC_API_KEY), jamais dans le site.

const PROJECT = "dogs-life-801c4";
const ORIGINS = ["https://wikzouustudio.github.io", "https://wikzouustudio.com", "https://www.wikzouustudio.com"];
const MODEL = "claude-sonnet-5-5";
const PER_DAY = 30;            // demandes max par personne et par jour
const MAX_INPUT = 12000;       // caractères max envoyés à Claude

const JWK_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
let jwkCache = null, jwkUntil = 0;

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": ORIGINS.includes(origin) ? origin : ORIGINS[0],
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}
function reply(status, body, origin) {
  return new Response(JSON.stringify(body), {status, headers: {"Content-Type": "application/json", ...cors(origin)}});
}
function b64u(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

async function googleKeys() {
  if (jwkCache && Date.now() < jwkUntil) return jwkCache;
  const r = await fetch(JWK_URL);
  if (!r.ok) throw new Error("jwk");
  const m = /max-age=(\d+)/.exec(r.headers.get("Cache-Control") || "");
  jwkCache = (await r.json()).keys; jwkUntil = Date.now() + (m ? +m[1] : 3600) * 1000;
  return jwkCache;
}

// Vérifie le jeton de connexion Firebase et renvoie l'identifiant de la personne.
async function verifyToken(token) {
  const parts = (token || "").split(".");
  if (parts.length !== 3) return null;
  let head, pay;
  try { head = JSON.parse(new TextDecoder().decode(b64u(parts[0]))); pay = JSON.parse(new TextDecoder().decode(b64u(parts[1]))); } catch { return null; }
  if (head.alg !== "RS256") return null;
  const jwk = (await googleKeys()).find(k => k.kid === head.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk, {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"}, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64u(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1]));
  const now = Math.floor(Date.now() / 1000);
  if (!ok || pay.aud !== PROJECT || pay.iss !== "https://securetoken.google.com/" + PROJECT) return null;
  if (!(pay.exp > now) || !(pay.iat <= now + 60) || !pay.sub) return null;
  return pay.sub;
}

// La personne doit faire partie de la famille (lu avec ses propres droits Firestore).
async function isMember(family, uid, token) {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(family || "")) return false;
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/families/${family}/access/${uid}`;
  const r = await fetch(url, {headers: {Authorization: "Bearer " + token}});
  return r.ok;
}

// Limite simple par personne et par jour.
async function underLimit(uid) {
  const cache = caches.default, day = new Date().toISOString().slice(0, 10);
  const key = new Request(`https://limite.carnet/${uid}/${day}`);
  const hit = await cache.match(key), n = hit ? +(await hit.text()) : 0;
  if (n >= PER_DAY) return false;
  await cache.put(key, new Response(String(n + 1), {headers: {"Cache-Control": "max-age=90000"}}));
  return true;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    if (request.method === "OPTIONS") return new Response(null, {status: 204, headers: cors(origin)});
    if (request.method !== "POST") return reply(405, {error: "method"}, origin);
    if (origin && !ORIGINS.includes(origin)) return reply(403, {error: "origin"}, origin);
    if (!env.ANTHROPIC_API_KEY) return reply(500, {error: "cle_manquante"}, origin);

    const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    let uid = null;
    try { uid = await verifyToken(token); } catch { uid = null; }
    if (!uid) return reply(401, {error: "connexion"}, origin);

    let body;
    try { body = await request.json(); } catch { return reply(400, {error: "json"}, origin); }
    const input = typeof body.input === "string" ? body.input.slice(0, MAX_INPUT) : "";
    if (!input) return reply(400, {error: "vide"}, origin);
    if (!(await isMember(body.family, uid, token))) return reply(403, {error: "famille"}, origin);
    if (!(await underLimit(uid))) return reply(429, {error: "limite"}, origin);

    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {"x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
      body: JSON.stringify({model: MODEL, max_tokens: 1200, messages: [{role: "user", content: input}]})
    });
    if (r.status === 429) return reply(429, {error: "limite"}, origin);
    if (!r.ok) return reply(502, {error: "claude", status: r.status, detail: (await r.text()).slice(0, 300)}, origin);

    const data = await r.json();
    const text = (data.content || []).filter(c => c.type === "text").map(c => c.text).join("");
    const a = text.indexOf("{"), b = text.lastIndexOf("}");
    try { return reply(200, JSON.parse(text.slice(a, b + 1)), origin); }
    catch { return reply(502, {error: "format"}, origin); }
  }
};
