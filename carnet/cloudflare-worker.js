// Dogs Life : petit serveur gratuit (Cloudflare Workers).
//  - POST /notify : quand quelqu'un note un pipi, coche une tâche ou écrit un message, prévient le reste de la famille.
//  - toutes les 5 minutes (Cron) : rappelle les tâches à l'heure, et une fois si elles ne sont toujours pas faites 30 min après.
//  - POST /      : (facultatif) conseils de Claude, seulement si un secret ANTHROPIC_API_KEY est ajouté.
// Secrets à ajouter dans Cloudflare (Settings → Variables and secrets) :
//  - FIREBASE_SA        : le contenu complet du fichier JSON « compte de service » de Firebase (obligatoire pour les notifications)
//  - ANTHROPIC_API_KEY  : facultatif

const PROJECT = "dogs-life-official-web";
const ORIGINS = ["https://wikzouustudio.github.io", "https://wikzouustudio.com", "https://www.wikzouustudio.com"];
const APP_URL = "https://wikzouustudio.github.io/WikzouuStudioOfficiel-/carnet/";
const MODEL = "claude-sonnet-5-5";
const MAX_INPUT = 12000;
const LATE_MIN = 30;           // second rappel si la tâche n'est pas cochée 30 min après
const DEFAULT_TZ = "Europe/Zurich";

const JWK_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const FS = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents`;
let jwkCache = null, jwkUntil = 0, saToken = null, saUntil = 0;

/* ---------- helpers ---------- */
function cors(origin) {
  return {"Access-Control-Allow-Origin": ORIGINS.includes(origin) ? origin : ORIGINS[0], "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Max-Age": "86400", "Vary": "Origin"};
}
const reply = (status, body, origin) => new Response(JSON.stringify(body), {status, headers: {"Content-Type": "application/json", ...cors(origin)}});
function b64u(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
const b64uEnc = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64uStr = s => b64uEnc(new TextEncoder().encode(s));

async function googleKeys() {
  if (jwkCache && Date.now() < jwkUntil) return jwkCache;
  const r = await fetch(JWK_URL); if (!r.ok) throw new Error("jwk");
  const m = /max-age=(\d+)/.exec(r.headers.get("Cache-Control") || "");
  jwkCache = (await r.json()).keys; jwkUntil = Date.now() + (m ? +m[1] : 3600) * 1000; return jwkCache;
}
// the person's Firebase sign-in token -> their account id
async function verifyToken(token) {
  const parts = (token || "").split("."); if (parts.length !== 3) return null;
  let head, pay; try { head = JSON.parse(new TextDecoder().decode(b64u(parts[0]))); pay = JSON.parse(new TextDecoder().decode(b64u(parts[1]))); } catch { return null; }
  if (head.alg !== "RS256") return null;
  const jwk = (await googleKeys()).find(k => k.kid === head.kid); if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk, {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"}, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64u(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1]));
  const now = Math.floor(Date.now() / 1000);
  if (!ok || pay.aud !== PROJECT || pay.iss !== "https://securetoken.google.com/" + PROJECT || !(pay.exp > now) || !(pay.iat <= now + 60) || !pay.sub) return null;
  return pay.sub;
}
const validId = s => /^[A-Za-z0-9_-]{1,64}$/.test(s || "");

/* ---------- service account: read Firestore and send notifications ---------- */
async function adminToken(env) {
  if (saToken && Date.now() < saUntil) return saToken;
  const sa = JSON.parse(env.FIREBASE_SA), now = Math.floor(Date.now() / 1000);
  const unsigned = b64uStr(JSON.stringify({alg: "RS256", typ: "JWT"})) + "." + b64uStr(JSON.stringify({iss: sa.client_email, sub: sa.client_email,
    aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600, scope: "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/firebase.messaging"}));
  const pem = sa.private_key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const key = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(pem), c => c.charCodeAt(0)), {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
  const r = await fetch("https://oauth2.googleapis.com/token", {method: "POST", headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + unsigned + "." + b64uEnc(sig)});
  if (!r.ok) throw new Error("oauth " + r.status);
  const j = await r.json(); saToken = j.access_token; saUntil = Date.now() + (j.expires_in - 120) * 1000; return saToken;
}
function val(v) {
  if (!v) return null;
  if ("stringValue" in v) return v.stringValue; if ("integerValue" in v) return +v.integerValue; if ("doubleValue" in v) return v.doubleValue;
  if ("booleanValue" in v) return v.booleanValue; if ("nullValue" in v) return null; if ("timestampValue" in v) return v.timestampValue;
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(val);
  if ("mapValue" in v) return fields(v.mapValue.fields); return null;
}
function fields(f) { const o = {}; for (const k in (f || {})) o[k] = val(f[k]); return o; }
const docId = name => name.split("/").pop();
async function list(env, path) {
  const tok = await adminToken(env), out = []; let page = "";
  for (let i = 0; i < 20; i++) {
    const r = await fetch(`${FS}/${path}?pageSize=300${page ? "&pageToken=" + page : ""}`, {headers: {Authorization: "Bearer " + tok}});
    if (!r.ok) break; const j = await r.json();
    (j.documents || []).forEach(d => out.push(Object.assign({_id: docId(d.name)}, fields(d.fields))));
    if (!j.nextPageToken) break; page = j.nextPageToken;
  }
  return out;
}
async function whereEq(env, parent, col, field, value) {
  const tok = await adminToken(env);
  const r = await fetch(`${FS}/${parent}:runQuery`, {method: "POST", headers: {Authorization: "Bearer " + tok, "Content-Type": "application/json"},
    body: JSON.stringify({structuredQuery: {from: [{collectionId: col}], where: {fieldFilter: {field: {fieldPath: field}, op: "EQUAL", value: {stringValue: value}}}, limit: 500}})});
  if (!r.ok) return [];
  return (await r.json()).filter(x => x.document).map(x => Object.assign({_id: docId(x.document.name)}, fields(x.document.fields)));
}
async function getDocAdmin(env, path) {
  const tok = await adminToken(env), r = await fetch(`${FS}/${path}`, {headers: {Authorization: "Bearer " + tok}});
  return r.ok ? fields((await r.json()).fields) : null;
}
async function delDocAdmin(env, path) { const tok = await adminToken(env); await fetch(`${FS}/${path}`, {method: "DELETE", headers: {Authorization: "Bearer " + tok}}); }

// one push to one phone; forgotten phones are removed
async function push(env, family, t, msg) {
  const tok = await adminToken(env);
  const r = await fetch(`https://fcm.googleapis.com/v1/projects/${PROJECT}/messages:send`, {method: "POST", headers: {Authorization: "Bearer " + tok, "Content-Type": "application/json"},
    body: JSON.stringify({message: {token: t.token, data: {title: msg.title, body: msg.body, tag: msg.tag || "", url: APP_URL},
      webpush: {headers: {Urgency: "high", TTL: "3600"}, fcm_options: {link: APP_URL}}}})});
  if (r.status === 404 || r.status === 400) { const e = await r.text(); if (/UNREGISTERED|INVALID_ARGUMENT|not a valid FCM/i.test(e)) await delDocAdmin(env, `families/${family}/pushTokens/${t._id}`); }
}

/* ---------- texts ---------- */
const L = {
  fr: {now: "C'est l'heure", late: "Toujours à faire", for: "pour", notYet: "n'est pas encore cochée.", did: "a fait", wrote: "Nouveau message de",
    k: {pipi: "Pipi", caca: "Caca", balade: "Balade", accident: "Accident", eau: "Eau", friandise: "Friandise", sieste: "Sieste", jeu: "Jeu", vomi: "Vomissement", photo: "Photo"}},
  en: {now: "It's time", late: "Still to do", for: "for", notYet: "hasn't been ticked yet.", did: "did", wrote: "New message from",
    k: {pipi: "Pee", caca: "Poo", balade: "Walk", accident: "Accident", eau: "Water", friandise: "Treat", sieste: "Nap", jeu: "Play", vomi: "Vomiting", photo: "Photo"}},
  hr: {now: "Vrijeme je", late: "Još za napraviti", for: "za", notYet: "još nije označeno.", did: "je obavio/la", wrote: "Nova poruka od",
    k: {pipi: "Piškenje", caca: "Kakanje", balade: "Šetnja", accident: "Nezgoda", eau: "Voda", friandise: "Poslastica", sieste: "Drijemež", jeu: "Igra", vomi: "Povraćanje", photo: "Fotografija"}}
};
const tx = t => L[t && t.lang] || L.fr;

/* ---------- family events: someone did something, tell the others ---------- */
async function onNotify(request, env, origin) {
  if (!env.FIREBASE_SA) return reply(500, {error: "cle_manquante"}, origin);
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const uid = await verifyToken(token).catch(() => null); if (!uid) return reply(401, {error: "connexion"}, origin);
  let b; try { b = await request.json(); } catch { return reply(400, {error: "json"}, origin); }
  if (!validId(b.family)) return reply(400, {error: "famille"}, origin);
  if (!(await getDocAdmin(env, `families/${b.family}/access/${uid}`))) return reply(403, {error: "famille"}, origin);
  const who = String(b.who || "").slice(0, 30), text = String(b.text || "").slice(0, 140), at = String(b.at || "").slice(0, 5);
  const tokens = (await list(env, `families/${b.family}/pushTokens`)).filter(t => t.token && t.uid !== uid && t.on !== false);
  await Promise.all(tokens.map(t => { const l = tx(t); let msg;
    if (b.kind === "msg") msg = {title: `${l.wrote} ${who}`, body: text, tag: "msg"};
    else if (b.kind === "log") msg = {title: `${who} · ${l.k[b.k] || text}`, body: at ? at : "", tag: "log"};
    else msg = {title: `${who} ${l.did}`, body: text + (at ? " · " + at : ""), tag: "tick"};
    return push(env, b.family, t, msg); }));
  return reply(200, {sent: tokens.length}, origin);
}

/* ---------- every 5 minutes: tasks that are due now, or still not done 30 min later ---------- */
function localNow(tz, when) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-CA", {timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23", weekday: "short"})
    .formatToParts(when).map(x => [x.type, x.value]));
  return {ds: `${p.year}-${p.month}-${p.day}`, min: +p.hour * 60 + +p.minute, wd: ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"].indexOf(p.weekday)};
}
const toMin = t => { const [h, m] = String(t || "0:0").split(":").map(Number); return h * 60 + (m || 0); };
async function remindFamily(env, fid, when) {
  const tokens = (await list(env, `families/${fid}/pushTokens`)).filter(t => t.token && t.on !== false);
  if (!tokens.length) return;
  const tz = tokens.find(t => t.tz) ? tokens.find(t => t.tz).tz : DEFAULT_TZ, n = localNow(tz, when);
  const inWindow = (tm, offset) => { const d = n.min - (toMin(tm) + offset); return d >= 0 && d < 5; };
  const [routine, meds, members, ticks, days, dogCfg] = await Promise.all([list(env, `families/${fid}/routine`), list(env, `families/${fid}/meds`), list(env, `families/${fid}/members`),
    whereEq(env, `families/${fid}`, "ticks", "date", n.ds), whereEq(env, `families/${fid}`, "days", "date", n.ds), getDocAdmin(env, `families/${fid}/config/dog`)]);
  const done = new Set(ticks.map(t => (t.dog || "main") + "|" + t.key));
  days.forEach(d => Object.keys(d.done || {}).forEach(k => done.add((d.dog || "main") + "|" + k)));
  const dogName = (dogCfg && dogCfg.name) || "";
  const tasks = [];
  routine.forEach(r => { if ((r.days || []).includes(n.wd)) tasks.push({key: "r-" + r._id, dog: r.dog || "main", time: r.time || "00:00", title: r.title || "", who: r.who || ""}); });
  meds.forEach(m => { if ((m.start && n.ds < m.start) || (m.end && n.ds > m.end)) return;
    (m.times || []).filter(Boolean).forEach(t => tasks.push({key: "m-" + m._id + "-" + t.replace(":", ""), dog: m.dog || "main", time: t, title: m.name || "", who: m.who || ""})); });
  for (const task of tasks) {
    if (done.has(task.dog + "|" + task.key)) continue;
    const now = inWindow(task.time, 0), late = inWindow(task.time, LATE_MIN); if (!now && !late) continue;
    const m = members.find(x => x._id === task.who), targets = m && m.uid ? tokens.filter(t => t.uid === m.uid) : tokens;
    await Promise.all(targets.map(t => { const l = tx(t), dn = task.dog === "main" && dogName ? ` ${l.for} ${dogName}` : "";
      return push(env, fid, t, now ? {title: `${l.now} · ${task.time}`, body: task.title + dn, tag: task.key} : {title: `${l.late} · ${task.time}`, body: `${task.title} ${l.notYet}`, tag: task.key}); }));
  }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "", path = new URL(request.url).pathname;
    if (request.method === "OPTIONS") return new Response(null, {status: 204, headers: cors(origin)});
    if (request.method !== "POST") return reply(405, {error: "method"}, origin);
    if (origin && !ORIGINS.includes(origin)) return reply(403, {error: "origin"}, origin);
    if (path === "/notify") return onNotify(request, env, origin);

    // advice from Claude (only if a key was added)
    if (!env.ANTHROPIC_API_KEY) return reply(500, {error: "cle_manquante"}, origin);
    const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    const uid = await verifyToken(token).catch(() => null); if (!uid) return reply(401, {error: "connexion"}, origin);
    let body; try { body = await request.json(); } catch { return reply(400, {error: "json"}, origin); }
    const input = typeof body.input === "string" ? body.input.slice(0, MAX_INPUT) : ""; if (!input) return reply(400, {error: "vide"}, origin);
    if (!validId(body.family)) return reply(403, {error: "famille"}, origin);
    const acc = await fetch(`${FS}/families/${body.family}/access/${uid}`, {headers: {Authorization: "Bearer " + token}}); if (!acc.ok) return reply(403, {error: "famille"}, origin);
    const r = await fetch("https://api.anthropic.com/v1/messages", {method: "POST", headers: {"x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
      body: JSON.stringify({model: MODEL, max_tokens: 1200, messages: [{role: "user", content: input}]})});
    if (r.status === 429) return reply(429, {error: "limite"}, origin);
    if (!r.ok) return reply(502, {error: "claude", status: r.status}, origin);
    const data = await r.json(), text = (data.content || []).filter(c => c.type === "text").map(c => c.text).join("");
    const a = text.indexOf("{"), b = text.lastIndexOf("}");
    try { return reply(200, JSON.parse(text.slice(a, b + 1)), origin); } catch { return reply(502, {error: "format"}, origin); }
  },
  async scheduled(event, env, ctx) {
    if (!env.FIREBASE_SA) return;
    const when = new Date(Math.floor(event.scheduledTime / 300000) * 300000); // the 5-minute slot this run covers
    const families = await list(env, "families");
    for (const f of families) { try { await remindFamily(env, f._id, when); } catch (e) { console.log("famille", f._id, e && e.message); } }
  }
};
