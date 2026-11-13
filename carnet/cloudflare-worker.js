// Dogs Life : petit serveur gratuit (Cloudflare Workers).
//  - POST /notify : quand quelqu'un note un pipi, coche une tâche ou écrit un message, prévient le reste de la famille.
//  - toutes les 5 minutes (Cron) : rappel 5 min avant chaque tâche (avec la météo pour les balades), relance 30 min après si pas faite,
//    beau temps pour sortir (1 fois par jour), rendez-vous (la veille à 18 h et 1 h avant), bilan du soir à 20 h 30, croquettes bientôt finies (9 h).
//  - centre de notifications : chaque événement crée une notification par destinataire (families/{id}/inbox), lue/non lue par personne,
//    synchronisée sur tous ses appareils par Firestore, plus une notification push sur chacun de ses téléphones.
//  - POST /test   : envoie une vraie notification à son propre téléphone (bouton « Tester » de l'app) et dit ce qui s'est passé.
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
const EARLY_MIN = 5;           // premier rappel 5 min avant l'heure
const DEFAULT_TZ = "Europe/Zurich";

const JWK_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const FS = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents`;
let jwkCache = null, jwkUntil = 0, saToken = null, saUntil = 0;

/* ---------- helpers ---------- */
function cors(origin) {
  return {"Access-Control-Allow-Origin": ORIGINS.includes(origin) ? origin : ORIGINS[0], "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Max-Age": "86400", "Vary": "Origin"};
}
const reply = (status, body, origin) => new Response(JSON.stringify(body), {status, headers: {"Content-Type": "application/json", "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", ...cors(origin)}});
// simple anti-spam: at most n requests per window for each account (per server instance)
const hits = new Map();
function tooMany(key, n, ms) {
  const now = Date.now(), h = (hits.get(key) || []).filter(t => now - t < ms); h.push(now); hits.set(key, h);
  if (hits.size > 5000) for (const [k, v] of hits) if (!v.length || now - v[v.length - 1] > ms) hits.delete(k);
  return h.length > n;
}
const clean = (v, n) => String(v || "").replace(/[\u0000-\u001F\u007F\u200B-\u200F\u202A-\u202E]/g, " ").trim().slice(0, n);
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
// who is in the family (access) and their phones; a phone only counts while its person is still in the family (left or removed: cleaned up)
async function familyCtx(env, fid) {
  const [toks, acc] = await Promise.all([list(env, `families/${fid}/pushTokens`), list(env, `families/${fid}/access`)]);
  const ok = new Set(acc.map(a => a._id)), tokens = [];
  for (const t of toks) { if (t.uid && ok.has(t.uid)) tokens.push(t); else await delDocAdmin(env, `families/${fid}/pushTokens/${t._id}`).catch(() => {}); }
  return {tokens, uids: [...ok]};
}

/* ---------- notification centre: one entry per person, written once (a retry never duplicates nor resets "read") ---------- */
const DB = `projects/${PROJECT}/databases/(default)/documents`;
const toFs = v => typeof v === "boolean" ? {booleanValue: v} : typeof v === "number" ? (Number.isInteger(v) ? {integerValue: String(v)} : {doubleValue: v}) : v == null ? {nullValue: null} : {stringValue: String(v)};
const nidOf = (ev, uid) => (String(ev).replace(/[^A-Za-z0-9_-]/g, "").slice(0, 90) || "ev" + Date.now()) + "-" + uid;
async function addInbox(env, fid, items) {
  const fresh = new Set(); if (!items.length) return fresh;
  const tok = await adminToken(env);
  for (let i = 0; i < items.length; i += 400) {
    const writes = items.slice(i, i + 400).map(({nid, data}) => { const f = {}; for (const k in data) f[k] = toFs(data[k]);
      return {update: {name: `${DB}/families/${fid}/inbox/${nid}`, fields: f}, currentDocument: {exists: false}}; });
    const r = await fetch(`https://firestore.googleapis.com/v1/${DB}:batchWrite`, {method: "POST", headers: {Authorization: "Bearer " + tok, "Content-Type": "application/json"}, body: JSON.stringify({writes})});
    const part = items.slice(i, i + 400);
    if (!r.ok) { console.log("inbox", r.status, (await r.text()).slice(0, 200)); part.forEach(x => fresh.add(x.nid)); continue; }
    const st = ((await r.json()).status || []); part.forEach((x, k) => { if (!st[k] || !st[k].code) fresh.add(x.nid); }); // already there = same event again: no second push
  }
  return fresh;
}
// an event for some people of the family: their notification centre + a push on each of their phones (pushOnly: the sender's own phones, no entry)
async function deliver(env, fid, ctx, o) {
  const at = Date.now(), who = [...new Set(o.uids || [])].filter(u => ctx.uids.includes(u)), per = {};
  const items = who.map(uid => { const t0 = ctx.tokens.find(t => t.uid === uid), m = o.make(tx(t0)), nid = nidOf(o.ev, uid); per[uid] = nid;
    return {nid, data: {to: uid, from: o.from || "", fromName: o.fromName || "", type: o.type, title: m.title, body: m.body || "", tab: o.tab || "", ev: String(o.ev), at, read: false}}; });
  const fresh = await addInbox(env, fid, items);
  if (items.length && !fresh.size) return []; // this exact event was already delivered
  const targets = ctx.tokens.filter(t => t.token && t.on !== false && wants(t, o.pref) && ((per[t.uid] && fresh.has(per[t.uid])) || (o.pushOnly || []).includes(t.uid)));
  return Promise.all(targets.map(t => { const nid = per[t.uid] || ""; return push(env, fid, t, Object.assign(o.make(tx(t)), {nid, tag: nid || String(o.ev), tab: o.tab || ""})); }));
}
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
async function patchDocAdmin(env, path, obj) {
  const tok = await adminToken(env), f = {}, mask = Object.keys(obj).map(k => "updateMask.fieldPaths=" + encodeURIComponent(k)).join("&");
  for (const k in obj) f[k] = {stringValue: String(obj[k])};
  await fetch(`${FS}/${path}?${mask}`, {method: "PATCH", headers: {Authorization: "Bearer " + tok, "Content-Type": "application/json"}, body: JSON.stringify({fields: f})});
}
async function delDocAdmin(env, path) { const tok = await adminToken(env); await fetch(`${FS}/${path}`, {method: "DELETE", headers: {Authorization: "Bearer " + tok}}); }

// one push to one phone; only a phone that no longer exists is forgotten (never because of a problem in the message)
async function push(env, family, t, msg) {
  const tok = await adminToken(env);
  const r = await fetch(`https://fcm.googleapis.com/v1/projects/${PROJECT}/messages:send`, {method: "POST", headers: {Authorization: "Bearer " + tok, "Content-Type": "application/json"},
    body: JSON.stringify({message: {token: t.token, data: {title: String(msg.title || "Dogs Life"), body: String(msg.body || ""), tag: String(msg.tag || ""), id: String(Date.now()) + Math.random().toString(36).slice(2, 6), nid: String(msg.nid || ""), tab: String(msg.tab || ""), url: APP_URL},
      webpush: {headers: {Urgency: "high", TTL: "86400"}, fcm_options: {link: APP_URL}}}})});
  if (r.ok) return {ok: true};
  const e = await r.text().catch(() => "");
  if (r.status === 404 || /UNREGISTERED|not a valid FCM registration token/i.test(e)) await delDocAdmin(env, `families/${family}/pushTokens/${t._id}`);
  const m = /"message"\s*:\s*"([^"]+)/.exec(e);
  console.log("fcm", r.status, e.slice(0, 300));
  return {ok: false, status: r.status, err: (m ? m[1] : e).slice(0, 140)};
}

/* ---------- texts ---------- */
const L = {
  fr: {test: "Notification envoyée par le serveur ✓", soon: "Dans 5 min", late: "Toujours à faire", for: "pour", notYet: "n'est pas encore cochée.", did: "a fait", wrote: "Nouveau message de",
    warn: "Météo à éviter pour la balade de {h}", better: "Mieux vers {h} : {i} {t}°, {p} % de pluie.", earlier: "Avancez-la ?", later: "Décalez-la ?", alsoBetter: "mieux vers {h}",
    ideal: "Temps idéal pour une balade", goOut: "Parfait pour sortir {n}", dryUntil: "sec jusqu'à", rain: "pluie probable", hot: "chaud, gardez-la courte", cold: "froid", nice: "temps idéal",
    tomorrow: "Demain", in1h: "Dans 1 heure", at: "à", recap: "Pas encore fait aujourd'hui", more: "et {n} autre(s)", food: "Croquettes bientôt finies", foodDays: "Il en reste pour environ {n} jour(s).",
    k: {pipi: "Pipi", caca: "Caca", balade: "Balade", accident: "Accident", eau: "Eau", friandise: "Friandise", sieste: "Sieste", jeu: "Jeu", vomi: "Vomissement", photo: "Photo"}},
  en: {test: "Notification sent by the server ✓", soon: "In 5 min", late: "Still to do", for: "for", notYet: "hasn't been ticked yet.", did: "did", wrote: "New message from",
    warn: "Bad weather for the {h} walk", better: "Better around {h}: {i} {t}°, {p}% rain.", earlier: "Go earlier?", later: "Go later?", alsoBetter: "better around {h}",
    ideal: "Perfect weather for a walk", goOut: "A great time to take {n} out", dryUntil: "dry until", rain: "rain likely", hot: "hot, keep it short", cold: "cold", nice: "ideal weather",
    tomorrow: "Tomorrow", in1h: "In 1 hour", at: "at", recap: "Not done yet today", more: "and {n} more", food: "Food running low", foodDays: "About {n} day(s) left.",
    k: {pipi: "Pee", caca: "Poo", balade: "Walk", accident: "Accident", eau: "Water", friandise: "Treat", sieste: "Nap", jeu: "Play", vomi: "Vomiting", photo: "Photo"}},
  hr: {test: "Obavijest poslana s poslužitelja ✓", soon: "Za 5 min", late: "Još za napraviti", for: "za", notYet: "još nije označeno.", did: "je obavio/la", wrote: "Nova poruka od",
    warn: "Loše vrijeme za šetnju u {h}", better: "Bolje oko {h}: {i} {t}°, {p} % kiše.", earlier: "Ranije?", later: "Kasnije?", alsoBetter: "bolje oko {h}",
    ideal: "Idealno vrijeme za šetnju", goOut: "Savršeno za izlazak ({n})", dryUntil: "suho do", rain: "moguća kiša", hot: "vruće, neka bude kratko", cold: "hladno", nice: "idealno vrijeme",
    tomorrow: "Sutra", in1h: "Za 1 sat", at: "u", recap: "Danas još nije napravljeno", more: "i još {n}", food: "Hrana pri kraju", foodDays: "Ostalo je za otprilike {n} dan(a).",
    k: {pipi: "Piškenje", caca: "Kakanje", balade: "Šetnja", accident: "Nezgoda", eau: "Voda", friandise: "Poslastica", sieste: "Drijemež", jeu: "Igra", vomi: "Povraćanje", photo: "Fotografija"}}
};
const tx = t => L[t && t.lang] || L.fr;
// each phone chooses what it wants: tasks, family, self (my own actions), weather, appts, daily (all on by default)
const wants = (t, k) => !k || !(t.prefs && t.prefs[k] === false);

/* ---------- family events: someone did something, tell the others ---------- */
async function onNotify(request, env, origin) {
  if (!env.FIREBASE_SA) return reply(500, {error: "cle_manquante"}, origin);
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const uid = await verifyToken(token).catch(() => null); if (!uid) return reply(401, {error: "connexion"}, origin);
  if (tooMany("n:" + uid, 30, 60000)) return reply(429, {error: "limite"}, origin);
  let b; try { b = await request.json(); } catch { return reply(400, {error: "json"}, origin); }
  if (!validId(b.family) || !["msg", "log", "tick"].includes(b.kind)) return reply(400, {error: "famille"}, origin);
  if (!(await getDocAdmin(env, `families/${b.family}/access/${uid}`))) return reply(403, {error: "famille"}, origin);
  const who = clean(b.who, 30), text = clean(b.text, 140), at = /^\d{1,2}:\d{2}$/.test(b.at || "") ? b.at : "";
  const ctx = await familyCtx(env, b.family), ev = (validId(b.ev) ? b.ev : b.kind + Date.now()).slice(0, 60);
  const make = l => b.kind === "msg" ? {title: `${l.wrote} ${who}`, body: text}
    : b.kind === "log" ? {title: `${who} · ${(Object.hasOwn(l.k, b.k) && l.k[b.k]) || text}`, body: at ? at : ""}
    : {title: `${who} ${l.did}`, body: text + (at ? " · " + at : "")};
  const self = ctx.tokens.some(t => t.uid === uid && wants(t, "self")) ? [uid] : [];
  const res = await deliver(env, b.family, ctx, {ev: b.kind + "-" + ev, uids: ctx.uids.filter(u => u !== uid), pushOnly: self, from: uid, fromName: who, pref: "family",
    type: b.kind === "msg" ? "message" : "activite", tab: b.kind === "msg" ? "famille" : "aujourdhui", make});
  const bad = res.filter(r => !r.ok);
  return reply(200, {sent: res.length, ok: res.length - bad.length, people: ctx.uids.length - 1, fail: bad.map(r => `${r.status} ${r.err}`).slice(0, 3)}, origin);
}

/* ---------- a real test: the server sends to the caller's own phones and reports what happened ---------- */
async function onTest(request, env, origin) {
  if (!env.FIREBASE_SA) return reply(500, {error: "cle_manquante"}, origin);
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const uid = await verifyToken(token).catch(() => null); if (!uid) return reply(401, {error: "connexion"}, origin);
  if (tooMany("t:" + uid, 10, 60000)) return reply(429, {error: "limite"}, origin);
  let b; try { b = await request.json(); } catch { return reply(400, {error: "json"}, origin); }
  if (!validId(b.family)) return reply(400, {error: "famille"}, origin);
  if (!(await getDocAdmin(env, `families/${b.family}/access/${uid}`))) return reply(403, {error: "famille"}, origin);
  const ctx = await familyCtx(env, b.family), all = ctx.tokens, mine = all.filter(t => t.uid === uid && t.token);
  const res = await deliver(env, b.family, ctx, {ev: "test-" + Date.now(), uids: [uid], type: "admin", tab: "profil", make: l => ({title: "Dogs Life", body: l.test})});
  const bad = res.filter(r => !r.ok);
  return reply(200, {tokens: mine.length, family: all.length, ok: res.length - bad.length, off: mine.filter(t => t.on === false).length, fail: bad.map(r => `${r.status} ${r.err}`).slice(0, 3)}, origin);
}

/* ---------- every 5 minutes: tasks that are due now, or still not done 30 min later ---------- */
function localNow(tz, when) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-CA", {timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23", weekday: "short"})
    .formatToParts(when).map(x => [x.type, x.value]));
  return {ds: `${p.year}-${p.month}-${p.day}`, min: +p.hour * 60 + +p.minute, wd: ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"].indexOf(p.weekday)};
}
const toMin = t => { const [h, m] = String(t || "0:0").split(":").map(Number); return h * 60 + (m || 0); };
const hm = m => String(Math.floor(m / 60)).padStart(2, "0") + ":" + String(m % 60).padStart(2, "0");
const wxIcon = c => c <= 1 ? "☀️" : c === 2 ? "🌤️" : c === 3 ? "☁️" : (c >= 71 && c <= 77) || c === 85 || c === 86 ? "❄️" : c >= 95 ? "⛈️" : (c >= 51 && c <= 67) || (c >= 80 && c <= 82) ? "🌧️" : "🌤️";
async function weather(cfg) {
  if (!cfg || cfg.lat == null) return null;
  try { const r = await fetch(`https://api.open-meteo.com/v1/forecast?latitude=${+cfg.lat}&longitude=${+cfg.lon}&hourly=temperature_2m,apparent_temperature,precipitation_probability,weather_code,wind_speed_10m&timezone=auto&forecast_days=1`);
    if (!r.ok) return null; const j = await r.json(), h = j.hourly;
    return hour => { const i = hour; if (!h || i < 0 || i >= h.time.length) return null; return {t: h.temperature_2m[i], f: h.apparent_temperature[i], p: h.precipitation_probability[i] || 0, c: h.weather_code[i], w: (h.wind_speed_10m || [])[i] || 0}; };
  } catch { return null; }
}
// how good an hour is for a walk (0 = perfect), and a better hour today within 3 hours
const wxScore = x => { if (!x) return 99; let s = 0; if (x.p >= 30) s += (x.p - 30) * .9;
  if (x.c >= 95) s += 90; else if ([63, 65, 66, 67, 81, 82].includes(x.c)) s += 35; else if ((x.c >= 71 && x.c <= 77) || x.c === 85 || x.c === 86) s += 30;
  if (x.f > 28) s += (x.f - 28) * 12; if (x.t < 0) s += -x.t * 7; if (x.w > 35) s += (x.w - 35) * 1.5; return s; };
function betterHour(w, T, fromMin) { const H0 = Math.floor(T / 60), cur = wxScore(w(H0)); let best = null;
  for (let H = Math.max(7, Math.ceil((fromMin + 10) / 60)); H <= 21; H++) { if (H === H0 || Math.abs(H - H0) > 3) continue; const x = w(H), sc = wxScore(x);
    if (sc < cur - 20 && sc < 25 && (!best || sc < best.sc || (sc === best.sc && Math.abs(H - H0) < Math.abs(best.H - H0)))) best = {H, sc, x}; }
  return best; }
const wxNote = (x, l) => !x ? "" : x.p >= 60 ? ` · 🌧️ ${l.rain} (${x.p} %)` : x.f >= 28 ? ` · 🥵 ${Math.round(x.f)}°, ${l.hot}` : x.t <= 0 ? ` · 🥶 ${Math.round(x.t)}°, ${l.cold}` : x.c <= 2 && x.p < 20 ? ` · ${wxIcon(x.c)} ${Math.round(x.t)}°, ${l.nice}` : ` · ${wxIcon(x.c)} ${Math.round(x.t)}°`;

async function remindFamily(env, fid, when) {
  const ctx = await familyCtx(env, fid), tokens = ctx.tokens.filter(t => t.token && t.on !== false);
  if (!tokens.length) return;
  const tz = tokens.find(t => t.tz) ? tokens.find(t => t.tz).tz : DEFAULT_TZ, n = localNow(tz, when), tmr = localNow(tz, new Date(when.getTime() + 86400000));
  const at = m => { const d = n.min - m; return d >= 0 && d < 5; }; // this 5-minute run covers minute m
  const [routine, meds, members, ticks, days, dogCfg, appts, wxCfg, food, state] = await Promise.all([list(env, `families/${fid}/routine`), list(env, `families/${fid}/meds`), list(env, `families/${fid}/members`),
    whereEq(env, `families/${fid}`, "ticks", "date", n.ds), whereEq(env, `families/${fid}`, "days", "date", n.ds), getDocAdmin(env, `families/${fid}/config/dog`),
    list(env, `families/${fid}/appts`), getDocAdmin(env, `families/${fid}/config/weather`), getDocAdmin(env, `families/${fid}/config/food`), getDocAdmin(env, `families/${fid}/config/notify`)]);
  const done = new Set(ticks.map(t => (t.dog || "main") + "|" + t.key));
  days.forEach(d => Object.keys(d.done || {}).forEach(k => done.add((d.dog || "main") + "|" + k)));
  const dogName = (dogCfg && dogCfg.name) || "";
  // send(pref, people, text, event id, type, tab): notification centre + phones
  const send = (k, uids, make, ev, type, tab) => deliver(env, fid, ctx, {ev, uids, make, pref: k, type, tab: tab || "aujourdhui"});
  const everyone = ctx.uids;
  const forWho = who => { const m = members.find(x => x._id === who); return m && m.uid && everyone.includes(m.uid) ? [m.uid] : everyone; };
  let wx; const getWx = async () => wx === undefined ? (wx = await weather(wxCfg)) : wx;

  // tasks: 5 min before, then once more 30 min after if still not ticked
  const tasks = [];
  routine.forEach(r => { if ((r.days || []).includes(n.wd)) tasks.push({key: "r-" + r._id, dog: r.dog || "main", time: r.time || "00:00", title: r.title || "", who: r.who || "", cat: r.cat || ""}); });
  meds.forEach(m => { if ((m.start && n.ds < m.start) || (m.end && n.ds > m.end)) return;
    (m.times || []).filter(Boolean).forEach(t => tasks.push({key: "m-" + m._id + "-" + t.replace(":", ""), dog: m.dog || "main", time: t, title: m.name || "", who: m.who || "", cat: "med"})); });
  for (const task of tasks) {
    if (done.has(task.dog + "|" + task.key)) continue;
    const T = toMin(task.time), walk = task.cat === "balade";
    // 2 hours ahead: the weather will be bad at walk time and a better hour exists -> suggest it
    if (walk && at(T - 120)) { const w = await getWx(), x = w && w(Math.floor(T / 60));
      if (x && wxScore(x) >= 45) { const b = betterHour(w, T, n.min);
        if (b) await send("weather", forWho(task.who), l => ({title: `${wxIcon(x.c)} ${l.warn.replace("{h}", task.time)}`,
          body: l.better.replace("{h}", hm(b.H * 60)).replace("{i}", wxIcon(b.x.c)).replace("{t}", Math.round(b.x.t)).replace("{p}", b.x.p) + " " + (b.H * 60 < T ? l.earlier : l.later)}), `wx-${task.key}-${n.ds}`, "alerte"); } }
    const soon = at(T - EARLY_MIN), late = at(T + LATE_MIN); if (!soon && !late) continue;
    const w = soon && walk ? await getWx() : null, x = w ? w(Math.floor(T / 60)) : null, b = x && wxScore(x) >= 45 ? betterHour(w, T, n.min) : null;
    await send("tasks", forWho(task.who), l => { const dn = task.dog === "main" && dogName ? ` ${l.for} ${dogName}` : "";
      return soon ? {title: `${l.soon} · ${task.time}`, body: task.title + dn + wxNote(x, l) + (b ? `, ${l.alsoBetter.replace("{h}", hm(b.H * 60))}` : "")} : {title: `${l.late} · ${task.time}`, body: `${task.title} ${l.notYet}`}; },
      `${soon ? "soon" : "late"}-${task.key}-${n.ds}`, "rappel");
  }

  // appointments: the evening before at 18:00, and 1 hour before
  for (const a of appts) {
    const T = a.time ? toMin(a.time) : null, title = a.title || "";
    if (a.date === tmr.ds && at(18 * 60)) await send("appts", forWho(a.who), l => ({title: `${l.tomorrow}${a.time ? " " + l.at + " " + a.time : ""}`, body: title + (dogName ? ` · ${dogName}` : "")}), `appt-${a._id}-eve`, "evenement", "planning");
    if (a.date === n.ds && T != null && at(T - 60)) await send("appts", forWho(a.who), l => ({title: `${l.in1h} · ${a.time}`, body: title + (dogName ? ` · ${dogName}` : "")}), `appt-${a._id}-1h`, "evenement", "planning");
  }

  // perfect weather to go out: once a day, between 10:00 and 18:00, dry for the next 2 hours
  if (wxCfg && wxCfg.lat != null && n.min >= 600 && n.min <= 1080 && (!state || state.wxDay !== n.ds)) {
    const w = await getWx(), H = Math.floor(n.min / 60), x = w && w(H);
    const ok = x && x.c <= 2 && x.p < 15 && x.f >= 10 && x.f <= 24 && [1, 2].every(k => { const y = w(H + k); return y && y.p < 25; });
    if (ok) { let dry = H + 2; while (dry < 21 && w(dry + 1) && w(dry + 1).p < 25) dry++;
      await patchDocAdmin(env, `families/${fid}/config/notify`, {wxDay: n.ds});
      await send("weather", everyone, l => ({title: `${wxIcon(x.c)} ${l.ideal}`, body: `${dogName ? l.goOut.replace("{n}", dogName) + " · " : ""}${Math.round(x.t)}° · ${l.dryUntil} ${hm((dry + 1) * 60)}`}), `wxday-${n.ds}`, "alerte"); }
  }

  // evening recap at 20:30: what's still not ticked today
  if (at(20 * 60 + 30)) {
    const left = tasks.filter(t => !done.has(t.dog + "|" + t.key) && toMin(t.time) <= n.min);
    if (left.length) await send("daily", everyone, l => ({title: l.recap, body: left.slice(0, 3).map(t => `${t.time} ${t.title}`).join(", ") + (left.length > 3 ? " " + l.more.replace("{n}", left.length - 3) : "")}), `recap-${n.ds}`, "rappel");
  }

  // food running low: 9:00, when about 3 days or less are left
  if (food && +food.bagKg && food.opened && at(9 * 60)) {
    let daily = +food.daily; if (!daily) { const m = String((dogCfg && dogCfg.ration) || "").match(/(\d+(?:[.,]\d+)?)\s*g/i); daily = m ? +m[1].replace(",", ".") : 0; }
    if (daily) { const since = Math.max(0, Math.round((Date.parse(n.ds) - Date.parse(food.opened)) / 86400000)), left = (food.bagKg * 1000 - since * daily) / daily;
      if (left > 0 && left <= 3) await send("daily", everyone, l => ({title: `🦴 ${l.food}`, body: l.foodDays.replace("{n}", Math.max(1, Math.floor(left)))}), `food-${n.ds}`, "alerte"); }
  }

  // 3:00: tidy the notification centre (read ones after 7 days, all after 30 days)
  if (at(3 * 60)) {
    const old = (await list(env, `families/${fid}/inbox`)).filter(x => { const age = Date.now() - (+x.at || 0); return age > 30 * 86400000 || (x.read && age > 7 * 86400000); });
    for (const x of old) await delDocAdmin(env, `families/${fid}/inbox/${x._id}`).catch(() => {});
  }
}


/* ---------- GET /widget?f=<family>&t=<key> : today's tasks for the iPhone widget (read-only, private key per phone) ---------- */
async function onWidget(url, env) {
  const J = (s, o) => new Response(JSON.stringify(o), {status: s, headers: {"Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}});
  if (!env.FIREBASE_SA) return J(500, {error: "cle_manquante"});
  const fid = url.searchParams.get("f") || "", key = url.searchParams.get("t") || "";
  if (!validId(fid) || !/^[a-f0-9]{48}$/.test(key)) return J(400, {error: "lien"});
  if (tooMany("w:" + fid + key.slice(0, 8), 120, 3600000)) return J(429, {error: "limite"});
  const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)))].map(x => x.toString(16).padStart(2, "0")).join("");
  const wd = await getDocAdmin(env, `families/${fid}/widgets/${hash}`); if (!wd) return J(403, {error: "lien"});
  if (!(await getDocAdmin(env, `families/${fid}/access/${wd.uid}`))) return J(403, {error: "famille"});
  const tz = wd.tz || DEFAULT_TZ, n = localNow(tz, new Date()), dog = wd.dog || "main";
  const [routine, meds, extras, ticks, days, dogDoc] = await Promise.all([list(env, `families/${fid}/routine`), list(env, `families/${fid}/meds`), whereEq(env, `families/${fid}`, "extras", "date", n.ds),
    whereEq(env, `families/${fid}`, "ticks", "date", n.ds), whereEq(env, `families/${fid}`, "days", "date", n.ds), getDocAdmin(env, dog === "main" ? `families/${fid}/config/dog` : `families/${fid}/dogs/${dog}`)]);
  const done = {}; ticks.forEach(t => { if ((t.dog || "main") === dog) done[t.key] = t; });
  days.forEach(d => { if ((d.dog || "main") === dog) Object.keys(d.done || {}).forEach(k => { done[k] = done[k] || {at: ""}; }); });
  const tasks = [];
  routine.forEach(r => { if ((r.dog || "main") === dog && (r.days || []).includes(n.wd)) tasks.push({key: "r-" + r._id, time: r.time || "00:00", title: r.title || "", cat: r.cat || "autre"}); });
  meds.forEach(m => { if ((m.dog || "main") !== dog || (m.start && n.ds < m.start) || (m.end && n.ds > m.end)) return;
    (m.times || []).filter(Boolean).forEach(t => tasks.push({key: "m-" + m._id + "-" + t.replace(":", ""), time: t, title: m.name || "", cat: "med"})); });
  extras.forEach(x => { if ((x.dog || "main") === dog) tasks.push({key: "x-" + x._id, time: x.time || "00:00", title: x.title || "", cat: x.cat || "autre", extra: true}); });
  tasks.sort((a, b) => toMin(a.time) - toMin(b.time));
  const out = tasks.map(t => ({time: t.time, title: clean(t.title, 60), cat: t.cat, extra: !!t.extra, done: !!done[t.key], at: done[t.key] ? String(done[t.key].at || "") : ""}));
  const next = out.find(t => !t.done && toMin(t.time) + 30 >= n.min) || null;
  return J(200, {dog: clean((dogDoc && dogDoc.name) || "", 40), date: n.ds, now: hm(n.min), done: out.filter(t => t.done).length, total: out.length,
    late: out.filter(t => !t.done && toMin(t.time) + 30 < n.min).length, next, upcoming: out.filter(t => !t.done && toMin(t.time) + 30 >= n.min).slice(0, 4), app: APP_URL});
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "", path = new URL(request.url).pathname;
    if (request.method === "OPTIONS") return new Response(null, {status: 204, headers: cors(origin)});
    if (request.method === "GET" && path === "/widget") return onWidget(new URL(request.url), env);
    if (request.method !== "POST") return reply(405, {error: "method"}, origin);
    // only the Dogs Life site may call this server
    if (!ORIGINS.includes(origin)) return reply(403, {error: "origin"}, origin);
    if (+(request.headers.get("Content-Length") || 0) > 65536) return reply(413, {error: "taille"}, origin);
    if (path === "/notify") return onNotify(request, env, origin);
    if (path === "/test") return onTest(request, env, origin);

    // advice from Claude (only if a key was added)
    if (!env.ANTHROPIC_API_KEY) return reply(500, {error: "cle_manquante"}, origin);
    const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    const uid = await verifyToken(token).catch(() => null); if (!uid) return reply(401, {error: "connexion"}, origin);
    if (tooMany("a:" + uid, 20, 3600000)) return reply(429, {error: "limite"}, origin);
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
