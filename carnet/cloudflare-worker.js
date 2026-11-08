// Dogs Life : petit serveur gratuit (Cloudflare Workers).
//  - POST /notify : quand quelqu'un note un pipi, coche une tâche ou écrit un message, prévient le reste de la famille.
//  - toutes les 5 minutes (Cron) : rappel 5 min avant chaque tâche (avec la météo pour les balades), relance 30 min après si pas faite,
//    beau temps pour sortir (1 fois par jour), rendez-vous (la veille à 18 h et 1 h avant), bilan du soir à 20 h 30, croquettes bientôt finies (9 h).
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
// a phone's notification address only counts while its person is still in the family (left or removed: cleaned up)
async function familyTokens(env, fid) {
  const [toks, acc] = await Promise.all([list(env, `families/${fid}/pushTokens`), list(env, `families/${fid}/access`)]);
  const ok = new Set(acc.map(a => a._id)), keep = [];
  for (const t of toks) { if (t.uid && ok.has(t.uid)) keep.push(t); else await delDocAdmin(env, `families/${fid}/pushTokens/${t._id}`).catch(() => {}); }
  return keep;
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
  fr: {soon: "Dans 5 min", late: "Toujours à faire", for: "pour", notYet: "n'est pas encore cochée.", did: "a fait", wrote: "Nouveau message de",
    warn: "Météo à éviter pour la balade de {h}", better: "Mieux vers {h} : {i} {t}°, {p} % de pluie.", earlier: "Avancez-la ?", later: "Décalez-la ?", alsoBetter: "mieux vers {h}",
    ideal: "Temps idéal pour une balade", goOut: "Parfait pour sortir {n}", dryUntil: "sec jusqu'à", rain: "pluie probable", hot: "chaud, gardez-la courte", cold: "froid", nice: "temps idéal",
    tomorrow: "Demain", in1h: "Dans 1 heure", at: "à", recap: "Pas encore fait aujourd'hui", more: "et {n} autre(s)", food: "Croquettes bientôt finies", foodDays: "Il en reste pour environ {n} jour(s).",
    k: {pipi: "Pipi", caca: "Caca", balade: "Balade", accident: "Accident", eau: "Eau", friandise: "Friandise", sieste: "Sieste", jeu: "Jeu", vomi: "Vomissement", photo: "Photo"}},
  en: {soon: "In 5 min", late: "Still to do", for: "for", notYet: "hasn't been ticked yet.", did: "did", wrote: "New message from",
    warn: "Bad weather for the {h} walk", better: "Better around {h}: {i} {t}°, {p}% rain.", earlier: "Go earlier?", later: "Go later?", alsoBetter: "better around {h}",
    ideal: "Perfect weather for a walk", goOut: "A great time to take {n} out", dryUntil: "dry until", rain: "rain likely", hot: "hot, keep it short", cold: "cold", nice: "ideal weather",
    tomorrow: "Tomorrow", in1h: "In 1 hour", at: "at", recap: "Not done yet today", more: "and {n} more", food: "Food running low", foodDays: "About {n} day(s) left.",
    k: {pipi: "Pee", caca: "Poo", balade: "Walk", accident: "Accident", eau: "Water", friandise: "Treat", sieste: "Nap", jeu: "Play", vomi: "Vomiting", photo: "Photo"}},
  hr: {soon: "Za 5 min", late: "Još za napraviti", for: "za", notYet: "još nije označeno.", did: "je obavio/la", wrote: "Nova poruka od",
    warn: "Loše vrijeme za šetnju u {h}", better: "Bolje oko {h}: {i} {t}°, {p} % kiše.", earlier: "Ranije?", later: "Kasnije?", alsoBetter: "bolje oko {h}",
    ideal: "Idealno vrijeme za šetnju", goOut: "Savršeno za izlazak ({n})", dryUntil: "suho do", rain: "moguća kiša", hot: "vruće, neka bude kratko", cold: "hladno", nice: "idealno vrijeme",
    tomorrow: "Sutra", in1h: "Za 1 sat", at: "u", recap: "Danas još nije napravljeno", more: "i još {n}", food: "Hrana pri kraju", foodDays: "Ostalo je za otprilike {n} dan(a).",
    k: {pipi: "Piškenje", caca: "Kakanje", balade: "Šetnja", accident: "Nezgoda", eau: "Voda", friandise: "Poslastica", sieste: "Drijemež", jeu: "Igra", vomi: "Povraćanje", photo: "Fotografija"}}
};
const tx = t => L[t && t.lang] || L.fr;
// each phone chooses what it wants: tasks, family, self (my own actions), weather, appts, daily (all on by default)
const wants = (t, k) => !(t.prefs && t.prefs[k] === false);

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
  const tokens = (await familyTokens(env, b.family)).filter(t => t.token && t.on !== false && wants(t, "family") && (t.uid !== uid || wants(t, "self")));
  await Promise.all(tokens.map(t => { const l = tx(t); let msg;
    if (b.kind === "msg") msg = {title: `${l.wrote} ${who}`, body: text, tag: "msg"};
    else if (b.kind === "log") msg = {title: `${who} · ${(Object.hasOwn(l.k, b.k) && l.k[b.k]) || text}`, body: at ? at : "", tag: "log"};
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
  const tokens = (await familyTokens(env, fid)).filter(t => t.token && t.on !== false);
  if (!tokens.length) return;
  const tz = tokens.find(t => t.tz) ? tokens.find(t => t.tz).tz : DEFAULT_TZ, n = localNow(tz, when), tmr = localNow(tz, new Date(when.getTime() + 86400000));
  const at = m => { const d = n.min - m; return d >= 0 && d < 5; }; // this 5-minute run covers minute m
  const [routine, meds, members, ticks, days, dogCfg, appts, wxCfg, food, state] = await Promise.all([list(env, `families/${fid}/routine`), list(env, `families/${fid}/meds`), list(env, `families/${fid}/members`),
    whereEq(env, `families/${fid}`, "ticks", "date", n.ds), whereEq(env, `families/${fid}`, "days", "date", n.ds), getDocAdmin(env, `families/${fid}/config/dog`),
    list(env, `families/${fid}/appts`), getDocAdmin(env, `families/${fid}/config/weather`), getDocAdmin(env, `families/${fid}/config/food`), getDocAdmin(env, `families/${fid}/config/notify`)]);
  const done = new Set(ticks.map(t => (t.dog || "main") + "|" + t.key));
  days.forEach(d => Object.keys(d.done || {}).forEach(k => done.add((d.dog || "main") + "|" + k)));
  const dogName = (dogCfg && dogCfg.name) || "";
  const send = (k, targets, make) => Promise.all(targets.filter(t => wants(t, k)).map(t => push(env, fid, t, make(tx(t)))));
  const forWho = who => { const m = members.find(x => x._id === who); return m && m.uid ? tokens.filter(t => t.uid === m.uid) : tokens; };
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
          body: l.better.replace("{h}", hm(b.H * 60)).replace("{i}", wxIcon(b.x.c)).replace("{t}", Math.round(b.x.t)).replace("{p}", b.x.p) + " " + (b.H * 60 < T ? l.earlier : l.later), tag: "wx-" + task.key})); } }
    const soon = at(T - EARLY_MIN), late = at(T + LATE_MIN); if (!soon && !late) continue;
    const w = soon && walk ? await getWx() : null, x = w ? w(Math.floor(T / 60)) : null, b = x && wxScore(x) >= 45 ? betterHour(w, T, n.min) : null;
    await send("tasks", forWho(task.who), l => { const dn = task.dog === "main" && dogName ? ` ${l.for} ${dogName}` : "";
      return soon ? {title: `${l.soon} · ${task.time}`, body: task.title + dn + wxNote(x, l) + (b ? `, ${l.alsoBetter.replace("{h}", hm(b.H * 60))}` : ""), tag: task.key} : {title: `${l.late} · ${task.time}`, body: `${task.title} ${l.notYet}`, tag: task.key}; });
  }

  // appointments: the evening before at 18:00, and 1 hour before
  for (const a of appts) {
    const T = a.time ? toMin(a.time) : null, title = a.title || "";
    if (a.date === tmr.ds && at(18 * 60)) await send("appts", forWho(a.who), l => ({title: `${l.tomorrow}${a.time ? " " + l.at + " " + a.time : ""}`, body: title + (dogName ? ` · ${dogName}` : ""), tag: "appt-" + a._id}));
    if (a.date === n.ds && T != null && at(T - 60)) await send("appts", forWho(a.who), l => ({title: `${l.in1h} · ${a.time}`, body: title + (dogName ? ` · ${dogName}` : ""), tag: "appt-" + a._id}));
  }

  // perfect weather to go out: once a day, between 10:00 and 18:00, dry for the next 2 hours
  if (wxCfg && wxCfg.lat != null && n.min >= 600 && n.min <= 1080 && (!state || state.wxDay !== n.ds)) {
    const w = await getWx(), H = Math.floor(n.min / 60), x = w && w(H);
    const ok = x && x.c <= 2 && x.p < 15 && x.f >= 10 && x.f <= 24 && [1, 2].every(k => { const y = w(H + k); return y && y.p < 25; });
    if (ok) { let dry = H + 2; while (dry < 21 && w(dry + 1) && w(dry + 1).p < 25) dry++;
      await patchDocAdmin(env, `families/${fid}/config/notify`, {wxDay: n.ds});
      await send("weather", tokens, l => ({title: `${wxIcon(x.c)} ${l.ideal}`, body: `${dogName ? l.goOut.replace("{n}", dogName) + " · " : ""}${Math.round(x.t)}° · ${l.dryUntil} ${hm((dry + 1) * 60)}`, tag: "wx"})); }
  }

  // evening recap at 20:30: what's still not ticked today
  if (at(20 * 60 + 30)) {
    const left = tasks.filter(t => !done.has(t.dog + "|" + t.key) && toMin(t.time) <= n.min);
    if (left.length) await send("daily", tokens, l => ({title: l.recap, body: left.slice(0, 3).map(t => `${t.time} ${t.title}`).join(", ") + (left.length > 3 ? " " + l.more.replace("{n}", left.length - 3) : ""), tag: "recap"}));
  }

  // food running low: 9:00, when about 3 days or less are left
  if (food && +food.bagKg && food.opened && at(9 * 60)) {
    let daily = +food.daily; if (!daily) { const m = String((dogCfg && dogCfg.ration) || "").match(/(\d+(?:[.,]\d+)?)\s*g/i); daily = m ? +m[1].replace(",", ".") : 0; }
    if (daily) { const since = Math.max(0, Math.round((Date.parse(n.ds) - Date.parse(food.opened)) / 86400000)), left = (food.bagKg * 1000 - since * daily) / daily;
      if (left > 0 && left <= 3) await send("daily", tokens, l => ({title: `🦴 ${l.food}`, body: l.foodDays.replace("{n}", Math.max(1, Math.floor(left))), tag: "food"})); }
  }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "", path = new URL(request.url).pathname;
    if (request.method === "OPTIONS") return new Response(null, {status: 204, headers: cors(origin)});
    if (request.method !== "POST") return reply(405, {error: "method"}, origin);
    // only the Dogs Life site may call this server
    if (!ORIGINS.includes(origin)) return reply(403, {error: "origin"}, origin);
    if (+(request.headers.get("Content-Length") || 0) > 65536) return reply(413, {error: "taille"}, origin);
    if (path === "/notify") return onNotify(request, env, origin);

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
