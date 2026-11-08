// Firebase bridge for the standalone Dogs Life app.
// The app was written against claude.ai's `window.claude.use(...)` API; this module answers the same calls
// with Firebase Auth (one account per person) and Firestore (one isolated space per family).
import { initializeApp } from "https://www.gstatic.com/firebasejs/13.2.0/firebase-app.js";
import { getAuth, onAuthStateChanged, GoogleAuthProvider, signInWithPopup, signInWithRedirect, getRedirectResult,
  signInWithEmailAndPassword, createUserWithEmailAndPassword, sendPasswordResetEmail, signOut } from "https://www.gstatic.com/firebasejs/13.2.0/firebase-auth.js";
import { getFirestore, initializeFirestore, persistentLocalCache, persistentMultipleTabManager, doc, getDoc, getDocs, setDoc, deleteDoc, updateDoc, writeBatch, collection, query, where, onSnapshot, terminate, clearIndexedDbPersistence, getDocFromServer } from "https://www.gstatic.com/firebasejs/13.2.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyCgpdewI-Nfnq8V3HKrBwvFz0FDXX-9HJw",
  authDomain: "dogs-life-official-web.firebaseapp.com",
  projectId: "dogs-life-official-web",
  storageBucket: "dogs-life-official-web.firebasestorage.app",
  messagingSenderId: "409663350418",
  appId: "1:409663350418:web:c8042a1a1d8d2d65e8284b"
};
// Claude's evening advice goes through a small relay that keeps the API key secret (empty = built-in advice only)
const ADVICE_URL = "";
// Notifications even when the app is closed (both must be filled in; see cloudflare-worker.js):
const VAPID_KEY = "BBlZEGcnrvBl4_EZyceCBOo4OYrUFjMpXx_MrcoBGUpjdT3O-Bpn1W236jMSuSNOTdaWydmd65OuuHKTXc3kJFo";   // Firebase → Paramètres du projet → Cloud Messaging → Certificats push Web → « Paire de clés »
const WORKER_URL = "https://dogs-life.radanovicvik.workers.dev";

const B = window.__carnetBridge; B.started = true;
const fb = initializeApp(firebaseConfig), auth = getAuth(fb);
// offline: everything is kept on the phone and sent when the network comes back
let fs; try { fs = initializeFirestore(fb, {localCache: persistentLocalCache({tabManager: persistentMultipleTabManager()})}); } catch(_) { fs = getFirestore(fb); }
if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
const LSg = k => { try { return localStorage.getItem(k); } catch(_) { return null; } }, LSs = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch(_) {} };

/* ---------- texts (the app's language setting) ---------- */
const LANG = (() => { try { const l = localStorage.getItem("carnet-lang"); if (["fr","en","hr"].includes(l)) return l; } catch(_) {} const n = (navigator.language || "fr").toLowerCase(); return n.startsWith("fr") ? "fr" : n.startsWith("hr") || n.startsWith("bs") || n.startsWith("sr") ? "hr" : "en"; })();
const TXT = {
  fr: {title:"Dogs Life", sub:"La routine, la santé et la famille de votre chien, sur tous vos appareils.", google:"Continuer avec Google", or:"ou", email:"Adresse e-mail", pass:"Mot de passe", signin:"Se connecter", signup:"Créer un compte", forgot:"Mot de passe oublié ?",
    resetSent:"Un e-mail pour changer le mot de passe a été envoyé.", hello:"Bonjour", choose:"Que voulez-vous faire ?", create:"Créer le carnet de mon chien", createS:"Vous serez le propriétaire et pourrez inviter la famille.",
    join:"Rejoindre une famille", joinS:"Avec le code qu'un membre de la famille vous a donné.", code:"Code reçu", name:"Votre prénom", joinBtn:"Rejoindre", back:"Retour", other:"Changer de compte",
    badCode:"Code incorrect ou expiré.", needName:"Indiquez votre prénom.", needCode:"Entrez le code.", wait:"Un instant…", errNet:"Connexion impossible. Vérifiez internet et réessayez.",
    errAuth:"Adresse ou mot de passe incorrect.", errWeak:"Le mot de passe doit faire au moins 6 caractères.", errUsed:"Un compte existe déjà avec cette adresse : connectez-vous.", errSetup:"Le carnet n'est pas encore prêt (règles de sécurité Firebase). Réessayez plus tard.",
    tooMany:"Trop d'essais. Réessayez dans une minute.", privacy:"Chaque famille ne voit que ses propres données."},
  en: {title:"Dogs Life", sub:"Your dog's routine, health and family, on all your devices.", google:"Continue with Google", or:"or", email:"Email address", pass:"Password", signin:"Sign in", signup:"Create an account", forgot:"Forgot password?",
    resetSent:"An email to reset your password has been sent.", hello:"Hello", choose:"What would you like to do?", create:"Create my dog's logbook", createS:"You'll be the owner and can invite the family.",
    join:"Join a family", joinS:"With the code a family member gave you.", code:"Code received", name:"Your first name", joinBtn:"Join", back:"Back", other:"Switch account",
    badCode:"Wrong or expired code.", needName:"Enter your first name.", needCode:"Enter the code.", wait:"One moment…", errNet:"Can't connect. Check the internet and try again.",
    errAuth:"Wrong email or password.", errWeak:"The password must be at least 6 characters.", errUsed:"An account already exists with this email: sign in.", errSetup:"The logbook isn't ready yet (Firebase security rules). Try again later.",
    tooMany:"Too many tries. Try again in a minute.", privacy:"Each family only sees its own data."},
  hr: {title:"Dogs Life", sub:"Rutina, zdravlje i obitelj vašeg psa, na svim vašim uređajima.", google:"Nastavi s Googleom", or:"ili", email:"E-adresa", pass:"Lozinka", signin:"Prijava", signup:"Izradi račun", forgot:"Zaboravljena lozinka?",
    resetSent:"Poslana je e-poruka za promjenu lozinke.", hello:"Bok", choose:"Što želite učiniti?", create:"Izradi dnevnik mog psa", createS:"Bit ćete vlasnik i moći ćete pozvati obitelj.",
    join:"Pridruži se obitelji", joinS:"S kodom koji vam je dao član obitelji.", code:"Primljeni kod", name:"Vaše ime", joinBtn:"Pridruži se", back:"Natrag", other:"Promijeni račun",
    badCode:"Kod je pogrešan ili istekao.", needName:"Upišite svoje ime.", needCode:"Unesite kod.", wait:"Trenutak…", errNet:"Povezivanje nije uspjelo. Provjerite internet i pokušajte ponovno.",
    errAuth:"Pogrešna e-adresa ili lozinka.", errWeak:"Lozinka mora imati najmanje 6 znakova.", errUsed:"Račun s ovom adresom već postoji: prijavite se.", errSetup:"Dnevnik još nije spreman (Firebase sigurnosna pravila). Pokušajte kasnije.",
    tooMany:"Previše pokušaja. Pokušajte ponovno za minutu.", privacy:"Svaka obitelj vidi samo svoje podatke."}
}[LANG];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

/* ---------- the same code hashing as the app ---------- */
const normCode = c => String(c || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toUpperCase().replace(/[^A-Z0-9]/g, "");
async function hashCode(c){ const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("carnet-chien|5WVU6oZS2Gzi53rfMeXpHR|" + normCode(c))); return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join(""); }
const newId = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
const clean = d => JSON.parse(JSON.stringify(d)); // Firestore refuses `undefined`

/* ---------- gate screen ---------- */
const DOG = document.querySelector("template#gate-dog") ? document.querySelector("template#gate-dog").innerHTML : "";
const root = document.getElementById("gate");
let busy = false, step = "auth", msg = "", authMode = "signin";
const F = {email:"", pass:"", code:"", name:""}; // typed values survive every re-render
function show(html){ root.innerHTML = `<div class="gate"><div class="g-in">${html}</div></div>`; document.body.classList.add("gated"); }
function hide(){ root.innerHTML = ""; document.body.classList.remove("gated"); }
function render(){
  const u = auth.currentUser;
  const head = `<div class="g-logo"><img src="icon-512.png" width="104" height="104" alt="Dogs Life"></div><h1>${TXT.title}</h1>`;
  const m = msg ? `<div class="g-msg">${esc(msg)}</div>` : "";
  if (step === "auth") return show(`${head}<p class="g-sub">${TXT.sub}</p>
    <button class="g-btn g-google" data-g="google" ${busy ? "disabled" : ""}><svg viewBox="0 0 48 48" width="20" height="20"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z"/><path fill="#FF3D00" d="m6.3 14.7 6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/><path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z"/><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z"/></svg>${TXT.google}</button>
    <div class="g-or"><span>${TXT.or}</span></div>
    <input class="g-f" id="g-email" data-f="email" type="email" autocomplete="email" placeholder="${TXT.email}" value="${esc(F.email)}">
    <input class="g-f" id="g-pass" data-f="pass" type="password" autocomplete="${authMode === "signup" ? "new-password" : "current-password"}" placeholder="${TXT.pass}" value="${esc(F.pass)}">
    ${m}
    <button class="g-btn g-main" data-g="${authMode}" ${busy ? "disabled" : ""}>${busy ? TXT.wait : authMode === "signup" ? TXT.signup : TXT.signin}</button>
    <div class="g-links"><button data-g="toggle">${authMode === "signup" ? TXT.signin : TXT.signup}</button><button data-g="forgot">${TXT.forgot}</button></div>
    <p class="g-fine">${TXT.privacy}</p>`);
  if (step === "choose") return show(`${head}<p class="g-sub">${TXT.hello}${u && u.displayName ? " " + esc(u.displayName.split(" ")[0]) : ""} ! ${TXT.choose}</p>${m}
    <button class="g-card" data-g="create" ${busy ? "disabled" : ""}><span class="g-ic" style="background:#E08A3C">${PAW}</span><span><b>${TXT.create}</b><small>${TXT.createS}</small></span></button>
    <button class="g-card" data-g="tojoin" ${busy ? "disabled" : ""}><span class="g-ic" style="background:#9B6BE0">${FAM}</span><span><b>${TXT.join}</b><small>${TXT.joinS}</small></span></button>
    <div class="g-links"><button data-g="logout">${TXT.other}</button></div>`);
  if (step === "join") return show(`${head}<p class="g-sub">${TXT.joinS}</p>
    <label class="g-lab">${TXT.code}</label><input class="g-f g-code" id="g-code" data-f="code" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" placeholder="ABCD 2345" maxlength="11" value="${esc(F.code)}">
    <label class="g-lab">${TXT.name}</label><input class="g-f" id="g-name" data-f="name" autocomplete="given-name" maxlength="24" placeholder="${TXT.name}" value="${esc(F.name || (u && u.displayName ? u.displayName.split(" ")[0] : ""))}">
    ${m}<button class="g-btn g-main" data-g="join" ${busy ? "disabled" : ""}>${busy ? TXT.wait : TXT.joinBtn}</button>
    <div class="g-links"><button data-g="back">${TXT.back}</button></div>`);
  if (step === "loading") return show(`${head}<div class="g-spin"></div>`);
  if (step === "offline") return show(`${head}<p class="g-sub">${TXT.errNet}</p><button class="g-btn g-main" onclick="location.reload()">${({fr:"Réessayer", en:"Try again", hr:"Pokušaj ponovno"})[LANG] || "Réessayer"}</button>`);
}
const PAW = '<svg viewBox="0 0 24 24" width="22" height="22" fill="#fff"><ellipse cx="6" cy="10" rx="2" ry="2.6"/><ellipse cx="10" cy="6" rx="2" ry="2.7"/><ellipse cx="14" cy="6" rx="2" ry="2.7"/><ellipse cx="18" cy="10" rx="2" ry="2.6"/><path d="M12 11c3 0 6 4.4 6 7 0 2-1.6 3-3.2 2.6-1-.3-1.8-.8-2.8-.8s-1.8.5-2.8.8C7.6 21 6 20 6 18c0-2.6 3-7 6-7Z"/></svg>';
const FAM = '<svg viewBox="0 0 24 24" width="22" height="22" fill="#fff"><circle cx="8" cy="7.5" r="3.2"/><circle cx="16.5" cy="8.5" r="2.6"/><path d="M2 19.2c0-3.4 2.7-6 6-6s6 2.6 6 6c0 .5-.4.8-.8.8H2.8c-.4 0-.8-.3-.8-.8Z"/><path d="M15.3 20c.2-.3.3-.5.3-.8 0-2-.8-3.8-2-5.1.9-.6 1.9-.9 3-.9 2.9 0 5.4 2.2 5.4 5.4 0 .8-.6 1.4-1.4 1.4h-5.3Z"/></svg>';
const errText = e => { const c = (e && e.code) || ""; if (/invalid-credential|wrong-password|user-not-found|invalid-email/.test(c)) return TXT.errAuth; if (/weak-password/.test(c)) return TXT.errWeak; if (/email-already-in-use/.test(c)) return TXT.errUsed; if (/permission-denied/.test(c)) return TXT.errSetup; if (/too-many-requests/.test(c)) return TXT.tooMany; return TXT.errNet; };
async function run(fn){ if (busy) return; busy = true; msg = ""; render(); try { await fn(); } catch(e) { console.warn(e); msg = errText(e); } busy = false; if (step !== "done") render(); }

root.addEventListener("click", async e => {
  const b = e.target.closest("[data-g]"); if (!b) return; const g = b.dataset.g;
  root.querySelectorAll("[data-f]").forEach(i => F[i.dataset.f] = i.value);
  const v = id => ({"g-email": F.email, "g-pass": F.pass, "g-code": F.code, "g-name": F.name})[id] || "";
  if (g === "toggle") { authMode = authMode === "signup" ? "signin" : "signup"; msg = ""; return render(); }
  if (g === "google") return run(async () => { const p = new GoogleAuthProvider();
    try { await signInWithPopup(auth, p); }
    catch(err) { const c = err.code || ""; if (/popup-blocked|operation-not-supported/.test(c)) await signInWithRedirect(auth, p); else if (!/popup-closed|cancelled-popup/.test(c)) throw err; } });
  if (g === "signin") return run(() => signInWithEmailAndPassword(auth, v("g-email").trim(), v("g-pass")));
  if (g === "signup") return run(() => createUserWithEmailAndPassword(auth, v("g-email").trim(), v("g-pass")));
  if (g === "forgot") return run(async () => { const m = v("g-email").trim(); if (!m) { msg = TXT.email; return; } await sendPasswordResetEmail(auth, m); msg = TXT.resetSent; });
  if (g === "logout") { await signOut(auth); step = "auth"; return render(); }
  if (g === "tojoin") { step = "join"; msg = ""; return render(); }
  if (g === "back") { step = "choose"; msg = ""; return render(); }
  if (g === "create") return run(createFamily);
  if (g === "join") return run(joinWithCode);
});
root.addEventListener("input", e => { const f = e.target.dataset && e.target.dataset.f; if (f) F[f] = e.target.value; });
root.addEventListener("keydown", e => { if (e.key !== "Enter") return; const b = root.querySelector(".g-main"); if (b) { e.preventDefault(); b.click(); } });

/* ---------- families ---------- */
let FID = null, UID = null, OWNER = false;
async function createFamily(){
  const fid = newId() + newId();
  await setDoc(doc(fs, "families", fid), {owner: UID, at: Date.now()});
  await setDoc(doc(fs, "families", fid, "access", UID), {at: Date.now(), owner: true});
  await setDoc(doc(fs, "users", UID), {family: fid});
  enter(fid, true);
}
let tries = 0, lockUntil = 0;
async function joinWithCode(fromApp){
  const code = F.code, name = F.name.trim() || ((auth.currentUser || {}).displayName || "").split(" ")[0];
  if (!normCode(code)) { msg = TXT.needCode; return; } if (!name) { msg = TXT.needName; return; }
  if (Date.now() < lockUntil) { msg = TXT.tooMany; return; }
  const h = await hashCode(code); let c = null;
  try { const s = await getDoc(doc(fs, "codes", h)); if (s.exists()) c = s.data(); } catch(_) {}
  if (!c || !c.family || (c.exp && c.exp < Date.now())) { if (++tries >= 5) { tries = 0; lockUntil = Date.now() + 60000; } msg = TXT.badCode; return; }
  const fid = c.family;
  await setDoc(doc(fs, "families", fid, "access", UID), {at: Date.now(), code: h, role: c.role || "famille"});
  await setDoc(doc(fs, "users", UID), {family: fid});
  // the person's place in the family, with the role chosen by whoever made the code
  const colors = ["#E07A5F","#3D8BD9","#5FA86B","#B57EDC","#E6A23C","#2BB0A5","#D9668F","#5E6AD2","#C9A227","#E5484D","#3FA7D6","#8B5E3C","#7B9E2F","#A35BB5"];
  await setDoc(doc(fs, "families", fid, "members", newId()), {name, uid: UID, role: c.role || "famille", since: Date.now(), color: colors[Math.floor(Math.random() * colors.length)], invitedBy: c.byName || ""});
  await setDoc(doc(fs, "families", fid, "notes", newId()), {kind: "join", name, text: name + " a rejoint la famille", uid: UID, at: new Date().toISOString()});
  try { if (c.invite) await deleteDoc(doc(fs, "families", fid, "invites", c.invite)); await deleteDoc(doc(fs, "codes", h)); } catch(_) {}
  if (fromApp) { location.reload(); return; }
  enter(fid, false);
}
/* ---------- notifications, even when the app is closed ---------- */
let msgMod = null;
const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
const standalone = matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
const pushReady = () => !!(VAPID_KEY && WORKER_URL && "serviceWorker" in navigator && "PushManager" in window && "Notification" in window);
async function sha(s){ const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)); return [...new Uint8Array(h)].map(x => x.toString(16).padStart(2, "0")).join(""); }
async function pushToken(ask){
  if (!pushReady() || !FID) return null;
  if (ask) { if ((await Notification.requestPermission()) !== "granted") return null; } else if (Notification.permission !== "granted") return null;
  msgMod = msgMod || await import("https://www.gstatic.com/firebasejs/13.2.0/firebase-messaging.js");
  if (!(await msgMod.isSupported())) return null;
  const reg = await navigator.serviceWorker.register("sw.js"); await navigator.serviceWorker.ready;
  const tok = await msgMod.getToken(msgMod.getMessaging(fb), {vapidKey: VAPID_KEY, serviceWorkerRegistration: reg}); if (!tok) return null;
  const id = (await sha(tok)).slice(0, 40), old = LSg("dl-push@" + UID);
  if (old && old !== id) { try { await deleteDoc(doc(fs, "families", FID, "pushTokens", old)); } catch(_) {} }
  await setDoc(doc(fs, "families", FID, "pushTokens", id), {uid: UID, token: tok, on: true, prefs: (() => { try { return JSON.parse(LSg("dl-push-prefs@" + UID) || "{}"); } catch(_) { return {}; } })(), lang: LANG, tz: Intl.DateTimeFormat().resolvedOptions().timeZone || "Europe/Zurich", at: Date.now()});
  LSs("dl-push@" + UID, id); return tok;
}
// re-register this phone whenever notifications are allowed (new family, new address from Apple/Google, rules changed…)
let pushAt = 0;
function pushRefresh(){
  if (!FID || !UID || !pushReady() || Notification.permission !== "granted" || LSg("dl-push-off@" + UID)) return;
  if (Date.now() - pushAt < 20 * 60000) return; pushAt = Date.now();
  pushToken(false).then(t => { if (t) LSs("dl-push-err", null); }).catch(e => { pushAt = 0; LSs("dl-push-err", String((e && (e.code || e.message)) || e).slice(0, 160)); });
}
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") pushRefresh(); });
async function pushOff(byUser){
  if (byUser) LSs("dl-push-off@" + UID, "1"); // the person switched notifications off on purpose: never turn them back on by ourselves
  const id = LSg("dl-push@" + UID); LSs("dl-push@" + UID, null);
  if (id && FID) { try { await deleteDoc(doc(fs, "families", FID, "pushTokens", id)); } catch(_) {} }
  try { if (msgMod) await msgMod.deleteToken(msgMod.getMessaging(fb)); } catch(_) {}
}
window.carnetPush = {available: () => pushReady() && (!isIOS || standalone), ios: isIOS && !standalone && !!(VAPID_KEY && WORKER_URL),
  state: () => !!LSg("dl-push@" + UID) && "Notification" in window && Notification.permission === "granted",
  enable: async () => { LSs("dl-push-err", null); LSs("dl-push-off@" + UID, null);
    try { const t = await pushToken(true); if (!t) LSs("dl-push-err", "Notification" in window && Notification.permission === "denied" ? "permission refusée" : "pas de jeton"); return !!t; }
    catch(e) { LSs("dl-push-err", String((e && (e.code || e.message)) || e).slice(0, 160)); console.warn(e); return false; } },
  disable: () => pushOff(true),
  // what this phone wants to hear about
  prefs: () => { try { return JSON.parse(LSg("dl-push-prefs@" + UID) || "{}"); } catch(_) { return {}; } },
  setPref: async (k, v) => { const p = window.carnetPush.prefs(); p[k] = !!v; LSs("dl-push-prefs@" + UID, JSON.stringify(p));
    const id = LSg("dl-push@" + UID); if (id && FID) await setDoc(doc(fs, "families", FID, "pushTokens", id), {prefs: p}, {merge: true}); },
  // what is going on on this phone, for the settings screen
  info: () => ({perm: "Notification" in window ? Notification.permission : "absent", sw: "serviceWorker" in navigator, pm: "PushManager" in window, standalone, ios: isIOS,
    on: !!LSg("dl-push@" + UID), err: LSg("dl-push-err") || ""}),
  // the real test: this phone re-registers, then the server sends it a notification and says what happened
  test: async () => {
    try { await pushToken(false); } catch(e) { LSs("dl-push-err", String((e && (e.code || e.message)) || e).slice(0, 160)); }
    if (!WORKER_URL || !FID || !auth.currentUser) return {error: "connexion"};
    const t = await auth.currentUser.getIdToken();
    const r = await fetch(WORKER_URL.replace(/\/$/, "") + "/test", {method: "POST", headers: {"Content-Type": "application/json", Authorization: "Bearer " + t}, body: JSON.stringify({family: FID})});
    let j = {}; try { j = await r.json(); } catch(_) {}
    if (j.tokens === undefined) j.old = true; // server not updated yet
    j.status = r.status; return j; },
  last: () => { try { return JSON.parse(LSg("dl-push-last") || "null"); } catch(_) { return null; } }};
// notification centre: my notifications in this family, live on every device (read status included); works offline too
window.carnetInbox = {
  watch(cb){ if (!FID || !UID) return () => {};
    return onSnapshot(query(collection(fs, "families", FID, "inbox"), where("to", "==", UID)), {includeMetadataChanges: true},
      s => cb(s.docs.map(d => Object.assign({id: d.id}, d.data())).sort((a, b) => (b.at || 0) - (a.at || 0)), !s.metadata.fromCache && navigator.onLine),
      e => { console.warn(e); cb(null, false); }); },
  read: id => updateDoc(doc(fs, "families", FID, "inbox", id), {read: true, readAt: Date.now()}).catch(e => console.warn(e)),
  readAll: async ids => { for (let i = 0; i < ids.length; i += 400) { const b = writeBatch(fs); ids.slice(i, i + 400).forEach(id => b.update(doc(fs, "families", FID, "inbox", id), {read: true, readAt: Date.now()})); await b.commit().catch(e => console.warn(e)); } },
  del: id => deleteDoc(doc(fs, "families", FID, "inbox", id)).catch(e => console.warn(e))
};
// tell the rest of the family (the server skips the sender)
window.carnetNotify = (kind, data) => { if (!WORKER_URL || !FID || !auth.currentUser) return;
  auth.currentUser.getIdToken().then(t => fetch(WORKER_URL.replace(/\/$/, "") + "/notify", {method: "POST", headers: {"Content-Type": "application/json", Authorization: "Bearer " + t},
    body: JSON.stringify(Object.assign({family: FID, kind}, data || {}))}))
    .then(async r => { let j = {}; try { j = await r.json(); } catch(_) {} LSs("dl-push-last", JSON.stringify({k: kind, at: Date.now(), s: r.status, n: j.sent, ok: j.ok, e: j.error || (j.fail || [])[0] || ""})); })
    .catch(e => LSs("dl-push-last", JSON.stringify({k: kind, at: Date.now(), s: 0, e: String((e && e.message) || e).slice(0, 80)}))); };

// a signed-out person keeps their place in the family; their picture just shows a small warning until they come back
async function setPresence(out){
  if (!FID || !UID) return;
  try { const qs = await getDocs(query(collection(fs, "families", FID, "members"), where("uid", "==", UID)));
    await Promise.all(qs.docs.map(d => setDoc(d.ref, out ? {signedOut: true, outAt: Date.now()} : {signedOut: false}, {merge: true}))); } catch(e) { console.warn(e); }
}
async function enter(fid, owner){
  FID = fid; OWNER = owner; step = "done"; setPresence(false); LSs("dl-fid@" + UID, fid);
  setTimeout(pushRefresh, 1500); // keep this phone's notification address fresh, in the family it is in now
  if (!owner) { try { const f = await getDoc(doc(fs, "families", fid)); OWNER = f.exists() && f.data().owner === UID; } catch(_) {} }
  hide();
  B.resolve(api());
}

/* ---------- what the app asks for ---------- */
function api(){
  const path = col => collection(fs, "families", FID, col);
  const wrapSnap = s => ({docs: s.docs.map(d => ({id: d.id, data: () => d.data()})), metadata: {fromCache: !navigator.onLine ? false : s.metadata.fromCache && !s.docs.length ? false : s.metadata.fromCache}});
  const coll = (col, filters) => ({
    where: (f, op, v) => coll(col, (filters || []).concat([[f, op, v]])),
    onSnapshot(cb, err){ const q = filters ? query(path(col), ...filters.map(([f, op, v]) => where(f, op, v))) : path(col); return onSnapshot(q, {includeMetadataChanges: true}, s => cb(wrapSnap(s)), e => err && err({code: e.code === "permission-denied" ? "revoked" : "unavailable", message: e.message})); },
    doc: id => ({
      async set(data){
        await setDoc(doc(fs, "families", FID, col, id), clean(data));
        // a join code is findable by its hash only, so a new member can locate the family
        if (col === "invites" && data && data.hash) await setDoc(doc(fs, "codes", data.hash), {family: FID, role: data.role || "famille", exp: data.exp || 0, invite: id, byName: data.byName || ""});
      },
      async delete(){
        if (col === "invites") { try { const s = await getDoc(doc(fs, "families", FID, col, id)); const h = s.exists() && s.data().hash; if (h) await deleteDoc(doc(fs, "codes", h)); } catch(_) {} }
        // removing someone from the family also closes their access to it
        let gone = null; if (col === "members") { try { const s = await getDoc(doc(fs, "families", FID, col, id)); gone = s.exists() && s.data().uid; } catch(_) {} }
        await deleteDoc(doc(fs, "families", FID, col, id));
        if (gone && gone !== UID) { try { await deleteDoc(doc(fs, "families", FID, "access", gone)); } catch(e) { console.warn(e); } }
      }
    })
  });
  const u = auth.currentUser;
  window.carnetAccount = {name: u.displayName || "", email: u.email || u.displayName || "", signOut: async () => { await setPresence(true); await pushOff().catch(() => {}); await signOut(auth); try { localStorage.removeItem("carnet-me@" + UID); } catch(_) {} location.reload(); }};
  return {
    db: {collection: col => coll(col)},
    user: {
      id: async () => UID, isOwner: async () => OWNER, canEdit: async () => true, can: async () => true, me: async () => ({id: UID, name: u.displayName || "", avatarUrl: u.photoURL || "", email: u.email}),
      profiles: async ids => Object.fromEntries([].concat(ids).map(id => [id, {id, name: id === UID ? (u.displayName || "") : "", avatarUrl: id === UID && u.photoURL ? u.photoURL : "data:,", isMe: id === UID}]))
    },
    downloads: {save: async ({filename, data}) => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([data], {type: /\.html$/.test(filename) ? "text/html" : "text/plain"})); a.download = filename; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000); }},
    sample: ADVICE_URL ? {json: async (input, opts) => {
      const r = await fetch(ADVICE_URL, {method: "POST", headers: {"Content-Type": "application/json", "Authorization": "Bearer " + await auth.currentUser.getIdToken()}, body: JSON.stringify({input, family: FID})});
      if (!r.ok) throw {code: r.status === 429 ? "rate_limited" : "unavailable"}; return r.json(); }} : null
  };
}

/* ---------- start ---------- */
step = "loading"; render();
getRedirectResult(auth).catch(e => { msg = errText(e); });
onAuthStateChanged(auth, async user => {
  if (step === "done") { if (!user) location.reload(); return; }
  if (!user) { step = "auth"; return render(); }
  UID = user.uid; step = "loading"; render();
  let fid = null, known = false;
  try { const us = await getDoc(doc(fs, "users", UID)); known = true; fid = us.exists() && us.data().family; }
  catch(e) { console.warn(e); if (/permission-denied/.test(e.code || "")) { msg = TXT.errSetup; step = "auth"; return render(); } }
  const saved = LSg("dl-fid@" + UID);
  if (!known) { if (saved) return enter(saved, false); step = "offline"; return render(); }
  if (fid) { let ok = null; try { ok = (await getDoc(doc(fs, "families", fid, "access", UID))).exists(); } catch(_) {} if (ok !== false) return enter(fid, false); }
  try { await createFamily(); } catch(e) { console.warn(e); msg = errText(e); step = "auth"; render(); }
});
// leaving the family: nothing of it stays on this account or this phone
window.carnetLeave = async (name, removed) => {
  if (!FID || !UID) return "no";
  if (!navigator.onLine) return "offline";
  const old = FID;
  // the owner hands the family over first (someone of the family rather than a sitter), so it keeps working without them
  try { const f = await getDoc(doc(fs, "families", old));
    if (f.exists() && f.data().owner === UID) {
      const others = (await getDocs(collection(fs, "families", old, "access"))).docs.filter(d => d.id !== UID);
      const next = others.find(d => (d.data().role || "famille") !== "garde") || others[0];
      if (next) await setDoc(doc(fs, "families", old), {owner: next.id}, {merge: true});
    } } catch(e) { console.warn(e); }
  try { if (name) await setDoc(doc(fs, "families", old, "notes", newId()), {kind: "leave", name: String(name).slice(0, 40), uid: UID, at: new Date().toISOString()}); } catch(_) {}
  try { const qs = await getDocs(query(collection(fs, "families", old, "members"), where("uid", "==", UID))); await Promise.all(qs.docs.map(d => deleteDoc(d.ref))); } catch(e) { console.warn(e); }
  await pushOff().catch(() => {});
  try { await deleteDoc(doc(fs, "families", old, "access", UID)); } catch(e) { console.warn(e); }
  // a new, empty space of one's own (Profile then offers to create or join a family)
  const fid = newId() + newId();
  await setDoc(doc(fs, "families", fid), {owner: UID, at: Date.now()});
  await setDoc(doc(fs, "families", fid, "access", UID), {at: Date.now(), owner: true});
  await setDoc(doc(fs, "users", UID), {family: fid});
  // forget everything this phone kept about the old family: chosen profile, dog, read messages, walk in progress, offline copy
  try { const drop = ["carnet-me@", "carnet-dog@", "carnet-notes-seen@", "dl-push@"].map(k => k + UID);
    Object.keys(localStorage).forEach(k => { if (drop.includes(k) || k.startsWith("dl-gps@")) localStorage.removeItem(k); });
    localStorage.setItem("dl-fid@" + UID, fid); sessionStorage.setItem("dl-left", removed ? "removed" : "1"); } catch(_) {}
  try { await terminate(fs); await clearIndexedDbPersistence(fs); } catch(e) { console.warn(e); }
  location.reload();
  return "ok";
};
// someone removed this account from the family: clean up this phone the same way (checked with the server, never on a hunch)
let goneCheck = false;
window.carnetCheckGone = async () => {
  if (goneCheck || !FID || !UID || !navigator.onLine) return false; goneCheck = true;
  let gone = false;
  try { gone = !(await getDocFromServer(doc(fs, "families", FID, "access", UID))).exists(); }
  catch(e) { gone = e && e.code === "permission-denied"; }
  if (!gone) { goneCheck = false; return false; }
  await window.carnetLeave("", true); return true;
};
// joining another family from inside the app (Profile → Rejoindre une famille)
window.carnetJoinCode = async (code, name) => { F.code = code; F.name = name; msg = ""; try { await joinWithCode(true); } catch(e) { console.warn(e); msg = errText(e); } return msg; };
