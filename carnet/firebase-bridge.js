// Firebase bridge for the standalone Carnet du chien.
// The app was written against claude.ai's `window.claude.use(...)` API; this module answers the same calls
// with Firebase Auth (one account per person) and Firestore (one isolated space per family).
import { initializeApp } from "https://www.gstatic.com/firebasejs/13.2.0/firebase-app.js";
import { getAuth, onAuthStateChanged, GoogleAuthProvider, signInWithPopup, signInWithRedirect, getRedirectResult,
  signInWithEmailAndPassword, createUserWithEmailAndPassword, sendPasswordResetEmail, signOut } from "https://www.gstatic.com/firebasejs/13.2.0/firebase-auth.js";
import { getFirestore, doc, getDoc, setDoc, deleteDoc, collection, query, where, onSnapshot } from "https://www.gstatic.com/firebasejs/13.2.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyDHk_d3qkOyci4ELyKhFzShOY5XU94oPOo",
  authDomain: "carnet-91f30.firebaseapp.com",
  projectId: "carnet-91f30",
  storageBucket: "carnet-91f30.firebasestorage.app",
  messagingSenderId: "961233839254",
  appId: "1:961233839254:web:ea3bff8f9692ee9e33ceb7"
};
// Claude's evening advice goes through a small relay that keeps the API key secret (empty = built-in advice only)
const ADVICE_URL = "";

const B = window.__carnetBridge; B.started = true;
const fb = initializeApp(firebaseConfig), auth = getAuth(fb), fs = getFirestore(fb);

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
    <label class="g-lab">${TXT.code}</label><input class="g-f g-code" id="g-code" data-f="code" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" placeholder="ABC 234" maxlength="9" value="${esc(F.code)}">
    <label class="g-lab">${TXT.name}</label><input class="g-f" id="g-name" data-f="name" autocomplete="given-name" maxlength="24" placeholder="${TXT.name}" value="${esc(F.name || (u && u.displayName ? u.displayName.split(" ")[0] : ""))}">
    ${m}<button class="g-btn g-main" data-g="join" ${busy ? "disabled" : ""}>${busy ? TXT.wait : TXT.joinBtn}</button>
    <div class="g-links"><button data-g="back">${TXT.back}</button></div>`);
  if (step === "loading") return show(`${head}<div class="g-spin"></div>`);
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
async function joinWithCode(){
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
  const colors = ["#E07A5F","#3D8BD9","#5FA86B","#B57EDC","#E6A23C","#2BB0A5","#D9668F"];
  await setDoc(doc(fs, "families", fid, "members", newId()), {name, uid: UID, role: c.role || "famille", since: Date.now(), color: colors[Math.floor(Math.random() * colors.length)], invitedBy: c.byName || ""});
  await setDoc(doc(fs, "families", fid, "notes", newId()), {kind: "join", name, text: name + " a rejoint la famille", uid: UID, at: new Date().toISOString()});
  try { if (c.invite) await deleteDoc(doc(fs, "families", fid, "invites", c.invite)); await deleteDoc(doc(fs, "codes", h)); } catch(_) {}
  enter(fid, false);
}
async function enter(fid, owner){
  FID = fid; OWNER = owner; step = "done";
  if (!owner) { try { const f = await getDoc(doc(fs, "families", fid)); OWNER = f.exists() && f.data().owner === UID; } catch(_) {} }
  hide();
  B.resolve(api());
}

/* ---------- what the app asks for ---------- */
function api(){
  const path = col => collection(fs, "families", FID, col);
  const wrapSnap = s => ({docs: s.docs.map(d => ({id: d.id, data: () => d.data()})), metadata: {fromCache: s.metadata.fromCache && !s.docs.length ? false : s.metadata.fromCache}});
  const coll = (col, filters) => ({
    where: (f, op, v) => coll(col, (filters || []).concat([[f, op, v]])),
    onSnapshot(cb, err){ const q = filters ? query(path(col), ...filters.map(([f, op, v]) => where(f, op, v))) : path(col); return onSnapshot(q, s => cb(wrapSnap(s)), e => err && err({code: e.code === "permission-denied" ? "revoked" : "unavailable", message: e.message})); },
    doc: id => ({
      async set(data){
        await setDoc(doc(fs, "families", FID, col, id), clean(data));
        // a join code is findable by its hash only, so a new member can locate the family
        if (col === "invites" && data && data.hash) await setDoc(doc(fs, "codes", data.hash), {family: FID, role: data.role || "famille", exp: data.exp || 0, invite: id, byName: data.byName || ""});
      },
      async delete(){
        if (col === "invites") { try { const s = await getDoc(doc(fs, "families", FID, col, id)); const h = s.exists() && s.data().hash; if (h) await deleteDoc(doc(fs, "codes", h)); } catch(_) {} }
        await deleteDoc(doc(fs, "families", FID, col, id));
      }
    })
  });
  const u = auth.currentUser;
  window.carnetAccount = {email: u.email || u.displayName || "", signOut: async () => { await signOut(auth); try { localStorage.removeItem("carnet-me@" + UID); } catch(_) {} location.reload(); }};
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
  try {
    const us = await getDoc(doc(fs, "users", UID)); const fid = us.exists() && us.data().family;
    if (fid) { let ok = false; try { ok = (await getDoc(doc(fs, "families", fid, "access", UID))).exists(); } catch(_) {} if (ok) return enter(fid, false); }
  } catch(e) { console.warn(e); if (/permission-denied/.test(e.code || "")) msg = TXT.errSetup; }
  step = "choose"; render();
});
