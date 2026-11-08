// Dogs Life service worker: opens without network, and shows family notifications even when the app is closed.
const CACHE = "dogslife-v25";
const SHELL = ["./", "index.html", "firebase-bridge.js", "manifest.webmanifest", "icon-192.png", "icon-512.png", "apple-touch-icon.png", "favicon.png", "dog.bin"];
const LIBS = ["www.gstatic.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net"]; // Firebase and three.js: versioned files, safe to keep

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => Promise.all(SHELL.map(u => c.add(u).catch(() => {})))).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  const req = e.request; if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin === location.origin) {
    // the app itself: newest version when online, the saved copy when offline
    e.respondWith(fetch(req, {cache: "no-cache"}).then(r => { if (r.ok) { const cp = r.clone(); caches.open(CACHE).then(c => c.put(req, cp)); } return r; })
      .catch(() => caches.match(req, {ignoreSearch: true}).then(r => r || (req.mode === "navigate" ? caches.match("index.html") : Response.error()))));
  } else if (LIBS.includes(url.hostname)) {
    e.respondWith(caches.match(req).then(hit => hit || fetch(req).then(r => { if (r.ok || r.type === "opaque") { const cp = r.clone(); caches.open(CACHE).then(c => c.put(req, cp)); } return r; })));
  }
});

// notifications sent by the family server (Firebase Cloud Messaging, data messages)
self.addEventListener("push", e => {
  let p = {}; try { p = e.data ? e.data.json() : {}; } catch (_) { p = {data: {title: "Dogs Life", body: e.data ? e.data.text() : ""}}; }
  const d = p.data || p.notification || p, title = d.title || "Dogs Life";
  // a unique tag: on iPhone, a notification with the same tag as an earlier one replaces it without any sound or banner
  // one notification per event (nid): the same event received twice replaces itself instead of showing twice
  const tag = d.nid ? "n-" + d.nid : (d.tag || "dl") + "-" + (d.id || Date.now());
  e.waitUntil(self.registration.showNotification(title, {body: d.body || "", icon: "icon-192.png", badge: "icon-192.png", tag, timestamp: Date.now(), data: {url: (d.url || "./") + (d.nid ? "#n=" + encodeURIComponent(d.nid) + (d.tab ? "&t=" + d.tab : "") : ""), nid: d.nid || "", tab: d.tab || ""}}));
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || "./";
  e.waitUntil(self.clients.matchAll({type: "window", includeUncontrolled: true}).then(ws => {
    const d = e.notification.data || {}, w = ws.find(c => c.url.includes("/carnet/"));
    if (w) { if (d.nid) w.postMessage({type: "open-notif", nid: d.nid, tab: d.tab}); return w.focus(); }
    return self.clients.openWindow(url);
  }));
});
