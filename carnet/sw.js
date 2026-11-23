// Dogs Life moved to https://wikzouustudio.com/ : this old service worker removes itself and its caches.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) await caches.delete(k);
    await self.registration.unregister();
    for (const c of await self.clients.matchAll({type: "window"})) c.navigate("https://wikzouustudio.com/");
  })());
});
