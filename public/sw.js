/* NVME service worker — STABLE (nvme-v36)
   v35 kill-switch caused an infinite reload loop: it unregistered
   itself + navigated clients, while app.html re-registered it on
   every load. v36 clears stale caches once, claims clients, and
   NEVER navigates or unregisters. Network-first for HTML/JS so
   deploys propagate; cache-first for static assets. */
const VER = 'nvme-v36-stable';
const STATIC_CACHE = VER + '-static';

self.addEventListener('install', (e) => {
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    try {
      const keys = await caches.keys();
      await Promise.all(keys.filter((k) => k !== STATIC_CACHE).map((k) => caches.delete(k)));
    } catch (_) {}
    try { await self.clients.claim(); } catch (_) {}
    // NO clients.navigate — no reload loop, ever.
  })());
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== self.location.origin) return;

  // HTML + sw.js: network-first (fresh deploys win), fall back to cache offline
  if (e.request.mode === 'navigate' || url.pathname === '/sw.js' || url.pathname.endsWith('.html')) {
    e.respondWith(
      fetch(e.request).then((res) => {
        const copy = res.clone();
        caches.open(STATIC_CACHE).then((c) => c.put(e.request, copy)).catch(() => {});
        return res;
      }).catch(() => caches.match(e.request))
    );
    return;
  }

  // Static assets: cache-first
  e.respondWith(
    caches.match(e.request).then((hit) => hit || fetch(e.request).then((res) => {
      if (res.ok) {
        const copy = res.clone();
        caches.open(STATIC_CACHE).then((c) => c.put(e.request, copy)).catch(() => {});
      }
      return res;
    }).catch(() => hit))
  );
});
