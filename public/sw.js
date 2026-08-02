/* NVME service worker — KILL SWITCH (nvme-v34)
   The legacy PWA worker (<= v33) cached the old static app.
   NVME is now a Next.js static export served fresh by the server,
   so this worker clears every cache, unregisters itself, and
   tells open tabs to reload once. */
const VER = 'nvme-v35-3d-landing';

self.addEventListener('install', (e) => {
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    try {
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));
    } catch (_) {}
    try { await self.clients.claim(); } catch (_) {}
    try { await self.registration.unregister(); } catch (_) {}
    try {
      const clients = await self.clients.matchAll({ type: 'window' });
      clients.forEach((c) => c.navigate(c.url).catch(() => {}));
    } catch (_) {}
  })());
});

// Never intercept — always go to network.
self.addEventListener('fetch', () => {});
