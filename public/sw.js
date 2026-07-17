// NVME Service Worker v15 — network-first for HTML, cache-first for assets
// Fixes: never cache app.html (strips OAuth ?token= params)
// v15: force-wipes all stale caches on Samsung/mobile after update
const CACHE = 'nvme-v21';
const STATIC_ASSETS = [
  '/img/icon-192.png',
  '/img/icon-512.png',
  '/img/icon-512-maskable.png',
  '/manifest.json'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // 1. API + auth routes: always network, never cache
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/auth/')) {
    e.respondWith(
      fetch(e.request).catch(() =>
        new Response(JSON.stringify({ ok: false, error: 'Offline' }), {
          headers: { 'Content-Type': 'application/json' }
        })
      )
    );
    return;
  }

  // 2. HTML files (app.html, index.html, merch.html):
  //    ALWAYS network-first — never serve from cache
  //    This preserves ?token= and ?auth= query params from OAuth redirects
  if (e.request.mode === 'navigate' || url.pathname.endsWith('.html') || url.pathname === '/') {
    e.respondWith(
      fetch(e.request)
        .catch(() => {
          // Offline fallback: serve cached index only for non-auth pages
          // Do NOT fall back for app.html — would strip OAuth token from URL
          if (url.pathname !== '/app.html') {
            return caches.match('/index.html');
          }
          return new Response('<h1>NVME — Please connect to the internet to sign in</h1>', {
            headers: { 'Content-Type': 'text/html' }
          });
        })
    );
    return;
  }

  // 3. Static assets (images, icons, fonts): cache-first
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        if (res.ok && e.request.method === 'GET') {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      });
    }).catch(() => new Response('', { status: 404 }))
  );
});
