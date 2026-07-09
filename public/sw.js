const CACHE = 'nvme-v1';
const STATIC = [
  '/app.html',
  '/img/icon-192.png',
  '/img/icon-512.png',
  '/manifest.json'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(STATIC)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  // Network first for API calls, cache first for static
  if(e.request.url.includes('/api/') || e.request.url.includes('/auth/')) {
    e.respondWith(fetch(e.request).catch(() => new Response(JSON.stringify({ok:false,error:'Offline'}), {headers:{'Content-Type':'application/json'}})));
    return;
  }
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request).then(res => {
      if(res.ok && e.request.method === 'GET') {
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
      }
      return res;
    })).catch(() => caches.match('/app.html'))
  );
});
