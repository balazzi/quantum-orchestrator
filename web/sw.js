/* QO-75 service worker: cache-first dashboard shell. */
const CACHE = 'qo75-v1';
const ASSETS = ['/', '/index.html', '/styles.css', '/manifest.json'];
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).then(()=>self.skipWaiting()));
});
self.addEventListener('activate', e => { e.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', e => {
  if (e.request.url.includes('/api/')) return; // always live for telemetry
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});
