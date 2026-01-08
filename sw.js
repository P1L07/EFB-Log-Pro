const CACHE_NAME = 'efb-log-pro-v1.1.2';
const ASSETS = [
  './',
  './index.html',
  './efb-log-pro.js',
  './pdf-lib.min.js',
  './pdf.min.js',
  './signature_pad.umd.min.js',
  './icon.png',
  './pdf.worker.min.js',
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(ASSETS);
    })
  );
});

self.addEventListener('fetch', (e) => {
  e.respondWith(
    caches.match(e.request).then(response => {
      return response || fetch(e.request);
    })
  );
});