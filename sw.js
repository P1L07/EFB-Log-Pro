const CACHE_NAME = 'efb-log-pro-v2.0.3';
const SW_VERSION = '2.0.3';

const STATIC_ASSETS = [
  './pdf-lib.min.js',
  './pdf.min.js',
  './signature_pad.umd.min.js',
  './icon.png',
  './pdf.worker.min.js',
];

const LOGIC_ASSETS = [
  './',
  './index.html',
  './efb-log-pro.js', 
];

const ALL_ASSETS = [...STATIC_ASSETS, ...LOGIC_ASSETS];

self.addEventListener('install', (e) => {
  self.skipWaiting(); 
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(ALL_ASSETS.map(url => new Request(url, { cache: 'reload' })));
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.map((key) => {
        if (key !== CACHE_NAME) return caches.delete(key);
      })
    ))
  );
  return self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // STRATEGY 1: Network First (For HTML and Main JS)
  // Tries to get the latest version from server. If offline, falls back to cache.
  if (url.pathname.endsWith('efb-log-pro.js') || url.pathname.endsWith('/') || url.pathname.endsWith('index.html')) {
    e.respondWith(
      fetch(e.request)
        .then(response => {
          // If valid response, clone and update cache for next time
          if (response.status === 200) {
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(e.request, responseClone));
          }
          return response;
        })
        .catch(() => {
          // If offline, return cache (ignore version query strings like ?v=1.1.9)
          return caches.match(e.request, { ignoreSearch: true });
        })
    );
    return;
  }

  // STRATEGY 2: Cache First (For heavy libs and PDFs)
  // Checks cache. If missing, fetches from network.
  e.respondWith(
    caches.match(e.request, { ignoreSearch: true }).then(response => {
      return response || fetch(e.request);
    })
  );
});