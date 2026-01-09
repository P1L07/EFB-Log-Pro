
const CACHE_NAME = 'efb-log-pro-v1.1.7'; 

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


self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// 2. UPDATED INSTALL EVENT (Force Network Fetch)
self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      const stack = ASSETS.map(url => {
        return new Request(url, { cache: 'reload' }); 
      });
      
      return cache.addAll(stack);
    })
  );
});

// 3. ACTIVATE EVENT
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('Deleting old cache:', key);
            return caches.delete(key);
          }
        })
      );
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