/* HeshmatWall service worker: keeps the app shell available offline (network first, so
 * updates of the package show up at once). The API (/cgi-bin/heshmatwall) is never cached. */
'use strict';
const CACHE = 'heshmatwall-v1';
const SHELL = [ './', 'index.html', 'app.css', 'app.js', 'manifest.webmanifest', 'icon.svg', 'icon-192.png', 'icon-512.png' ];

self.addEventListener('install', (e) => {
	e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
	e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
		.then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
	const url = new URL(e.request.url);
	if (e.request.method !== 'GET' || url.origin !== self.location.origin || !url.pathname.startsWith(new URL(self.registration.scope).pathname))
		return;
	e.respondWith(fetch(e.request).then((res) => {
		if (res.ok) {
			const copy = res.clone();
			caches.open(CACHE).then((c) => c.put(e.request, copy));
		}
		return res;
	}).catch(() => caches.match(e.request, { ignoreSearch: true }).then((r) => r || caches.match('index.html'))));
});
