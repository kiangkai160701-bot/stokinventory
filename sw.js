// Push notifications have been removed. Keep this lightweight worker only so
// browsers with an old registration can update and retire the previous push handler.
self.addEventListener("install", event => { event.waitUntil(self.skipWaiting()); });
self.addEventListener("activate", event => { event.waitUntil(self.clients.claim()); });
