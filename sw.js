// Retire legacy Web Push registrations on clients that still have the old worker.
// This worker deliberately does not display notifications or cache application data.
self.addEventListener("install", event => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    try {
      const registration = self.registration;
      if (registration && registration.pushManager) {
        const subscription = await registration.pushManager.getSubscription();
        if (subscription) await subscription.unsubscribe();
      }
    } catch (_) {}
    try {
      await self.registration.unregister();
    } catch (_) {}
    try {
      await self.clients.claim();
    } catch (_) {}
  })());
});
