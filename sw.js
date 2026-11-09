self.addEventListener("install", event => { event.waitUntil(self.skipWaiting()); });
self.addEventListener("activate", event => { event.waitUntil(self.clients.claim()); });

self.addEventListener("push", event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch {
    try { data = { body: event.data?.text() || "" }; } catch {}
  }
  const title = String(data.title || "Stock Inventory");
  const options = {
    body: String(data.body || "มีการเปลี่ยนแปลงข้อมูลคลังสินค้า"),
    tag: String(data.tag || "stokinventory-notification"),
    renotify: false,
    data: { url: String(data.url || "/") },
    icon: "/favicon.ico",
    badge: "/favicon.ico"
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", event => {
  event.notification.close();
  const rawUrl = event.notification.data?.url || "./";
  const target = rawUrl === "/" ? new URL("./", self.registration.scope) : new URL(rawUrl, self.registration.scope);
  if (target.origin !== self.location.origin) return;
  event.waitUntil((async () => {
    const windows = await clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const client of windows) {
      if ("focus" in client) {
        if ("navigate" in client && client.url !== target.href) await client.navigate(target.href);
        return client.focus();
      }
    }
    if (clients.openWindow) return clients.openWindow(target.href);
  })());
});
