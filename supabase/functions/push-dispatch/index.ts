import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import webpush from "npm:web-push@3.6.7";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Content-Type": "application/json",
};
function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers });
}
async function rest(path: string, init: RequestInit = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: SERVICE_KEY,
      Authorization: `Bearer ${SERVICE_KEY}`,
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  const text = await res.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) throw new Error(typeof data === "object" ? (data?.message || data?.error || JSON.stringify(data)) : String(data));
  return data;
}
async function rpc(name: string, args: Record<string, unknown> = {}) {
  return await rest(`rpc/${name}`, { method: "POST", body: JSON.stringify(args) });
}
async function getConfig() {
  const config = await rpc("get_inventory_push_config");
  if (!config?.vapid_public_key || !config?.vapid_private_key || !config?.cron_secret) {
    throw new Error("Push secrets are not configured in Supabase Vault");
  }
  return config;
}
function vapidReady(config: any) {
  webpush.setVapidDetails(
    String(config.vapid_subject || "mailto:admin@example.com"),
    String(config.vapid_public_key),
    String(config.vapid_private_key),
  );
}
async function authContext(token: string) {
  if (!token || token.length < 40 || token.length > 256) throw new Error("invalid_session");
  const ctx = await rpc("notification_auth_context", { p_token: token });
  if (!ctx?.ok || !ctx?.branch_id || !ctx?.username) throw new Error("invalid_session");
  return ctx;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers });
  if (req.method !== "GET" && req.method !== "POST") return response({ ok: false, error: "method_not_allowed" }, 405);
  try {
    const config = await getConfig();
    if (req.method === "GET") return response({ ok: true, publicKey: config.vapid_public_key });

    const body = await req.json();
    const action = String(body?.action ?? "");
    const token = String(body?.token ?? "");
    let branchId: string | null = null;
    let username: string | null = null;
    if (action === "dispatch" && req.headers.get("x-push-cron-secret") === config.cron_secret) {
      branchId = null;
    } else {
      const ctx = await authContext(token);
      branchId = String(ctx.branch_id);
      username = String(ctx.username);
    }
    const deviceId = String(body?.deviceId ?? "");
    if (action === "test") {
      if (!deviceId || !branchId || !username) return response({ ok: false, error: "invalid_device" }, 400);
      const subscriptions = await rest(
        `inventory_push_subscriptions?select=id,endpoint,p256dh,auth&branch_id=eq.${encodeURIComponent(branchId)}&username=eq.${encodeURIComponent(username)}&device_id=eq.${encodeURIComponent(deviceId)}&limit=1`,
      ) ?? [];
      const sub = subscriptions[0];
      if (!sub) return response({ ok: false, error: "device_not_registered" }, 404);
      vapidReady(config);
      try {
        await webpush.sendNotification(
          { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
          JSON.stringify({
            title: "ทดสอบการแจ้งเตือน",
            body: "ระบบ Push Notification ของ Stock Inventory ทำงานแล้ว",
            url: "/",
            tag: `push-test-${crypto.randomUUID()}`,
            eventType: "test",
          }),
          { TTL: 60 },
        );
      } catch (error) {
        const statusCode = Number((error as any)?.statusCode ?? 0);
        if (statusCode === 404 || statusCode === 410) {
          await rest(`inventory_push_subscriptions?id=eq.${encodeURIComponent(sub.id)}`, { method: "DELETE" });
          return response({ ok: false, error: "subscription_expired_please_enable_push_again" }, 410);
        }
        throw error;
      }
      return response({ ok: true, sent: true });
    }
    if (action === "register") {
      const sub = body?.subscription;
      if (!deviceId || !sub?.endpoint || !sub?.keys?.p256dh || !sub?.keys?.auth) {
        return response({ ok: false, error: "invalid_subscription" }, 400);
      }
      const result = await rpc("notification_register_device", {
        p_token: token, p_device_id: deviceId, p_endpoint: sub.endpoint,
        p_p256dh: sub.keys.p256dh, p_auth: sub.keys.auth,
        p_user_agent: req.headers.get("user-agent") ?? "",
      });
      if (!result?.ok) return response(result, 400);
      return response({ ok: true, subscriptionId: result.subscription_id });
    }
    if (action === "preferences") {
      if (!deviceId || !body?.preferences || typeof body.preferences !== "object") {
        return response({ ok: false, error: "invalid_preferences" }, 400);
      }
      const result = await rpc("notification_update_preferences", {
        p_token: token, p_device_id: deviceId, p_preferences: body.preferences,
      });
      return response(result, result?.ok ? 200 : 400);
    }
    if (action === "unregister") {
      if (!deviceId) return response({ ok: false, error: "invalid_device" }, 400);
      const result = await rpc("notification_remove_device", { p_token: token, p_device_id: deviceId });
      return response(result);
    }
    if (action !== "dispatch") return response({ ok: false, error: "unknown_action" }, 400);

    vapidReady(config);
    const claimed = await rpc("claim_inventory_push_events", { p_limit: 40, p_branch_id: branchId });
    const events = Array.isArray(claimed) ? claimed : [];
    let sent = 0, failed = 0, expired = 0;
    for (const event of events) {
      let eventFailed = false;
      const subscriptions = await rest(
        `inventory_push_subscriptions?select=id,endpoint,p256dh,auth,preferences&branch_id=eq.${encodeURIComponent(event.branch_id)}`,
      ) ?? [];
      for (const sub of subscriptions) {
        if (sub.preferences?.[event.event_type] !== true) continue;
        const delivered = await rest(
          `inventory_push_deliveries?select=event_id&event_id=eq.${encodeURIComponent(event.event_id)}&subscription_id=eq.${encodeURIComponent(sub.id)}&limit=1`,
        ) ?? [];
        if (delivered.length) continue;
        try {
          const payload = {
            title: String(event.payload?.title ?? "Stock Inventory"),
            body: String(event.payload?.body ?? "มีการเปลี่ยนแปลงข้อมูลคลังสินค้า"),
            url: String(event.payload?.url ?? "/"),
            tag: String(event.event_id),
            eventType: event.event_type,
          };
          await webpush.sendNotification(
            { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
            JSON.stringify(payload),
            { TTL: 3600 },
          );
          await rest("inventory_push_deliveries", {
            method: "POST",
            headers: { Prefer: "resolution=ignore-duplicates,return=minimal" },
            body: JSON.stringify({ event_id: event.event_id, subscription_id: sub.id }),
          });
          sent++;
        } catch (error) {
          const statusCode = Number((error as any)?.statusCode ?? 0);
          if (statusCode === 404 || statusCode === 410) {
            await rest(`inventory_push_subscriptions?id=eq.${encodeURIComponent(sub.id)}`, { method: "DELETE" });
            expired++;
          } else {
            eventFailed = true;
            failed++;
          }
        }
      }
      await rest(`inventory_push_events?event_id=eq.${encodeURIComponent(event.event_id)}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify(eventFailed
          ? { claimed_at: null }
          : { processed_at: new Date().toISOString(), claimed_at: null }),
      });
    }
    return response({ ok: true, sent, failed, expired, claimed: events.length });
  } catch (error) {
    const message = String((error as Error)?.message ?? error);
    const status = message === "invalid_session" ? 401 : message.includes("secrets are not configured") ? 503 : 400;
    return response({ ok: false, error: message }, status);
  }
});
