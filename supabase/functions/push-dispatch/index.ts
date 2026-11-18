import "jsr:@supabase/functions-js/edge-runtime.d.ts";

// Push notifications were intentionally retired. Keep the endpoint inert so
// old installed clients cannot register devices or dispatch queued notifications.
Deno.serve((_req: Request) => new Response(
  JSON.stringify({ ok: false, error: "push_notifications_disabled" }),
  {
    status: 410,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    },
  },
));
