// worker.js
const RATE_LIMIT = 30;        // requests
const WINDOW_SECS = 60;       // per minute
const MAX_BODY_BYTES = 10 * 1024; // 10 KB
const BLOCKED_METHODS = new Set(["DELETE", "PUT", "PATCH"]);

const ALLOWED_ORIGIN_RE = /^https:\/\/[^.]+\.renfoc\.us$/;

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin");

    if (!origin || !ALLOWED_ORIGIN_RE.test(origin)) {
      return new Response("Forbidden", { status: 403 });
    }

    // Handle CORS preflight
    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }
      });
    }

    if (BLOCKED_METHODS.has(req.method)) {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const contentLength = parseInt(req.headers.get("Content-Length") ?? "0");
    if (contentLength > MAX_BODY_BYTES) {
      return new Response("Payload Too Large", { status: 413 });
    }

    if (req.body) {
      const body = await req.arrayBuffer();
      if (body.byteLength > MAX_BODY_BYTES) {
        return new Response("Payload Too Large", { status: 413 });
      }
      req = new Request(req, { body });
    }

    const ip = req.headers.get("CF-Connecting-IP");

    // --- Rate limiting via Cloudflare KV ---
    const key = `rl:${ip}`;
    const current = parseInt(await env.RATE_KV.get(key) ?? "0");

    if (current >= RATE_LIMIT) {
      return new Response("Too Many Requests", {
        status: 429,
        headers: { "Retry-After": String(WINDOW_SECS) }
      });
    }

    // Increment counter, set TTL on first request
    await env.RATE_KV.put(key, String(current + 1), {
      expirationTtl: WINDOW_SECS
    });

    // --- Proxy to Supabase ---
    const url = new URL(req.url);
    const supabaseUrl = `${env.SUPABASE_URL}/rest/v1${url.pathname}${url.search}`;

    const response = await fetch(supabaseUrl, {
      method: req.method,
      headers: {
        "Content-Type": "application/json",
        "apikey": env.SUPABASE_ANON_KEY,
      },
      body: req.method !== "GET" ? req.body : undefined
    });

    return new Response(response.body, {
      status: response.status,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": origin
      }
    });
  }
};
