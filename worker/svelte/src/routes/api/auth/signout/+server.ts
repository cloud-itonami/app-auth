import type { RequestHandler } from "./$types";
import { clearSessionCookie } from "$lib/session";

export const POST: RequestHandler = async () => {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      // no-cookie: allow clearing legacy auth cookie during passkey migration
      "set-cookie": clearSessionCookie(),
    },
  });
};

export const GET: RequestHandler = async () => {
  return new Response(null, {
    status: 302,
    headers: {
      "location": "/sign-in",
      // no-cookie: allow clearing legacy auth cookie during passkey migration
      "set-cookie": clearSessionCookie(),
    },
  });
};
