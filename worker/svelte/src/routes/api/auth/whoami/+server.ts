import type { RequestHandler } from "./$types";
import { verifySession, extractSessionToken } from "$lib/session";

type Env = { SS_AT_SESSION_SECRET?: string };

export const GET: RequestHandler = async (event) => {
  const env = (event.platform as { env?: Env } | undefined)?.env ?? {};
  const secret = env.SS_AT_SESSION_SECRET ?? "";
  const token = extractSessionToken(event.request);

  if (!token) {
    return new Response(JSON.stringify({ anon: true }), {
      status: 200,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }

  try {
    const payload = await verifySession(secret, token, "access");
    const did = payload.did as string;
    const handle = payload.handle as string;
    return new Response(JSON.stringify({ did, handle, accountDid: did, activeDid: did, anon: false }), {
      status: 200,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  } catch {
    return new Response(JSON.stringify({ anon: true }), {
      status: 200,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }
};
