import { decodeBase64Url, encodeBase64Url, encodeJsonBase64Url } from "./base64url";

export interface SessionTokens {
  accessJwt: string;
  refreshJwt: string;
  did: string;
  handle: string;
}

export interface SessionIdentity {
  did: string;
  handle: string;
}

const ISS = "https://auth.etzhayyim.com";
const ACCESS_TOKEN_EXPIRY_SECS = 7 * 24 * 3600;
const REFRESH_TOKEN_EXPIRY_SECS = 90 * 24 * 3600;
const COOKIE_NAME = "etzhayyim_session";

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

let cachedHmacKey: { secret: string; key: CryptoKey } | null = null;

async function importHmacKey(secret: string): Promise<CryptoKey> {
  const s = secret.trim();
  if (!s) throw new Error("SS_AT_SESSION_SECRET required");
  if (cachedHmacKey && cachedHmacKey.secret === s) return cachedHmacKey.key;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(s),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  cachedHmacKey = { secret: s, key };
  return key;
}

async function signHs256(secret: string, headerB64: string, payloadB64: string): Promise<string> {
  const key = await importHmacKey(secret);
  const input = `${headerB64}.${payloadB64}`;
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input));
  return `${input}.${encodeBase64Url(sig)}`;
}

export async function issueSession(secret: string, identity: SessionIdentity): Promise<SessionTokens> {
  const now = nowSecs();
  const headerB64 = encodeJsonBase64Url({ alg: "HS256", typ: "JWT" });
  const sid = crypto.randomUUID();

  const accessJwt = await signHs256(secret, headerB64, encodeJsonBase64Url({
    iss: ISS,
    sub: identity.did,
    did: identity.did,
    handle: identity.handle,
    scope: "access",
    iat: now,
    exp: now + ACCESS_TOKEN_EXPIRY_SECS,
    jti: crypto.randomUUID(),
    sid,
  }));

  const refreshJwt = await signHs256(secret, headerB64, encodeJsonBase64Url({
    iss: ISS,
    sub: identity.did,
    did: identity.did,
    handle: identity.handle,
    scope: "refresh",
    iat: now,
    exp: now + REFRESH_TOKEN_EXPIRY_SECS,
    jti: crypto.randomUUID(),
    sid,
  }));

  return { accessJwt, refreshJwt, did: identity.did, handle: identity.handle };
}

export async function verifySession(secret: string, token: string, scope: "access" | "refresh"): Promise<Record<string, unknown>> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid token format");
  const [headerB64, payloadB64, sigB64] = parts;
  const key = await importHmacKey(secret);
  const valid = await crypto.subtle.verify(
    "HMAC", key,
    decodeBase64Url(sigB64),
    new TextEncoder().encode(`${headerB64}.${payloadB64}`),
  );
  if (!valid) throw new Error("signature mismatch");

  const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(payloadB64))) as Record<string, unknown>;
  if (nowSecs() > Number(payload.exp ?? 0)) throw new Error("token expired");
  if (payload.iss !== ISS) throw new Error("issuer mismatch");
  if (payload.scope !== scope) throw new Error("scope mismatch");
  return payload;
}

export async function refreshSession(secret: string, refreshToken: string): Promise<SessionTokens> {
  const payload = await verifySession(secret, refreshToken, "refresh");
  const did = String(payload.did ?? payload.sub ?? "");
  const handle = String(payload.handle ?? did);
  if (!did) throw new Error("missing did");
  return issueSession(secret, { did, handle });
}

export function sessionCookie(jwt: string): string {
  return `${COOKIE_NAME}=${jwt}; Domain=.etzhayyim.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${ACCESS_TOKEN_EXPIRY_SECS}`;
}

export function clearSessionCookie(): string {
  return `${COOKIE_NAME}=; Domain=.etzhayyim.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
}

export function extractSessionToken(request: Request): string | null {
  const cookie = request.headers.get("cookie") ?? "";
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  return match ? match[1] : null;
}
