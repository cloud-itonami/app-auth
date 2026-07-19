import { decodeBase64Url, encodeBase64Url, encodeJsonBase64Url } from "./base64url";

export interface SessionTokens {
  'accessJwt': string;
  'refreshJwt': string;
  did: string;
  'accountDid': string;
  'activeDid': string;
  handle: string;
}

export interface SessionIdentity {
  'accountDid': string;
  'activeDid': string;
  handle: string;
  /**
   * DPoP JWK SHA-256 thumbprint (RFC 9449 §6). When set, the issued access
   * token carries `cnf: {jkt}` so the Resource Server can verify the proof
   * key matches (ADR-2604240914 Y1 A2).
   */
  'cnfJkt'?: string;
}

const ACCESS_TOKEN_EXPIRY_SECS = 7 * 24 * 3600;
const REFRESH_TOKEN_EXPIRY_SECS = 90 * 24 * 3600;

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

function uuid(): string {
  return crypto.randomUUID();
}

let cachedHmacKey: { secret: string; key: CryptoKey } | null = null;

async function importHmacKey(secret: string): Promise<CryptoKey> {
  const normalizedSecret = secret.trim();
  if (!normalizedSecret) throw new Error("SS_AT_SESSION_SECRET required");
  if (cachedHmacKey && cachedHmacKey.secret === normalizedSecret) return cachedHmacKey.key;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(normalizedSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  cachedHmacKey = { secret: normalizedSecret, key };
  return key;
}

async function signHs256(secret: string, headerB64: string, payloadB64: string): Promise<string> {
  const key = await importHmacKey(secret);
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${encodeBase64Url(signature)}`;
}

export async function issueSession(
  secret: string,
  identity: SessionIdentity,
  opts: { sid?: string } = {},
): Promise<SessionTokens> {
  const now = nowSecs();
  const headerB64 = encodeJsonBase64Url({ alg: "HS256", typ: "JWT" });
  const did = identity.accountDid;
  const activeDid = identity.activeDid || did;
  const handle = identity.handle;
  // ADR-2604240914 Y2 B3 — session-family id shared by the access/refresh
  // pair. RFC 7009 §2.1: revoking one token in the family invalidates the
  // other. Inherited across refresh rotation; freshly minted on sign-in.
  const sid = opts.sid || uuid();
  const accessPayloadB64 = encodeJsonBase64Url({
    iss: "https://authn.etzhayyim.com",
    aud: "atproto",
    sub: did,
    did,
    accountDid: did,
    activeDid,
    handle,
    scope: "com.atproto.access",
    iat: now,
    exp: now + ACCESS_TOKEN_EXPIRY_SECS,
    jti: uuid(),
    sid,
    // RFC 9449 §6: DPoP-bound access tokens carry the proof-key thumbprint.
    // Absent for non-DPoP sessions (Bearer / passkey UI flow).
    ...(identity.cnfJkt ? { cnf: { jkt: identity.cnfJkt } } : {}),
  });
  const refreshPayloadB64 = encodeJsonBase64Url({
    iss: "https://authn.etzhayyim.com",
    aud: "atproto",
    sub: did,
    did,
    accountDid: did,
    activeDid,
    handle,
    scope: "com.atproto.refresh",
    iat: now,
    exp: now + REFRESH_TOKEN_EXPIRY_SECS,
    jti: uuid(),
    sid,
  });

  return {
    'accessJwt': await signHs256(secret, headerB64, accessPayloadB64),
    'refreshJwt': await signHs256(secret, headerB64, refreshPayloadB64),
    did,
    'accountDid': did,
    'activeDid': activeDid,
    handle,
  };
}

export async function verifySession(secret: string, token: string, expectedScope: string): Promise<Record<string, unknown>> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid token format");

  const [headerB64, payloadB64, sigB64] = parts;
  const key = await importHmacKey(secret);
  const signingInput = `${headerB64}.${payloadB64}`;
  const valid = await crypto.subtle.verify("HMAC", key, decodeBase64Url(sigB64), new TextEncoder().encode(signingInput));
  if (!valid) throw new Error("signature mismatch");

  const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(payloadB64))) as Record<string, unknown>;
  const exp = Number(payload.exp ?? 0);
  if (!exp) throw new Error("missing exp");
  if (nowSecs() > exp) throw new Error("token expired");

  const scope = String(payload.scope ?? "");
  const normalizedScope = scope === "atproto" ? "com.atproto.access" : scope;
  const normalizedExpected = expectedScope === "atproto" ? "com.atproto.access" : expectedScope;
  if (normalizedScope !== normalizedExpected) throw new Error("scope mismatch");

  if (payload.iss !== "https://authn.etzhayyim.com") throw new Error("issuer mismatch");
  return payload;
}

export async function refreshSession(
  secret: string,
  refreshToken: string,
  opts: { cnfJkt?: string } = {},
): Promise<SessionTokens> {
  const payload = await verifySession(secret, refreshToken, "com.atproto.refresh");
  const accountDid = String(payload.accountDid ?? payload.sub ?? "");
  const activeDid = String(payload.activeDid ?? accountDid);
  const handle = String(payload.handle ?? accountDid);
  if (!accountDid) throw new Error("missing sub");
  // RFC 9449 §5: refresh_token exchange binds the new access token to the
  // DPoP key presented on the refresh request. If the caller doesn't pass
  // a fresh jkt we retain whatever cnf was on the inbound refresh token.
  const cnfJkt = opts.cnfJkt
    || (payload.cnf && typeof payload.cnf === "object" && "jkt" in (payload.cnf as Record<string, unknown>)
      ? String((payload.cnf as Record<string, unknown>).jkt)
      : undefined);
  // ADR-2604240914 Y2 B3: preserve session-family id so a cascade revoke
  // on the refresh_token also invalidates the pre-refresh access_token.
  const sid = typeof payload.sid === "string" ? payload.sid : undefined;
  return issueSession(secret, { accountDid, activeDid, handle, cnfJkt }, { sid });
}
