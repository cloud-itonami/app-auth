/**
 * Session Proof-of-Possession verification (ADR-2606014500 C-3, server side).
 *
 * Verifies the compact EdDSA JWS produced by the yoro client
 * (`session-key.ts::signSessionPoP`) — `b64url(header).b64url(payload).b64url(sig)` —
 * against the member's CLIENT-REGISTERED Ed25519 session key, looked up from the
 * public projection (`vertex_etzhayyim_key_signing`, `human_self_custody`). The server
 * holds NO private key and mints nothing here — this is read-only verification,
 * the zero-access replacement for a server-signed HS256 session JWT.
 *
 * ADDITIVE: this does not change session ISSUANCE. The cutover that makes
 * createSession verify a PoP instead of signing HS256 is a separate, gated step
 * (ADR-2605231525 Stage C-3) — `SS_REPO_SIGNING_KEK` stays until C-4.
 */

import { decodeBase64Url } from "./base64url";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Standard base58btc (Bitcoin alphabet) decode. Returns null on invalid input. */
function base58Decode(s: string): Uint8Array | null {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros += 1;
  const bytes: number[] = [];
  for (let i = zeros; i < s.length; i += 1) {
    let carry = BASE58_ALPHABET.indexOf(s[i]);
    if (carry < 0) return null;
    for (let j = 0; j < bytes.length; j += 1) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i += 1) out[zeros + bytes.length - 1 - i] = bytes[i];
  return out;
}

/** Decode a did:key-style Ed25519 multibase (`z` + base58btc(0xed01 || key)) → 32-byte key. */
export function decodeEd25519Multibase(mb: string): Uint8Array | null {
  if (!mb || mb[0] !== "z") return null;
  const decoded = base58Decode(mb.slice(1));
  if (!decoded || decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) return null;
  return decoded.slice(2);
}

export interface PopResult {
  valid: boolean;
  did?: string;
  claims?: Record<string, unknown>;
  reason?: string;
}

interface KeysDbLike {
  prepare(query: string): {
    bind(...vals: unknown[]): { first<T = unknown>(): Promise<T | null> };
  };
}

/**
 * Verify a session PoP token. Returns `{ valid, did, claims }` on success, or
 * `{ valid: false, reason }` otherwise. Never throws.
 */
export async function verifySessionPoP(
  env: { KEYS_DB?: KeysDbLike },
  token: string,
): Promise<PopResult> {
  const parts = token.split(".");
  if (parts.length !== 3) return { valid: false, reason: "malformed token" };
  const [h, p, s] = parts;

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(decodeBase64Url(h)));
    payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(p)));
  } catch {
    return { valid: false, reason: "bad header/payload encoding" };
  }

  if (header.alg !== "EdDSA") return { valid: false, reason: `unsupported alg ${String(header.alg)}` };
  const did = typeof payload.iss === "string" ? payload.iss : "";
  if (!did) return { valid: false, reason: "missing iss" };

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number" && payload.exp < now) return { valid: false, did, reason: "expired" };

  if (!env.KEYS_DB) return { valid: false, did, reason: "KEYS_DB unavailable" };
  const row = await env.KEYS_DB.prepare(
    "SELECT public_key_multibase FROM vertex_etzhayyim_key_signing WHERE vertex_id = ? AND key_custody_tier IN ('human_self_custody','agent_self_custody') LIMIT 1",
  )
    .bind(did)
    .first<{ public_key_multibase: string }>();
  if (!row) return { valid: false, did, reason: "no self-custody key registered for iss" };

  const pub = decodeEd25519Multibase(row.public_key_multibase);
  if (!pub) return { valid: false, did, reason: "stored key is not an Ed25519 multibase" };

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return { valid: false, did, reason: "Ed25519 key import failed" };
  }

  const sig = decodeBase64Url(s);
  const signingInput = new TextEncoder().encode(`${h}.${p}`);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, signingInput);
  return ok ? { valid: true, did, claims: payload } : { valid: false, did, reason: "signature invalid" };
}
