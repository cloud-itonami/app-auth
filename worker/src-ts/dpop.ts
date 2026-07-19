import { decodeBase64Url, encodeBase64Url } from "./base64url";

const DPOP_MAX_AGE_SECS = 300;

export interface DpopProofClaims {
  htm: string;
  htu: string;
  iat: number;
  jti: string;
  ath?: string;
}

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return encodeBase64Url(digest);
}

async function importJwkP256(jwk: JsonWebKey): Promise<CryptoKey> {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
    throw new Error("invalid P-256 JWK");
  }
  return crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

async function computeJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return sha256Base64Url(canonical);
}

export async function verifyDpopProof(
  proof: string,
  expectedHtm: string,
  expectedHtu: string,
  usedJtis: Set<string>,
): Promise<{ jkt: string; claims: DpopProofClaims }> {
  const parts = proof.split(".");
  if (parts.length !== 3) throw new Error("invalid DPoP proof format");
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(new TextDecoder().decode(decodeBase64Url(headerB64))) as { typ?: string; alg?: string; jwk?: JsonWebKey };
  if (header.typ !== "dpop+jwt") throw new Error("typ must be dpop+jwt");
  if (header.alg !== "ES256") throw new Error("only ES256 supported");
  if (!header.jwk) throw new Error("missing jwk in header");

  const claims = JSON.parse(new TextDecoder().decode(decodeBase64Url(payloadB64))) as DpopProofClaims;
  if (claims.htm !== expectedHtm) throw new Error("htm mismatch");
  if (!claims.htu.includes(expectedHtu)) throw new Error("htu mismatch");
  const now = nowSecs();
  if (claims.iat > now + 30) throw new Error("iat in the future");
  if (now - claims.iat > DPOP_MAX_AGE_SECS) throw new Error("DPoP proof too old");
  if (!claims.jti) throw new Error("missing jti");
  if (usedJtis.has(claims.jti)) throw new Error("jti replay detected");

  const key = await importJwkP256(header.jwk);
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    decodeBase64Url(sigB64),
    new TextEncoder().encode(`${headerB64}.${payloadB64}`),
  );
  if (!valid) throw new Error("DPoP signature verification failed");

  usedJtis.add(claims.jti);
  if (usedJtis.size > 10000) {
    const keep = Array.from(usedJtis).slice(-5000);
    usedJtis.clear();
    for (const jti of keep) usedJtis.add(jti);
  }

  return { jkt: await computeJwkThumbprint(header.jwk), claims };
}
