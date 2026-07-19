import { decodeBase64Url, encodeBase64Url, encodeJsonBase64Url } from "./base64url";

const SERVICE_AUTH_EXPIRY_SECS = 60;

const P = BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
const A = BigInt("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
const GX = BigInt("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
const GY = BigInt("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

type Point = { x: bigint; y: bigint } | null;

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

function mod(value: bigint): bigint {
  const result = value % P;
  return result >= 0n ? result : result + P;
}

function modPow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let current = mod(base);
  let power = exp;
  while (power > 0n) {
    if (power & 1n) result = mod(result * current);
    current = mod(current * current);
    power >>= 1n;
  }
  return result;
}

function inv(value: bigint): bigint {
  return modPow(value, P - 2n);
}

function addPoints(p1: Point, p2: Point): Point {
  if (!p1) return p2;
  if (!p2) return p1;
  if (p1.x === p2.x && mod(p1.y + p2.y) === 0n) return null;

  const lambda =
    p1.x === p2.x && p1.y === p2.y
      ? mod((3n * p1.x * p1.x + A) * inv(2n * p1.y))
      : mod((p2.y - p1.y) * inv(p2.x - p1.x));
  const x = mod(lambda * lambda - p1.x - p2.x);
  const y = mod(lambda * (p1.x - x) - p1.y);
  return { x, y };
}

function scalarMultiply(scalar: bigint, point: Point): Point {
  let n = scalar;
  let result: Point = null;
  let current = point;
  while (n > 0n) {
    if (n & 1n) result = addPoints(result, current);
    current = addPoints(current, current);
    n >>= 1n;
  }
  return result;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt(`0x${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`);
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const hex = value.toString(16).padStart(length * 2, "0");
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function derivePublicCoordinates(privateKeyB64: string): { x: string; y: string } {
  const scalar = bytesToBigInt(decodeBase64Url(privateKeyB64));
  const point = scalarMultiply(scalar, { x: GX, y: GY });
  if (!point) throw new Error("invalid derived public key");
  return {
    x: encodeBase64Url(bigIntToBytes(point.x, 32)),
    y: encodeBase64Url(bigIntToBytes(point.y, 32)),
  };
}

let cachedPrivateKey: { b64: string; key: CryptoKey } | null = null;

async function importPrivateKey(privateKeyB64: string): Promise<CryptoKey> {
  if (cachedPrivateKey && cachedPrivateKey.b64 === privateKeyB64) return cachedPrivateKey.key;
  const { x, y } = derivePublicCoordinates(privateKeyB64);
  const key = await crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      d: privateKeyB64,
      x,
      y,
      ext: true,
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  cachedPrivateKey = { b64: privateKeyB64, key };
  return key;
}

export async function signServiceAuth(
  privateKeyB64: string,
  iss: string,
  aud: string,
  lxm?: string,
  sub?: string,
): Promise<string> {
  const now = nowSecs();
  const headerB64 = encodeJsonBase64Url({ alg: "ES256", typ: "JWT" });
  const payloadB64 = encodeJsonBase64Url({
    iss,
    sub: sub || iss,
    aud,
    exp: now + SERVICE_AUTH_EXPIRY_SECS,
    iat: now,
    jti: crypto.randomUUID(),
    ...(lxm ? { lxm } : {}),
  });
  const signingInput = `${headerB64}.${payloadB64}`;
  const key = await importPrivateKey(privateKeyB64);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${encodeBase64Url(signature)}`;
}

export function buildJwks(publicKeyB64: string): Record<string, unknown> {
  try {
    const bytes = decodeBase64Url(publicKeyB64);
    if (bytes.length === 65 && bytes[0] === 0x04) {
      return {
        keys: [
          {
            kty: "EC",
            crv: "P-256",
            alg: "ES256",
            use: "sig",
            kid: "etzhayyim-auth-1",
            x: encodeBase64Url(bytes.slice(1, 33)),
            y: encodeBase64Url(bytes.slice(33, 65)),
          },
        ],
      };
    }
  } catch {
    // ignore
  }
  return { keys: [] };
}
