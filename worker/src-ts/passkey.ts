import { decodeBase64Url, encodeBase64Url } from "./base64url";

const RP_ID = "etzhayyim.com";
const RP_NAME = "etzhayyim Platform";
const RP_ORIGIN = "https://authn.etzhayyim.com";

export interface PasskeyCredential {
  'credentialId': string;
  'publicKeyB64': string;
  'signCount': number;
  'createdAt': string;
}

function nowIso(): string {
  return new Date().toISOString();
}

function generateChallenge(): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

function toArrayBufferView(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function decodeJsonBase64Url<T>(value: string): T {
  return JSON.parse(new TextDecoder().decode(decodeBase64Url(value))) as T;
}

function normalizeOrigin(origin: string): boolean {
  return origin === RP_ORIGIN || origin.endsWith(".etzhayyim.com");
}

type CborValue = number | Uint8Array | string | CborValue[] | Map<CborValue, CborValue>;

function readLength(view: Uint8Array, offset: number, addl: number): [number, number] {
  if (addl < 24) return [addl, offset];
  if (addl === 24) return [view[offset], offset + 1];
  if (addl === 25) return [(view[offset] << 8) | view[offset + 1], offset + 2];
  if (addl === 26) {
    return [
      (view[offset] * 2 ** 24) + (view[offset + 1] << 16) + (view[offset + 2] << 8) + view[offset + 3],
      offset + 4,
    ];
  }
  throw new Error("unsupported CBOR length");
}

function decodeCborItem(view: Uint8Array, start = 0): [CborValue, number] {
  const head = view[start];
  const major = head >> 5;
  const addl = head & 0x1f;
  let offset = start + 1;
  if (major === 0) {
    const [value, next] = readLength(view, offset, addl);
    return [value, next];
  }
  if (major === 1) {
    const [value, next] = readLength(view, offset, addl);
    return [-1 - value, next];
  }
  if (major === 2) {
    const [length, next] = readLength(view, offset, addl);
    return [view.slice(next, next + length), next + length];
  }
  if (major === 3) {
    const [length, next] = readLength(view, offset, addl);
    return [new TextDecoder().decode(view.slice(next, next + length)), next + length];
  }
  if (major === 4) {
    const [length, next] = readLength(view, offset, addl);
    const items: CborValue[] = [];
    offset = next;
    for (let i = 0; i < length; i += 1) {
      const [item, nextOffset] = decodeCborItem(view, offset);
      items.push(item);
      offset = nextOffset;
    }
    return [items, offset];
  }
  if (major === 5) {
    const [length, next] = readLength(view, offset, addl);
    const map = new Map<CborValue, CborValue>();
    offset = next;
    for (let i = 0; i < length; i += 1) {
      const [key, keyOffset] = decodeCborItem(view, offset);
      const [value, valueOffset] = decodeCborItem(view, keyOffset);
      map.set(key, value);
      offset = valueOffset;
    }
    return [map, offset];
  }
  throw new Error("unsupported CBOR major type");
}

function parseCbor(bytes: Uint8Array): CborValue {
  const [value] = decodeCborItem(bytes, 0);
  return value;
}

function getMapValue<T extends CborValue>(map: CborValue, key: string | number): T | null {
  if (!(map instanceof Map)) return null;
  return (map.get(key) as T | undefined) ?? null;
}

async function sha256Bytes(value: string | Uint8Array): Promise<Uint8Array> {
  const input = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", input);
  return new Uint8Array(digest);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

function base64UrlSegment(bytes: Uint8Array): string {
  return encodeBase64Url(bytes);
}

async function verifyP256Signature(publicKeyB64: string, message: Uint8Array, signatureB64: string): Promise<boolean> {
  const raw = decodeBase64Url(publicKeyB64);
  if (raw.length !== 65 || raw[0] !== 0x04) throw new Error("invalid public key encoding");
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: base64UrlSegment(raw.slice(1, 33)),
    y: base64UrlSegment(raw.slice(33, 65)),
    ext: true,
  };
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    toArrayBufferView(decodeBase64Url(signatureB64)),
    toArrayBufferView(message),
  );
}

function extractP256PublicKey(coseBytes: Uint8Array): string {
  const cose = parseCbor(coseBytes);
  const x = getMapValue<Uint8Array>(cose, -2);
  const y = getMapValue<Uint8Array>(cose, -3);
  if (!x || !y || x.length !== 32 || y.length !== 32) throw new Error("invalid COSE key");
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(x, 1);
  raw.set(y, 33);
  return encodeBase64Url(raw);
}

export function beginRegistration(userId = crypto.randomUUID(), userName = `${crypto.randomUUID().slice(0, 8)}@etzhayyim.com`): Record<string, unknown> {
  const authenticatorSelection = {
    'authenticatorAttachment': "platform",
    'residentKey': "required",
    'userVerification': "preferred", // Touch ID / Face ID 優先。unavailable 時のみ PIN/password fallback
    // Compatibility for older clients expecting snake_case.
    'authenticator_attachment': "platform",
    'resident_key': "required",
    'user_verification': "preferred",
  };
  return {
    challenge: generateChallenge(),
    rp: { id: RP_ID, name: RP_NAME },
    user: {
      id: encodeBase64Url(crypto.getRandomValues(new Uint8Array(16))),
      name: userName,
      'displayName': userName,
    },
    'pubKeyCredParams': [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
    ],
    timeout: 60000,
    'authenticatorSelection': authenticatorSelection,
    // Compatibility for older clients expecting snake_case.
    'authenticator_selection': authenticatorSelection,
    attestation: "none",
    'userId': userId,
  };
}

export function beginAuthentication(): Record<string, unknown> {
  return {
    challenge: generateChallenge(),
    'rpId': RP_ID,
    timeout: 60000,
    'userVerification': "preferred", // Touch ID / Face ID 優先
    // Compatibility for older clients expecting snake_case.
    'rp_id': RP_ID,
    'user_verification': "preferred",
  };
}

export async function verifyRegistration(challengeB64: string, clientDataJsonB64: string, attestationObjectB64: string): Promise<PasskeyCredential> {
  const clientData = decodeJsonBase64Url<Record<string, string>>(clientDataJsonB64);
  if (clientData.type !== "webauthn.create") throw new Error("wrong ceremony type");
  if (clientData.challenge !== challengeB64) throw new Error("challenge mismatch");
  if (!normalizeOrigin(clientData.origin || "")) throw new Error("origin mismatch");

  const attestation = parseCbor(decodeBase64Url(attestationObjectB64));
  const authData = getMapValue<Uint8Array>(attestation, "authData");
  if (!authData || authData.length < 55) throw new Error("missing authData");

  const rpIdHash = await sha256Bytes(RP_ID);
  if (!bytesEqual(authData.slice(0, 32), rpIdHash)) throw new Error("rpIdHash mismatch");

  // WebAuthn flags byte: bit0=UP (user present), bit2=UV (user verified), bit6=AT (attested credential)
  // UV required — beginRegistration sets 'userVerification': "required" to guarantee this flag
  const flags = authData[32];
  if ((flags & 0x01) === 0) throw new Error("user not present");
  // UV flag: preferred — warn but allow if biometric unavailable
  if ((flags & 0x04) === 0) console.warn("passkey registration: UV flag not set (biometric may be unavailable)");
  if ((flags & 0x40) === 0) throw new Error("no attested credential data");

  const signCount =
    (authData[33] << 24) |
    (authData[34] << 16) |
    (authData[35] << 8) |
    authData[36];
  const credIdLen = (authData[53] << 8) | authData[54];
  const credIdStart = 55;
  const credIdEnd = credIdStart + credIdLen;
  if (authData.length < credIdEnd) throw new Error("credential ID truncated");
  const credentialId = encodeBase64Url(authData.slice(credIdStart, credIdEnd));
  const publicKeyB64 = extractP256PublicKey(authData.slice(credIdEnd));

  return {
    'credentialId': credentialId,
    'publicKeyB64': publicKeyB64,
    'signCount': signCount >>> 0,
    'createdAt': nowIso(),
  };
}

export async function verifyAuthentication(
  challengeB64: string,
  clientDataJsonB64: string,
  authenticatorDataB64: string,
  signatureB64: string,
  storedPublicKeyB64: string,
  storedSignCount: number,
): Promise<number> {
  const clientDataBytes = decodeBase64Url(clientDataJsonB64);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes)) as Record<string, string>;
  if (clientData.type !== "webauthn.get") throw new Error("wrong ceremony type");
  if (clientData.challenge !== challengeB64) throw new Error("challenge mismatch");
  if (!normalizeOrigin(clientData.origin || "")) throw new Error("origin mismatch");

  const authData = decodeBase64Url(authenticatorDataB64);
  if (authData.length < 37) throw new Error("authenticatorData too short");
  const rpIdHash = await sha256Bytes(RP_ID);
  if (!bytesEqual(authData.slice(0, 32), rpIdHash)) throw new Error("rpIdHash mismatch");

  // WebAuthn flags byte: bit0=UP (required), bit2=UV (preferred — Touch ID/Face ID when available)
  const flags = authData[32];
  if ((flags & 0x01) === 0) throw new Error("user not present");
  if ((flags & 0x04) === 0) console.warn("passkey auth: UV flag not set (biometric may be unavailable)");

  const newSignCount =
    (authData[33] << 24) |
    (authData[34] << 16) |
    (authData[35] << 8) |
    authData[36];
  if (newSignCount !== 0 && storedSignCount !== 0 && newSignCount <= storedSignCount) {
    throw new Error("sign count replay detected");
  }

  const clientHash = await sha256Bytes(clientDataBytes);
  const signedData = new Uint8Array(authData.length + clientHash.length);
  signedData.set(authData, 0);
  signedData.set(clientHash, authData.length);

  const valid = await verifyP256Signature(storedPublicKeyB64, signedData, signatureB64);
  if (!valid) throw new Error("signature verification failed");
  return newSignCount >>> 0;
}
