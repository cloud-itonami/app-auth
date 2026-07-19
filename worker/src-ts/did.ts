import { encodeBase64Url } from "./base64url";
import { fnv1a32 } from "./security";

export type PerformerType = "service" | "system" | "person" | "organization";

export interface DIDDocument {
  did: string;
  controller: string;
  'publicKeyMultibase': string;
  'performerType': PerformerType;
  'createdAt': string;
  'updatedAt': string;
}

const MULTICODEC_P256_PREFIX = new Uint8Array([0x80, 0x24]);
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function nowIso(): string {
  return new Date().toISOString();
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      carry += digits[i] * 256;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let out = "";
  for (const byte of bytes) {
    if (byte !== 0) break;
    out += BASE58_ALPHABET[0];
  }
  for (let i = digits.length - 1; i >= 0; i -= 1) out += BASE58_ALPHABET[digits[i]];
  return out;
}

function pubkeyToMultibase(compressed: Uint8Array): string {
  return `z${base58Encode(concatBytes(MULTICODEC_P256_PREFIX, compressed))}`;
}

/**
 * ADR-0023 P4: Encode an uncompressed P-256 public key (65 bytes, 0x04 || x || y,
 * base64url) as multibase for publication in did:web did.json. Caller provides
 * the raw uncompressed key bytes as base64url (same format as SS_AUTH_PUBLIC_KEY_B64).
 */
export function uncompressedPubkeyB64UrlToMultibase(b64url: string): string {
  const pad = b64url.length % 4 === 0 ? "" : "=".repeat(4 - (b64url.length % 4));
  const bin = atob(b64url.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  if (bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new Error("uncompressedPubkeyB64UrlToMultibase: expected 65-byte uncompressed P-256 key (0x04 || x || y)");
  }
  return pubkeyToMultibase(compressPoint(bytes.slice(1, 33), bytes.slice(33, 65)));
}

function bigintToUint8Array(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let current = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(current & 0xffn);
    current >>= 8n;
  }
  return out;
}

function compressPoint(x: Uint8Array, y: Uint8Array): Uint8Array {
  const prefix = (y[y.length - 1] & 1) === 0 ? 0x02 : 0x03;
  const out = new Uint8Array(33);
  out[0] = prefix;
  out.set(x, 1);
  return out;
}

async function generateP256Key(): Promise<{ privateKeyB64url: string; publicKeyMultibase: string; publicKeyRaw: Uint8Array }> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  if (!privateJwk.d || !publicJwk.x || !publicJwk.y) {
    throw new Error("failed to export P-256 key");
  }
  const x = Uint8Array.from(atob(publicJwk.x.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - publicJwk.x.length % 4) % 4)), (c) => c.charCodeAt(0));
  const y = Uint8Array.from(atob(publicJwk.y.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - publicJwk.y.length % 4) % 4)), (c) => c.charCodeAt(0));
  const compressed = compressPoint(x, y);
  return {
    privateKeyB64url: privateJwk.d,
    publicKeyMultibase: pubkeyToMultibase(compressed),
    publicKeyRaw: compressed,
  };
}

export async function createDid(path: string, performerType: PerformerType): Promise<{ 'privateKeyB64url': string; 'didDocument': DIDDocument }> {
  const key = await generateP256Key();
  const now = nowIso();
  return {
    'privateKeyB64url': key.privateKeyB64url,
    'didDocument': {
      did: `did:web:authn.etzhayyim.com:${path}`,
      controller: "did:web:authn.etzhayyim.com",
      'publicKeyMultibase': key.publicKeyMultibase,
      'performerType': performerType,
      'createdAt': now,
      'updatedAt': now,
    },
  };
}

/** Generate a did:etzhayyim:{hash} DID. Hash = first 24 chars of hex(SHA-256(compressed public key)). */
export async function createetzhayyimDid(performerType: PerformerType): Promise<{ privateKeyB64url: string; did: string; publicKeyMultibase: string }> {
  const key = await generateP256Key();
  const hashBuf = await crypto.subtle.digest("SHA-256", key.publicKeyRaw);
  const hashHex = Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  const did = `did:etzhayyim:${hashHex.slice(0, 24)}`;
  return { privateKeyB64url: key.privateKeyB64url, did, publicKeyMultibase: key.publicKeyMultibase };
}

export function userDidPath(): string {
  const alpha = "abcdefghijklmnopqrstuvwxyz";
  const alphanum = "abcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let id = alpha[bytes[0] % alpha.length];
  for (let i = 1; i < bytes.length; i += 1) id += alphanum[bytes[i] % alphanum.length];
  return `user:${id}`;
}

export function defaultHumanSubActorPath(accountPath: string): string {
  return `${accountPath}:person:default`;
}

export function agentDidPath(appNanoid: string, subPath?: string | null): string {
  return subPath ? `${appNanoid}:${subPath}` : appNanoid;
}

export function didToUrl(did: string): string | null {
  if (!did.startsWith("did:web:")) return null;
  const stripped = did.slice("did:web:".length);
  const parts = stripped.split(":");
  if (parts.length === 1) return `https://${parts[0]}/.well-known/did.json`;
  return `https://${parts[0]}/${parts.slice(1).join("/")}/did.json`;
}

export function ownerHash(did: string): number {
  return fnv1a32(did);
}

export function toDidDocumentJsonld(doc: DIDDocument): Record<string, unknown> {
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1",
    ],
    id: doc.did,
    controller: doc.controller,
    verificationMethod: [
      {
        id: `${doc.did}#key-1`,
        type: "Multikey",
        controller: doc.controller,
        publicKeyMultibase: doc.publicKeyMultibase,
      },
    ],
    authentication: [`${doc.did}#key-1`],
    assertionMethod: [`${doc.did}#key-1`],
  };
}

/* ────────────────────────────────────────────────────────────────────────
 * ADR-0029 — did:etzhayyim recursive hash/Merkle form
 *
 * Child DID = did:etzhayyim:{h0}:{h1}:…:{hN}
 * hN = SHA-256(utf8(parent_did) || 0x1F || materialBytes)[:24]
 *
 * `material_hash_proof` stored in RisingWave is hex(materialBytes) so any
 * resolver can recompute hN and verify the chain without the signing key.
 * ──────────────────────────────────────────────────────────────────────── */

export type MaterialKind = "root" | "pubkey" | "role" | "matter" | "doc" | "grant" | "session";

const CHILD_HASH_HEX_LEN = 24;
const MERKLE_SEPARATOR = new Uint8Array([0x1f]);
const MAX_DID_DEPTH = 6;

export interface ChildDidInput {
  parentDid: string;
  kind: Exclude<MaterialKind, "root">;
  roleName?: string;
  holderDid?: string;
  matterTid?: string;
  docCid?: string;
  granteeDid?: string;
  grantExpiresAt?: string;
  grantNonceHex?: string;
  parentSessionJti?: string;
  sessionNonceHex?: string;
}

export interface ChildDidResult {
  did: string;
  parentDid: string;
  materialKind: Exclude<MaterialKind, "root">;
  materialHashProof: string;
  privateKeyB64url?: string;
  publicKeyMultibase?: string;
}

function hexEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function hexDecode(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex input");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("invalid hex");
    out[i] = byte;
  }
  return out;
}

export function didDepth(did: string): number {
  if (!did.startsWith("did:etzhayyim:")) throw new Error("not a did:etzhayyim");
  const tail = did.slice("did:etzhayyim:".length);
  return tail.split(":").length;
}

export function didParent(did: string): string | null {
  const depth = didDepth(did);
  if (depth <= 1) return null;
  const idx = did.lastIndexOf(":");
  return did.slice(0, idx);
}

export function didParsesAsetzhayyim(did: string): boolean {
  return /^did:etzhayyim:[0-9a-f]{24}(:[0-9a-f]{24}){0,5}$/.test(did);
}

export async function computeChildHashHex(parentDid: string, materialBytes: Uint8Array): Promise<string> {
  const parentBytes = new TextEncoder().encode(parentDid);
  const buf = new Uint8Array(parentBytes.length + MERKLE_SEPARATOR.length + materialBytes.length);
  buf.set(parentBytes, 0);
  buf.set(MERKLE_SEPARATOR, parentBytes.length);
  buf.set(materialBytes, parentBytes.length + MERKLE_SEPARATOR.length);
  const hashBuf = await crypto.subtle.digest("SHA-256", buf);
  return hexEncode(new Uint8Array(hashBuf)).slice(0, CHILD_HASH_HEX_LEN);
}

export function encodeMaterialBytes(input: ChildDidInput, pubkeyCompressed?: Uint8Array): Uint8Array {
  switch (input.kind) {
    case "pubkey": {
      if (!pubkeyCompressed || pubkeyCompressed.length !== 33) {
        throw new Error("pubkey kind requires a 33-byte compressed P-256 key");
      }
      return pubkeyCompressed;
    }
    case "role": {
      if (!input.roleName || !input.holderDid) throw new Error("role kind requires roleName and holderDid");
      return new TextEncoder().encode(`role:${input.roleName}:${input.holderDid}`);
    }
    case "matter": {
      if (!input.matterTid) throw new Error("matter kind requires matterTid");
      return new TextEncoder().encode(`matter:${input.matterTid}`);
    }
    case "doc": {
      if (!input.docCid) throw new Error("doc kind requires docCid");
      return new TextEncoder().encode(`doc:${input.docCid}`);
    }
    case "grant": {
      if (!input.granteeDid || !input.grantExpiresAt || !input.grantNonceHex) {
        throw new Error("grant kind requires granteeDid, grantExpiresAt, grantNonceHex");
      }
      return new TextEncoder().encode(`grant:${input.granteeDid}:${input.grantExpiresAt}:${input.grantNonceHex}`);
    }
    case "session": {
      if (!input.parentSessionJti || !input.sessionNonceHex) {
        throw new Error("session kind requires parentSessionJti, sessionNonceHex");
      }
      return new TextEncoder().encode(`session:${input.parentSessionJti}:${input.sessionNonceHex}`);
    }
  }
}

export async function createetzhayyimChildDid(input: ChildDidInput): Promise<ChildDidResult> {
  if (!didParsesAsetzhayyim(input.parentDid)) throw new Error("parentDid must be a valid did:etzhayyim");
  if (didDepth(input.parentDid) >= MAX_DID_DEPTH) {
    throw new Error(`recursion exceeds MAX_DID_DEPTH (${MAX_DID_DEPTH})`);
  }

  let materialBytes: Uint8Array;
  let privateKeyB64url: string | undefined;
  let publicKeyMultibase: string | undefined;

  if (input.kind === "pubkey") {
    const key = await generateP256Key();
    privateKeyB64url = key.privateKeyB64url;
    publicKeyMultibase = key.publicKeyMultibase;
    materialBytes = encodeMaterialBytes(input, key.publicKeyRaw);
  } else {
    materialBytes = encodeMaterialBytes(input);
  }

  const childHashHex = await computeChildHashHex(input.parentDid, materialBytes);
  const did = `${input.parentDid}:${childHashHex}`;
  return {
    did,
    parentDid: input.parentDid,
    materialKind: input.kind,
    materialHashProof: hexEncode(materialBytes),
    privateKeyB64url,
    publicKeyMultibase,
  };
}

export async function verifyDidChain(childDid: string, parentDid: string, materialHashProofHex: string): Promise<boolean> {
  if (!childDid.startsWith(`${parentDid}:`)) return false;
  const childHash = childDid.slice(parentDid.length + 1);
  if (!/^[0-9a-f]{24}$/.test(childHash)) return false;
  let materialBytes: Uint8Array;
  try {
    materialBytes = hexDecode(materialHashProofHex);
  } catch {
    return false;
  }
  const computed = await computeChildHashHex(parentDid, materialBytes);
  return computed === childHash;
}

/* ────────────────────────────────────────────────────────────────────────
 * ADR-0029 (revised 2026-04-19) — did:etzhayyim recursive semantic path form
 *
 * Child DID = did:etzhayyim:{s0}:{s1}:…:{sN}   where each sN is a semantic segment
 * (sub / id / lexicon / role / pubkey / grant). Collision prevention is via
 * vertex_etzhayyim_identity UNIQUE (parent_did, segment_kind, segment_value).
 *
 * Coexists with the hex form above (Phase 1 grandfather). New mints use this
 * API; existing hex mints continue to work through the legacy helpers.
 * ──────────────────────────────────────────────────────────────────────── */

export type SegmentKind = "root" | "sub" | "id" | "lexicon" | "role" | "pubkey" | "grant";

const SEGMENT_REGEX = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*$/;
const DID_etzhayyim_SEMANTIC_REGEX = /^did:etzhayyim:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*(:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*){0,5}$/;

export interface SemanticChildDidInput {
  parentDid: string;
  segmentKind: Exclude<SegmentKind, "root">;
  segmentValue: string;
}

export interface SemanticChildDidResult {
  did: string;
  parentDid: string;
  segmentKind: Exclude<SegmentKind, "root">;
  segmentValue: string;
  privateKeyB64url?: string;
  publicKeyMultibase?: string;
}

/** True iff `did` is a valid did:etzhayyim in either legacy hex or semantic form. */
export function didParsesAsetzhayyimAny(did: string): boolean {
  return didParsesAsetzhayyim(did) || DID_etzhayyim_SEMANTIC_REGEX.test(did);
}

/** Validate a single semantic segment value (NSID-compatible, DNS-label length). */
export function isValidetzhayyimSegmentValue(segmentValue: string): boolean {
  if (segmentValue.length === 0 || segmentValue.length > 63) return false;
  return SEGMENT_REGEX.test(segmentValue);
}

/**
 * Mint a semantic child DID. For `segmentKind === "pubkey"` a fresh P-256
 * keypair is generated and returned; other kinds are keyless (signing falls
 * through to the nearest ancestor key, ADR-0029 Key Custody).
 */
export async function createetzhayyimChildDidSemantic(input: SemanticChildDidInput): Promise<SemanticChildDidResult> {
  if (!didParsesAsetzhayyimAny(input.parentDid)) {
    throw new Error("parentDid must be a valid did:etzhayyim (legacy hex or semantic form)");
  }
  if (didDepth(input.parentDid) >= MAX_DID_DEPTH) {
    throw new Error(`recursion exceeds MAX_DID_DEPTH (${MAX_DID_DEPTH})`);
  }
  if (!isValidetzhayyimSegmentValue(input.segmentValue)) {
    throw new Error(`invalid segmentValue (regex: ${SEGMENT_REGEX}): ${input.segmentValue}`);
  }

  let privateKeyB64url: string | undefined;
  let publicKeyMultibase: string | undefined;
  if (input.segmentKind === "pubkey") {
    const key = await generateP256Key();
    privateKeyB64url = key.privateKeyB64url;
    publicKeyMultibase = key.publicKeyMultibase;
  }

  const did = `${input.parentDid}:${input.segmentValue}`;
  return {
    did,
    parentDid: input.parentDid,
    segmentKind: input.segmentKind,
    segmentValue: input.segmentValue,
    privateKeyB64url,
    publicKeyMultibase,
  };
}
