/**
 * SIWE (EIP-4361) message parser + secp256k1 signature recovery.
 *
 * Used by `com.etzhayyim.authz.linkEthereumBegin` / `linkEthereumVerify` to bind a
 * private-chain Ethereum address (did:pkh:eip155:<chainId>:<address>) to an
 * already-authenticated ERC725 root identity. ADR-0074 Phase 1
 * (passkey-first; Ethereum is a linked method, never a primary sign-in path).
 *
 * Crypto comes from `@noble/curves@2` (secp256k1 ECDSA recovery) +
 * `@noble/hashes@2` (keccak256 for the personal_sign prefix and address
 * derivation). Both live in the workspace-root node_modules; wrangler bundles
 * them via esbuild like the rest of the worker-authz dependencies (`hono`).
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

// ── Address utilities ────────────────────────────────────────────────────────

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

export function isValidAddress(addr: string): boolean {
  return ADDRESS_RE.test(addr);
}

/** Lowercase 0x-prefixed Ethereum address (we don't enforce EIP-55 checksum). */
export function normalizeAddress(addr: string): string {
  if (!isValidAddress(addr)) throw new Error("invalid Ethereum address");
  return addr.toLowerCase();
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("invalid hex");
    out[i] = byte;
  }
  return out;
}

/**
 * Derive an Ethereum address from an uncompressed (65-byte, 0x04-prefixed) or
 * raw 64-byte secp256k1 public key. Address = last 20 bytes of keccak256 of
 * the 64-byte X||Y coordinates (per yellow paper §4.1).
 */
function pubkeyToAddress(uncompressed65or64: Uint8Array): string {
  const xy = uncompressed65or64.length === 65
    ? uncompressed65or64.slice(1)
    : uncompressed65or64;
  if (xy.length !== 64) throw new Error("invalid pubkey length");
  const hash = keccak_256(xy);
  return "0x" + bytesToHex(hash.slice(-20));
}

// ── personal_sign hash + recovery ────────────────────────────────────────────

/**
 * Compute the hash that EIP-191 personal_sign / SIWE actually signs:
 *   keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)
 */
export function personalSignHash(message: string): Uint8Array {
  const msgBytes = new TextEncoder().encode(message);
  const prefix = `\x19Ethereum Signed Message:\n${msgBytes.length}`;
  const prefixBytes = new TextEncoder().encode(prefix);
  const buf = new Uint8Array(prefixBytes.length + msgBytes.length);
  buf.set(prefixBytes, 0);
  buf.set(msgBytes, prefixBytes.length);
  return keccak_256(buf);
}

/**
 * Recover the 0x-prefixed lowercase Ethereum address that produced a 65-byte
 * personal_sign signature over `messageHash`. Throws on malformed signature
 * or unrecoverable curve point.
 */
export function recoverEthAddress(messageHash: Uint8Array, signatureHex: string): string {
  const sigBytes = hexToBytes(signatureHex);
  if (sigBytes.length !== 65) throw new Error("signature must be 65 bytes");
  let v = sigBytes[64];
  if (v >= 27) v -= 27;            // legacy ethereum personal_sign uses {27, 28}
  if (v !== 0 && v !== 1) throw new Error("invalid recovery byte");
  // Noble v2 'recovered' format = r(32) || s(32) || recovery(1).
  const recoveredSig = new Uint8Array(65);
  recoveredSig.set(sigBytes.slice(0, 64), 0);
  recoveredSig[64] = v;
  const sig = secp256k1.Signature.fromBytes(recoveredSig, "recovered");
  const point = sig.recoverPublicKey(messageHash);
  const pubBytes = point.toBytes(false); // uncompressed: 0x04 || X(32) || Y(32)
  return pubkeyToAddress(pubBytes);
}

// ── EIP-4361 (SIWE) message build + parse ───────────────────────────────────

export interface SiweMessage {
  domain: string;
  address: string;       // lowercase 0x-prefixed
  statement?: string;
  uri: string;
  version: string;       // currently always "1"
  chainId: number;
  nonce: string;
  issuedAt: string;      // ISO 8601
  expirationTime?: string;
  resources?: string[];
}

export interface SiweBuildInput {
  domain: string;            // e.g. "authz.etzhayyim.com"
  address: string;           // lowercase 0x-prefixed
  statement?: string;
  uri: string;               // origin (https://authz.etzhayyim.com)
  chainId: number;
  nonce: string;             // hex, single-use
  issuedAt: Date;
  expirationTime: Date;
}

/**
 * Build an EIP-4361 SIWE message string, in canonical form (no trailing
 * whitespace, fields in the order required by §3 of the spec).
 */
export function buildSiweMessage(input: SiweBuildInput): string {
  const lines: string[] = [];
  lines.push(`${input.domain} wants you to sign in with your Ethereum account:`);
  lines.push(input.address);
  lines.push("");
  if (input.statement && input.statement.length > 0) {
    lines.push(input.statement);
    lines.push("");
  }
  lines.push(`URI: ${input.uri}`);
  lines.push("Version: 1");
  lines.push(`Chain ID: ${input.chainId}`);
  lines.push(`Nonce: ${input.nonce}`);
  lines.push(`Issued At: ${input.issuedAt.toISOString()}`);
  lines.push(`Expiration Time: ${input.expirationTime.toISOString()}`);
  return lines.join("\n");
}

/**
 * Parse an EIP-4361 SIWE message produced by buildSiweMessage (or any
 * compliant client). Tolerates an optional Statement block and optional
 * Resources list. Throws on missing/malformed required fields.
 */
export function parseSiweMessage(raw: string): SiweMessage {
  const lines = raw.split("\n");
  if (lines.length < 6) throw new Error("SIWE message too short");

  const headerMatch = lines[0].match(/^([^\s]+) wants you to sign in with your Ethereum account:$/);
  if (!headerMatch) throw new Error("invalid SIWE header");
  const domain = headerMatch[1];
  const address = lines[1];
  if (!isValidAddress(address)) throw new Error("invalid SIWE address line");

  // statement (optional): lines[2] is blank; if lines[3] is non-blank text and
  // lines[4] is blank, treat lines[3] as the statement. Otherwise body starts
  // at lines[2 + 1] (i.e. URI on line 3).
  let cursor = 2;
  if (lines[cursor] !== "") throw new Error("expected blank line after address");
  cursor += 1;
  let statement: string | undefined;
  if (cursor < lines.length && !lines[cursor].startsWith("URI:")) {
    statement = lines[cursor];
    cursor += 1;
    if (lines[cursor] !== "") throw new Error("expected blank line after statement");
    cursor += 1;
  }

  const fields: Record<string, string> = {};
  const resources: string[] = [];
  let inResources = false;
  for (; cursor < lines.length; cursor += 1) {
    const line = lines[cursor];
    if (line === "") continue;
    if (inResources) {
      if (line.startsWith("- ")) { resources.push(line.slice(2)); continue; }
      inResources = false;
    }
    if (line === "Resources:") { inResources = true; continue; }
    const idx = line.indexOf(": ");
    if (idx < 0) throw new Error(`unparseable SIWE line: ${line}`);
    const k = line.slice(0, idx);
    const v = line.slice(idx + 2);
    fields[k] = v;
  }

  const uri = fields["URI"];
  const version = fields["Version"];
  const chainIdStr = fields["Chain ID"];
  const nonce = fields["Nonce"];
  const issuedAt = fields["Issued At"];
  const expirationTime = fields["Expiration Time"];
  if (!uri || !version || !chainIdStr || !nonce || !issuedAt) {
    throw new Error("missing required SIWE field");
  }
  const chainId = Number(chainIdStr);
  if (!Number.isInteger(chainId) || chainId < 0) throw new Error("invalid Chain ID");

  return {
    domain,
    address: address.toLowerCase(),
    statement,
    uri,
    version,
    chainId,
    nonce,
    issuedAt,
    expirationTime,
    resources: resources.length > 0 ? resources : undefined,
  };
}

// ERC-1271 intermediate form only — NOT persisted to DB or returned in API responses (ADR-0095 §D1).
// Store wallet addresses as `wallet_address: "0x..."` instead.
export function didPkhFromAddress(chainId: number, address: string): string {
  return `did:pkh:eip155:${chainId}:${normalizeAddress(address)}`;
}

// ── Random nonce ─────────────────────────────────────────────────────────────

/** 16-byte random nonce, hex-encoded (32 chars). Single-use, server-issued. */
export function generateSiweNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return bytesToHex(bytes);
}
