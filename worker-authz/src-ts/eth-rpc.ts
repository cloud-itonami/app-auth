/**
 * Tiny JSON-RPC client for the etzhayyim private chain (`https://geth.etzhayyim.com`).
 *
 * Read-only paths (eth_call, eth_chainId, etc.) are public on the proxy.
 * Privileged paths (eth_sendRawTransaction, etc.) require an HMAC-SHA256
 * over the body in `X-etzhayyim-Rpc-Auth`. This module exposes both.
 *
 * Worker-side keccak256 comes from `@noble/hashes/sha3.js` (already in the
 * workspace from the SIWE link work).
 */

import { keccak_256 } from "@noble/hashes/sha3.js";

export interface EthRpcEnv {
  ETH_PRIVATE_RPC_URL?: string;
  /** Secrets-Store binding holding the HMAC key. May be absent if all
   *  callsites only use public methods. */
  SS_RPC_HMAC?: { get(): Promise<string> } | string;
  /** Service binding to `etzhayyim-geth-rpc-proxy`. When present, JSON-RPC
   *  goes Worker→Worker instead of through public HTTPS — required to
   *  avoid CF's subrequest loop guard, which silently times out same-zone
   *  Worker→Worker public fetches with HTTP 522 after ~19s. */
  GETH_RPC_PROXY?: Fetcher;
}

function bytesToHex(bytes: Uint8Array): string {
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

function hexWord(value: number | bigint): string {
  return BigInt(value).toString(16).padStart(64, "0");
}

function bytesToAbiHex(bytes: Uint8Array): string {
  const hex = bytesToHex(bytes);
  const paddedBytes = Math.ceil(bytes.length / 32) * 32;
  return hex.padEnd(paddedBytes * 2, "0");
}

async function hmacHex(key: string, body: string): Promise<string> {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, enc.encode(body));
  return bytesToHex(new Uint8Array(sig));
}

async function resolveHmacKey(env: EthRpcEnv): Promise<string> {
  const raw = env.SS_RPC_HMAC;
  if (!raw) return "";
  if (typeof raw === "string") return raw;
  try { return await raw.get(); } catch { return ""; }
}

/** keccak256 of the UTF-8 bytes of `s`, hex with `0x` prefix. */
export function keccakHex(s: string | Uint8Array): string {
  const bytes = typeof s === "string" ? new TextEncoder().encode(s) : s;
  return "0x" + bytesToHex(keccak_256(bytes));
}

/** First 4 bytes of `keccak256(signature)` — the Solidity function selector. */
export function selector(sig: string): string {
  const h = keccak_256(new TextEncoder().encode(sig));
  return "0x" + bytesToHex(h.slice(0, 4));
}

interface JsonRpcResponse<T> {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: T;
  error?: { code: number; message: string };
}

interface RpcOptions { privileged?: boolean; }

export async function rpc<T = unknown>(
  env: EthRpcEnv,
  method: string,
  params: unknown[],
  opts: RpcOptions = {},
): Promise<T> {
  const url = (env.ETH_PRIVATE_RPC_URL || "").trim();
  if (!url) throw new Error("ETH_PRIVATE_RPC_URL is not configured");
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.privileged) {
    const key = await resolveHmacKey(env);
    if (!key) throw new Error("SS_RPC_HMAC required for privileged RPC");
    headers["x-etzhayyim-rpc-auth"] = await hmacHex(key, body);
  }

  // Worker→Worker service binding when available (avoids CF subrequest loop
  // guard that silently 522s same-zone Worker→public-HTTPS calls). Falls
  // back to public fetch when no binding (e.g. from outside the etzhayyim account).
  // Build a Request first so the service binding fetch sees a proper input —
  // passing (url, init) to Fetcher.fetch trips a V8 "illegal invocation".
  const req = new Request(url, { method: "POST", headers, body });
  const resp = env.GETH_RPC_PROXY ? await env.GETH_RPC_PROXY.fetch(req) : await fetch(req);
  if (!resp.ok) {
    const text = await resp.text().catch((e: unknown) => `<unreadable: ${e instanceof Error ? e.message : String(e)}>`);
    throw new Error(`rpc ${method} HTTP ${resp.status}: ${text.slice(0, 200)}`);
  }
  const json = await resp.json<JsonRpcResponse<T>>();
  if (json.error) throw new Error(`rpc ${method} error ${json.error.code}: ${json.error.message}`);
  return json.result as T;
}

/** Standard `eth_call` (latest block, no value, no from). */
export async function ethCall(env: EthRpcEnv, to: string, data: string): Promise<string> {
  return rpc<string>(env, "eth_call", [{ to, data }, "latest"]);
}

const ERC1271_MAGIC = "0x1626ba7e";
const IS_VALID_SIGNATURE_SELECTOR = selector("isValidSignature(bytes32,bytes)");

/**
 * ERC-1271 validation for contract accounts / smart wallets.
 *
 * ABI: isValidSignature(bytes32 hash, bytes signature) returns (bytes4)
 * Returns true only when the contract returns 0x1626ba7e.
 */
export async function isValidErc1271Signature(
  env: EthRpcEnv,
  contractAddress: string,
  hash32: string,
  signatureHex: string,
): Promise<boolean> {
  if (!/^0x[0-9a-fA-F]{40}$/.test(contractAddress)) throw new Error("invalid ERC-1271 contract address");
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash32)) throw new Error("invalid ERC-1271 hash");

  try {
    const sigBytes = hexToBytes(signatureHex);
    const calldata = [
      IS_VALID_SIGNATURE_SELECTOR.slice(2),
      hash32.slice(2),
      hexWord(64),
      hexWord(sigBytes.length),
      bytesToAbiHex(sigBytes),
    ].join("");
    const raw = await ethCall(env, contractAddress.toLowerCase(), "0x" + calldata);
    const clean = raw.toLowerCase();
    return clean === ERC1271_MAGIC || clean.startsWith(ERC1271_MAGIC);
  } catch {
    return false;
  }
}

/** Decode a 32-byte ABI-encoded address (left-padded with 12 zero bytes). */
export function decodeAddress(hex: string): string {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length < 64) throw new Error("expected 32-byte ABI address word");
  return "0x" + clean.slice(-40).toLowerCase();
}

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export function isZeroAddress(addr: string): boolean {
  return addr.toLowerCase() === ZERO_ADDRESS;
}
