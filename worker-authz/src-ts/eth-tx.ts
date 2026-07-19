/**
 * Sealer-sponsored EIP-155 legacy transaction builder for the etzhayyim
 * private chain (chainId 260425). Used by `com.etzhayyim.authz.activateActorAccount`
 * to call `etzhayyimActorRegistry.activate(...)` on behalf of the user without
 * forcing them to hold gas.
 *
 * Crypto comes from `@noble/curves@2` (secp256k1 sign + recovery) and
 * `@noble/hashes@2` (keccak256). RLP encoding is implemented inline — the
 * legacy tx shape is small enough that a focused encoder beats vendoring
 * a library.
 *
 * Security note (ADR-0074 Phase 2-A.5): the SEALER_PRIV secret bound to
 * this Worker is the *single* authority on chain 260425. Any code path
 * that can call `signAndSendTx` here can therefore mint GCC, transfer
 * contract ownership, or freeze the chain. Phase 3 swaps this for a
 * dedicated activator key with a registry-side allow-list — keep call
 * sites narrow until then.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { rpc } from "./eth-rpc";
import type { EthRpcEnv } from "./eth-rpc";

export interface EthTxEnv extends EthRpcEnv {
  ETH_PRIVATE_CHAIN_ID?: string;
  /** 0x-prefixed 32-byte hex private key for the chain sealer (also the
   *  gas sponsor for sealer-funded txs). Must NOT appear in any response
   *  body or log line. */
  SEALER_PRIV?: string;
}

// ── byte / hex helpers ──────────────────────────────────────────────────────

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
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bigintToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(0);
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) hex = "0" + hex;
  return hexToBytes(hex);
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

// ── RLP encoding (just enough for legacy tx) ────────────────────────────────
// RFC: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/

function rlpLength(len: number, offset: number): Uint8Array {
  if (len < 56) return new Uint8Array([offset + len]);
  const lenBytes = bigintToBytes(BigInt(len));
  return concat(new Uint8Array([offset + 55 + lenBytes.length]), lenBytes);
}

function rlpEncodeBytes(input: Uint8Array): Uint8Array {
  if (input.length === 1 && input[0] < 0x80) return input;
  return concat(rlpLength(input.length, 0x80), input);
}

function rlpEncodeList(items: Uint8Array[]): Uint8Array {
  const body = concat(...items);
  return concat(rlpLength(body.length, 0xc0), body);
}

// ── secp256k1 keypair → address ─────────────────────────────────────────────

function privToAddress(priv: Uint8Array): string {
  const pub = secp256k1.getPublicKey(priv, false); // 0x04 || X || Y
  const xy = pub.slice(1);
  const hash = keccak_256(xy);
  return "0x" + bytesToHex(hash.slice(-20));
}

// ── Legacy EIP-155 transaction signing ──────────────────────────────────────

export interface LegacyTxRequest {
  /** 0x-prefixed contract address */
  to: string;
  /** 0x-prefixed calldata */
  data: string;
  /** wei, default 0 */
  value?: bigint;
  /** legacy gasPrice in wei. Chain 260425 has 1 gwei min so 1.5 gwei is safe. */
  gasPrice?: bigint;
  gasLimit?: bigint;
}

const DEFAULT_GAS_PRICE = 1_500_000_000n; // 1.5 gwei
const DEFAULT_GAS_LIMIT = 600_000n;       // generous for activate() + factory.createAccount()

/**
 * Build, EIP-155-sign, and broadcast a legacy transaction from the sealer
 * key. Returns the transaction hash from `eth_sendRawTransaction`.
 *
 * Notes on the EIP-155 v calculation:
 *   v = recovery + 35 + 2 * chainId
 * which for chainId 260425 gives v = recovery + 520885.
 */
export async function signAndSendTx(env: EthTxEnv, req: LegacyTxRequest): Promise<{ txHash: string; sealerAddress: string; nonce: bigint }>{
  const sealerPriv = (env.SEALER_PRIV || "").trim();
  if (!sealerPriv) throw new Error("SEALER_PRIV is not configured");
  const chainIdStr = (env.ETH_PRIVATE_CHAIN_ID || "").trim();
  if (!chainIdStr) throw new Error("ETH_PRIVATE_CHAIN_ID is not configured");
  const chainId = BigInt(chainIdStr);

  const priv = hexToBytes(sealerPriv);
  if (priv.length !== 32) throw new Error("SEALER_PRIV must be 32 bytes (0x + 64 hex chars)");
  const sealerAddress = privToAddress(priv);

  // Pull current nonce (latest, not pending — single sealer means no in-flight contention).
  const nonceHex = await rpc<string>(env, "eth_getTransactionCount", [sealerAddress, "latest"]);
  const nonce = BigInt(nonceHex);

  const gasPrice = req.gasPrice ?? DEFAULT_GAS_PRICE;
  const gasLimit = req.gasLimit ?? DEFAULT_GAS_LIMIT;
  const value = req.value ?? 0n;
  const toBytes = hexToBytes(req.to);
  const dataBytes = req.data ? hexToBytes(req.data) : new Uint8Array(0);

  // Pre-sign payload (EIP-155): RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
  const presignFields: Uint8Array[] = [
    rlpEncodeBytes(bigintToBytes(nonce)),
    rlpEncodeBytes(bigintToBytes(gasPrice)),
    rlpEncodeBytes(bigintToBytes(gasLimit)),
    rlpEncodeBytes(toBytes),
    rlpEncodeBytes(bigintToBytes(value)),
    rlpEncodeBytes(dataBytes),
    rlpEncodeBytes(bigintToBytes(chainId)),
    rlpEncodeBytes(new Uint8Array(0)),
    rlpEncodeBytes(new Uint8Array(0)),
  ];
  const presignRlp = rlpEncodeList(presignFields);
  const sigHash = keccak_256(presignRlp);

  // secp256k1 sign with recovery byte. lowS=true (canonical, EIP-2 compliant).
  const sig = secp256k1.sign(sigHash, priv, { prehash: false, lowS: true });
  // Noble v2 signed bytes layout in 'recovered' format = r(32) || s(32) || recovery(1)
  const recoveredBytes = sig.toBytes("recovered");
  const r = recoveredBytes.slice(0, 32);
  const s = recoveredBytes.slice(32, 64);
  const recovery = recoveredBytes[64]; // 0 or 1
  const v = recovery + 35 + Number(chainId * 2n);

  // Final RLP includes the signature instead of (chainId, 0, 0).
  const finalFields: Uint8Array[] = [
    rlpEncodeBytes(bigintToBytes(nonce)),
    rlpEncodeBytes(bigintToBytes(gasPrice)),
    rlpEncodeBytes(bigintToBytes(gasLimit)),
    rlpEncodeBytes(toBytes),
    rlpEncodeBytes(bigintToBytes(value)),
    rlpEncodeBytes(dataBytes),
    rlpEncodeBytes(bigintToBytes(BigInt(v))),
    rlpEncodeBytes(r[0] === 0 ? r.slice(1) : r), // RLP wants minimal-length integers
    rlpEncodeBytes(s[0] === 0 ? s.slice(1) : s),
  ];
  const rawTx = "0x" + bytesToHex(rlpEncodeList(finalFields));

  const txHash = await rpc<string>(env, "eth_sendRawTransaction", [rawTx]);
  return { txHash, sealerAddress, nonce };
}

/**
 * Wait for a tx receipt by polling `eth_getTransactionReceipt`. Returns
 * null if the receipt doesn't appear within the timeout (typical use is
 * to fall back to "pending — check getActorAccount in a few seconds").
 */
export async function waitForReceipt(
  env: EthRpcEnv,
  txHash: string,
  opts: { timeoutMs?: number; pollMs?: number } = {},
): Promise<{ status: "0x1" | "0x0"; blockNumber: string } | null> {
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const pollMs = opts.pollMs ?? 1_500;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const r = await rpc<{ status: "0x1" | "0x0"; blockNumber: string } | null>(env, "eth_getTransactionReceipt", [txHash]);
    if (r) return r;
    await new Promise((res) => setTimeout(res, pollMs));
  }
  return null;
}

// ── Solidity ABI encoding for activate(bytes32, bytes[]) ───────────────────

import { selector } from "./eth-rpc";

const ACTIVATE_SELECTOR = selector("activate(bytes32,bytes[])");

/**
 * Encode the calldata for `etzhayyimActorRegistry.activate(bytes32 didHash,
 * bytes[] owners)` with a single 64-byte owner (packed P-256 pubkey
 * X||Y, the format `MultiOwnable.addOwnerPublicKey` consumes inside the
 * Coinbase Smart Wallet).
 */
export function encodeActivateCalldata(didHash: string, owner64: Uint8Array): string {
  if (!didHash.startsWith("0x") || didHash.length !== 66) throw new Error("invalid didHash");
  if (owner64.length !== 64) throw new Error("owner must be 64 bytes (P-256 X||Y)");
  // bytes32 didHash:                                    32 bytes
  // bytes[] outer offset (constant 0x40 = 64):          32 bytes
  // bytes[] length (1 element):                          32 bytes
  // owner offset (constant 0x20 = 32):                   32 bytes
  // owner length (64):                                   32 bytes
  // owner data (64):                                     64 bytes
  const parts = [
    didHash.slice(2),                                                       // bytes32 didHash
    "0000000000000000000000000000000000000000000000000000000000000040",     // outer offset = 64
    "0000000000000000000000000000000000000000000000000000000000000001",     // outer length = 1
    "0000000000000000000000000000000000000000000000000000000000000020",     // element offset = 32
    "0000000000000000000000000000000000000000000000000000000000000040",     // element length = 64
    bytesToHex(owner64),                                                    // 64 bytes data (already 32-byte aligned)
  ];
  return ACTIVATE_SELECTOR + parts.join("");
}
