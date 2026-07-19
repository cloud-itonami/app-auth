/**
 * ADR-2604261717 Phase 2-B settler — sealer-signed `escrow.settle()` driver.
 *
 * Pairs with the yabai auto-challenger (`auto-challenge.ts`) and closes the
 * back half of the loop: once a decision exists for `claimId` (recorded
 * either off-chain via human review, or on-chain via a future
 * `RegoArbiter.recordDecision` that this branch hasn't ported yet), the
 * settler signs an arbiter ECDSA over `keccak256(abi.encode(claimId,
 * claimWins, escrowAddr, chainId))` with `SEALER_PRIV` and submits
 * `ClaimStakeEscrow.settle(claimId, claimWins, sig)`.
 *
 * Why this Worker holds the arbiter key: ClaimStakeEscrow.arbiter is set
 * to the sealer EOA at deploy (see `script/DeployClaimStake.s.sol`). The
 * escrow's `settle()` does an `ECDSA.recover(...) == arbiter` check, so
 * whoever holds SEALER_PRIV can settle. Phase 3 swaps `arbiter` to a
 * dedicated multisig.
 */

import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

import { decodeAddress, ethCall, isZeroAddress, selector } from "./eth-rpc";
import type { EthRpcEnv } from "./eth-rpc";
import { signAndSendTx, waitForReceipt } from "./eth-tx";
import type { EthTxEnv } from "./eth-tx";
import { settleClaim } from "./claim-stake";

export interface RegoArbiterEnv extends EthRpcEnv, EthTxEnv {
  etzhayyim_CLAIM_STAKE_ESCROW_ADDR?: string;
  etzhayyim_REGO_ARBITER_ADDR?: string;
  ETH_PRIVATE_CHAIN_ID?: string;
}

const RECORD_DECISION_SELECTOR = selector("recordDecision(bytes32,bool,bytes32,bytes)");
const DECISION_VIEW_SELECTOR   = selector("decision(bytes32)");

function regoAddr(env: RegoArbiterEnv): string {
  const a = (env.etzhayyim_REGO_ARBITER_ADDR || "").trim();
  if (!a) throw new Error("etzhayyim_REGO_ARBITER_ADDR is not configured");
  return a;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}
function hexNoPrefix(hex: string): string { return hex.startsWith("0x") ? hex.slice(2) : hex; }
function hexToBytes(hex: string): Uint8Array {
  const clean = hexNoPrefix(hex);
  if (clean.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function uintToHex(value: bigint): string {
  if (value < 0n) throw new Error("uint must be non-negative");
  return value.toString(16).padStart(64, "0");
}
function ensureBytes32(name: string, hex: string): string {
  if (!hex.startsWith("0x") || hex.length !== 66) throw new Error(`invalid ${name}: must be 0x + 64 hex chars`);
  return hex.toLowerCase();
}

/**
 * Build the 65-byte ECDSA signature `ClaimStakeEscrow.settle()` expects from
 * its arbiter: ECDSA over `eth_sign(keccak256(abi.encode(claimId,
 * claimWins, escrowAddr, chainId)))` using the sealer key. Output format
 * matches OpenZeppelin's ECDSA.recover: r ‖ s ‖ v∈{27,28}, lowS canonical.
 */
export function signArbiterSettlement(
  env: RegoArbiterEnv,
  claimId: string,
  claimWins: boolean,
): { sig: string; signerAddress: string } {
  const sealerPriv = (env.SEALER_PRIV || "").trim();
  if (!sealerPriv) throw new Error("SEALER_PRIV is not configured");
  const escrow = (env.etzhayyim_CLAIM_STAKE_ESCROW_ADDR || "").trim();
  if (!escrow) throw new Error("etzhayyim_CLAIM_STAKE_ESCROW_ADDR is not configured");
  const chainId = Number((env.ETH_PRIVATE_CHAIN_ID || "0").trim());
  if (chainId <= 0) throw new Error("ETH_PRIVATE_CHAIN_ID is not configured");

  const id = ensureBytes32("claimId", claimId);

  // abi.encode(bytes32 claimId, bool claimWins, address escrow, uint256 chainId)
  // — 4 × 32 byte words.
  const composed =
      hexNoPrefix(id)
    + (claimWins ? "01" : "00").padStart(64, "0")
    + hexNoPrefix(escrow).toLowerCase().padStart(64, "0")
    + uintToHex(BigInt(chainId));
  const payload = hexToBytes(composed);
  const payloadHash = keccak_256(payload);

  const prefix = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");
  const prefixed = new Uint8Array(prefix.length + payloadHash.length);
  prefixed.set(prefix, 0);
  prefixed.set(payloadHash, prefix.length);
  const ethSignedHash = keccak_256(prefixed);

  const privBytes = hexToBytes(sealerPriv);
  const sig = secp256k1.sign(ethSignedHash, privBytes, { prehash: false, lowS: true });
  const compact = sig.toBytes("compact");
  const v = sig.recovery + 27;
  const out = new Uint8Array(65);
  out.set(compact, 0);
  out[64] = v;
  return {
    sig: "0x" + bytesToHex(out),
    signerAddress: "0x" + bytesToHex(keccak_256(secp256k1.getPublicKey(privBytes, false).slice(1)).slice(-20)),
  };
}

export interface AutoSettleResult {
  txHash: string;
  receiptStatus: "0x1" | "0x0" | null;
  outcome: "upheld" | "slashed";
  arbiterAddress: string;
}

/**
 * One-shot: sign the arbiter payload + submit `escrow.settle()`. Caller
 * (handleAutoSettleClaim) is expected to have already snapshotClaim'd to
 * confirm `state === 'challenged'` before calling — the contract reverts
 * with InvalidState otherwise.
 */
export async function autoSettleClaim(
  env: RegoArbiterEnv,
  claimId: string,
  claimWins: boolean,
): Promise<AutoSettleResult> {
  const { sig, signerAddress } = signArbiterSettlement(env, claimId, claimWins);
  const result = await settleClaim(env, claimId, claimWins, sig);
  return {
    txHash: result.txHash,
    receiptStatus: result.receiptStatus ?? null,
    outcome: claimWins ? "upheld" : "slashed",
    arbiterAddress: signerAddress,
  };
}

// ── Decision recording (judge → RegoArbiter on-chain trail) ────────────────

function padBytes32(hex: string): string {
  const clean = hexNoPrefix(hex);
  if (clean.length > 64) throw new Error("hex too long for 32 bytes");
  return clean.padStart(64, "0");
}

/** Sign keccak256(abi.encode(claimId, claimWins, regoAddr, chainId, evidenceCid))
 *  with sealer. Format = OZ ECDSA: r ‖ s ‖ v∈{27,28}, lowS canonical.
 *  RegoArbiter.recordDecision validates this against its `signers` set. */
export function signRegoDecision(
  env: RegoArbiterEnv,
  claimId: string,
  claimWins: boolean,
  evidenceCid: string,
): { sig: string; signerAddress: string } {
  const sealerPriv = (env.SEALER_PRIV || "").trim();
  if (!sealerPriv) throw new Error("SEALER_PRIV is not configured");
  const arbiter = regoAddr(env);
  const chainId = Number((env.ETH_PRIVATE_CHAIN_ID || "0").trim());
  if (chainId <= 0) throw new Error("ETH_PRIVATE_CHAIN_ID is not configured");

  const id = ensureBytes32("claimId", claimId);
  const evidence = ensureBytes32("evidenceCid", evidenceCid);

  const composed =
      hexNoPrefix(id)
    + (claimWins ? "01" : "00").padStart(64, "0")
    + hexNoPrefix(arbiter).toLowerCase().padStart(64, "0")
    + uintToHex(BigInt(chainId))
    + hexNoPrefix(evidence);
  const payload = hexToBytes(composed);
  const payloadHash = keccak_256(payload);

  const prefix = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");
  const prefixed = new Uint8Array(prefix.length + payloadHash.length);
  prefixed.set(prefix, 0);
  prefixed.set(payloadHash, prefix.length);
  const ethSignedHash = keccak_256(prefixed);

  const privBytes = hexToBytes(sealerPriv);
  const sig = secp256k1.sign(ethSignedHash, privBytes, { prehash: false, lowS: true });
  const compact = sig.toBytes("compact");
  const v = sig.recovery + 27;
  const out = new Uint8Array(65);
  out.set(compact, 0);
  out[64] = v;
  return {
    sig: "0x" + bytesToHex(out),
    signerAddress: "0x" + bytesToHex(keccak_256(secp256k1.getPublicKey(privBytes, false).slice(1)).slice(-20)),
  };
}

function encodeRecordDecision(claimId: string, claimWins: boolean, evidenceCid: string, sig: string): string {
  const sigBytes = hexToBytes(sig);
  if (sigBytes.length !== 65) throw new Error("sig must be 65 bytes");
  const head =
    padBytes32(claimId)
    + padBytes32(claimWins ? "0x01" : "0x00")
    + padBytes32(evidenceCid)
    + padBytes32("0x80");
  const lengthWord = uintToHex(BigInt(sigBytes.length));
  const padded = sigBytes.length % 32 === 0
    ? bytesToHex(sigBytes)
    : (bytesToHex(sigBytes) + "0".repeat((32 - (sigBytes.length % 32)) * 2));
  return RECORD_DECISION_SELECTOR + head + lengthWord + padded;
}

export type DecisionOutcome = "none" | "upheld" | "slashed";
const OUTCOME_NAMES: ReadonlyArray<DecisionOutcome> = ["none", "upheld", "slashed"];

export async function readDecision(
  env: RegoArbiterEnv,
  claimId: string,
): Promise<{ outcome: DecisionOutcome; evidenceCid: string; signer: string; recordedAt: number } | null> {
  const id = ensureBytes32("claimId", claimId);
  const calldata = DECISION_VIEW_SELECTOR + padBytes32(id);
  const raw = await ethCall(env, regoAddr(env), calldata);
  const clean = hexNoPrefix(raw);
  if (clean.length < 64 * 4) return null;
  const word = (i: number) => "0x" + clean.slice(i * 64, (i + 1) * 64);
  const outcomeIdx = Number(BigInt(word(0)));
  const outcome = OUTCOME_NAMES[outcomeIdx] ?? "none";
  if (outcome === "none") return null;
  return {
    outcome,
    evidenceCid: word(1),
    signer: "0x" + word(2).slice(-40).toLowerCase(),
    recordedAt: Number(BigInt(word(3))),
  };
}

export interface RecordDecisionResult {
  txHash: string;
  receiptStatus: "0x1" | "0x0" | null;
  signerAddress: string;
}

export async function submitRecordDecision(
  env: RegoArbiterEnv,
  claimId: string,
  claimWins: boolean,
  evidenceCid: string,
): Promise<RecordDecisionResult> {
  const { sig, signerAddress } = signRegoDecision(env, claimId, claimWins, evidenceCid);
  const data = encodeRecordDecision(claimId, claimWins, evidenceCid, sig);
  const sent = await signAndSendTx(env, { to: regoAddr(env), data, gasLimit: 250_000n });
  let receiptStatus: "0x1" | "0x0" | null = null;
  try {
    const receipt = await waitForReceipt(env, sent.txHash, { timeoutMs: 30_000 });
    if (receipt) receiptStatus = receipt.status;
  } catch { /* best-effort */ }
  return { txHash: sent.txHash, receiptStatus, signerAddress };
}

// Suppress unused warnings — decodeAddress + isZeroAddress kept for future extensions.
void decodeAddress;
void isZeroAddress;
