/**
 * ADR-2604261717 Phase 1 — claim-level stake handler module.
 *
 * Builds + signs + sends sealer-funded transactions to ClaimStakeEscrow on
 * the etzhayyim private chain, and reflects the on-chain Claim/Challenge structs
 * back to callers. Caller authentication / approval / graph projection live
 * in `index.ts` route handlers and a separate Phase 1.5 graph consumer
 * respectively (this module is wire-format only).
 *
 * Calldata is hand-encoded against the 0.8.23 ABI rather than pulling in a
 * full ethers/viem dependency — every selector lives next to its encoder so
 * the layout stays auditable.
 */

import { keccak_256 } from "@noble/hashes/sha3.js";

import { decodeAddress, ethCall, keccakHex, selector } from "./eth-rpc";
import type { EthRpcEnv } from "./eth-rpc";
import { signAndSendTx, waitForReceipt } from "./eth-tx";
import type { EthTxEnv } from "./eth-tx";

// ── Env shape ───────────────────────────────────────────────────────────────

export interface ClaimStakeEnv extends EthRpcEnv, EthTxEnv {
  etzhayyim_CLAIM_STAKE_ESCROW_ADDR?: string;
  ETH_PRIVATE_CHAIN_ID?: string;
}

function escrowAddr(env: ClaimStakeEnv): string {
  const addr = (env.etzhayyim_CLAIM_STAKE_ESCROW_ADDR || "").trim();
  if (!addr) throw new Error("etzhayyim_CLAIM_STAKE_ESCROW_ADDR is not configured");
  return addr;
}

function chainIdNum(env: ClaimStakeEnv): number {
  return Number((env.ETH_PRIVATE_CHAIN_ID || "0").trim()) || 0;
}

// ── byte / hex helpers (mirror eth-tx, kept private here for clarity) ───────

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

function hexNoPrefix(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2) : hex;
}

function padBytes32(hex: string): string {
  const clean = hexNoPrefix(hex);
  if (clean.length > 64) throw new Error("bytes32 hex too long");
  return clean.padStart(64, "0");
}

function uintToHex(value: bigint): string {
  if (value < 0n) throw new Error("uint must be non-negative");
  return value.toString(16).padStart(64, "0");
}

function uintToBigInt(value: string | bigint | number): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(value);
  const trimmed = value.trim();
  if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) return BigInt(trimmed);
  return BigInt(trimmed);
}

function hexToBigInt(hex: string): bigint {
  const clean = hexNoPrefix(hex);
  if (!clean) return 0n;
  return BigInt("0x" + clean);
}

function ensureBytes32(name: string, hex: string): string {
  if (!hex.startsWith("0x") || hex.length !== 66) throw new Error(`invalid ${name}: must be 0x + 64 hex chars`);
  return hex.toLowerCase();
}

// ── claimId derivation ──────────────────────────────────────────────────────

/**
 * `claimId = keccak256(claimHash || didHash || nonce32)` — matches the
 * shape recommended in ADR-2604261717 §2 and used as the contract mapping
 * key. `nonce` keeps repeated identical claim text from colliding for the
 * same author.
 */
export function deriveClaimId(claimHash: string, didHash: string, nonce: bigint): string {
  const a = ensureBytes32("claimHash", claimHash);
  const b = ensureBytes32("didHash", didHash);
  const composed = hexNoPrefix(a) + hexNoPrefix(b) + uintToHex(nonce);
  return keccakHex(hexToBytes(composed));
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hexNoPrefix(hex);
  if (clean.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ── Selectors ───────────────────────────────────────────────────────────────

const POST_CLAIM_SELECTOR        = selector("postClaim(bytes32,bytes32,bytes32,uint256,uint64)");
const CHALLENGE_SELECTOR         = selector("challenge(bytes32,bytes32,uint256)");
const CLAIM_UNCHALLENGED_SEL     = selector("claimUnchallenged(bytes32)");
const SETTLE_SELECTOR            = selector("settle(bytes32,bool,bytes)");
const CLAIMS_VIEW_SELECTOR       = selector("claims(bytes32)");
const CHALLENGES_VIEW_SELECTOR   = selector("challenges(bytes32)");

// ── Calldata encoders ───────────────────────────────────────────────────────

export function encodePostClaim(claimId: string, didHash: string, atRecordCid: string, bond: bigint, challengePeriodSec: bigint): string {
  return POST_CLAIM_SELECTOR
    + padBytes32(claimId)
    + padBytes32(didHash)
    + padBytes32(atRecordCid)
    + uintToHex(bond)
    + uintToHex(challengePeriodSec);
}

export function encodeChallenge(claimId: string, challengerDidHash: string, counterBond: bigint): string {
  return CHALLENGE_SELECTOR
    + padBytes32(claimId)
    + padBytes32(challengerDidHash)
    + uintToHex(counterBond);
}

export function encodeClaimUnchallenged(claimId: string): string {
  return CLAIM_UNCHALLENGED_SEL + padBytes32(claimId);
}

/** `settle(bytes32 claimId, bool claimWins, bytes arbiterSig)` */
export function encodeSettle(claimId: string, claimWins: boolean, arbiterSig: string): string {
  const sigBytes = hexToBytes(arbiterSig);
  if (sigBytes.length !== 65) throw new Error("arbiterSig must be 65 bytes (r || s || v)");

  const head =
    padBytes32(claimId)
    + padBytes32(claimWins ? "0x01" : "0x00")
    + padBytes32("0x60");                     // offset to bytes payload = 3 * 32 bytes
  const lengthWord = uintToHex(BigInt(sigBytes.length));
  // Right-pad the 65-byte signature to a 32-byte multiple (96 bytes = 3 words).
  const padded = sigBytes.length % 32 === 0
    ? bytesToHex(sigBytes)
    : (bytesToHex(sigBytes) + "0".repeat((32 - (sigBytes.length % 32)) * 2));
  return SETTLE_SELECTOR + head + lengthWord + padded;
}

// ── Read-side decoders ──────────────────────────────────────────────────────

export type ClaimState = "none" | "pending" | "challenged" | "upheld" | "slashed" | "refunded";

const CLAIM_STATE_NAMES: ReadonlyArray<ClaimState> = ["none", "pending", "challenged", "upheld", "slashed", "refunded"];

export interface ClaimStruct {
  claimId: string;
  didHash: string;
  atRecordCid: string;
  bond: string;
  postedAt: number;
  challengePeriodSec: number;
  claimant: string;
  state: ClaimState;
}

export interface ChallengeStruct {
  challengerDidHash: string;
  counterBond: string;
  postedAt: number;
  challenger: string;
}

/**
 * Decode the ABI-encoded `Claim` struct returned by `ClaimStakeEscrow.claims(bytes32)`.
 *
 * Layout (8 32-byte words):
 *   0  claimId         (bytes32)
 *   1  didHash         (bytes32)
 *   2  atRecordCid     (bytes32)
 *   3  bond            (uint256)
 *   4  postedAt        (uint64, padded)
 *   5  challengePeriod (uint64, padded)
 *   6  claimant        (address, padded)
 *   7  state           (uint8 enum, padded)
 *
 * The enum layout above matches the Solidity source field order. Solidity
 * packs `uint64`/`uint64`/`address`/`uint8` into one storage slot but the
 * ABI return struct does NOT pack — each field is its own 32-byte word.
 */
export function decodeClaim(hex: string): ClaimStruct {
  const clean = hexNoPrefix(hex);
  if (clean.length < 64 * 8) throw new Error("claims() returndata too short");
  const word = (i: number) => "0x" + clean.slice(i * 64, (i + 1) * 64);
  const stateOrd = Number(hexToBigInt(word(7)));
  const state = CLAIM_STATE_NAMES[stateOrd] ?? "none";
  return {
    claimId:     word(0),
    didHash:     word(1),
    atRecordCid: word(2),
    bond:        hexToBigInt(word(3)).toString(),
    postedAt:    Number(hexToBigInt(word(4))),
    challengePeriodSec: Number(hexToBigInt(word(5))),
    claimant:    decodeAddress(word(6)),
    state,
  };
}

/**
 * Decode the ABI-encoded `Challenge` struct returned by `challenges(bytes32)`.
 *
 * Layout (4 32-byte words): challengerDidHash, counterBond, postedAt, challenger.
 */
export function decodeChallenge(hex: string): ChallengeStruct {
  const clean = hexNoPrefix(hex);
  if (clean.length < 64 * 4) throw new Error("challenges() returndata too short");
  const word = (i: number) => "0x" + clean.slice(i * 64, (i + 1) * 64);
  return {
    challengerDidHash: word(0),
    counterBond:       hexToBigInt(word(1)).toString(),
    postedAt:          Number(hexToBigInt(word(2))),
    challenger:        decodeAddress(word(3)),
  };
}

// ── High-level orchestration ────────────────────────────────────────────────

export interface PostClaimRequest {
  claimId: string;
  didHash: string;
  atRecordCid: string;
  bond: bigint;
  challengePeriodSec: bigint;
}

export interface SubmitResult {
  txHash: string;
  receiptStatus: "0x1" | "0x0" | null;
}

async function submit(env: ClaimStakeEnv, calldata: string): Promise<SubmitResult> {
  const { txHash } = await signAndSendTx(env, { to: escrowAddr(env), data: calldata });
  const receipt = await waitForReceipt(env, txHash, { timeoutMs: 12_000, pollMs: 1_500 });
  if (receipt && receipt.status === "0x0") {
    const err = new Error(`tx reverted (txHash=${txHash} block=${receipt.blockNumber})`);
    (err as Error & { code?: string }).code = "TxRevert";
    throw err;
  }
  return { txHash, receiptStatus: receipt?.status ?? null };
}

export async function postClaim(env: ClaimStakeEnv, req: PostClaimRequest): Promise<SubmitResult> {
  return submit(env, encodePostClaim(req.claimId, req.didHash, req.atRecordCid, req.bond, req.challengePeriodSec));
}

export async function challengeClaim(env: ClaimStakeEnv, claimId: string, challengerDidHash: string, counterBond: bigint): Promise<SubmitResult> {
  return submit(env, encodeChallenge(claimId, challengerDidHash, counterBond));
}

export async function settleClaim(env: ClaimStakeEnv, claimId: string, claimWins: boolean, arbiterSig: string): Promise<SubmitResult> {
  return submit(env, encodeSettle(claimId, claimWins, arbiterSig));
}

export async function claimUnchallenged(env: ClaimStakeEnv, claimId: string): Promise<SubmitResult> {
  return submit(env, encodeClaimUnchallenged(claimId));
}

export interface ClaimSnapshot {
  claimId: string;
  state: ClaimState;
  didHash: string;
  atRecordCid: string;
  bond: string;
  postedAt: number;
  challengePeriodSec: number;
  claimant: string;
  challenger?: string;
  challengerDidHash?: string;
  counterBond?: string;
  challengePostedAt?: number;
  chainId: number;
  escrowAddr: string;
}

/** Snapshot the full Claim + (optional) Challenge state via two eth_calls. */
export async function snapshotClaim(env: ClaimStakeEnv, claimId: string): Promise<ClaimSnapshot | null> {
  const id = ensureBytes32("claimId", claimId);
  const calldata = CLAIMS_VIEW_SELECTOR + padBytes32(id);
  const raw = await ethCall(env, escrowAddr(env), calldata);
  const c = decodeClaim(raw);
  if (c.state === "none") return null;

  const out: ClaimSnapshot = {
    claimId: c.claimId,
    state: c.state,
    didHash: c.didHash,
    atRecordCid: c.atRecordCid,
    bond: c.bond,
    postedAt: c.postedAt,
    challengePeriodSec: c.challengePeriodSec,
    claimant: c.claimant,
    chainId: chainIdNum(env),
    escrowAddr: escrowAddr(env),
  };

  if (c.state === "challenged" || c.state === "upheld" || c.state === "slashed") {
    const chCalldata = CHALLENGES_VIEW_SELECTOR + padBytes32(id);
    const chRaw = await ethCall(env, escrowAddr(env), chCalldata);
    const ch = decodeChallenge(chRaw);
    out.challenger = ch.challenger;
    out.challengerDidHash = ch.challengerDidHash;
    out.counterBond = ch.counterBond;
    out.challengePostedAt = ch.postedAt;
  }
  return out;
}

// ── Caller-input parsing ────────────────────────────────────────────────────

export interface PostClaimInput {
  claim: string;
  claimType?: string;
  bond: string | number | bigint;
  challengePeriodSec?: number;
  arbiter?: string;
  evidence?: string[];
  atRecordCid?: string;
}

export interface PreparedPostClaim {
  claimId: string;
  claimHash: string;
  didHash: string;
  atRecordCid: string;
  bond: bigint;
  challengePeriodSec: bigint;
  nonce: bigint;
}

const TWO_POW_64 = 1n << 64n;

function randomNonce(): bigint {
  // 8 random bytes = uint64. Plenty for collision avoidance per (claimHash, didHash).
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return BigInt("0x" + bytesToHex(bytes)) % TWO_POW_64;
}

/**
 * Compute claimHash + claimId from caller input. atRecordCid defaults to
 * `claimHash` for Phase 1 — when an actual AT Record CID is recorded
 * server-side it gets overwritten.
 */
export function preparePostClaim(input: PostClaimInput, didHash: string): PreparedPostClaim {
  const claimText = String(input.claim ?? "").trim();
  if (!claimText) throw new Error("claim text required");
  if (claimText.length > 4096) throw new Error("claim too long (>4096 chars)");

  const claimHash = keccakHex(new TextEncoder().encode(claimText));
  const nonce = randomNonce();
  const claimId = deriveClaimId(claimHash, didHash, nonce);

  const atRecordCid = input.atRecordCid ? ensureBytes32("atRecordCid", input.atRecordCid) : claimHash;
  const bond = uintToBigInt(input.bond);
  if (bond <= 0n) throw new Error("bond must be > 0");

  const period = BigInt(input.challengePeriodSec ?? 7 * 24 * 60 * 60);
  if (period < 60n || period > 90n * 24n * 60n * 60n) throw new Error("challengePeriodSec out of range (60..7776000)");

  return { claimId, claimHash, didHash, atRecordCid, bond, challengePeriodSec: period, nonce };
}
