/**
 * ADR-2604261717 yabai auto-challenger — sealer-funded challenge against a
 * pending claim, with arbitrary challenger DID hash on-chain.
 *
 * The sealer is the EOA that holds (a) infinite ETH, and (b) masterMinter
 * authority on `GCCStablecoin`. This module wires those into the existing
 * `ClaimStakeEscrow.challenge(...)` flow:
 *
 *   1. Ensure sealer GCC balance ≥ counterBond. Mint the shortfall via
 *      `GCCStablecoin.mint(sealer, amount)` if not.
 *   2. Ensure sealer allowance(escrow) ≥ counterBond. Approve MAX_UINT
 *      once if not (saves a tx per future challenge).
 *   3. Sealer signs+sends `escrow.challenge(claimId, challengerDidHash,
 *      counterBond)`. Note `msg.sender = sealer`, so on-chain the
 *      challenger.address row is the sealer, but `challengerDidHash` is
 *      whatever the auto-challenger picked (e.g. `keccak256(rootDid of
 *      did:web:yabai.etzhayyim.com)`). Slashed/refunded payouts go to sealer
 *      address; treasury redirection is a Phase 3 concern.
 *
 * Same pattern as the auto-settler — single sealer, deterministic on a
 * private chain, no UserOps/paymaster needed.
 */

import { ethCall, isZeroAddress, selector } from "./eth-rpc";
import type { EthRpcEnv } from "./eth-rpc";
import { signAndSendTx, waitForReceipt } from "./eth-tx";
import type { EthTxEnv } from "./eth-tx";
import { encodeChallenge } from "./claim-stake";

export interface AutoChallengeEnv extends EthRpcEnv, EthTxEnv {
  etzhayyim_CLAIM_STAKE_ESCROW_ADDR?: string;
  etzhayyim_CREDIT_ADDR?: string;
  ETH_PRIVATE_CHAIN_ID?: string;
}

const ERC20_BALANCE_OF_SELECTOR = selector("balanceOf(address)");
const ERC20_ALLOWANCE_SELECTOR  = selector("allowance(address,address)");
const ERC20_APPROVE_SELECTOR    = selector("approve(address,uint256)");
const ERC20_MINT_SELECTOR       = selector("mint(address,uint256)");

const MAX_UINT256 = "0x" + "f".repeat(64);

function escrow(env: AutoChallengeEnv): string {
  const a = (env.etzhayyim_CLAIM_STAKE_ESCROW_ADDR || "").trim();
  if (!a) throw new Error("etzhayyim_CLAIM_STAKE_ESCROW_ADDR is not configured");
  return a;
}
function gcc(env: AutoChallengeEnv): string {
  const a = (env.etzhayyim_CREDIT_ADDR || "").trim();
  if (!a) throw new Error("etzhayyim_CREDIT_ADDR is not configured");
  return a;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}
function hexNoPrefix(hex: string): string { return hex.startsWith("0x") ? hex.slice(2) : hex; }
function padBytes32(hex: string): string {
  const clean = hexNoPrefix(hex).toLowerCase();
  if (clean.length > 64) throw new Error("hex too long for 32 bytes");
  return clean.padStart(64, "0");
}
function uintToHex(value: bigint): string {
  if (value < 0n) throw new Error("uint must be non-negative");
  return value.toString(16).padStart(64, "0");
}
function hexToBigInt(hex: string): bigint {
  const clean = hexNoPrefix(hex);
  return clean ? BigInt("0x" + clean) : 0n;
}

function encodeBalanceOf(addr: string): string {
  return ERC20_BALANCE_OF_SELECTOR + padBytes32(addr);
}
function encodeAllowance(owner: string, spender: string): string {
  return ERC20_ALLOWANCE_SELECTOR + padBytes32(owner) + padBytes32(spender);
}
function encodeApprove(spender: string, amount: string): string {
  return ERC20_APPROVE_SELECTOR + padBytes32(spender) + padBytes32(amount);
}
function encodeMint(to: string, amount: bigint): string {
  return ERC20_MINT_SELECTOR + padBytes32(to) + uintToHex(amount);
}

async function readUint256(env: AutoChallengeEnv, to: string, calldata: string): Promise<bigint> {
  const raw = await ethCall(env, to, calldata);
  return hexToBigInt(raw);
}

export interface AutoChallengeRequest {
  claimId: string;
  challengerDidHash: string;
  counterBond: bigint;
  /** Caller-supplied sealer address; if omitted we derive from `signAndSendTx`'s
   *  return on the first chain write. Most callers leave this unset. */
  sealerAddress?: string;
}

export interface AutoChallengeResult {
  challengeTxHash: string;
  challengeReceiptStatus: "0x1" | "0x0" | null;
  /** Set when the helper had to mint GCC (sealer balance was below
   *  counterBond before the call). */
  mintTxHash?: string;
  /** Set when the helper had to send a one-time approve. */
  approveTxHash?: string;
  /** Sealer's GCC balance after the call. Helps the auto-challenger spot
   *  budget exhaustion drift. */
  postBalance: string;
}

/**
 * Drive a single auto-challenge end-to-end. Idempotent at the on-chain
 * level via the escrow's own state guards (a second `challenge` for the
 * same claimId reverts `InvalidState`).
 */
export async function autoChallengeClaim(
  env: AutoChallengeEnv,
  req: AutoChallengeRequest,
): Promise<AutoChallengeResult> {
  if (req.counterBond <= 0n) throw new Error("counterBond must be > 0");
  if (!req.claimId.startsWith("0x") || req.claimId.length !== 66) throw new Error("invalid claimId");
  if (!req.challengerDidHash.startsWith("0x") || req.challengerDidHash.length !== 66) throw new Error("invalid challengerDidHash");

  const escrowAddr = escrow(env);
  const gccAddr = gcc(env);

  // Send a tiny zero-value tx if we don't yet know the sealer address. We
  // could derive it from SEALER_PRIV directly via privToAddress, but
  // signAndSendTx already exposes it on its return — piggyback on the
  // mint/approve path below. For this first read, fall back to a 1-wei
  // self-send only if needed.
  // In practice the sealer address is statically known; callers can pass
  // it through `req.sealerAddress` to skip the discovery hop.
  let sealerAddr = (req.sealerAddress || "").trim().toLowerCase();
  if (!sealerAddr) {
    // Cheapest path: read from a no-op (mint of 0 wei reverts; instead
    // send a 0-allowance approve which always succeeds). We don't actually
    // need sealer addr until the balance check. Fall through and resolve
    // it from the first state-changing tx.
  }

  let mintTxHash: string | undefined;
  let approveTxHash: string | undefined;

  // Step 1 — top up sealer GCC balance if needed. We can only check after
  // we know sealer's address; for the first call we always send a no-op
  // that surfaces the sealer addr, then loop back for the balance check.
  // Cheaper: skip the read, mint speculatively. Mint + transferFrom is
  // ~80k gas combined; on a private chain that's ~$0.
  if (!sealerAddr) {
    // 0-amount approve to escrow — guaranteed cheap and surfaces sealer addr.
    const sent = await signAndSendTx(env, {
      to: gccAddr,
      data: encodeApprove(escrowAddr, padBytes32("0x00")),
      gasLimit: 80_000n,
    });
    sealerAddr = sent.sealerAddress.toLowerCase();
  }

  const balance = await readUint256(env, gccAddr, encodeBalanceOf(sealerAddr));
  if (balance < req.counterBond) {
    // Mint 100x the deficit so we don't churn — masterMinter on private chain.
    const deficit = req.counterBond - balance;
    const amount = deficit * 100n;
    const sent = await signAndSendTx(env, {
      to: gccAddr,
      data: encodeMint(sealerAddr, amount),
      gasLimit: 200_000n,
    });
    mintTxHash = sent.txHash;
    const r = await waitForReceipt(env, sent.txHash, { timeoutMs: 12_000, pollMs: 1_500 });
    if (r && r.status === "0x0") {
      const err = new Error(`mint reverted (txHash=${sent.txHash}) — sealer is masterMinter, check supply cap`);
      (err as Error & { code?: string }).code = "MintRevert";
      throw err;
    }
  }

  // Step 2 — approve allowance if not yet ≥ counterBond.
  const allowance = await readUint256(env, gccAddr, encodeAllowance(sealerAddr, escrowAddr));
  if (allowance < req.counterBond) {
    const sent = await signAndSendTx(env, {
      to: gccAddr,
      data: encodeApprove(escrowAddr, MAX_UINT256.slice(2)),
      gasLimit: 80_000n,
    });
    approveTxHash = sent.txHash;
    const r = await waitForReceipt(env, sent.txHash, { timeoutMs: 12_000, pollMs: 1_500 });
    if (r && r.status === "0x0") {
      const err = new Error(`approve reverted (txHash=${sent.txHash})`);
      (err as Error & { code?: string }).code = "ApproveRevert";
      throw err;
    }
  }

  // Step 3 — challenge. msg.sender on-chain is sealer; off-chain
  // challengerDidHash is whatever the caller picked (yabai DID for the
  // auto-challenger).
  const calldata = encodeChallenge(req.claimId, req.challengerDidHash, req.counterBond);
  const sent = await signAndSendTx(env, { to: escrowAddr, data: calldata, gasLimit: 300_000n });
  const r = await waitForReceipt(env, sent.txHash, { timeoutMs: 12_000, pollMs: 1_500 });
  if (r && r.status === "0x0") {
    const err = new Error(`challenge reverted (txHash=${sent.txHash}) — likely InvalidState (already challenged) or ChallengeWindowClosed`);
    (err as Error & { code?: string }).code = "ChallengeRevert";
    throw err;
  }

  const postBalance = await readUint256(env, gccAddr, encodeBalanceOf(sealerAddr));
  return {
    challengeTxHash: sent.txHash,
    challengeReceiptStatus: r?.status ?? null,
    mintTxHash,
    approveTxHash,
    postBalance: postBalance.toString(),
  };
}
