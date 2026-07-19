/**
 * Resolve an ERC725 root identity's ERC-4337 smart-account address
 * on the etzhayyim private chain (ADR-0074 Phase 2-B).
 *
 * On-chain shape: `etzhayyimActorRegistry.actorByDid(bytes32 didHash) → address`
 * where `didHash = keccak256(utf8(canonicalRootDid))`. Off-chain mirror lives
 * in `linked_auth_methods` (provider="ethereum-actor") for cheap reads
 * without a chain round-trip; this module is the source of truth that
 * populates / refreshes that mirror.
 */

import { decodeAddress, ethCall, isZeroAddress, selector } from "./eth-rpc";
import type { EthRpcEnv } from "./eth-rpc";
import { requireRootIdentity } from "./root-identity";

export interface ActorAccountEnv extends EthRpcEnv {
  etzhayyim_ACTOR_REGISTRY_ADDR?: string;
  etzhayyim_ROOT_IDENTITY_REGISTRY_ADDR?: string;
  ETH_PRIVATE_CHAIN_ID?: string;
  /** GCCStablecoin contract address (= etzhayyim_CREDIT_ADDR in wrangler.jsonc). */
  etzhayyim_CREDIT_ADDR?: string;
}

const ACTOR_BY_DID_SELECTOR = selector("actorByDid(bytes32)");
const BALANCE_OF_SELECTOR = selector("balanceOf(address)");

/** Read ERC-20 balanceOf for `address`. Returns wei as decimal string, "0" on any failure. */
async function fetchErc20Balance(env: EthRpcEnv, tokenAddr: string, address: string): Promise<string> {
  const addrPadded = address.slice(2).toLowerCase().padStart(64, "0");
  try {
    const raw = await ethCall(env, tokenAddr, BALANCE_OF_SELECTOR + addrPadded);
    const clean = (raw.startsWith("0x") ? raw.slice(2) : raw).slice(0, 64).padStart(64, "0");
    return BigInt("0x" + clean).toString();
  } catch {
    return "0";
  }
}

/**
 * Read GCC balance for a known smart-account address.
 * Returns wei as decimal string, "0" if etzhayyim_CREDIT_ADDR is absent or call fails.
 */
export async function fetchGccBalance(env: ActorAccountEnv, smartAccount: string | null): Promise<string> {
  const gccAddr = (env.etzhayyim_CREDIT_ADDR || "").trim();
  if (!gccAddr || !smartAccount) return "0";
  return fetchErc20Balance(env, gccAddr, smartAccount);
}

/**
 * Query the registry for the activated smart-account address tied to
 * `didHash`. Returns `null` if the actor has not activated yet (the
 * registry mapping returns the zero address).
 */
export async function getActivatedAddress(env: ActorAccountEnv, didHash: string): Promise<string | null> {
  const registry = (env.etzhayyim_ACTOR_REGISTRY_ADDR || "").trim();
  if (!registry) throw new Error("etzhayyim_ACTOR_REGISTRY_ADDR is not configured");
  if (!didHash.startsWith("0x") || didHash.length !== 66) throw new Error("invalid didHash");
  const calldata = ACTOR_BY_DID_SELECTOR + didHash.slice(2);
  const raw = await ethCall(env, registry, calldata);
  const addr = decodeAddress(raw);
  return isZeroAddress(addr) ? null : addr;
}

export interface ActorAccountSnapshot {
  accountDid: string;
  rootDid: string;
  rootIdentity: string | null;
  didHash: string;
  activated: boolean;
  smartAccount: string | null;
  /** GCC balance of the smart account in wei (decimal string). "0" when not activated or etzhayyim_CREDIT_ADDR absent. */
  gccBalance: string;
  chainId: number;
  registryAddr: string;
  rootRegistryAddr: string | null;
  migratedRoot: boolean;
  resolvedFromFacade: boolean;
}

export async function snapshotActorAccount(env: ActorAccountEnv, accountDid: string): Promise<ActorAccountSnapshot> {
  const root = await requireRootIdentity(env, accountDid);
  const didHash = root.rootDidHash;
  const smartAccount = await getActivatedAddress(env, didHash);
  const gccBalance = await fetchGccBalance(env, smartAccount);
  return {
    accountDid,
    rootDid: root.rootDid,
    rootIdentity: root.rootIdentity,
    didHash,
    activated: smartAccount !== null,
    smartAccount,
    gccBalance,
    chainId: Number((env.ETH_PRIVATE_CHAIN_ID || "0").trim()) || 0,
    registryAddr: (env.etzhayyim_ACTOR_REGISTRY_ADDR || "").trim(),
    rootRegistryAddr: root.registryAddr,
    migratedRoot: root.migrated,
    resolvedFromFacade: root.resolvedFromFacade,
  };
}

import { encodeActivateCalldata, signAndSendTx, waitForReceipt } from "./eth-tx";
import type { EthTxEnv } from "./eth-tx";
import { decodeBase64Url } from "../../worker/src-ts/base64url";

export interface ActivateActorAccountEnv extends ActorAccountEnv, EthTxEnv {}

export interface ActivateResult extends ActorAccountSnapshot {
  /** Set when this call submitted a transaction. Idempotent re-activation
   *  (the account already existed) returns the snapshot without txHash. */
  txHash?: string;
  /** Set when the receipt landed before the wait-timeout. `null` means
   *  the tx is in the mempool but not yet mined; the snapshot still
   *  reflects the post-call state (which is "activated" once the receipt
   *  lands — call `getActorAccount` again to confirm). */
  receiptStatus?: "0x1" | "0x0" | null;
}

/**
 * Decode the user's primary passkey credential (stored in D1 as
 * base64url-encoded uncompressed P-256 pubkey, 65 bytes 0x04||X||Y) into
 * the 64-byte X||Y owner format that `MultiOwnable.addOwnerPublicKey`
 * inside CoinbaseSmartWallet consumes.
 *
 * Returns `null` if the user has no passkey on record (which means the
 * sign-in path itself is broken — callers can surface a clear error).
 */
async function ownerFromPrimaryPasskey(
  authDb: D1Database,
  accountDid: string,
): Promise<Uint8Array | null> {
  const row = await authDb
    .prepare(
      "SELECT public_key_b64 AS pubkey FROM passkey_credentials WHERE did = ? ORDER BY created_at ASC LIMIT 1",
    )
    .bind(accountDid)
    .first<{ pubkey: string }>();
  if (!row?.pubkey) return null;
  const decoded = decodeBase64Url(row.pubkey);
  if (decoded.length !== 65 || decoded[0] !== 0x04) {
    throw new Error(`unexpected passkey pubkey shape: ${decoded.length} bytes, prefix 0x${decoded[0].toString(16)}`);
  }
  return decoded.slice(1); // strip 0x04 → 64 bytes X||Y
}

/**
 * Activate the caller's smart account on the etzhayyim private chain. Reads
 * their primary passkey, packs the P-256 pubkey as a 64-byte owner,
 * builds + signs + sends `etzhayyimActorRegistry.activate(didHash, [owner])`
 * from the sealer key, then re-snapshots the registry to confirm.
 *
 * The contract is idempotent: if an account already exists for `didHash`
 * the call is a near-no-op (still costs gas to enter the function but
 * returns the existing address). We surface the txHash either way so the
 * caller can correlate logs.
 */
export async function activateActorAccount(
  env: ActivateActorAccountEnv,
  authDb: D1Database,
  accountDid: string,
): Promise<ActivateResult> {
  const registry = (env.etzhayyim_ACTOR_REGISTRY_ADDR || "").trim();
  if (!registry) throw new Error("etzhayyim_ACTOR_REGISTRY_ADDR is not configured");

  const root = await requireRootIdentity(env, accountDid);
  const didHash = root.rootDidHash;

  // Cheap pre-check — if already activated, skip the whole sign/send dance.
  const existing = await getActivatedAddress(env, didHash);
  if (existing) {
    return {
      ...(await snapshotActorAccount(env, accountDid)),
    };
  }

  const owner = await ownerFromPrimaryPasskey(authDb, accountDid);
  if (!owner) {
    const err = new Error("no passkey credential found for this account");
    (err as Error & { code?: string }).code = "PasskeyMissing";
    throw err;
  }

  const calldata = encodeActivateCalldata(didHash, owner);
  const { txHash } = await signAndSendTx(env, { to: registry, data: calldata });

  // Best-effort receipt wait. CF Worker subrequests are rate-limited so
  // we cap the poll at ~12s (8 attempts × 1.5s). On miss the UI just
  // re-fetches getActorAccount a few seconds later.
  const receipt = await waitForReceipt(env, txHash, { timeoutMs: 12_000, pollMs: 1_500 });

  if (receipt && receipt.status === "0x0") {
    const err = new Error(`activate tx reverted (txHash=${txHash} block=${receipt.blockNumber})`);
    (err as Error & { code?: string }).code = "TxRevert";
    throw err;
  }

  const snap = await snapshotActorAccount(env, accountDid);
  return { ...snap, txHash, receiptStatus: receipt?.status ?? null };
}
