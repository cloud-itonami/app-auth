/**
 * ADR-0074 sign-up — provision an ERC725 root identity for a new account.
 *
 * Private-chain v1 path (single sealer signs everything):
 *
 *   1. Sealer calls `etzhayyimRootIdentityRegistry.deployRootIdentity(seedHash,
 *      label, controller=sealer)`. Contract deploys a fresh `etzhayyimRootIdentity`
 *      and stores `identityByRootDid[seedHash] = newIdentity`.
 *   2. After the receipt lands we read `identityByRootDid(seedHash)` to
 *      recover the deployed address (the contract uses plain `new`, not
 *      CREATE2, so the address is non-deterministic and only known
 *      post-mine).
 *   3. Build canonical `rootDid = did:erc725:etzhayyim:260425:<identityAddr>`
 *      and return it. authn writes that string as the session JWT's
 *      `accountDid`.
 *   4. Optional facade pass — register legacy `did:web:authn.etzhayyim.com:user:*`
 *      hashes as facades pointing to the same root identity, so in-flight
 *      sessions whose JWT.iss is still the legacy DID resolve to the
 *      freshly-deployed identity via `resolveFacade(keccak256(legacyDid))`.
 *
 * `seedHash` is opaque per-account ID — typically
 * `keccak256("etzhayyim-account:" || nanoid)` from authn. It does NOT have to
 * equal `keccak256(rootDid)`; the resolver fast-paths the canonical
 * `did:erc725:` form via `parseErc725RootDid`.
 *
 * CSW execution accounts are intentionally NOT provisioned here. On a
 * single-sealer private chain the sealer signs every user-initiated tx,
 * so a per-account ERC-4337 execution account adds no function. Phase 3
 * (multisig + paymaster) is when CSW activation moves into sign-up.
 */

import { keccak_256 } from "@noble/hashes/sha3.js";

import { decodeAddress, ethCall, isZeroAddress, selector } from "./eth-rpc";
import { signAndSendTx, waitForReceipt } from "./eth-tx";
import type { EthTxEnv } from "./eth-tx";
import type { RootIdentityEnv } from "./root-identity";
import { rootDidFromIdentity } from "./root-identity";

const DEPLOY_ROOT_IDENTITY_SELECTOR = selector("deployRootIdentity(bytes32,string,address)");
const LINK_FACADE_SELECTOR          = selector("linkFacade(bytes32,bytes32,string)");
const IDENTITY_BY_ROOT_DID_SELECTOR = selector("identityByRootDid(bytes32)");
const ROOT_BY_FACADE_DID_SELECTOR   = selector("rootByFacadeDid(bytes32)");

export interface SignUpEnv extends RootIdentityEnv, EthTxEnv {}

export interface ProvisionRootIdentityRequest {
  /** 0x-prefixed bytes32 — opaque per-account ID. */
  seedHash: string;
  /** Free-form label written to `RootIdentityRegistered` event. */
  label: string;
  /** etzhayyimRootIdentity owner. Defaults to sealer (zero-address sentinel). */
  controller?: string;
  /** Legacy DIDs to register as facades pointing to this root. */
  facadeDids?: string[];
}

export interface ProvisionRootIdentityResult {
  rootDid: string;
  rootDidHash: string;
  identityAddress: string;
  seedHash: string;
  txHash: string;
  receiptStatus: "0x1" | "0x0" | null;
  facades?: Array<{ did: string; facadeDidHash: string; linked: boolean; txHash?: string; reason?: string }>;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}
function hexNoPrefix(hex: string): string { return hex.startsWith("0x") ? hex.slice(2) : hex; }
function padBytes32(hex: string): string {
  const clean = hexNoPrefix(hex);
  if (clean.length > 64) throw new Error("bytes32 hex too long");
  return clean.padStart(64, "0");
}
function uintToHex(value: bigint): string {
  if (value < 0n) throw new Error("uint must be non-negative");
  return value.toString(16).padStart(64, "0");
}
function utf8Pad32(value: string): { len: bigint; padded: string } {
  const bytes = new TextEncoder().encode(value);
  const len = BigInt(bytes.length);
  const need = (32 - (bytes.length % 32 || 32)) % 32;
  const padded = bytesToHex(bytes) + "0".repeat(need * 2);
  return { len, padded };
}

function encodeDeployRootIdentity(rootDidHash: string, rootDidUri: string, controller: string): string {
  const head = padBytes32(rootDidHash) + padBytes32("0x60") + padBytes32(controller);
  const { len, padded } = utf8Pad32(rootDidUri);
  return DEPLOY_ROOT_IDENTITY_SELECTOR + head + uintToHex(len) + padded;
}

function encodeLinkFacade(rootDidHash: string, facadeDidHash: string, facadeDidUri: string): string {
  const head = padBytes32(rootDidHash) + padBytes32(facadeDidHash) + padBytes32("0x60");
  const { len, padded } = utf8Pad32(facadeDidUri);
  return LINK_FACADE_SELECTOR + head + uintToHex(len) + padded;
}

export function deriveSeedHash(stableId: string): string {
  const bytes = keccak_256(new TextEncoder().encode(`etzhayyim-account:${stableId}`));
  return "0x" + bytesToHex(bytes);
}

function rootDidHashFromIdentity(chainId: string | number, identity: string): string {
  const did = rootDidFromIdentity(chainId, identity);
  const bytes = keccak_256(new TextEncoder().encode(did));
  return "0x" + bytesToHex(bytes);
}

function facadeDidHashOf(did: string): string {
  const bytes = keccak_256(new TextEncoder().encode(did));
  return "0x" + bytesToHex(bytes);
}

async function readIdentityByRootDid(env: SignUpEnv, registry: string, seedHash: string): Promise<string | null> {
  const calldata = IDENTITY_BY_ROOT_DID_SELECTOR + hexNoPrefix(seedHash).padStart(64, "0");
  const raw = await ethCall(env, registry, calldata);
  const addr = decodeAddress(raw);
  return isZeroAddress(addr) ? null : addr;
}

async function readFacadeRoot(env: SignUpEnv, registry: string, facadeDidHash: string): Promise<string | null> {
  const calldata = ROOT_BY_FACADE_DID_SELECTOR + hexNoPrefix(facadeDidHash).padStart(64, "0");
  const raw = await ethCall(env, registry, calldata);
  const clean = hexNoPrefix(raw);
  if (clean.length < 64) return null;
  const word = "0x" + clean.slice(0, 64).toLowerCase();
  return /^0x0+$/.test(word) ? null : word;
}

export async function provisionRootIdentity(
  env: SignUpEnv,
  req: ProvisionRootIdentityRequest,
): Promise<ProvisionRootIdentityResult> {
  const registry = (env.etzhayyim_ROOT_IDENTITY_REGISTRY_ADDR || "").trim();
  if (!registry) throw new Error("etzhayyim_ROOT_IDENTITY_REGISTRY_ADDR is not configured");
  const chainId = (env.ETH_PRIVATE_CHAIN_ID || "").trim();
  if (!chainId) throw new Error("ETH_PRIVATE_CHAIN_ID is not configured");
  if (!req.seedHash.startsWith("0x") || req.seedHash.length !== 66) throw new Error("seedHash must be 0x + 64 hex chars");
  if (!req.label) throw new Error("label is required");

  // Idempotency — fast-return if seed already provisioned.
  const existing = await readIdentityByRootDid(env, registry, req.seedHash);
  if (existing) {
    const rootDid = rootDidFromIdentity(chainId, existing);
    return {
      rootDid,
      rootDidHash: rootDidHashFromIdentity(chainId, existing),
      identityAddress: existing,
      seedHash: req.seedHash,
      txHash: "0x" + "0".repeat(64),
      receiptStatus: "0x1",
    };
  }

  const controller = (req.controller || "0x0000000000000000000000000000000000000000").toLowerCase();
  const data = encodeDeployRootIdentity(req.seedHash, req.label, controller);
  const { txHash } = await signAndSendTx(env, { to: registry, data, gasLimit: 1_500_000n });
  const receipt = await waitForReceipt(env, txHash, { timeoutMs: 12_000, pollMs: 1_500 });
  if (receipt && receipt.status === "0x0") {
    const err = new Error(`deployRootIdentity reverted (txHash=${txHash})`);
    (err as Error & { code?: string }).code = "TxRevert";
    throw err;
  }

  const identity = await readIdentityByRootDid(env, registry, req.seedHash);
  if (!identity) {
    const err = new Error(`deployRootIdentity completed but registry has no identity for seedHash=${req.seedHash}`);
    (err as Error & { code?: string }).code = "RegistryNotPopulated";
    throw err;
  }

  const rootDid = rootDidFromIdentity(chainId, identity);

  // Optional facade pass — best-effort, never throws.
  const facades: NonNullable<ProvisionRootIdentityResult["facades"]> = [];
  for (const facadeDid of req.facadeDids ?? []) {
    const facadeDidHash = facadeDidHashOf(facadeDid);
    try {
      const existingRoot = await readFacadeRoot(env, registry, facadeDidHash);
      if (existingRoot && existingRoot.toLowerCase() === req.seedHash.toLowerCase()) {
        facades.push({ did: facadeDid, facadeDidHash, linked: true, reason: "already linked" });
        continue;
      }
      if (existingRoot) {
        facades.push({ did: facadeDid, facadeDidHash, linked: false, reason: `facade points to a different root (${existingRoot})` });
        continue;
      }
      const linkData = encodeLinkFacade(req.seedHash, facadeDidHash, facadeDid);
      const linkTx = await signAndSendTx(env, { to: registry, data: linkData, gasLimit: 200_000n });
      const linkReceipt = await waitForReceipt(env, linkTx.txHash, { timeoutMs: 12_000, pollMs: 1_500 });
      if (linkReceipt && linkReceipt.status === "0x0") {
        facades.push({ did: facadeDid, facadeDidHash, linked: false, txHash: linkTx.txHash, reason: "tx reverted" });
      } else {
        facades.push({ did: facadeDid, facadeDidHash, linked: true, txHash: linkTx.txHash });
      }
    } catch (e) {
      facades.push({ did: facadeDid, facadeDidHash, linked: false, reason: e instanceof Error ? e.message.slice(0, 200) : String(e).slice(0, 200) });
    }
  }

  return {
    rootDid,
    rootDidHash: rootDidHashFromIdentity(chainId, identity),
    identityAddress: identity,
    seedHash: req.seedHash,
    txHash,
    receiptStatus: receipt?.status ?? null,
    facades: facades.length ? facades : undefined,
  };
}
