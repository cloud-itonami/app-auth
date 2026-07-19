/**
 * ERC725 root identity resolver for ADR-0074.
 *
 * New sessions eventually use `did:erc725:etzhayyim:260425:<identity>` directly.
 * Legacy sessions (`did:etzhayyim` / `did:web`) are treated as facade DIDs and
 * resolved through `etzhayyimRootIdentityRegistry.resolveFacade(bytes32)`.
 */

import { decodeAddress, ethCall, isZeroAddress, keccakHex, selector } from "./eth-rpc";
import type { EthRpcEnv } from "./eth-rpc";

export interface RootIdentityEnv extends EthRpcEnv {
  ETH_PRIVATE_CHAIN_ID?: string;
  etzhayyim_ROOT_IDENTITY_REGISTRY_ADDR?: string;
}

export interface RootIdentityResolution {
  /** Original session/account DID seen by authz. */
  accountDid: string;
  /** Canonical root DID used for on-chain root-DID keyed reads. */
  rootDid: string;
  /** 0x-prefixed 32-byte keccak256(rootDid). */
  rootDidHash: string;
  /** ERC725 root identity contract address when known. */
  rootIdentity: string | null;
  /** True when accountDid was already the root DID. */
  migrated: boolean;
  /** True when a legacy facade DID resolved through the root registry. */
  resolvedFromFacade: boolean;
  /** Root registry address used for resolution, when configured. */
  registryAddr: string | null;
}

export class RootIdentityRequiredError extends Error {
  constructor(accountDid: string) {
    super(`ERC725 root identity is not migrated or linked for accountDid=${accountDid}`);
    this.name = "RootIdentityRequiredError";
  }
}

const IDENTITY_BY_ROOT_DID_SELECTOR = selector("identityByRootDid(bytes32)");
const RESOLVE_FACADE_SELECTOR = selector("resolveFacade(bytes32)");

const ERC725_DID_RE = /^did:erc725:etzhayyim:(\d+):(0x[0-9a-fA-F]{40})$/;

function parseErc725RootDid(did: string, expectedChainId: string): string | null {
  const match = ERC725_DID_RE.exec(did);
  if (!match) return null;
  const chainId = match[1];
  if (expectedChainId && chainId !== expectedChainId) return null;
  return match[2].toLowerCase();
}

async function rootIdentityByRootDid(env: RootIdentityEnv, rootDidHash: string): Promise<string | null> {
  const registry = (env.etzhayyim_ROOT_IDENTITY_REGISTRY_ADDR || "").trim();
  if (!registry) return null;
  const raw = await ethCall(env, registry, IDENTITY_BY_ROOT_DID_SELECTOR + rootDidHash.slice(2));
  const addr = decodeAddress(raw);
  return isZeroAddress(addr) ? null : addr;
}

async function rootIdentityByFacadeDid(env: RootIdentityEnv, facadeDidHash: string): Promise<string | null> {
  const registry = (env.etzhayyim_ROOT_IDENTITY_REGISTRY_ADDR || "").trim();
  if (!registry) return null;
  const raw = await ethCall(env, registry, RESOLVE_FACADE_SELECTOR + facadeDidHash.slice(2));
  const addr = decodeAddress(raw);
  return isZeroAddress(addr) ? null : addr;
}

export function rootDidFromIdentity(chainId: string | number, identity: string): string {
  return `did:erc725:etzhayyim:${String(chainId)}:${identity.toLowerCase()}`;
}

export async function resolveRootIdentity(
  env: RootIdentityEnv,
  accountDid: string,
): Promise<RootIdentityResolution> {
  const expectedChainId = (env.ETH_PRIVATE_CHAIN_ID || "").trim();
  const registryAddr = (env.etzhayyim_ROOT_IDENTITY_REGISTRY_ADDR || "").trim() || null;
  const parsedIdentity = parseErc725RootDid(accountDid, expectedChainId);

  if (parsedIdentity) {
    const rootDid = rootDidFromIdentity(expectedChainId || "260425", parsedIdentity);
    const rootDidHash = keccakHex(rootDid);
    const registeredIdentity = await rootIdentityByRootDid(env, rootDidHash).catch(() => null);
    return {
      accountDid,
      rootDid,
      rootDidHash,
      rootIdentity: registeredIdentity || parsedIdentity,
      migrated: true,
      resolvedFromFacade: false,
      registryAddr,
    };
  }

  const facadeDidHash = keccakHex(accountDid);
  const facadeIdentity = await rootIdentityByFacadeDid(env, facadeDidHash).catch(() => null);
  if (facadeIdentity) {
    const rootDid = rootDidFromIdentity(expectedChainId || "260425", facadeIdentity);
    return {
      accountDid,
      rootDid,
      rootDidHash: keccakHex(rootDid),
      rootIdentity: facadeIdentity,
      migrated: false,
      resolvedFromFacade: true,
      registryAddr,
    };
  }

  return {
    accountDid,
    rootDid: accountDid,
    rootDidHash: keccakHex(accountDid),
    rootIdentity: null,
    migrated: false,
    resolvedFromFacade: false,
    registryAddr,
  };
}

export async function requireRootIdentity(
  env: RootIdentityEnv,
  accountDid: string,
): Promise<RootIdentityResolution> {
  const resolved = await resolveRootIdentity(env, accountDid);
  if (!resolved.rootIdentity) throw new RootIdentityRequiredError(accountDid);
  return resolved;
}
