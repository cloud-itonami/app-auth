/**
 * authz.etzhayyim.com — Authorization Worker (T4 split, ADR-0024)
 *
 * Responsibility: linked auth methods, actor score, org management, /manage UI.
 * Session verification: inline HS256 verify using shared SS_AT_SESSION_SECRET.
 * AuthN (passkey/session issuance/DID): → authn.etzhayyim.com (AUTHN_SERVICE binding).
 *
 * Routes: authz.etzhayyim.com/*, accounts.etzhayyim.com/* (absorbed, 301 not needed — same Worker)
 * XRPC NSIDs: com.etzhayyim.authz.*
 */

import { Hono } from "hono";
import { decodeBase64Url, encodeBase64Url, encodeJsonBase64Url } from "../../worker/src-ts/base64url";
import { beginRegistration, verifyRegistration } from "../../worker/src-ts/passkey";
import {
  buildSiweMessage, bytesToHex, didPkhFromAddress, generateSiweNonce, isValidAddress,
  normalizeAddress, parseSiweMessage, personalSignHash, recoverEthAddress,
} from "./siwe";
import { decodeAddress, ethCall, isValidErc1271Signature, isZeroAddress, keccakHex, selector } from "./eth-rpc";
import { activateActorAccount, fetchGccBalance, snapshotActorAccount } from "./actor-account";
import { requireRootIdentity, resolveRootIdentity } from "./root-identity";
import {
  challengeClaim as ethChallengeClaim,
  claimUnchallenged as ethClaimUnchallenged,
  postClaim as ethPostClaim,
  preparePostClaim,
  settleClaim as ethSettleClaim,
  snapshotClaim,
} from "./claim-stake";
import { autoChallengeClaim } from "./auto-challenge";
import { autoSettleClaim, readDecision, submitRecordDecision } from "./rego-arbiter";
import { deriveSeedHash, provisionRootIdentity } from "./sign-up";

// ── Env ──────────────────────────────────────────────────────────────────────

interface Env {
  AUTH_DB?: D1Database;
  KEYS_DB?: D1Database;
  ASSETS?: Fetcher;
  AUTHN_SERVICE?: Fetcher;
  PDS_SERVICE?: Fetcher;
  SS_AT_SESSION_SECRET?: string;
  GOOGLE_OAUTH_CLIENT_ID?: string;
  GOOGLE_OAUTH_CLIENT_SECRET?: string;
  MICROSOFT_OAUTH_CLIENT_ID?: string;
  MICROSOFT_OAUTH_CLIENT_SECRET?: string;
  GMAIL_OAUTH_ID?: string;
  GMAIL_OAUTH_SECRET?: string;
  OUTLOOK_SECRET?: string;
  OUTLOOK_SECRET_ID?: string;
  ENVIRONMENT?: string;
  EMAIL_FROM?: string;
  SS_RESEND_API_KEY?: { get(): Promise<string> } | string;
  // ADR-0074 Phase 1 — Ethereum identity bridge (private chain).
  // chainId for the private EVM chain that wallet signatures must reference;
  // SIWE messages with a different Chain ID line are rejected with InvalidChainId.
  ETH_PRIVATE_CHAIN_ID?: string;
  // ADR-0074 Phase 2-A — geth-private RPC (https://geth.etzhayyim.com), the
  // Phase 2-A contract addresses on chain 260425, and the HMAC secret used
  // when this Worker submits privileged JSON-RPC calls (eth_sendRaw…) to
  // the proxy. SIWE link continues to work without any of these — the
  // smart-account `getActorAccount` path skips gracefully if RPC is empty.
  ETH_PRIVATE_RPC_URL?: string;
  etzhayyim_ACTOR_REGISTRY_ADDR?: string;
  etzhayyim_CSW_FACTORY_ADDR?: string;
  etzhayyim_CREDIT_ADDR?: string;
  etzhayyim_DEPLOY_REGISTRY_ADDR?: string;
  etzhayyim_ROOT_IDENTITY_REGISTRY_ADDR?: string;
  etzhayyim_MURAKUMO_REGISTRY_ADDR?: string;
  etzhayyim_MURAKUMO_ESCROW_ADDR?: string;
  // ADR-2604261717 Phase 1 — claim-level stake escrow on the same private chain.
  // Set after `forge script script/DeployClaimStake.s.sol --broadcast`.
  etzhayyim_CLAIM_STAKE_ESCROW_ADDR?: string;
  SS_RPC_HMAC?: { get(): Promise<string> } | string;
  // ADR-0074 Phase 2-A.5 — sealer private key for activateActorAccount
  // (sealer-sponsored tx that calls etzhayyimActorRegistry.activate). Provisioned
  // via `wrangler secret put SEALER_PRIV` from the worker-authz/ dir; the
  // canonical local backup is the macOS Keychain entry
  // `etzhayyim.private-chain / SEALER_PRIV`. Holding this secret = holding the
  // entire chain-260425 authority — keep call sites narrow until Phase 3
  // swaps this for a dedicated activator key.
  SEALER_PRIV?: string;
  // ADR-2604261717 yabai auto-challenger — shared HMAC gating the
  // `/internal/auto-challenge-claim` route. Provisioned via
  // `wrangler secret put CLAIM_SETTLER_HMAC` on this Worker AND on
  // `etzhayyim-claim-consumer` with an identical value (mirrored in
  // macOS Keychain `etzhayyim.cloudflare/CLAIM_SETTLER_HMAC`).
  CLAIM_SETTLER_HMAC?: string;
  // ADR-2604261717 Phase 2-B — RegoArbiter address for the on-chain
  // decision-registry adapter. Already-deployed `0x53E29CA1...`.
  etzhayyim_REGO_ARBITER_ADDR?: string;
  // ADR-2604261717 Phase 2-B rebuttal pipe — service binding to
  // claim-consumer's `/rebuttal-ingest` route. Persists the off-chain
  // rebuttal text to `vertex_claim_challenge.rebuttal` so judgeTick can
  // pass it to Murakumo. authz is zero-npm + no Hyperdrive, so the
  // write goes through the consumer Worker that already owns the table.
  CLAIM_CONSUMER_RPC?: Fetcher;
}

// ── Table init (lazy, once per isolate) ─────────────────────────────────────

let authTablesReady: Promise<void> | null = null;

async function ensureAuthTables(env: Env): Promise<void> {
  if (!env.AUTH_DB) return;
  if (!authTablesReady) {
    authTablesReady = env.AUTH_DB.batch([
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS passkey_credentials (
          credential_id TEXT PRIMARY KEY,
          did TEXT NOT NULL,
          handle TEXT NOT NULL,
          public_key_b64 TEXT NOT NULL,
          sign_count INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
      `),
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS linked_auth_methods (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_did TEXT NOT NULL,
          provider TEXT NOT NULL,
          provider_subject TEXT NOT NULL,
          display_label TEXT NOT NULL,
          verified INTEGER NOT NULL DEFAULT 0,
          metadata_json TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(account_did, provider, provider_subject)
        )
      `),
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS email_link_codes (
          account_did TEXT NOT NULL,
          email TEXT NOT NULL,
          code TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          PRIMARY KEY(account_did, email)
        )
      `),
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS vertex_etzhayyim_auth_account (
          vertex_id TEXT PRIMARY KEY,
          sensitivity_ord INTEGER NOT NULL DEFAULT 3,
          owner_did TEXT,
          did TEXT NOT NULL,
          legacy_did TEXT,
          handle TEXT,
          performer_type TEXT NOT NULL DEFAULT 'person',
          controller_did TEXT,
          actor_score INTEGER NOT NULL DEFAULT 25,
          auth_methods_summary TEXT NOT NULL DEFAULT '[]',
          status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
      `),
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS vertex_etzhayyim_auth_org (
          vertex_id TEXT PRIMARY KEY,
          sensitivity_ord INTEGER NOT NULL DEFAULT 2,
          owner_did TEXT NOT NULL,
          org_did TEXT NOT NULL,
          name TEXT NOT NULL,
          domain TEXT,
          org_type TEXT NOT NULL DEFAULT 'personal',
          settings_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
      `),
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS edge_etzhayyim_auth_member (
          edge_id TEXT PRIMARY KEY,
          src_vid TEXT NOT NULL,
          dst_vid TEXT NOT NULL,
          sensitivity_ord INTEGER NOT NULL DEFAULT 2,
          owner_did TEXT NOT NULL,
          org_did TEXT NOT NULL,
          member_did TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'member',
          invited_by TEXT,
          joined_at TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          UNIQUE(org_did, member_did)
        )
      `),
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS vertex_etzhayyim_auth_invite (
          vertex_id TEXT PRIMARY KEY,
          sensitivity_ord INTEGER NOT NULL DEFAULT 3,
          owner_did TEXT,
          org_did TEXT NOT NULL,
          email TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'member',
          invite_token TEXT,
          expires_at INTEGER NOT NULL,
          inviter_did TEXT NOT NULL,
          accepted_did TEXT,
          status TEXT NOT NULL DEFAULT 'pending',
          accepted_at TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
      `),
      // ADR-0074 Phase 1 — single-use SIWE nonces. Bound to (account_did, address)
      // so a nonce issued for wallet A can't be replayed against wallet B; deleted
      // on successful verify (linkEthereumVerify) or by TTL on next begin.
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS siwe_link_nonces (
          account_did TEXT NOT NULL,
          address TEXT NOT NULL,
          nonce TEXT NOT NULL,
          chain_id INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          PRIMARY KEY(account_did, address)
        )
      `),
      // Optional companion table for additional WebAuthn devices: stores the
      // human label so /manage can render "iPhone 15" instead of a base64 blob.
      // The credential itself lives in passkey_credentials (same as primary).
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS additional_passkey_labels (
          credential_id TEXT PRIMARY KEY,
          account_did TEXT NOT NULL,
          label TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL
        )
      `),
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS vertex_etzhayyim_claim_index (
          claim_id TEXT PRIMARY KEY,
          account_did TEXT NOT NULL,
          at_record_cid TEXT NOT NULL DEFAULT '',
          bond_gcc TEXT NOT NULL DEFAULT '0',
          posted_at INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL
        )
      `),
      env.AUTH_DB.prepare(`
        CREATE INDEX IF NOT EXISTS idx_claim_index_account_did
          ON vertex_etzhayyim_claim_index(account_did, posted_at DESC)
      `),
      env.AUTH_DB.prepare(`
        CREATE INDEX IF NOT EXISTS idx_claim_index_at_record_cid
          ON vertex_etzhayyim_claim_index(at_record_cid)
      `),
    ]).then(() => undefined).catch((err: unknown) => {
      authTablesReady = null;
      throw err;
    });
  }
  await authTablesReady;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function nowIso(): string { return new Date().toISOString(); }
function nowSecs(): number { return Math.floor(Date.now() / 1000); }
function generateOtp(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  const value = new DataView(bytes.buffer).getUint32(0, true) % 1_000_000;
  return value.toString().padStart(6, "0");
}

function json(body: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
      ...headers,
    },
  });
}

function jsonErr(status: number, error: string, message: string): Response {
  return json({ error, message }, status);
}

function parseCookieHeader(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const part of cookieHeader.split(";")) {
    const [rawKey, ...rawValue] = part.trim().split("=");
    if (!rawKey) continue;
    cookies[rawKey] = rawValue.join("=");
  }
  return cookies;
}

function getSessionSecret(env: Env): string {
  return (env.SS_AT_SESSION_SECRET || "").trim();
}

function getVar(env: Env, name: keyof Env): string {
  return typeof env[name] === "string" ? (env[name] as string) : "";
}

function getGoogleOauthClientId(env: Env): string {
  return getVar(env, "GOOGLE_OAUTH_CLIENT_ID") || getVar(env, "GMAIL_OAUTH_ID");
}
function getGoogleOauthClientSecret(env: Env): string {
  return getVar(env, "GOOGLE_OAUTH_CLIENT_SECRET") || getVar(env, "GMAIL_OAUTH_SECRET");
}
function getMicrosoftOauthClientId(env: Env): string {
  return getVar(env, "MICROSOFT_OAUTH_CLIENT_ID") || getVar(env, "OUTLOOK_SECRET");
}
function getMicrosoftOauthClientSecret(env: Env): string {
  return getVar(env, "MICROSOFT_OAUTH_CLIENT_SECRET") || getVar(env, "OUTLOOK_SECRET_ID");
}

function formDecode(value: string): string {
  return decodeURIComponent(value.replace(/\+/g, " "));
}

async function parseJson<T>(request: Request): Promise<T> {
  return request.json<T>();
}

function isProduction(env: Env): boolean {
  return (env.ENVIRONMENT || "").toLowerCase() === "production";
}

/** Clamp offset>=0, clamp limit to [1, 500] (default = defaultLimit). */
function parsePagination(params: URLSearchParams, defaultLimit: number): { offset: number; limit: number } {
  const offset = Math.max(0, Math.floor(Number(params.get("offset") || 0) || 0));
  const rawLimit = Math.floor(Number(params.get("limit") || defaultLimit) || defaultLimit);
  const limit = Math.min(500, Math.max(1, rawLimit));
  return { offset, limit };
}

async function resolveResendApiKey(env: Env): Promise<string> {
  const raw = env.SS_RESEND_API_KEY;
  if (!raw) return "";
  if (typeof raw === "string") return raw;
  try { return await raw.get(); } catch { return ""; }
}

/**
 * Send email via Resend. Returns { sent: true, messageId } on success, or
 * { sent: false, reason } if the provider is not configured or the request
 * failed. Failures are never thrown — callers decide whether to surface them.
 */
async function sendEmail(env: Env, to: string, subject: string, text: string, html?: string): Promise<{ sent: boolean; messageId?: string; reason?: string }> {
  const apiKey = await resolveResendApiKey(env);
  const from = env.EMAIL_FROM || "accounts@etzhayyim.com";
  if (!apiKey) return { sent: false, reason: "RESEND_API_KEY not configured" };
  const payload: Record<string, unknown> = { from, to: [to], subject, text };
  if (html) payload.html = html;
  try {
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "authorization": `Bearer ${apiKey}`, "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      console.warn(`[authz] resend_api_failed status=${resp.status} body=${body.slice(0, 200)}`);
      return { sent: false, reason: `resend_api_failed:${resp.status}` };
    }
    const parsed = await resp.json<{ id?: string }>().catch(() => ({} as { id?: string }));
    return { sent: true, messageId: parsed.id || "" };
  } catch (e: unknown) {
    console.warn("[authz] resend_api_exception:", e);
    return { sent: false, reason: "resend_api_exception" };
  }
}

// ── Session verification (inline HS256, shared secret with authn) ─────────

let cachedHmacKey: { secret: string; key: CryptoKey } | null = null;

async function importHmacKey(secret: string): Promise<CryptoKey> {
  if (cachedHmacKey && cachedHmacKey.secret === secret) return cachedHmacKey.key;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  cachedHmacKey = { secret, key };
  return key;
}

async function verifySession(secret: string, token: string, expectedScope: string): Promise<Record<string, unknown>> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid token format");
  const [headerB64, payloadB64, sigB64] = parts;
  const key = await importHmacKey(secret);
  const signingInput = `${headerB64}.${payloadB64}`;
  const valid = await crypto.subtle.verify("HMAC", key, decodeBase64Url(sigB64), new TextEncoder().encode(signingInput));
  if (!valid) throw new Error("signature mismatch");
  const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(payloadB64))) as Record<string, unknown>;
  const exp = Number(payload.exp ?? 0);
  if (!exp) throw new Error("missing exp");
  if (nowSecs() > exp) throw new Error("token expired");
  const scope = String(payload.scope ?? "");
  const normalizedScope = scope === "atproto" ? "com.atproto.access" : scope;
  const normalizedExpected = expectedScope === "atproto" ? "com.atproto.access" : expectedScope;
  if (normalizedScope !== normalizedExpected) throw new Error("scope mismatch");
  if (payload.iss !== "https://authn.etzhayyim.com") throw new Error("issuer mismatch");
  return payload;
}

interface SessionAccount {
  accountDid: string;
  activeDid: string;
  handle: string;
  token: string;
  payload: Record<string, unknown>;
}

function getAccessTokenFromRequest(request: Request): string {
  const authorization = request.headers.get("Authorization") || "";
  if (authorization.startsWith("Bearer ")) return authorization.slice("Bearer ".length);
  const cookies = parseCookieHeader(request.headers.get("Cookie") || "");
  return cookies.etzhayyim_session || "";
}

function deriveDefaultHumanDid(accountDid: string): string {
  return accountDid.startsWith("did:web:authn.etzhayyim.com:")
    ? `${accountDid}:person:default`
    : accountDid;
}

async function requireSessionAccount(request: Request, env: Env): Promise<SessionAccount> {
  const token = getAccessTokenFromRequest(request);
  if (!token) throw new Error("missing session");
  const payload = await verifySession(getSessionSecret(env), token, "com.atproto.access");
  const accountDid = String(payload.accountDid ?? payload.sub ?? "");
  if (!accountDid) throw new Error("missing accountDid");
  const activeDid = String(payload.activeDid ?? deriveDefaultHumanDid(accountDid));
  const handle = String(payload.handle ?? accountDid);
  if (env.KEYS_DB) {
    const jti = String(payload.jti ?? "");
    if (jti) {
      const revoked = await env.KEYS_DB.prepare(
        "SELECT 1 FROM revoked_sessions WHERE jti = ? LIMIT 1"
      ).bind(jti).first().catch(() => null);
      if (revoked) throw new Error("session revoked");
    }
  }
  return { accountDid, activeDid, handle, token, payload };
}

// ── Linked auth methods ──────────────────────────────────────────────────────

interface LinkedAuthMethod {
  provider: string;
  providerSubject: string;
  displayLabel: string;
  verified: boolean;
  createdAt: string;
  updatedAt: string;
  metadata?: Record<string, unknown>;
}

interface AuthScoreSummary {
  score: number;
  verifiedMethodCount: number;
  methods: Array<{ provider: string; verified: boolean; label: string }>;
}

function providerDisplayLabel(provider: string, subject: string, metadata?: Record<string, unknown>): string {
  if (provider === "passkey") return "Passkey";
  if (provider === "email") return subject;
  if (provider === "google") return String(metadata?.email || subject);
  if (provider === "microsoft") return String(metadata?.email || subject);
  if (provider === "ethereum" || provider === "coinbase-smart-wallet") {
    // Show the checksum-aware shortened form: 0x1234…abcd
    const addr = subject.startsWith("0x") ? subject : `0x${subject}`;
    const suffix = provider === "coinbase-smart-wallet" ? " Smart Wallet" : "";
    return `${addr.slice(0, 6)}…${addr.slice(-4)}${suffix}`;
  }
  if (provider === "webauthn-additional") {
    const label = String(metadata?.label || "").trim();
    return label || "Additional passkey";
  }
  return subject;
}

function normalizeProvider(provider: string): "email" | "google" | "microsoft" | null {
  const v = provider.trim().toLowerCase();
  if (v === "email") return "email";
  if (v === "google" || v === "gmail") return "google";
  if (v === "microsoft" || v === "azure" || v === "outlook") return "microsoft";
  return null;
}

async function countPasskeysForAccount(env: Env, accountDid: string): Promise<number> {
  if (!env.AUTH_DB) return 0;
  await ensureAuthTables(env);
  const row = await env.AUTH_DB.prepare(
    "SELECT COUNT(*) AS count FROM passkey_credentials WHERE did = ?"
  ).bind(accountDid).first<{ count: number }>();
  return Number(row?.count || 0);
}

async function authStorageDid(env: Env, accountDid: string): Promise<string> {
  const root = await resolveRootIdentity(env, accountDid);
  if (!root.rootIdentity || root.rootDid === accountDid) return accountDid;
  if (env.AUTH_DB) {
    await ensureAuthTables(env);
    const now = nowIso();
    await env.AUTH_DB.prepare(
      "UPDATE OR IGNORE linked_auth_methods SET account_did = ?, updated_at = ? WHERE account_did = ?"
    ).bind(root.rootDid, now, accountDid).run();
    await env.AUTH_DB.prepare(
      "DELETE FROM linked_auth_methods WHERE account_did = ?"
    ).bind(accountDid).run();
  }
  return root.rootDid;
}

async function listLinkedAuthMethods(env: Env, accountDid: string): Promise<LinkedAuthMethod[]> {
  const methods: LinkedAuthMethod[] = [];
  const storageDid = await authStorageDid(env, accountDid);
  const passkeyCount = await countPasskeysForAccount(env, accountDid);
  if (passkeyCount > 0) {
    methods.push({
      provider: "passkey",
      providerSubject: `passkey:${accountDid}`,
      displayLabel: passkeyCount > 1 ? `Passkey (${passkeyCount})` : "Passkey",
      verified: true,
      createdAt: "",
      updatedAt: "",
    });
  }
  if (!env.AUTH_DB) return methods;
  await ensureAuthTables(env);
  const rows = await env.AUTH_DB.prepare(`
    SELECT provider, provider_subject AS providerSubject, display_label AS displayLabel, verified, metadata_json AS metadataJson, created_at AS createdAt, updated_at AS updatedAt
    FROM linked_auth_methods
    WHERE account_did = ?
    ORDER BY provider ASC, created_at ASC
  `).bind(storageDid).all();
  for (const row of (rows.results || []) as Array<{ provider: string; providerSubject: string; displayLabel: string; verified: number; metadataJson?: string | null; createdAt: string; updatedAt: string }>) {
    let metadata: Record<string, unknown> | undefined;
    if (row.metadataJson) {
      try { metadata = JSON.parse(row.metadataJson) as Record<string, unknown>; }
      catch { metadata = undefined; }
    }
    methods.push({
      provider: row.provider,
      providerSubject: row.providerSubject,
      displayLabel: row.displayLabel,
      verified: Boolean(row.verified),
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      metadata,
    });
  }
  return methods;
}

function buildActorScoreSummary(methods: LinkedAuthMethod[]): AuthScoreSummary {
  const uniqueVerified = new Map<string, { provider: string; verified: boolean; label: string }>();
  for (const m of methods) {
    if (!m.verified) continue;
    uniqueVerified.set(m.provider, { provider: m.provider, verified: m.verified, label: m.displayLabel });
  }
  const verifiedMethodCount = uniqueVerified.size;
  return {
    score: Math.max(0, Math.min(100, verifiedMethodCount * 25)),
    verifiedMethodCount,
    methods: methods.map((m) => ({ provider: m.provider, verified: m.verified, label: m.displayLabel })),
  };
}

async function upsertLinkedAuthMethod(
  env: Env,
  accountDid: string,
  provider: string,
  providerSubject: string,
  displayLabel: string,
  verified: boolean,
  metadata?: Record<string, unknown>,
): Promise<void> {
  if (!env.AUTH_DB) return;
  await ensureAuthTables(env);
  const storageDid = await authStorageDid(env, accountDid);
  const now = nowIso();
  await env.AUTH_DB.prepare(`
    INSERT INTO linked_auth_methods (account_did, provider, provider_subject, display_label, verified, metadata_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(account_did, provider, provider_subject) DO UPDATE SET
      display_label=excluded.display_label, verified=excluded.verified,
      metadata_json=excluded.metadata_json, updated_at=excluded.updated_at
  `).bind(storageDid, provider, providerSubject, displayLabel, verified ? 1 : 0,
    metadata ? JSON.stringify(metadata) : null, now, now).run();
}

async function deleteLinkedAuthMethod(env: Env, accountDid: string, provider: string, providerSubject: string): Promise<void> {
  if (!env.AUTH_DB) return;
  await ensureAuthTables(env);
  const storageDid = await authStorageDid(env, accountDid);
  await env.AUTH_DB.prepare(
    "DELETE FROM linked_auth_methods WHERE account_did = ? AND provider = ? AND provider_subject = ?"
  ).bind(storageDid, provider, providerSubject).run();
}

async function syncAuthMethodToGraph(env: Env, accountDid: string, provider: string, email: string, verified: boolean): Promise<void> {
  const rootDid = await authStorageDid(env, accountDid);
  if (!rootDid.startsWith("did:erc725:")) return;
  if (!env.AUTH_DB) return;
  await ensureAuthTables(env);
  const row = await env.AUTH_DB.prepare(
    "SELECT auth_methods_summary, actor_score FROM vertex_etzhayyim_auth_account WHERE vertex_id = ? LIMIT 1"
  ).bind(rootDid).first<{ auth_methods_summary: string; actor_score: number }>();
  if (!row) return;

  const methods: Array<Record<string, unknown>> = JSON.parse(row.auth_methods_summary || "[]");
  const existing = methods.findIndex((m) => m.provider === provider || m.id === `#${provider}`);
  const type = provider === "email"
    ? "EmailVerification"
    : (provider === "ethereum" || provider === "coinbase-smart-wallet") ? "WalletProof" : "OIDCProvider";
  const entry: Record<string, unknown> = { id: `#${provider}`, type, provider, verified };
  if (existing >= 0) methods[existing] = entry;
  else methods.push(entry);

  const verifiedTypes = new Set<string>();
  for (const m of methods) {
    if (m.verified || m.primary) {
      verifiedTypes.add(String(m.type) === "WebAuthnAuthenticator" ? "passkey" : String(m.provider || m.type));
    }
  }
  const score = Math.min(verifiedTypes.size * 25, 100);
  await env.AUTH_DB.prepare(
    "UPDATE vertex_etzhayyim_auth_account SET auth_methods_summary = ?, actor_score = ?, updated_at = ? WHERE vertex_id = ?"
  ).bind(JSON.stringify(methods), score, nowIso(), rootDid).run();

  if (env.PDS_SERVICE) {
    // ADR-0036: auth-control graph edges (edge_etzhayyim_authenticates) follow the
    // same PDS pipethrough exception as vault/signal/messaging — this Worker
    // is intentionally zero-npm and has no HYPERDRIVE binding. The call is
    // non-fatal (see .catch below) so sync failures never block auth.
    const now = nowIso();
    env.PDS_SERVICE.fetch("https://atproto.etzhayyim.com/xrpc/com.etzhayyim.graph.batchInsert", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-kotodama-verified": "true" },
      body: JSON.stringify({
        edges: [{
          table: "edge_etzhayyim_authenticates",
          edge_id: `${rootDid}:auth:${provider}`,
          src_vid: rootDid,
          dst_vid: `${provider}:${rootDid}`,
          auth_type: provider === "email" ? "EmailVerification" : "OIDCProvider",
          provider,
          email,
          verified: verified ? 1 : 0,
          is_primary: 0,
          linked_at: now,
        }],
      }),
    }).catch((e: unknown) => console.warn("[authz] graph sync failed (non-fatal):", e));
  }
}

// ── HMAC OAuth code (stateless, no KV/DO) ────────────────────────────────────

interface OAuthStateCode {
  code: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  state: string;
  did: string;
  handle: string;
  expiresAt: number;
}

async function encodeOAuthCode(secret: string, payload: OAuthStateCode): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const data = new TextEncoder().encode(JSON.stringify(payload));
  const sig = await crypto.subtle.sign("HMAC", key, data);
  return `${encodeBase64Url(new Uint8Array(data))}.${encodeBase64Url(new Uint8Array(sig))}`;
}

async function decodeOAuthCode(secret: string, token: string): Promise<OAuthStateCode | null> {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  try {
    const data = decodeBase64Url(parts[0]);
    const sig = decodeBase64Url(parts[1]);
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"],
    );
    const valid = await crypto.subtle.verify("HMAC", key, sig, data);
    if (!valid) return null;
    return JSON.parse(new TextDecoder().decode(data)) as OAuthStateCode;
  } catch { return null; }
}

function oauthLinkRedirectUri(request: Request, provider: "google" | "microsoft"): string {
  return `${new URL(request.url).origin}/oauth/link/${provider}/callback`;
}

async function exchangeOAuthCode(provider: "google" | "microsoft", request: Request, env: Env, code: string): Promise<Record<string, unknown>> {
  const redirectUri = oauthLinkRedirectUri(request, provider);
  const clientId = provider === "google" ? getGoogleOauthClientId(env) : getMicrosoftOauthClientId(env);
  const clientSecret = provider === "google" ? getGoogleOauthClientSecret(env) : getMicrosoftOauthClientSecret(env);
  if (!clientId || !clientSecret) throw new Error(`${provider} OAuth is not configured`);
  const tokenUrl = provider === "google"
    ? "https://oauth2.googleapis.com/token"
    : "https://login.microsoftonline.com/common/oauth2/v2.0/token";
  const params = new URLSearchParams({ client_id: clientId, client_secret: clientSecret, code, grant_type: "authorization_code", redirect_uri: redirectUri });
  const tokenResp = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  if (!tokenResp.ok) throw new Error(`${provider} token exchange failed`);
  const tokenBody = await tokenResp.json() as { access_token?: string };
  const accessToken = String(tokenBody.access_token || "");
  if (!accessToken) throw new Error(`${provider} access token missing`);
  if (provider === "google") {
    const resp = await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { Authorization: `Bearer ${accessToken}` } });
    if (!resp.ok) throw new Error("google profile fetch failed");
    return resp.json();
  }
  const resp = await fetch("https://graph.microsoft.com/v1.0/me", { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) throw new Error("microsoft profile fetch failed");
  return resp.json();
}

function renderLinkResultPage(success: boolean, provider: string, errorMsg?: string): string {
  const status = success ? "Linked" : "Failed";
  const message = success
    ? `${provider} account linked successfully.`
    : `Failed to link ${provider}: ${errorMsg || "unknown error"}`;
  return `<!doctype html><html><head><title>${provider} Link ${status}</title></head><body>
<script>
  const msg = ${JSON.stringify(message)};
  const ok = ${success};
  if (window.opener) {
    window.opener.postMessage({ type: 'oauth-link-result', ok, provider: ${JSON.stringify(provider)}, message: msg }, '*');
    window.close();
  } else {
    const redirectUrl = ok ? '/manage?linked=${provider.toLowerCase()}' : '/manage?error=' + encodeURIComponent(msg);
    setTimeout(() => { window.location.href = redirectUrl; }, 500);
  }
</script>
<p>${message}</p></body></html>`;
}

// ── XRPC Handlers ──────────────────────────────────────────────────────────

async function handleGetSession(request: Request, env: Env): Promise<Response> {
  const token = getAccessTokenFromRequest(request);
  if (!token) return json({ ok: false, authenticated: false }, 200);
  try {
    const payload = await verifySession(getSessionSecret(env), token, "com.atproto.access");
    const accountDid = String(payload.accountDid ?? payload.sub ?? "");
    if (!accountDid) return json({ ok: false, authenticated: false }, 200);
    const activeDid = String(payload.activeDid ?? deriveDefaultHumanDid(accountDid));
    const handle = String(payload.handle ?? accountDid);
    const rootIdentity = await resolveRootIdentity(env, accountDid);

    // Load linked methods + actor score
    const linkedMethods = await listLinkedAuthMethods(env, accountDid);
    const actorScore = buildActorScoreSummary(linkedMethods);

    return json({
      ok: true,
      authenticated: true,
      accountDid,
      rootDid: rootIdentity.rootDid,
      rootDidHash: rootIdentity.rootDidHash,
      rootIdentity: rootIdentity.rootIdentity,
      migratedRoot: rootIdentity.migrated,
      resolvedFromFacade: rootIdentity.resolvedFromFacade,
      activeDid,
      handle,
      linkedMethods,
      actorScore,
    });
  } catch {
    return json({ ok: false, authenticated: false }, 200);
  }
}

async function handleLinkEmailBegin(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB is required");
  try {
    const session = await requireSessionAccount(request, env);
    const storageDid = await authStorageDid(env, session.accountDid);
    const body = await parseJson<{ email: string }>(request);
    const email = String(body.email || "").trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return jsonErr(400, "BadRequest", "valid email is required");
    await ensureAuthTables(env);
    const code = generateOtp();
    const expiresAt = nowSecs() + 600;
    await env.AUTH_DB.prepare(`
      INSERT OR REPLACE INTO email_link_codes (account_did, email, code, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(storageDid, email, code, expiresAt, nowIso()).run();
    const subject = "etzhayyim — Email verification code";
    const text = `Your etzhayyim email verification code is: ${code}\n\nThis code expires in 10 minutes. If you didn't request it, you can ignore this message.`;
    const delivery = await sendEmail(env, email, subject, text);
    if (!isProduction(env)) {
      console.log(`[authz] EMAIL LINK CODE ${storageDid} ${email} -> ${code} (delivery.sent=${delivery.sent})`);
    }
    const resp: Record<string, unknown> = { sent: delivery.sent, email, expiresIn: 600 };
    if (!delivery.sent) resp.deliveryError = delivery.reason || "email_not_sent";
    // Only expose the raw code in non-production, to keep dev ergonomics without
    // leaking OTPs in logs/responses once ENVIRONMENT=production is set.
    if (!isProduction(env)) resp.debugCode = code;
    return json(resp);
  } catch (error) {
    if (error instanceof Error && error.message.includes("ERC725 root identity")) {
      return jsonErr(409, "RootIdentityRequired", error.message);
    }
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function handleLinkEmailVerify(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB is required");
  try {
    const session = await requireSessionAccount(request, env);
    const storageDid = await authStorageDid(env, session.accountDid);
    const body = await parseJson<{ email: string; code: string }>(request);
    const email = String(body.email || "").trim().toLowerCase();
    const code = String(body.code || "").trim();
    await ensureAuthTables(env);
    const row = await env.AUTH_DB.prepare(
      "SELECT code, expires_at AS expiresAt FROM email_link_codes WHERE account_did = ? AND email = ? LIMIT 1"
    ).bind(storageDid, email).first<{ code: string; expiresAt: number }>();
    if (!row || row.code !== code || Number(row.expiresAt || 0) < nowSecs()) {
      return jsonErr(401, "InvalidCode", "invalid or expired code");
    }
    await env.AUTH_DB.prepare(
      "DELETE FROM email_link_codes WHERE account_did = ? AND email = ?"
    ).bind(storageDid, email).run();
    await upsertLinkedAuthMethod(env, session.accountDid, "email", email, email, true, { email, verifiedAt: nowIso() });
    await syncAuthMethodToGraph(env, session.accountDid, "email", email, true);
    const methods = await listLinkedAuthMethods(env, session.accountDid);
    return json({ ok: true, linkedMethods: methods, actorScore: buildActorScoreSummary(methods) });
  } catch (error) {
    if (error instanceof Error && error.message.includes("ERC725 root identity")) {
      return jsonErr(409, "RootIdentityRequired", error.message);
    }
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function handleLinkOAuthStart(request: Request, env: Env): Promise<Response> {
  try {
    const session = await requireSessionAccount(request, env);
    const storageDid = await authStorageDid(env, session.accountDid);
    const body = await parseJson<{ provider: string }>(request);
    const provider = normalizeProvider(String(body.provider || ""));
    if (!provider || provider === "email") return jsonErr(400, "BadRequest", "provider must be google or microsoft");
    const clientId = provider === "google" ? getGoogleOauthClientId(env) : getMicrosoftOauthClientId(env);
    if (!clientId) return jsonErr(503, "ConfigError", `${provider} OAuth is not configured`);

    const redirectUri = oauthLinkRedirectUri(request, provider);
    const state = await encodeOAuthCode(getSessionSecret(env) || "fallback", {
      code: "",
      clientId,
      redirectUri,
      codeChallenge: "",
      codeChallengeMethod: "S256",
      state: crypto.randomUUID(),
      did: storageDid,
      handle: session.handle,
      expiresAt: nowSecs() + 600,
    });

    const authorizationUrl = provider === "google"
      ? `https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent("openid email profile")}&state=${encodeURIComponent(state)}&access_type=offline&prompt=consent`
      : `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent("openid email profile User.Read")}&response_mode=query&state=${encodeURIComponent(state)}`;

    return json({ ok: true, authorizationUrl, provider });
  } catch (error) {
    if (error instanceof Error && error.message.includes("ERC725 root identity")) {
      return jsonErr(409, "RootIdentityRequired", error.message);
    }
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function handleUnlinkMethod(request: Request, env: Env): Promise<Response> {
  try {
    const session = await requireSessionAccount(request, env);
    const body = await parseJson<{ provider: string; providerSubject: string }>(request);
    if (body.provider === "passkey") return jsonErr(400, "BadRequest", "passkey cannot be removed here");
    const provider = String(body.provider || "");
    const providerSubject = String(body.providerSubject || "");

    // For additional WebAuthn devices we also have to drop the underlying
    // credential row, otherwise the device would still be able to sign in
    // (passkey_credentials is what passkeyVerifyAuth resolves against). The
    // last *signin-eligible* device must remain — refuse to remove it.
    if (provider === "webauthn-additional" && env.AUTH_DB) {
      const remaining = await countPasskeysForAccount(env, session.accountDid);
      if (remaining <= 1) {
        return jsonErr(400, "BadRequest", "cannot remove the last passkey on this account");
      }
      await env.AUTH_DB.prepare(
        "DELETE FROM passkey_credentials WHERE credential_id = ? AND did = ?"
      ).bind(providerSubject, session.accountDid).run();
      await env.AUTH_DB.prepare(
        "DELETE FROM additional_passkey_labels WHERE credential_id = ? AND account_did = ?"
      ).bind(providerSubject, session.accountDid).run();
    }

    if ((provider === "ethereum" || provider === "coinbase-smart-wallet") && env.AUTH_DB) {
      const storageDid = await authStorageDid(env, session.accountDid);
      // Drop any pending nonce so a stale begin/verify pair can't resurrect
      // the link silently after unlink.
      await env.AUTH_DB.prepare(
        "DELETE FROM siwe_link_nonces WHERE account_did = ? AND address = ?"
      ).bind(storageDid, providerSubject).run();
    }

    await deleteLinkedAuthMethod(env, session.accountDid, provider, providerSubject);
    const methods = await listLinkedAuthMethods(env, session.accountDid);
    return json({ ok: true, linkedMethods: methods, actorScore: buildActorScoreSummary(methods) });
  } catch (error) {
    if (error instanceof Error && error.message.includes("ERC725 root identity")) {
      return jsonErr(409, "RootIdentityRequired", error.message);
    }
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

// ── ADR-0074 Phase 1 — Ethereum (SIWE) link as authenticated linked method ──

function getEthChainId(env: Env): number {
  const raw = String(env.ETH_PRIVATE_CHAIN_ID || "").trim();
  if (!raw) return 0;
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) return 0;
  return n;
}

async function handleLinkEthereumBegin(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB is required");
  const chainId = getEthChainId(env);
  if (!chainId) return jsonErr(503, "ConfigError", "ETH_PRIVATE_CHAIN_ID is not configured");
  try {
    const session = await requireSessionAccount(request, env);
    const rootIdentity = await requireRootIdentity(env, session.accountDid);
    const body = await parseJson<{ address: string; statement?: string; walletKind?: string }>(request);
    const rawAddress = String(body.address || "").trim();
    if (!isValidAddress(rawAddress)) return jsonErr(400, "BadRequest", "address must be a 0x-prefixed 20-byte hex string");
    const address = normalizeAddress(rawAddress);

    await ensureAuthTables(env);
    const nonce = generateSiweNonce();
    const issuedAt = new Date();
    const expirationTime = new Date(issuedAt.getTime() + 5 * 60 * 1000); // 5 min
    const expiresAt = Math.floor(expirationTime.getTime() / 1000);

    await env.AUTH_DB.prepare(`
      INSERT INTO siwe_link_nonces (account_did, address, nonce, chain_id, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(account_did, address) DO UPDATE SET
        nonce=excluded.nonce, chain_id=excluded.chain_id,
        expires_at=excluded.expires_at, created_at=excluded.created_at
    `).bind(rootIdentity.rootDid, address, nonce, chainId, expiresAt, nowIso()).run();

    const url = new URL(request.url);
    const domain = url.hostname;
    const uri = `${url.protocol}//${url.host}`;
    const statement = (body.statement && String(body.statement).trim())
      || `Link this Ethereum address to ${rootIdentity.rootDid} on etzhayyim.`;

    const message = buildSiweMessage({
      domain,
      address,
      statement,
      uri,
      chainId,
      nonce,
      issuedAt,
      expirationTime,
    });

    return json({ message, nonce, chainId, expiresAt });
  } catch (error) {
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function handleLinkEthereumVerify(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB is required");
  const expectedChainId = getEthChainId(env);
  if (!expectedChainId) return jsonErr(503, "ConfigError", "ETH_PRIVATE_CHAIN_ID is not configured");
  try {
    const session = await requireSessionAccount(request, env);
    const rootIdentity = await requireRootIdentity(env, session.accountDid);
    const body = await parseJson<{ message: string; signature: string; walletKind?: string }>(request);
    const message = String(body.message || "");
    const signature = String(body.signature || "");
    if (!message || !signature) return jsonErr(400, "BadRequest", "message and signature are required");

    let parsed;
    try { parsed = parseSiweMessage(message); }
    catch (e) { return jsonErr(400, "BadRequest", e instanceof Error ? e.message : "invalid SIWE message"); }

    if (parsed.chainId !== expectedChainId) {
      return jsonErr(400, "InvalidChainId", `expected chainId=${expectedChainId}, got ${parsed.chainId}`);
    }

    if (parsed.expirationTime) {
      const exp = Date.parse(parsed.expirationTime);
      if (Number.isFinite(exp) && exp <= Date.now()) {
        return jsonErr(400, "MessageExpired", "SIWE message has expired");
      }
    }

    await ensureAuthTables(env);
    const nonceRow = await env.AUTH_DB.prepare(
      "SELECT nonce, chain_id AS chainId, expires_at AS expiresAt FROM siwe_link_nonces WHERE account_did = ? AND address = ? LIMIT 1"
    ).bind(rootIdentity.rootDid, parsed.address).first<{ nonce: string; chainId: number; expiresAt: number }>();
    if (!nonceRow || nonceRow.nonce !== parsed.nonce || Number(nonceRow.expiresAt || 0) < nowSecs()) {
      return jsonErr(401, "InvalidNonce", "nonce is unknown, expired, or not bound to this account");
    }
    if (Number(nonceRow.chainId) !== expectedChainId) {
      return jsonErr(400, "InvalidChainId", "stored chainId does not match server configuration");
    }

    const hash = personalSignHash(message);
    const hashHex = "0x" + bytesToHex(hash);
    let verificationKind: "eoa" | "erc1271" | null = null;
    let recovered: string | null = null;
    let eoaError = "";

    try {
      recovered = recoverEthAddress(hash, signature);
      if (recovered.toLowerCase() === parsed.address) verificationKind = "eoa";
    } catch (e) {
      eoaError = e instanceof Error ? e.message : "signature recovery failed";
    }

    if (!verificationKind) {
      const erc1271Valid = await isValidErc1271Signature(env, parsed.address, hashHex, signature);
      if (erc1271Valid) verificationKind = "erc1271";
    }

    if (!verificationKind) {
      const reason = recovered
        ? "recovered address does not match SIWE message and ERC-1271 validation failed"
        : `${eoaError || "EOA recovery failed"}; ERC-1271 validation failed`;
      return jsonErr(401, "InvalidSignature", reason);
    }

    // Single-use: drop the nonce before the linked-method write so a parallel
    // verify on the same nonce loses the race cleanly.
    await env.AUTH_DB.prepare(
      "DELETE FROM siwe_link_nonces WHERE account_did = ? AND address = ?"
    ).bind(rootIdentity.rootDid, parsed.address).run();

    const didPkh = didPkhFromAddress(expectedChainId, parsed.address);
    const walletKindHint = String(body.walletKind || "").trim().toLowerCase();
    const provider = verificationKind === "erc1271" || walletKindHint === "coinbase-smart-wallet"
      ? "coinbase-smart-wallet"
      : "ethereum";
    await upsertLinkedAuthMethod(
      env,
      session.accountDid,
      provider,
      parsed.address,
      providerDisplayLabel(provider, parsed.address),
      true,
      {
        rootDid: rootIdentity.rootDid,
        rootDidHash: rootIdentity.rootDidHash,
        rootIdentity: rootIdentity.rootIdentity,
        rootRegistryAddr: rootIdentity.registryAddr,
        migratedRoot: rootIdentity.migrated,
        resolvedFromFacade: rootIdentity.resolvedFromFacade,
        walletAddress: parsed.address,
        chainId: expectedChainId,
        verifiedAt: nowIso(),
        verificationKind,
        walletKind: provider,
        siweHash: hashHex,
      },
    );
    await syncAuthMethodToGraph(env, session.accountDid, provider, parsed.address, true);

    // Phase 2-B: if a smart account is already activated on-chain for this
    // root identity, persist it as a second ethereum-actor linked method so
    // callers get the full picture without a separate getActorAccount call.
    let smartAccount: string | null = null;
    if ((env.ETH_PRIVATE_RPC_URL || "").trim() && (env.etzhayyim_ACTOR_REGISTRY_ADDR || "").trim()) {
      try {
        const snap = await snapshotActorAccount(env, session.accountDid);
        if (snap.activated && snap.smartAccount) {
          smartAccount = snap.smartAccount;
          await upsertLinkedAuthMethod(
            env,
            session.accountDid,
            "ethereum-actor",
            snap.smartAccount,
            `Smart Account (${snap.smartAccount.slice(0, 6)}…${snap.smartAccount.slice(-4)})`,
            true,
            {
              smartAccount: snap.smartAccount,
              didHash: snap.didHash,
              chainId: snap.chainId,
              registryAddr: snap.registryAddr,
              linkedAt: nowIso(),
            },
          );
          await syncAuthMethodToGraph(env, session.accountDid, "ethereum-actor", snap.smartAccount, true);
        }
      } catch { /* best-effort — don't fail the SIWE verify if chain is unreachable */ }
    }

    const methods = await listLinkedAuthMethods(env, session.accountDid);
    return json({
      ok: true,
      address: parsed.address,
      walletAddress: parsed.address,
      provider,
      verificationKind,
      smartAccount,
      linkedMethods: methods,
      actorScore: buildActorScoreSummary(methods),
    });
  } catch (error) {
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

// ── ADR-0074 Phase 1 — multi-device WebAuthn (additional passkey) ────────────

async function handleLinkPasskeyAdditionalBegin(request: Request, env: Env): Promise<Response> {
  try {
    const session = await requireSessionAccount(request, env);
    // Reuse the canonical registration challenge generator. user.id in the
    // returned options is opaque to WebAuthn — we tag it with the session
    // accountDid so the client can confirm later, but the binding that
    // matters is enforced server-side in linkPasskeyAdditionalVerify (we
    // INSERT with did = session.accountDid regardless of the client value).
    const userName = session.handle || session.accountDid;
    const options = beginRegistration(session.accountDid, userName);
    return json(options);
  } catch (error) {
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function handleLinkPasskeyAdditionalVerify(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB is required");
  try {
    const session = await requireSessionAccount(request, env);
    const body = await parseJson<{
      challenge: string;
      clientDataJson: string;
      attestationObject: string;
      label?: string;
    }>(request);

    let credential;
    try {
      credential = await verifyRegistration(
        String(body.challenge || ""),
        String(body.clientDataJson || ""),
        String(body.attestationObject || ""),
      );
    } catch (e) {
      return jsonErr(400, "AttestationFailed", e instanceof Error ? e.message : "attestation verification failed");
    }

    await ensureAuthTables(env);
    const handle = session.handle || session.accountDid;
    const label = String(body.label || "").trim();
    const now = nowIso();

    // INSERT into passkey_credentials so the device can drive primary signin
    // next time (passkeyVerifyAuth resolves credential_id → did from this
    // table). did is taken from the server session — never trusted from the
    // client — which is what makes this "additional passkey on existing
    // account" rather than "new account".
    await env.AUTH_DB.prepare(`
      INSERT INTO passkey_credentials (
        credential_id, did, handle, public_key_b64, sign_count, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(credential_id) DO UPDATE SET
        public_key_b64=excluded.public_key_b64,
        sign_count=excluded.sign_count,
        updated_at=excluded.updated_at
    `).bind(
      credential.credentialId,
      session.accountDid,
      handle,
      credential.publicKeyB64,
      credential.signCount >>> 0,
      now,
      now,
    ).run();

    if (label) {
      await env.AUTH_DB.prepare(`
        INSERT INTO additional_passkey_labels (credential_id, account_did, label, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(credential_id) DO UPDATE SET label=excluded.label
      `).bind(credential.credentialId, session.accountDid, label, now).run();
    }

    await upsertLinkedAuthMethod(
      env,
      session.accountDid,
      "webauthn-additional",
      credential.credentialId,
      providerDisplayLabel("webauthn-additional", credential.credentialId, { label }),
      true,
      { label, addedAt: now },
    );

    const methods = await listLinkedAuthMethods(env, session.accountDid);
    return json({
      ok: true,
      credentialId: credential.credentialId,
      linkedMethods: methods,
      actorScore: buildActorScoreSummary(methods),
    });
  } catch (error) {
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function handleOAuthLinkCallback(request: Request, env: Env, provider: "google" | "microsoft"): Promise<Response> {
  const url = new URL(request.url);
  const stateToken = url.searchParams.get("state") || "";
  const code = url.searchParams.get("code") || "";
  if (!stateToken || !code) return htmlResp(renderLinkResultPage(false, provider, "missing code or state"));
  try {
    const state = await decodeOAuthCode(getSessionSecret(env) || "fallback", stateToken);
    if (!state || !state.did || Number(state.expiresAt || 0) < nowSecs()) {
      return htmlResp(renderLinkResultPage(false, provider, "state is invalid or expired"));
    }
    const profile = await exchangeOAuthCode(provider, request, env, code);
    const subject = provider === "google"
      ? String(profile.sub || profile.email || "")
      : String((profile as Record<string, unknown>).id || (profile as Record<string, unknown>).userPrincipalName || (profile as Record<string, unknown>).mail || "");
    const email = provider === "google"
      ? String(profile.email || "")
      : String((profile as Record<string, unknown>).mail || (profile as Record<string, unknown>).userPrincipalName || "");
    if (!subject) return htmlResp(renderLinkResultPage(false, provider, "provider account id missing"));
    const verified = provider === "google" ? Boolean((profile as Record<string, unknown>).email_verified ?? true) : true;
    await upsertLinkedAuthMethod(env, state.did, provider, subject, providerDisplayLabel(provider, subject, { email }), verified, { email, profile });
    await syncAuthMethodToGraph(env, state.did, provider, email, verified);
    return htmlResp(renderLinkResultPage(true, provider));
  } catch (error) {
    return htmlResp(renderLinkResultPage(false, provider, error instanceof Error ? error.message : "link failed"));
  }
}

function htmlResp(body: string): Response {
  return new Response(body, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-cache",
      "access-control-allow-origin": "*",
    },
  });
}

// ── ADR-0074 Phase 2-B — smart-account address resolver ─────────────────────

async function handleGetActorAccount(request: Request, env: Env): Promise<Response> {
  if (!(env.ETH_PRIVATE_RPC_URL || "").trim()) {
    return jsonErr(503, "ConfigError", "ETH_PRIVATE_RPC_URL is not configured");
  }
  if (!(env.etzhayyim_ACTOR_REGISTRY_ADDR || "").trim()) {
    return jsonErr(503, "ConfigError", "etzhayyim_ACTOR_REGISTRY_ADDR is not configured");
  }
  let session: SessionAccount;
  try { session = await requireSessionAccount(request, env); }
  catch (e) { return jsonErr(401, "AuthRequired", e instanceof Error ? e.message : "auth required"); }

  try {
    const snap = await snapshotActorAccount(env, session.accountDid);
    return json(snap);
  } catch (e) {
    if (e instanceof Error && e.message.includes("ERC725 root identity")) {
      return jsonErr(409, "RootIdentityRequired", e.message);
    }
    return jsonErr(502, "RpcError", e instanceof Error ? e.message : "rpc failed");
  }
}

// ── Public GCC balance lookup (no auth required) ────────────────────────────

const _ACTOR_BY_DID_SEL = selector("actorByDid(bytes32)");

/**
 * GET /xrpc/com.etzhayyim.authz.getActorTokenBalance?did={did}
 *
 * Public endpoint — no session required. Looks up the caller's (or any DID's)
 * smart-account address on-chain via etzhayyimActorRegistry, then reads the GCC
 * (GCCStablecoin) balance. Returns wei as a decimal string.
 */
async function handleGetActorTokenBalance(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const did = (url.searchParams.get("did") || "").trim();
  if (!did) return jsonErr(400, "InvalidRequest", "did query parameter is required");

  const registryAddr = (env.etzhayyim_ACTOR_REGISTRY_ADDR || "").trim();
  const gccAddr = (env.etzhayyim_CREDIT_ADDR || "").trim();
  if (!registryAddr || !gccAddr) return jsonErr(503, "ConfigError", "chain config missing");
  if (!(env.ETH_PRIVATE_RPC_URL || "").trim()) return jsonErr(503, "ConfigError", "ETH_PRIVATE_RPC_URL not configured");

  try {
    const didHash = keccakHex(did);
    const addrCalldata = _ACTOR_BY_DID_SEL + didHash.slice(2);
    const rawAddr = await ethCall(env, registryAddr, addrCalldata);
    const smartAccount = decodeAddress(rawAddr);

    if (isZeroAddress(smartAccount)) {
      return json({ did, smartAccount: null, gccBalance: "0", activated: false });
    }

    const gccBalance = await fetchGccBalance(env, smartAccount);
    return json({ did, smartAccount, gccBalance, activated: true });
  } catch (e) {
    return jsonErr(502, "RpcError", e instanceof Error ? e.message : "rpc failed");
  }
}

// ── ADR-0074 Phase 2-B.2 — activate caller's smart account ──────────────────

async function handleActivateActorAccount(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB is required");
  if (!(env.ETH_PRIVATE_RPC_URL || "").trim()) {
    return jsonErr(503, "ConfigError", "ETH_PRIVATE_RPC_URL is not configured");
  }
  if (!(env.etzhayyim_ACTOR_REGISTRY_ADDR || "").trim()) {
    return jsonErr(503, "ConfigError", "etzhayyim_ACTOR_REGISTRY_ADDR is not configured");
  }
  if (!(env.SEALER_PRIV || "").trim()) {
    return jsonErr(503, "ConfigError", "SEALER_PRIV is not configured");
  }
  let session: SessionAccount;
  try { session = await requireSessionAccount(request, env); }
  catch (e) { return jsonErr(401, "AuthRequired", e instanceof Error ? e.message : "auth required"); }

  try {
    const result = await activateActorAccount(env, env.AUTH_DB, session.accountDid);
    return json(result);
  } catch (e) {
    const err = e as Error & { code?: string };
    if (err.message?.includes("ERC725 root identity")) return jsonErr(409, "RootIdentityRequired", err.message);
    if (err.code === "PasskeyMissing") return jsonErr(409, "PasskeyMissing", err.message);
    if (err.code === "TxRevert")       return jsonErr(502, "TxRevert", err.message);
    return jsonErr(502, "RpcError", err.message ?? "activation failed");
  }
}

/**
 * POST /xrpc/com.etzhayyim.authz.switchActiveDid
 * Body: { activeDid }
 * Proxies to authn (AUTHN_SERVICE) which re-issues the session JWT with the
 * new activeDid. Set-Cookie header is forwarded back so the browser picks up
 * the new session cookie on .etzhayyim.com.
 */
async function handleSwitchActiveDidProxy(request: Request, env: Env): Promise<Response> {
  if (!env.AUTHN_SERVICE) return jsonErr(503, "ConfigError", "AUTHN_SERVICE binding required");
  // Validate the caller has a session before we forward — returns clean 401 on absence.
  try { await requireSessionAccount(request, env); }
  catch (error) { return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required"); }

  const bodyText = await request.text();
  const upstream = await env.AUTHN_SERVICE.fetch("https://authn.etzhayyim.com/xrpc/com.etzhayyim.auth.switchActiveDid", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      // Forward the session cookie so authn's getAccessTokenFromRequest resolves it.
      "cookie": request.headers.get("Cookie") || "",
      "authorization": request.headers.get("Authorization") || "",
    },
    body: bodyText,
  });
  const respText = await upstream.text();
  const headers: Record<string, string> = {
    "content-type": upstream.headers.get("content-type") || "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
  };
  const setCookie = upstream.headers.get("set-cookie");
  if (setCookie) headers["Set-Cookie"] = setCookie;
  return new Response(respText, { status: upstream.status, headers });
}

// ── Org management handlers ──────────────────────────────────────────────────

interface OrgInfo {
  orgDid: string;
  name: string;
  domain: string | null;
  orgType: string;
  settings: Record<string, unknown>;
  memberCount?: number;
  createdAt: string;
}

interface OrgMember {
  memberDid: string;
  role: string;
  invitedBy: string | null;
  joinedAt: string;
  status: string;
}

/** Generate a HMAC invite token bound to org+email+expiry. */
async function encodeInviteToken(secret: string, orgDid: string, email: string, role: string, expiresAt: number): Promise<string> {
  const payload = { orgDid, email, role, expiresAt, nonce: crypto.randomUUID() };
  return encodeOAuthCode(secret, {
    code: "", clientId: "", redirectUri: "", codeChallenge: "", codeChallengeMethod: "S256",
    state: "", did: orgDid, handle: email, expiresAt,
    ...payload,
  } as unknown as OAuthStateCode);
}

async function decodeInviteToken(secret: string, token: string): Promise<{ orgDid: string; email: string; role: string; expiresAt: number } | null> {
  const decoded = await decodeOAuthCode(secret, token);
  if (!decoded) return null;
  const orgDid = (decoded as unknown as Record<string, string>).orgDid || decoded.did;
  const email = (decoded as unknown as Record<string, string>).email || decoded.handle;
  const role = (decoded as unknown as Record<string, string>).role || "member";
  const expiresAt = decoded.expiresAt;
  if (!orgDid || !email || !expiresAt) return null;
  return { orgDid, email, role, expiresAt };
}

async function rootDidFor(env: Env, did: string): Promise<string> {
  // resolveRootIdentity falls back to accountDid when no ERC725 identity is linked (Account=Actor=Org).
  const resolved = await resolveRootIdentity(env, did);
  return resolved.rootDid;
}

async function orgDidForInput(env: Env, provided: string | undefined, fallbackRootDid: string): Promise<string> {
  const raw = String(provided || "").trim();
  return raw ? rootDidFor(env, raw) : fallbackRootDid;
}

function rootRequiredResponse(error: unknown): Response | null {
  return error instanceof Error && error.message.includes("ERC725 root identity")
    ? jsonErr(409, "RootIdentityRequired", error.message)
    : null;
}

/**
 * POST /xrpc/com.etzhayyim.authz.orgCreate
 * Body: { name, domain?, orgType? }
 * Creates (or upgrades) the caller's account DID as an org.
 * Account = Actor = Org (CLAUDE.md §CRITICAL). Personal accounts are already orgs.
 */
async function handleOrgCreate(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB required");
  try {
    const session = await requireSessionAccount(request, env);
    const orgDid = await rootDidFor(env, session.accountDid);
    const body = await parseJson<{ name: string; domain?: string; orgType?: string }>(request);
    const name = String(body.name || "").trim();
    if (!name || name.length < 2) return jsonErr(400, "BadRequest", "name must be at least 2 characters");
    const domain = body.domain ? String(body.domain).trim().toLowerCase() : null;
    const orgType = ["personal", "company", "npo", "community", "team"].includes(String(body.orgType || "personal"))
      ? String(body.orgType || "personal")
      : "personal";
    const now = nowIso();
    await ensureAuthTables(env);

    // Upsert org vertex
    await env.AUTH_DB.prepare(`
      INSERT INTO vertex_etzhayyim_auth_org (vertex_id, sensitivity_ord, owner_did, org_did, name, domain, org_type, settings_json, created_at, updated_at)
      VALUES (?, 2, ?, ?, ?, ?, ?, '{}', ?, ?)
      ON CONFLICT(vertex_id) DO UPDATE SET
        name=excluded.name, domain=excluded.domain, org_type=excluded.org_type, updated_at=excluded.updated_at
    `).bind(orgDid, orgDid, orgDid, name, domain, orgType, now, now).run();

    // Update account performer_type to organization (if not already)
    await env.AUTH_DB.prepare(
      "UPDATE vertex_etzhayyim_auth_account SET performer_type='organization', updated_at=? WHERE vertex_id=?"
    ).bind(now, orgDid).run();

    // Auto-add creator as owner member
    await env.AUTH_DB.prepare(`
      INSERT INTO edge_etzhayyim_auth_member (edge_id, src_vid, dst_vid, sensitivity_ord, owner_did, org_did, member_did, role, invited_by, joined_at, status)
      VALUES (?, ?, ?, 2, ?, ?, ?, 'owner', NULL, ?, 'active')
      ON CONFLICT(org_did, member_did) DO UPDATE SET role='owner', status='active', joined_at=excluded.joined_at
    `).bind(`${orgDid}:member:${orgDid}`, orgDid, orgDid,
      orgDid, orgDid, orgDid, now).run();

    return json({ ok: true, orgDid, name, domain, orgType });
  } catch (error) {
    const rootErr = rootRequiredResponse(error);
    if (rootErr) return rootErr;
    return jsonErr(error instanceof Error && error.message === "missing session" ? 401 : 400,
      "Error", error instanceof Error ? error.message : "org creation failed");
  }
}

/**
 * GET /xrpc/com.etzhayyim.authz.orgInfo?orgDid=...
 */
async function handleOrgInfo(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB required");
  const url = new URL(request.url);
  const rawOrgDid = url.searchParams.get("orgDid") || "";
  if (!rawOrgDid) return jsonErr(400, "BadRequest", "orgDid is required");
  let orgDid: string;
  try { orgDid = await rootDidFor(env, rawOrgDid); }
  catch (error) {
    const rootErr = rootRequiredResponse(error);
    if (rootErr) return rootErr;
    return jsonErr(400, "BadRequest", error instanceof Error ? error.message : "invalid orgDid");
  }
  await ensureAuthTables(env);
  const org = await env.AUTH_DB.prepare(
    "SELECT org_did AS orgDid, name, domain, org_type AS orgType, settings_json AS settingsJson, created_at AS createdAt FROM vertex_etzhayyim_auth_org WHERE vertex_id=? LIMIT 1"
  ).bind(orgDid).first<{ orgDid: string; name: string; domain: string | null; orgType: string; settingsJson: string; createdAt: string }>();
  if (!org) return jsonErr(404, "NotFound", "org not found");
  const countRow = await env.AUTH_DB.prepare(
    "SELECT COUNT(*) AS count FROM edge_etzhayyim_auth_member WHERE org_did=? AND status='active'"
  ).bind(orgDid).first<{ count: number }>();
  const info: OrgInfo = {
    orgDid: org.orgDid,
    name: org.name,
    domain: org.domain,
    orgType: org.orgType,
    settings: JSON.parse(org.settingsJson || "{}") as Record<string, unknown>,
    memberCount: Number(countRow?.count || 0),
    createdAt: org.createdAt,
  };
  return json({ ok: true, org: info });
}

/**
 * GET /xrpc/com.etzhayyim.authz.orgMembers?orgDid=&offset=&limit=
 */
async function handleOrgMembers(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB required");
  try {
    const session = await requireSessionAccount(request, env);
    const memberDid = await rootDidFor(env, session.accountDid);
    const url = new URL(request.url);
    const orgDid = await orgDidForInput(env, url.searchParams.get("orgDid") || undefined, memberDid);
    const { offset, limit } = parsePagination(url.searchParams, 100);
    await ensureAuthTables(env);
    // verify caller is a member
    const membership = await env.AUTH_DB.prepare(
      "SELECT role FROM edge_etzhayyim_auth_member WHERE org_did=? AND member_did=? AND status='active' LIMIT 1"
    ).bind(orgDid, memberDid).first<{ role: string }>();
    if (!membership) return jsonErr(403, "Forbidden", "not a member of this org");
    const totalRow = await env.AUTH_DB.prepare(
      "SELECT COUNT(*) AS count FROM edge_etzhayyim_auth_member WHERE org_did=? AND status='active'"
    ).bind(orgDid).first<{ count: number }>();
    const total = Number(totalRow?.count || 0);
    const rows = await env.AUTH_DB.prepare(`
      SELECT member_did AS memberDid, role, invited_by AS invitedBy, joined_at AS joinedAt, status
      FROM edge_etzhayyim_auth_member
      WHERE org_did=? AND status='active'
      ORDER BY role DESC, joined_at ASC
      LIMIT ? OFFSET ?
    `).bind(orgDid, limit, offset).all();
    const members: OrgMember[] = (rows.results || []).map((r) => ({
      memberDid: String((r as Record<string, unknown>).memberDid || ""),
      role: String((r as Record<string, unknown>).role || "member"),
      invitedBy: (r as Record<string, unknown>).invitedBy as string | null,
      joinedAt: String((r as Record<string, unknown>).joinedAt || ""),
      status: String((r as Record<string, unknown>).status || "active"),
    }));
    return json({ ok: true, orgDid, members, total, offset, limit });
  } catch (error) {
    const rootErr = rootRequiredResponse(error);
    if (rootErr) return rootErr;
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

/**
 * POST /xrpc/com.etzhayyim.authz.orgInvite
 * Body: { orgDid, email, role? }
 * Sends an invite (HMAC token). Must be org owner or admin.
 */
async function handleOrgInvite(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB required");
  try {
    const session = await requireSessionAccount(request, env);
    const inviterDid = await rootDidFor(env, session.accountDid);
    const body = await parseJson<{ orgDid?: string; email: string; role?: string }>(request);
    const orgDid = await orgDidForInput(env, body.orgDid, inviterDid);
    const email = String(body.email || "").trim().toLowerCase();
    const role = ["member", "admin"].includes(String(body.role || "member")) ? String(body.role || "member") : "member";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return jsonErr(400, "BadRequest", "valid email required");
    await ensureAuthTables(env);

    // verify caller is owner/admin
    const callerRole = await env.AUTH_DB.prepare(
      "SELECT role FROM edge_etzhayyim_auth_member WHERE org_did=? AND member_did=? AND status='active' LIMIT 1"
    ).bind(orgDid, inviterDid).first<{ role: string }>();
    if (!callerRole || (callerRole.role !== "owner" && callerRole.role !== "admin")) {
      return jsonErr(403, "Forbidden", "only org owners and admins can invite members");
    }

    const expiresAt = nowSecs() + 7 * 24 * 3600; // 7 days
    const token = await encodeInviteToken(getSessionSecret(env) || "fallback", orgDid, email, role, expiresAt);
    const now = nowIso();
    const inviteId = `${orgDid}:invite:${email}`;

    await env.AUTH_DB.prepare(`
      INSERT INTO vertex_etzhayyim_auth_invite
        (vertex_id, sensitivity_ord, owner_did, org_did, email, role, invite_token, expires_at, inviter_did, status, created_at, updated_at)
      VALUES (?, 3, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
      ON CONFLICT(vertex_id) DO UPDATE SET
        role=excluded.role, invite_token=excluded.invite_token, expires_at=excluded.expires_at,
        inviter_did=excluded.inviter_did, status='pending', updated_at=excluded.updated_at
    `).bind(inviteId, inviterDid, orgDid, email, role, token, expiresAt, inviterDid, now, now).run();

    // Prefer the short /invite/<token> public route — it survives sign-in.
    const acceptUrl = `https://accounts.etzhayyim.com/invite/${encodeURIComponent(token)}`;
    const subject = `etzhayyim — invited to ${orgDid}`;
    const text = `You have been invited to join ${orgDid} on etzhayyim as ${role}.\n\nAccept the invitation: ${acceptUrl}\n\nThis link expires in 7 days.`;
    const delivery = await sendEmail(env, email, subject, text);
    if (!isProduction(env)) {
      console.log(`[authz] ORG INVITE ${orgDid} → ${email} (role=${role}) token=${token.slice(0, 20)}... (delivery.sent=${delivery.sent})`);
    }
    const resp: Record<string, unknown> = { ok: true, sent: delivery.sent, orgDid, email, role, expiresIn: 7 * 24 * 3600 };
    if (!delivery.sent) resp.deliveryError = delivery.reason || "email_not_sent";
    if (!isProduction(env)) resp.debugToken = token;
    return json(resp);
  } catch (error) {
    const rootErr = rootRequiredResponse(error);
    if (rootErr) return rootErr;
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

/**
 * POST /xrpc/com.etzhayyim.authz.orgInviteAccept
 * Body: { token }
 * Accepts an org invite. Caller's DID becomes a member.
 */
async function handleOrgInviteAccept(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB required");
  try {
    const session = await requireSessionAccount(request, env);
    const body = await parseJson<{ token: string }>(request);
    const token = String(body.token || "").trim();
    if (!token) return jsonErr(400, "BadRequest", "token is required");

    const decoded = await decodeInviteToken(getSessionSecret(env) || "fallback", token);
    if (!decoded) return jsonErr(400, "InvalidToken", "invalid invite token");
    if (decoded.expiresAt < nowSecs()) return jsonErr(400, "TokenExpired", "invite token has expired");
    const orgDid = await rootDidFor(env, decoded.orgDid);

    await ensureAuthTables(env);
    // Find the invite record
    const invite = await env.AUTH_DB.prepare(
      "SELECT vertex_id, inviter_did AS inviterDid, status FROM vertex_etzhayyim_auth_invite WHERE org_did=? AND email=? AND status='pending' LIMIT 1"
    ).bind(orgDid, decoded.email).first<{ vertex_id: string; inviterDid: string; status: string }>();
    if (!invite) return jsonErr(404, "NotFound", "invite not found or already accepted");

    const now = nowIso();
    const edgeId = `${orgDid}:member:${memberDid}`;

    await env.AUTH_DB.batch([
      // Add member edge
      env.AUTH_DB.prepare(`
        INSERT INTO edge_etzhayyim_auth_member (edge_id, src_vid, dst_vid, sensitivity_ord, owner_did, org_did, member_did, role, invited_by, joined_at, status)
        VALUES (?, ?, ?, 2, ?, ?, ?, ?, ?, ?, 'active')
        ON CONFLICT(org_did, member_did) DO UPDATE SET role=excluded.role, status='active', joined_at=excluded.joined_at
      `).bind(edgeId, orgDid, memberDid, orgDid, orgDid, memberDid,
        decoded.role, invite.inviterDid, now),
      // Mark invite as accepted
      env.AUTH_DB.prepare(
        "UPDATE vertex_etzhayyim_auth_invite SET status='accepted', accepted_did=?, accepted_at=?, updated_at=? WHERE vertex_id=?"
      ).bind(memberDid, now, now, invite.vertex_id),
    ]);

    return json({ ok: true, orgDid, memberDid, role: decoded.role, joinedAt: now });
  } catch (error) {
    const rootErr = rootRequiredResponse(error);
    if (rootErr) return rootErr;
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

/**
 * POST /xrpc/com.etzhayyim.authz.orgMemberRemove
 * Body: { orgDid, memberDid }
 * Owner/admin removes a member. Cannot remove the owner.
 */
async function handleOrgMemberRemove(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB required");
  try {
    const session = await requireSessionAccount(request, env);
    const callerDid = await rootDidFor(env, session.accountDid);
    const body = await parseJson<{ orgDid?: string; memberDid: string }>(request);
    const orgDid = await orgDidForInput(env, body.orgDid, callerDid);
    const rawMemberDid = String(body.memberDid || "").trim();
    if (!rawMemberDid) return jsonErr(400, "BadRequest", "memberDid required");
    const memberDid = await rootDidFor(env, rawMemberDid);
    await ensureAuthTables(env);

    const callerRow = await env.AUTH_DB.prepare(
      "SELECT role FROM edge_etzhayyim_auth_member WHERE org_did=? AND member_did=? AND status='active' LIMIT 1"
    ).bind(orgDid, callerDid).first<{ role: string }>();
    if (!callerRow || (callerRow.role !== "owner" && callerRow.role !== "admin")) {
      return jsonErr(403, "Forbidden", "only org owners and admins can remove members");
    }
    const targetRow = await env.AUTH_DB.prepare(
      "SELECT role FROM edge_etzhayyim_auth_member WHERE org_did=? AND member_did=? AND status='active' LIMIT 1"
    ).bind(orgDid, memberDid).first<{ role: string }>();
    if (!targetRow) return jsonErr(404, "NotFound", "member not found");
    if (targetRow.role === "owner") return jsonErr(400, "BadRequest", "cannot remove the org owner");

    await env.AUTH_DB.prepare(
      "UPDATE edge_etzhayyim_auth_member SET status='removed', joined_at=joined_at WHERE org_did=? AND member_did=?"
    ).bind(orgDid, memberDid).run();

    return json({ ok: true, orgDid, removedDid: memberDid });
  } catch (error) {
    const rootErr = rootRequiredResponse(error);
    if (rootErr) return rootErr;
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

/**
 * POST /xrpc/com.etzhayyim.authz.orgMemberRoleUpdate
 * Body: { orgDid?, memberDid, role }  role ∈ {member, admin}
 * Owner/admin updates a non-owner member's role. Owners cannot be demoted here
 * (use orgTransferOwnership instead).
 */
async function handleOrgMemberRoleUpdate(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB required");
  try {
    const session = await requireSessionAccount(request, env);
    const callerDid = await rootDidFor(env, session.accountDid);
    const body = await parseJson<{ orgDid?: string; memberDid: string; role: string }>(request);
    const orgDid = await orgDidForInput(env, body.orgDid, callerDid);
    const rawMemberDid = String(body.memberDid || "").trim();
    const role = String(body.role || "").trim();
    if (!rawMemberDid) return jsonErr(400, "BadRequest", "memberDid required");
    const memberDid = await rootDidFor(env, rawMemberDid);
    if (role !== "member" && role !== "admin") {
      return jsonErr(400, "BadRequest", "role must be 'member' or 'admin'");
    }
    await ensureAuthTables(env);

    const caller = await env.AUTH_DB.prepare(
      "SELECT role FROM edge_etzhayyim_auth_member WHERE org_did=? AND member_did=? AND status='active' LIMIT 1"
    ).bind(orgDid, callerDid).first<{ role: string }>();
    if (!caller || (caller.role !== "owner" && caller.role !== "admin")) {
      return jsonErr(403, "Forbidden", "only org owners and admins can change roles");
    }
    const target = await env.AUTH_DB.prepare(
      "SELECT role FROM edge_etzhayyim_auth_member WHERE org_did=? AND member_did=? AND status='active' LIMIT 1"
    ).bind(orgDid, memberDid).first<{ role: string }>();
    if (!target) return jsonErr(404, "NotFound", "member not found");
    if (target.role === "owner") return jsonErr(400, "BadRequest", "use orgTransferOwnership to change the owner");
    // admin cannot demote another admin (only owner can)
    if (target.role === "admin" && caller.role !== "owner") {
      return jsonErr(403, "Forbidden", "only the owner can change an admin's role");
    }

    await env.AUTH_DB.prepare(
      "UPDATE edge_etzhayyim_auth_member SET role=? WHERE org_did=? AND member_did=?"
    ).bind(role, orgDid, memberDid).run();
    return json({ ok: true, orgDid, memberDid, role });
  } catch (error) {
    const rootErr = rootRequiredResponse(error);
    if (rootErr) return rootErr;
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

/**
 * POST /xrpc/com.etzhayyim.authz.orgTransferOwnership
 * Body: { orgDid?, newOwnerDid }
 * Current owner transfers ownership to another active member. The old owner
 * becomes 'admin'. New owner inherits 'owner'. vertex_etzhayyim_auth_org.owner_did
 * is also updated so subsequent queries reflect the change.
 */
async function handleOrgTransferOwnership(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB required");
  try {
    const session = await requireSessionAccount(request, env);
    const callerDid = await rootDidFor(env, session.accountDid);
    const body = await parseJson<{ orgDid?: string; newOwnerDid: string }>(request);
    const orgDid = await orgDidForInput(env, body.orgDid, callerDid);
    const rawNewOwnerDid = String(body.newOwnerDid || "").trim();
    if (!rawNewOwnerDid) return jsonErr(400, "BadRequest", "newOwnerDid required");
    const newOwnerDid = await rootDidFor(env, rawNewOwnerDid);
    if (newOwnerDid === callerDid) {
      return jsonErr(400, "BadRequest", "cannot transfer ownership to yourself");
    }
    await ensureAuthTables(env);

    const caller = await env.AUTH_DB.prepare(
      "SELECT role FROM edge_etzhayyim_auth_member WHERE org_did=? AND member_did=? AND status='active' LIMIT 1"
    ).bind(orgDid, callerDid).first<{ role: string }>();
    if (!caller || caller.role !== "owner") {
      return jsonErr(403, "Forbidden", "only the current owner can transfer ownership");
    }
    const target = await env.AUTH_DB.prepare(
      "SELECT role FROM edge_etzhayyim_auth_member WHERE org_did=? AND member_did=? AND status='active' LIMIT 1"
    ).bind(orgDid, newOwnerDid).first<{ role: string }>();
    if (!target) return jsonErr(404, "NotFound", "new owner must be an active member of this org");

    const now = nowIso();
    await env.AUTH_DB.batch([
      env.AUTH_DB.prepare(
        "UPDATE edge_etzhayyim_auth_member SET role='admin' WHERE org_did=? AND member_did=?"
      ).bind(orgDid, callerDid),
      env.AUTH_DB.prepare(
        "UPDATE edge_etzhayyim_auth_member SET role='owner' WHERE org_did=? AND member_did=?"
      ).bind(orgDid, newOwnerDid),
      env.AUTH_DB.prepare(
        "UPDATE vertex_etzhayyim_auth_org SET owner_did=?, updated_at=? WHERE vertex_id=?"
      ).bind(newOwnerDid, now, orgDid),
    ]);
    return json({ ok: true, orgDid, previousOwnerDid: callerDid, newOwnerDid });
  } catch (error) {
    const rootErr = rootRequiredResponse(error);
    if (rootErr) return rootErr;
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

/**
 * POST /xrpc/com.etzhayyim.authz.orgLeave
 * Body: { orgDid }
 */
async function handleOrgLeave(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB required");
  try {
    const session = await requireSessionAccount(request, env);
    const memberDid = await rootDidFor(env, session.accountDid);
    const body = await parseJson<{ orgDid: string }>(request);
    const rawOrgDid = String(body.orgDid || "").trim();
    if (!rawOrgDid) return jsonErr(400, "BadRequest", "orgDid required");
    const orgDid = await rootDidFor(env, rawOrgDid);
    await ensureAuthTables(env);

    const row = await env.AUTH_DB.prepare(
      "SELECT role FROM edge_etzhayyim_auth_member WHERE org_did=? AND member_did=? AND status='active' LIMIT 1"
    ).bind(orgDid, memberDid).first<{ role: string }>();
    if (!row) return jsonErr(404, "NotFound", "you are not a member of this org");
    if (row.role === "owner") return jsonErr(400, "BadRequest", "owner cannot leave; transfer ownership first");

    await env.AUTH_DB.prepare(
      "UPDATE edge_etzhayyim_auth_member SET status='left' WHERE org_did=? AND member_did=?"
    ).bind(orgDid, memberDid).run();

    return json({ ok: true, orgDid, leftDid: memberDid });
  } catch (error) {
    const rootErr = rootRequiredResponse(error);
    if (rootErr) return rootErr;
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

/**
 * GET /xrpc/com.etzhayyim.authz.orgList?offset=&limit=
 * Returns orgs the caller belongs to.
 */
async function handleOrgList(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB required");
  try {
    const session = await requireSessionAccount(request, env);
    const memberDid = await rootDidFor(env, session.accountDid);
    const url = new URL(request.url);
    const { offset, limit } = parsePagination(url.searchParams, 50);
    await ensureAuthTables(env);
    const totalRow = await env.AUTH_DB.prepare(
      "SELECT COUNT(*) AS count FROM edge_etzhayyim_auth_member WHERE member_did=? AND status='active'"
    ).bind(memberDid).first<{ count: number }>();
    const total = Number(totalRow?.count || 0);
    const rows = await env.AUTH_DB.prepare(`
      SELECT m.org_did AS orgDid, m.role, o.name, o.domain, o.org_type AS orgType
      FROM edge_etzhayyim_auth_member m
      LEFT JOIN vertex_etzhayyim_auth_org o ON o.vertex_id = m.org_did
      WHERE m.member_did=? AND m.status='active'
      ORDER BY m.joined_at ASC
      LIMIT ? OFFSET ?
    `).bind(memberDid, limit, offset).all();
    const orgs = (rows.results || []).map((r) => ({
      orgDid: String((r as Record<string, unknown>).orgDid || ""),
      role: String((r as Record<string, unknown>).role || "member"),
      name: String((r as Record<string, unknown>).name || (r as Record<string, unknown>).orgDid || ""),
      domain: (r as Record<string, unknown>).domain as string | null,
      orgType: String((r as Record<string, unknown>).orgType || "personal"),
    }));
    return json({ ok: true, orgs, total, offset, limit });
  } catch (error) {
    const rootErr = rootRequiredResponse(error);
    if (rootErr) return rootErr;
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

/**
 * POST /xrpc/com.etzhayyim.authz.orgUpdate
 * Body: { orgDid?, name?, domain?, orgType? }
 * Owner/admin updates org metadata. Only provided fields are changed.
 */
async function handleOrgUpdate(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB required");
  try {
    const session = await requireSessionAccount(request, env);
    const callerDid = await rootDidFor(env, session.accountDid);
    const body = await parseJson<{ orgDid?: string; name?: string; domain?: string; orgType?: string }>(request);
    const orgDid = await orgDidForInput(env, body.orgDid, callerDid);
    await ensureAuthTables(env);

    const caller = await env.AUTH_DB.prepare(
      "SELECT role FROM edge_etzhayyim_auth_member WHERE org_did=? AND member_did=? AND status='active' LIMIT 1"
    ).bind(orgDid, callerDid).first<{ role: string }>();
    if (!caller || (caller.role !== "owner" && caller.role !== "admin")) {
      return jsonErr(403, "Forbidden", "only org owners and admins can update org metadata");
    }

    const setClauses: string[] = [];
    const values: (string | null)[] = [];
    if (typeof body.name === "string") {
      const name = body.name.trim();
      if (name.length < 2) return jsonErr(400, "BadRequest", "name must be at least 2 characters");
      setClauses.push("name=?");
      values.push(name);
    }
    if (typeof body.domain === "string") {
      const domain = body.domain.trim().toLowerCase();
      setClauses.push("domain=?");
      values.push(domain || null);
    }
    if (typeof body.orgType === "string") {
      const orgType = body.orgType.trim();
      if (!["personal", "company", "npo", "community", "team"].includes(orgType)) {
        return jsonErr(400, "BadRequest", "orgType must be one of personal|company|npo|community|team");
      }
      setClauses.push("org_type=?");
      values.push(orgType);
    }
    if (setClauses.length === 0) return jsonErr(400, "BadRequest", "no fields to update");

    setClauses.push("updated_at=?");
    values.push(nowIso());
    values.push(orgDid);
    await env.AUTH_DB.prepare(
      `UPDATE vertex_etzhayyim_auth_org SET ${setClauses.join(", ")} WHERE vertex_id=?`
    ).bind(...values).run();
    return json({ ok: true, orgDid });
  } catch (error) {
    const rootErr = rootRequiredResponse(error);
    if (rootErr) return rootErr;
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

// ── ADR-2604261717 Phase 1 — claim-level stake handlers ─────────────────────
// Game theory: bond `b` + challenge probability `P > 0` makes EV(lie) < 0.
// Three procedures + one query bridge the AT-Record claim shape to
// ClaimStakeEscrow on the etzhayyim private chain. The handler does not write to
// graph (vertex_claim_stake) directly — Phase 1.5 adds a graph consumer that
// tails ClaimPosted/Challenged/Upheld/Slashed/Refunded events.

function ensureClaimStakeConfig(env: Env): Response | null {
  if (!(env.ETH_PRIVATE_RPC_URL || "").trim()) {
    return jsonErr(503, "ConfigError", "ETH_PRIVATE_RPC_URL is not configured");
  }
  if (!(env.etzhayyim_CLAIM_STAKE_ESCROW_ADDR || "").trim()) {
    return jsonErr(503, "ConfigError", "etzhayyim_CLAIM_STAKE_ESCROW_ADDR is not configured (deploy ClaimStakeEscrow + set the env var)");
  }
  return null;
}

async function handlePostStakedAttestation(request: Request, env: Env): Promise<Response> {
  const cfg = ensureClaimStakeConfig(env);
  if (cfg) return cfg;
  if (!(env.SEALER_PRIV || "").trim()) return jsonErr(503, "ConfigError", "SEALER_PRIV is not configured");

  let session: SessionAccount;
  try { session = await requireSessionAccount(request, env); }
  catch (e) { return jsonErr(401, "AuthRequired", e instanceof Error ? e.message : "auth required"); }

  let body: { claim?: string; claimType?: string; bond?: string | number; challengePeriodSec?: number; arbiter?: string; evidence?: string[]; atRecordCid?: string };
  try { body = await parseJson(request); }
  catch (e) { return jsonErr(400, "BadRequest", e instanceof Error ? e.message : "invalid json"); }
  if (!body.claim) return jsonErr(400, "BadRequest", "claim text required");
  if (body.bond === undefined || body.bond === null) return jsonErr(400, "BadRequest", "bond required");

  let prepared;
  try {
    const rootIdentity = await requireRootIdentity(env, session.accountDid);
    prepared = preparePostClaim(
      { claim: body.claim, claimType: body.claimType, bond: body.bond, challengePeriodSec: body.challengePeriodSec, arbiter: body.arbiter, evidence: body.evidence, atRecordCid: body.atRecordCid },
      rootIdentity.rootDidHash,
    );
  } catch (e) {
    const message = e instanceof Error ? e.message : "invalid input";
    return jsonErr(message.includes("ERC725 root identity") ? 409 : 400, message.includes("ERC725 root identity") ? "RootIdentityRequired" : "BadRequest", message);
  }

  try {
    const result = await ethPostClaim(env, {
      claimId: prepared.claimId,
      didHash: prepared.didHash,
      atRecordCid: prepared.atRecordCid,
      bond: prepared.bond,
      challengePeriodSec: prepared.challengePeriodSec,
    });
    // Index claim in D1 for history lookups (best-effort — don't fail the tx on D1 error).
    if (env.AUTH_DB) {
      env.AUTH_DB.prepare(
        `INSERT OR IGNORE INTO vertex_etzhayyim_claim_index
           (claim_id, account_did, at_record_cid, bond_gcc, posted_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        prepared.claimId,
        session.accountDid,
        body.atRecordCid || "",
        String(Number(body.bond ?? 0)),
        Math.floor(Date.now() / 1000),
        nowIso(),
      ).run().catch((err: unknown) => console.warn("[claim-index] D1 insert failed", err));
    }
    return json({
      ok: true,
      claimId: prepared.claimId,
      txHash: result.txHash,
      didHash: prepared.didHash,
      escrowAddr: env.etzhayyim_CLAIM_STAKE_ESCROW_ADDR,
      chainId: Number((env.ETH_PRIVATE_CHAIN_ID || "0").trim()) || 0,
      challengePeriodSec: Number(prepared.challengePeriodSec),
      receiptStatus: result.receiptStatus ?? null,
    });
  } catch (e) {
    const err = e as Error & { code?: string };
    if (err.code === "TxRevert") return jsonErr(502, "TxRevert", err.message);
    if (/insufficient/i.test(err.message ?? "")) return jsonErr(402, "InsufficientApproval", err.message);
    return jsonErr(502, "RpcError", err.message ?? "postClaim failed");
  }
}

/** List the caller's own staked attestations with live chain state. */
async function handleListStakedAttestations(request: Request, env: Env): Promise<Response> {
  const cfg = ensureClaimStakeConfig(env);
  if (cfg) return cfg;
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB not configured");

  let session: SessionAccount;
  try { session = await requireSessionAccount(request, env); }
  catch (e) { return jsonErr(401, "AuthRequired", e instanceof Error ? e.message : "auth required"); }

  const url = new URL(request.url);
  const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") || "20")));
  const offset = Math.max(0, Number(url.searchParams.get("offset") || "0"));

  await ensureAuthTables(env);
  const rows = await env.AUTH_DB.prepare(
    `SELECT claim_id, at_record_cid, bond_gcc, posted_at FROM vertex_etzhayyim_claim_index
       WHERE account_did = ?
       ORDER BY posted_at DESC
       LIMIT ? OFFSET ?`,
  ).bind(session.accountDid, limit, offset).all<{ claim_id: string; at_record_cid: string; bond_gcc: string; posted_at: number }>();

  const items = rows.results ?? [];
  // Snapshot each claim from chain concurrently (cap at 20 parallel eth_calls).
  const snapshots = await Promise.all(
    items.map(async (row) => {
      try {
        const snap = await snapshotClaim(env, row.claim_id);
        if (!snap) return { claimId: row.claim_id, atRecordCid: row.at_record_cid, bondGcc: row.bond_gcc, postedAt: row.posted_at, state: "none" as const };
        return { ...snap, atRecordCid: snap.atRecordCid || row.at_record_cid, bondGcc: row.bond_gcc };
      } catch {
        return { claimId: row.claim_id, atRecordCid: row.at_record_cid, bondGcc: row.bond_gcc, postedAt: row.posted_at, state: "error" as const };
      }
    }),
  );

  return json({ ok: true, claims: snapshots, offset, limit });
}

/** Batch-lookup staked attestations by at_record_cid (public, for feed challenge UI). */
async function handleLookupStakedAttestations(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return json({ ok: true, claims: {} });
  const url = new URL(request.url);
  const cidsParam = (url.searchParams.get("atRecordCids") || "").trim();
  if (!cidsParam) return json({ ok: true, claims: {} });

  const cids = cidsParam.split(",").map((s) => s.trim()).filter(Boolean).slice(0, 50);
  if (cids.length === 0) return json({ ok: true, claims: {} });

  await ensureAuthTables(env);
  const placeholders = cids.map(() => "?").join(",");
  const rows = await env.AUTH_DB.prepare(
    `SELECT claim_id, at_record_cid FROM vertex_etzhayyim_claim_index WHERE at_record_cid IN (${placeholders}) LIMIT 50`,
  ).bind(...cids).all<{ claim_id: string; at_record_cid: string }>();

  const claimsMap: Record<string, string> = {};
  for (const row of rows.results ?? []) {
    claimsMap[row.at_record_cid] = row.claim_id;
  }
  return json({ ok: true, claims: claimsMap });
}

async function handleChallengeStakedAttestation(request: Request, env: Env): Promise<Response> {
  const cfg = ensureClaimStakeConfig(env);
  if (cfg) return cfg;
  if (!(env.SEALER_PRIV || "").trim()) return jsonErr(503, "ConfigError", "SEALER_PRIV is not configured");

  let session: SessionAccount;
  try { session = await requireSessionAccount(request, env); }
  catch (e) { return jsonErr(401, "AuthRequired", e instanceof Error ? e.message : "auth required"); }

  let body: { claimId?: string; counterBond?: string | number; rebuttal?: string; evidence?: string[] };
  try { body = await parseJson(request); }
  catch (e) { return jsonErr(400, "BadRequest", e instanceof Error ? e.message : "invalid json"); }
  if (!body.claimId) return jsonErr(400, "BadRequest", "claimId required");
  if (body.counterBond === undefined || body.counterBond === null) return jsonErr(400, "BadRequest", "counterBond required");
  if (!body.rebuttal) return jsonErr(400, "BadRequest", "rebuttal required");
  if (body.rebuttal.length > 4096) return jsonErr(400, "BadRequest", "rebuttal too long");

  let counterBond: bigint;
  try { counterBond = BigInt(String(body.counterBond)); }
  catch { return jsonErr(400, "BadRequest", "counterBond must be a uint256-shaped string"); }
  if (counterBond <= 0n) return jsonErr(400, "BadRequest", "counterBond must be > 0");

  let challengerDidHash: string;
  try {
    const rootIdentity = await requireRootIdentity(env, session.accountDid);
    challengerDidHash = rootIdentity.rootDidHash;
  } catch (e) {
    return jsonErr(409, "RootIdentityRequired", e instanceof Error ? e.message : "ERC725 root identity is required");
  }

  try {
    const result = await ethChallengeClaim(env, body.claimId, challengerDidHash, counterBond);
    // Best-effort rebuttal persistence — the chain only stores claimId +
    // counterBond; the text rebuttal lives off-chain in
    // `vertex_claim_challenge.rebuttal` so judgeTick can pass it to
    // Murakumo. Routed through claim-consumer because authz is zero-npm
    // and has no Hyperdrive binding.
    let rebuttalPersisted = false;
    let rebuttalPersistError: string | undefined;
    try {
      const persisted = await persistChallengeRebuttal(env, body.claimId, body.rebuttal);
      rebuttalPersisted = persisted.ok;
      rebuttalPersistError = persisted.error;
    } catch (e) {
      rebuttalPersistError = e instanceof Error ? e.message : String(e);
    }
    return json({
      ok: true,
      claimId: body.claimId,
      txHash: result.txHash,
      challengerDidHash,
      receiptStatus: result.receiptStatus ?? null,
      rebuttalPersisted,
      rebuttalPersistError,
    });
  } catch (e) {
    const err = e as Error & { code?: string };
    if (err.code === "TxRevert") return jsonErr(502, "TxRevert", err.message);
    return jsonErr(502, "RpcError", err.message ?? "challenge failed");
  }
}

async function persistChallengeRebuttal(
  env: Env,
  claimId: string,
  rebuttal: string,
): Promise<{ ok: boolean; error?: string }> {
  if (!env.CLAIM_CONSUMER_RPC) return { ok: false, error: "CLAIM_CONSUMER_RPC binding not configured" };
  const hmacKey = (env.CLAIM_SETTLER_HMAC || "").trim();
  if (!hmacKey) return { ok: false, error: "CLAIM_SETTLER_HMAC not configured" };
  const body = JSON.stringify({ claimId, rebuttal });
  const sig = await hmacSha256Hex(hmacKey, new TextEncoder().encode(body));
  const resp = await env.CLAIM_CONSUMER_RPC.fetch(new Request("https://claim-consumer.internal/rebuttal-ingest", {
    method: "POST",
    headers: { "content-type": "application/json", "x-claim-settler-auth": sig },
    body,
  }));
  if (!resp.ok) {
    return { ok: false, error: `rebuttal-ingest HTTP ${resp.status}: ${(await resp.text()).slice(0, 200)}` };
  }
  return { ok: true };
}

async function handleSettleStakedAttestation(request: Request, env: Env): Promise<Response> {
  const cfg = ensureClaimStakeConfig(env);
  if (cfg) return cfg;
  if (!(env.SEALER_PRIV || "").trim()) return jsonErr(503, "ConfigError", "SEALER_PRIV is not configured");
  // Settle is unauthenticated by design — anyone can drive a claim to its
  // terminal state once the arbiter has signed, or once the period elapses.
  // Authenticity comes from the on-chain ECDSA check, not from caller auth.

  let body: { claimId?: string; claimWins?: boolean; arbiterSig?: string };
  try { body = await parseJson(request); }
  catch (e) { return jsonErr(400, "BadRequest", e instanceof Error ? e.message : "invalid json"); }
  if (!body.claimId) return jsonErr(400, "BadRequest", "claimId required");

  // Path A vs Path B is decided by whether arbiterSig is supplied.
  if (body.arbiterSig) {
    if (typeof body.claimWins !== "boolean") return jsonErr(400, "BadRequest", "claimWins required when arbiterSig is supplied");
    try {
      const result = await ethSettleClaim(env, body.claimId, body.claimWins, body.arbiterSig);
      return json({
        ok: true,
        claimId: body.claimId,
        txHash: result.txHash,
        outcome: body.claimWins ? "upheld" : "slashed",
        receiptStatus: result.receiptStatus ?? null,
      });
    } catch (e) {
      const err = e as Error & { code?: string };
      if (err.code === "TxRevert") return jsonErr(502, "TxRevert", err.message);
      if (/InvalidArbiterSignature/.test(err.message ?? "")) return jsonErr(401, "InvalidArbiterSignature", err.message);
      return jsonErr(502, "RpcError", err.message ?? "settle failed");
    }
  }

  // Path A — `claimUnchallenged`. The contract enforces that the period has
  // elapsed and the claim is still Pending; surface the on-chain revert as
  // a 4xx with a stable code so callers can retry later.
  try {
    const result = await ethClaimUnchallenged(env, body.claimId);
    return json({
      ok: true,
      claimId: body.claimId,
      txHash: result.txHash,
      outcome: "unchallenged",
      receiptStatus: result.receiptStatus ?? null,
    });
  } catch (e) {
    const err = e as Error & { code?: string };
    if (err.code === "TxRevert") return jsonErr(409, "ChallengeWindowOpen", err.message);
    return jsonErr(502, "RpcError", err.message ?? "claimUnchallenged failed");
  }
}

async function handleGetStakedAttestation(request: Request, env: Env): Promise<Response> {
  const cfg = ensureClaimStakeConfig(env);
  if (cfg) return cfg;

  const url = new URL(request.url);
  const claimId = (url.searchParams.get("claimId") || "").trim();
  if (!claimId) return jsonErr(400, "BadRequest", "claimId query param required");

  try {
    const snap = await snapshotClaim(env, claimId);
    if (!snap) return jsonErr(404, "ClaimNotFound", `no claim with id ${claimId}`);
    return json(snap);
  } catch (e) {
    const err = e as Error;
    if (/invalid claimId/.test(err.message)) return jsonErr(400, "BadRequest", err.message);
    return jsonErr(502, "RpcError", err.message ?? "snapshot failed");
  }
}

// ── Yabai auto-challenger (ADR-2604261717) ──────────────────────────────────
// Internal-only. Called by `claim-consumer.challengerTick` after Murakumo
// classifies a pending claim as fraud-likely. Sealer signs everything;
// trust comes from a shared HMAC over canonical body bytes.

function constantTimeEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacSha256Hex(key: string, body: ArrayBuffer | Uint8Array): Promise<string> {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const buf = body instanceof Uint8Array ? body : new Uint8Array(body);
  const sig = await crypto.subtle.sign("HMAC", k, buf);
  const bytes = new Uint8Array(sig);
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

async function handleRecordRegoDecision(request: Request, env: Env): Promise<Response> {
  if (!(env.etzhayyim_REGO_ARBITER_ADDR || "").trim()) return jsonErr(503, "ConfigError", "etzhayyim_REGO_ARBITER_ADDR is not configured");
  if (!(env.SEALER_PRIV || "").trim()) return jsonErr(503, "ConfigError", "SEALER_PRIV is not configured");
  const hmacKey = (env.CLAIM_SETTLER_HMAC || "").trim();
  if (!hmacKey) return jsonErr(503, "ConfigError", "CLAIM_SETTLER_HMAC is not configured");

  const headerSig = (request.headers.get("x-claim-settler-auth") || "").trim().toLowerCase();
  if (!headerSig) return jsonErr(401, "AuthRequired", "x-claim-settler-auth header missing");

  const bodyBytes = await request.arrayBuffer();
  const expected = await hmacSha256Hex(hmacKey, bodyBytes);
  if (!constantTimeEq(headerSig, expected)) return jsonErr(403, "InvalidHmac", "settler signature mismatch");

  let body: { claimId?: string; claimWins?: boolean; evidenceCid?: string };
  try { body = JSON.parse(new TextDecoder().decode(bodyBytes)); }
  catch (e) { return jsonErr(400, "BadRequest", e instanceof Error ? e.message : "invalid json"); }
  if (!body.claimId) return jsonErr(400, "BadRequest", "claimId required");
  if (typeof body.claimWins !== "boolean") return jsonErr(400, "BadRequest", "claimWins required");
  if (!body.evidenceCid) return jsonErr(400, "BadRequest", "evidenceCid required");

  // Idempotency — skip if already recorded.
  try {
    const existing = await readDecision(env, body.claimId);
    if (existing && existing.outcome !== "none") {
      return json({
        ok: true, skipped: true,
        reason: `decision already recorded (${existing.outcome})`,
        claimId: body.claimId,
        existingEvidenceCid: existing.evidenceCid,
      });
    }
  } catch (e) { return jsonErr(502, "RpcError", e instanceof Error ? e.message : "decision read failed"); }

  try {
    const result = await submitRecordDecision(env, body.claimId, body.claimWins, body.evidenceCid);
    return json({
      ok: true, claimId: body.claimId, claimWins: body.claimWins,
      evidenceCid: body.evidenceCid, ...result,
    });
  } catch (e) {
    const err = e as Error & { code?: string };
    if (err.code === "TxRevert") return jsonErr(502, "TxRevert", err.message);
    if (/AlreadyDecided/.test(err.message ?? "")) return jsonErr(409, "AlreadyDecided", err.message);
    if (/UnknownSigner/.test(err.message ?? "")) return jsonErr(401, "UnknownSigner", err.message);
    return jsonErr(502, "RpcError", err.message ?? "recordDecision failed");
  }
}

async function handleProvisionRootIdentity(request: Request, env: Env): Promise<Response> {
  if (!(env.etzhayyim_ROOT_IDENTITY_REGISTRY_ADDR || "").trim()) {
    return jsonErr(503, "ConfigError", "etzhayyim_ROOT_IDENTITY_REGISTRY_ADDR is not configured");
  }
  if (!(env.SEALER_PRIV || "").trim()) return jsonErr(503, "ConfigError", "SEALER_PRIV is not configured");
  const hmacKey = (env.CLAIM_SETTLER_HMAC || "").trim();
  if (!hmacKey) return jsonErr(503, "ConfigError", "CLAIM_SETTLER_HMAC is not configured");

  const headerSig = (request.headers.get("x-claim-settler-auth") || "").trim().toLowerCase();
  if (!headerSig) return jsonErr(401, "AuthRequired", "x-claim-settler-auth header missing");

  const bodyBytes = await request.arrayBuffer();
  const expected = await hmacSha256Hex(hmacKey, bodyBytes);
  if (!constantTimeEq(headerSig, expected)) return jsonErr(403, "InvalidHmac", "settler signature mismatch");

  let body: { stableId?: string; seedHash?: string; label?: string; controller?: string; facadeDids?: string[] };
  try { body = JSON.parse(new TextDecoder().decode(bodyBytes)); }
  catch (e) { return jsonErr(400, "BadRequest", e instanceof Error ? e.message : "invalid json"); }
  if (!body.label) return jsonErr(400, "BadRequest", "label required");
  const seedHash = body.seedHash || (body.stableId ? deriveSeedHash(body.stableId) : "");
  if (!seedHash) return jsonErr(400, "BadRequest", "seedHash or stableId required");

  try {
    const result = await provisionRootIdentity(env, {
      seedHash,
      label: body.label,
      controller: body.controller,
      facadeDids: body.facadeDids,
    });
    return json({ ok: true, ...result });
  } catch (e) {
    const err = e as Error & { code?: string };
    if (err.code === "TxRevert") return jsonErr(502, "TxRevert", err.message);
    if (err.code === "RegistryNotPopulated") return jsonErr(504, "RegistryNotPopulated", err.message);
    if (/IdentityAlreadyRegistered/.test(err.message ?? "")) return jsonErr(409, "AlreadyRegistered", err.message);
    return jsonErr(502, "RpcError", err.message ?? "provisionRootIdentity failed");
  }
}

async function handleAutoSettleClaim(request: Request, env: Env): Promise<Response> {
  const cfg = ensureClaimStakeConfig(env);
  if (cfg) return cfg;
  if (!(env.SEALER_PRIV || "").trim()) return jsonErr(503, "ConfigError", "SEALER_PRIV is not configured");
  const hmacKey = (env.CLAIM_SETTLER_HMAC || "").trim();
  if (!hmacKey) return jsonErr(503, "ConfigError", "CLAIM_SETTLER_HMAC is not configured");

  const headerSig = (request.headers.get("x-claim-settler-auth") || "").trim().toLowerCase();
  if (!headerSig) return jsonErr(401, "AuthRequired", "x-claim-settler-auth header missing");

  const bodyBytes = await request.arrayBuffer();
  const expected = await hmacSha256Hex(hmacKey, bodyBytes);
  if (!constantTimeEq(headerSig, expected)) return jsonErr(403, "InvalidHmac", "settler signature mismatch");

  let body: { claimId?: string; claimWins?: boolean; evidenceCid?: string };
  try { body = JSON.parse(new TextDecoder().decode(bodyBytes)); }
  catch (e) { return jsonErr(400, "BadRequest", e instanceof Error ? e.message : "invalid json"); }
  if (!body.claimId) return jsonErr(400, "BadRequest", "claimId required");
  if (typeof body.claimWins !== "boolean") return jsonErr(400, "BadRequest", "claimWins required");

  // Idempotency: skip cleanly if not Challenged. Caller (claim-consumer
  // settlerTick) records a successful skip and moves its cursor.
  let snap;
  try { snap = await snapshotClaim(env, body.claimId); }
  catch (e) { return jsonErr(502, "RpcError", e instanceof Error ? e.message : "snapshot failed"); }
  if (!snap) return jsonErr(404, "ClaimNotFound", `no claim with id ${body.claimId}`);
  if (snap.state !== "challenged") {
    return json({ ok: true, skipped: true, reason: `claim state is ${snap.state}, nothing to settle`, claimId: body.claimId });
  }

  // Phase 2-B: record decision on RegoArbiter for on-chain audit trail
  // before submitting the escrow settle. Best-effort — a chain hiccup here
  // should not block the actual settlement.
  let regoRecord: { txHash: string; receiptStatus: string | null } | null = null;
  if ((env.etzhayyim_REGO_ARBITER_ADDR || "").trim()) {
    // evidenceCid must be bytes32. Use caller-supplied CID or derive a
    // synthetic one from keccak256(claimId ‖ outcome) so it's deterministic.
    const evidenceCid = body.evidenceCid && body.evidenceCid.startsWith("0x") && body.evidenceCid.length === 66
      ? body.evidenceCid
      : "0x" + Array.from(new Uint8Array(
          await crypto.subtle.digest("SHA-256",
            new TextEncoder().encode(body.claimId + (body.claimWins ? ":1" : ":0")))
        )).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 64);
    try {
      regoRecord = await submitRecordDecision(env, body.claimId, body.claimWins, evidenceCid);
    } catch (e) {
      console.error("[auto-settle] RegoArbiter.recordDecision failed (non-fatal):", e instanceof Error ? e.message : e);
    }
  }

  try {
    const result = await autoSettleClaim(env, body.claimId, body.claimWins);
    return json({ ok: true, claimId: body.claimId, regoRecord, ...result });
  } catch (e) {
    const err = e as Error & { code?: string };
    if (err.code === "TxRevert") return jsonErr(502, "TxRevert", err.message);
    if (/InvalidArbiterSignature/.test(err.message ?? "")) return jsonErr(401, "InvalidArbiterSignature", err.message);
    return jsonErr(502, "RpcError", err.message ?? "auto-settle failed");
  }
}

async function handleAutoChallengeClaim(request: Request, env: Env): Promise<Response> {
  const cfg = ensureClaimStakeConfig(env);
  if (cfg) return cfg;
  if (!(env.SEALER_PRIV || "").trim()) return jsonErr(503, "ConfigError", "SEALER_PRIV is not configured");
  if (!(env.etzhayyim_CREDIT_ADDR || "").trim()) return jsonErr(503, "ConfigError", "etzhayyim_CREDIT_ADDR is not configured");
  const hmacKey = (env.CLAIM_SETTLER_HMAC || "").trim();
  if (!hmacKey) return jsonErr(503, "ConfigError", "CLAIM_SETTLER_HMAC is not configured");

  const headerSig = (request.headers.get("x-claim-settler-auth") || "").trim().toLowerCase();
  if (!headerSig) return jsonErr(401, "AuthRequired", "x-claim-settler-auth header missing");

  const bodyBytes = await request.arrayBuffer();
  const expected = await hmacSha256Hex(hmacKey, bodyBytes);
  if (!constantTimeEq(headerSig, expected)) return jsonErr(403, "InvalidHmac", "settler signature mismatch");

  let body: { claimId?: string; challengerDidHash?: string; counterBond?: string | number };
  try { body = JSON.parse(new TextDecoder().decode(bodyBytes)); }
  catch (e) { return jsonErr(400, "BadRequest", e instanceof Error ? e.message : "invalid json"); }
  if (!body.claimId) return jsonErr(400, "BadRequest", "claimId required");
  if (!body.challengerDidHash) return jsonErr(400, "BadRequest", "challengerDidHash required");
  if (body.counterBond === undefined || body.counterBond === null) return jsonErr(400, "BadRequest", "counterBond required");

  let counterBond: bigint;
  try { counterBond = BigInt(String(body.counterBond)); }
  catch { return jsonErr(400, "BadRequest", "counterBond must be uint256-shaped"); }
  if (counterBond <= 0n) return jsonErr(400, "BadRequest", "counterBond must be > 0");

  // Idempotency: if the claim is already past Pending we'd revert on-chain.
  // Cheap-check first so cron-ticks don't waste a tx + sealer GCC.
  let snap;
  try { snap = await snapshotClaim(env, body.claimId); }
  catch (e) { return jsonErr(502, "RpcError", e instanceof Error ? e.message : "snapshot failed"); }
  if (!snap) return jsonErr(404, "ClaimNotFound", `no claim with id ${body.claimId}`);
  if (snap.state !== "pending") {
    return json({ ok: true, skipped: true, reason: `claim state is ${snap.state}, no challenge needed`, claimId: body.claimId });
  }

  try {
    const result = await autoChallengeClaim(env, {
      claimId: body.claimId,
      challengerDidHash: body.challengerDidHash,
      counterBond,
    });
    return json({ ok: true, claimId: body.claimId, ...result });
  } catch (e) {
    const err = e as Error & { code?: string };
    if (err.code === "ChallengeRevert") return jsonErr(409, "ChallengeRevert", err.message);
    if (err.code === "MintRevert" || err.code === "ApproveRevert") return jsonErr(502, err.code, err.message);
    return jsonErr(502, "RpcError", err.message ?? "auto-challenge failed");
  }
}

// ── Unchallenged sweep handler (ADR-2604261717 Phase 4) ──────────────────────
// HMAC-gated internal route. Called by claim-consumer unchallengedSweep() once
// per hour (driven by claimAutoChallenge.bpmn R/PT1H). Submits claimUnchallenged()
// on-chain for each eligible claimId (best-effort, returns per-item results).
async function handleClaimUnchallengedSweep(request: Request, env: Env): Promise<Response> {
  const cfg = ensureClaimStakeConfig(env);
  if (cfg) return cfg;
  if (!(env.SEALER_PRIV || "").trim()) return jsonErr(503, "ConfigError", "SEALER_PRIV is not configured");
  const hmacKey = (env.CLAIM_SETTLER_HMAC || "").trim();
  if (!hmacKey) return jsonErr(503, "ConfigError", "CLAIM_SETTLER_HMAC is not configured");

  const headerSig = (request.headers.get("x-claim-settler-auth") || "").trim().toLowerCase();
  if (!headerSig) return jsonErr(401, "AuthRequired", "x-claim-settler-auth header missing");

  const bodyBytes = await request.arrayBuffer();
  const expected = await hmacSha256Hex(hmacKey, bodyBytes);
  if (!constantTimeEq(headerSig, expected)) return jsonErr(403, "InvalidHmac", "settler signature mismatch");

  let body: { claimIds?: string[] };
  try { body = JSON.parse(new TextDecoder().decode(bodyBytes)); }
  catch (e) { return jsonErr(400, "BadRequest", e instanceof Error ? e.message : "invalid json"); }
  if (!Array.isArray(body.claimIds) || body.claimIds.length === 0) return jsonErr(400, "BadRequest", "claimIds array required");
  if (body.claimIds.length > 20) return jsonErr(400, "BadRequest", "claimIds max 20 per call");

  const results: Array<{ claimId: string; ok: boolean; txHash?: string; skipped?: boolean; reason?: string; error?: string }> = [];
  for (const claimId of body.claimIds) {
    try {
      // Idempotency: skip if claim is no longer pending (already challenged,
      // settled, or refunded from a prior tick — RW PK-implicit upsert handles
      // the state update, so the chain is the source of truth here).
      let snap;
      try { snap = await snapshotClaim(env, claimId); }
      catch (e) {
        results.push({ claimId, ok: false, error: `snapshot failed: ${e instanceof Error ? e.message : String(e)}` });
        continue;
      }
      if (!snap) {
        results.push({ claimId, ok: true, skipped: true, reason: "claim not found on-chain" });
        continue;
      }
      if (snap.state !== "pending") {
        results.push({ claimId, ok: true, skipped: true, reason: `claim state is ${snap.state}` });
        continue;
      }
      const result = await ethClaimUnchallenged(env, claimId);
      results.push({ claimId, ok: true, txHash: result.txHash });
    } catch (e) {
      const err = e as Error & { code?: string };
      results.push({ claimId, ok: false, error: err.message ?? String(e) });
    }
  }
  return json({ ok: true, results });
}

// ── Hono router (Phase C edge HTTP migration, 2026-04-23) ──
// Business logic (handleLinkEmail*/handleOrg*/handleGetSession/...) unchanged.
// Only the dispatch layer moves from if-else chain to Hono route declarations.
const app = new Hono<{ Bindings: Env }>();

app.options("*", () => new Response(null, {
  status: 204,
  headers: {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
    "Access-Control-Max-Age": "86400",
  },
}));

app.get("/health", () => new Response("ok"));

// accounts.etzhayyim.com host redirects (absorbed into authz Worker).
app.get("/", (c) => {
  const url = new URL(c.req.url);
  if (url.hostname === "accounts.etzhayyim.com") {
    return Response.redirect(`${url.origin}/manage`, 302);
  }
  if (c.env.ASSETS) return c.env.ASSETS.fetch(c.req.raw);
  return new Response("Not Found", { status: 404 });
});
app.get("/sign-in", (c) => {
  const url = new URL(c.req.url);
  if (url.hostname === "accounts.etzhayyim.com") {
    return Response.redirect(`https://authn.etzhayyim.com/sign-in${url.search}`, 302);
  }
  if (c.env.ASSETS) return c.env.ASSETS.fetch(c.req.raw);
  return new Response("Not Found", { status: 404 });
});
app.get("/sign-up", (c) => {
  const url = new URL(c.req.url);
  if (url.hostname === "accounts.etzhayyim.com") {
    return Response.redirect(`https://authn.etzhayyim.com/sign-up${url.search}`, 302);
  }
  if (c.env.ASSETS) return c.env.ASSETS.fetch(c.req.raw);
  return new Response("Not Found", { status: 404 });
});

// /manage[/]: session-gated UI — redirect to authn sign-in when missing/expired,
// preserving query so `?invite=<token>` survives the round trip.
async function manageHandler(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const sessionToken = parseCookieHeader(request.headers.get("Cookie") || "").etzhayyim_session;
  const managePath = `/manage${url.search}`;
  if (!sessionToken) {
    const redirectUrl = encodeURIComponent(`https://${url.hostname}${managePath}`);
    return Response.redirect(`https://authn.etzhayyim.com/sign-in?redirectUrl=${redirectUrl}`, 302);
  }
  try {
    await verifySession(getSessionSecret(env), sessionToken, "com.atproto.access");
    if (env.ASSETS) return await env.ASSETS.fetch(new Request(url.toString(), request));
    return htmlResp("<!doctype html><html><body><script>location.replace('/manage')</script></body></html>");
  } catch {
    const redirectUrl = encodeURIComponent(`https://${url.hostname}${managePath}`);
    return Response.redirect(`https://authn.etzhayyim.com/sign-in?redirectUrl=${redirectUrl}`, 302);
  }
}
app.get("/manage", (c) => manageHandler(c.req.raw, c.env));
app.get("/manage/", (c) => manageHandler(c.req.raw, c.env));

// Public short-link: /invite/<token> → /manage?invite=<token>
app.get("/invite/:token", (c) => {
  const token = c.req.param("token");
  if (!token) return new Response("Not Found", { status: 404 });
  const url = new URL(c.req.url);
  return Response.redirect(`https://${url.hostname}/manage?invite=${encodeURIComponent(token)}`, 302);
});

// XRPC — authz endpoints (com.etzhayyim.authz.*)
app.get("/xrpc/com.etzhayyim.authz.getSession", (c) => handleGetSession(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.linkEmailBegin", (c) => handleLinkEmailBegin(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.linkEmailVerify", (c) => handleLinkEmailVerify(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.linkOAuthStart", (c) => handleLinkOAuthStart(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.unlinkMethod", (c) => handleUnlinkMethod(c.req.raw, c.env));
// ADR-0074 Phase 2-B — read smart-account address for the signed-in actor.
app.get("/xrpc/com.etzhayyim.authz.getActorAccount", (c) => handleGetActorAccount(c.req.raw, c.env));
// Public GCC balance lookup by DID (no auth required).
app.get("/xrpc/com.etzhayyim.authz.getActorTokenBalance", (c) => handleGetActorTokenBalance(c.req.raw, c.env));
// ADR-0074 Phase 2-B.2 — activate (deploy proxy) the caller's smart account.
app.post("/xrpc/com.etzhayyim.authz.activateActorAccount", (c) => handleActivateActorAccount(c.req.raw, c.env));
// ADR-0074 Phase 1 — Ethereum (private chain) link as authenticated linked method.
app.post("/xrpc/com.etzhayyim.authz.linkEthereumBegin", (c) => handleLinkEthereumBegin(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.linkEthereumVerify", (c) => handleLinkEthereumVerify(c.req.raw, c.env));
// Multi-device WebAuthn — adds another passkey to the same account.
app.post("/xrpc/com.etzhayyim.authz.linkPasskeyAdditionalBegin", (c) => handleLinkPasskeyAdditionalBegin(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.linkPasskeyAdditionalVerify", (c) => handleLinkPasskeyAdditionalVerify(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.switchActiveDid", (c) => handleSwitchActiveDidProxy(c.req.raw, c.env));

// ADR-2604261717 Phase 1 — staked claim attestation
app.post("/xrpc/com.etzhayyim.claim.postStakedAttestation",         (c) => handlePostStakedAttestation(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.claim.challengeStakedAttestation",    (c) => handleChallengeStakedAttestation(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.claim.settleStakedAttestation",       (c) => handleSettleStakedAttestation(c.req.raw, c.env));
app.get("/xrpc/com.etzhayyim.claim.getStakedAttestation",           (c) => handleGetStakedAttestation(c.req.raw, c.env));
app.get("/xrpc/com.etzhayyim.claim.listStakedAttestations",         (c) => handleListStakedAttestations(c.req.raw, c.env));
app.get("/xrpc/com.etzhayyim.claim.lookupStakedAttestations",       (c) => handleLookupStakedAttestations(c.req.raw, c.env));
// ADR-2604261717 yabai auto-challenger — internal-only, HMAC-gated.
// Called by `claim-consumer.challengerTick` after Murakumo classifies a
// pending claim as fraud-likely. NOT under /xrpc to make the
// internal-trust boundary explicit.
app.post("/internal/auto-challenge-claim",                 (c) => handleAutoChallengeClaim(c.req.raw, c.env));
app.post("/internal/auto-settle-claim",                    (c) => handleAutoSettleClaim(c.req.raw, c.env));
app.post("/internal/record-rego-decision",                 (c) => handleRecordRegoDecision(c.req.raw, c.env));
app.post("/internal/claim-unchallenged-sweep",             (c) => handleClaimUnchallengedSweep(c.req.raw, c.env));
// ADR-0074 — authn calls this after Passkey verify / guest sign-up to mint
// an ERC725 root identity contract on chain 260425. HMAC-gated.
app.post("/internal/provision-root-identity",              (c) => handleProvisionRootIdentity(c.req.raw, c.env));

// Org management (com.etzhayyim.authz.org*)
app.post("/xrpc/com.etzhayyim.authz.orgCreate", (c) => handleOrgCreate(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.orgUpdate", (c) => handleOrgUpdate(c.req.raw, c.env));
app.get("/xrpc/com.etzhayyim.authz.orgInfo", (c) => handleOrgInfo(c.req.raw, c.env));
app.get("/xrpc/com.etzhayyim.authz.orgMembers", (c) => handleOrgMembers(c.req.raw, c.env));
app.get("/xrpc/com.etzhayyim.authz.orgList", (c) => handleOrgList(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.orgInvite", (c) => handleOrgInvite(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.orgInviteAccept", (c) => handleOrgInviteAccept(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.orgMemberRemove", (c) => handleOrgMemberRemove(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.orgMemberRoleUpdate", (c) => handleOrgMemberRoleUpdate(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.orgTransferOwnership", (c) => handleOrgTransferOwnership(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.authz.orgLeave", (c) => handleOrgLeave(c.req.raw, c.env));

// OAuth link callbacks.
app.get("/oauth/link/google/callback", (c) => handleOAuthLinkCallback(c.req.raw, c.env, "google"));
app.get("/oauth/link/microsoft/callback", (c) => handleOAuthLinkCallback(c.req.raw, c.env, "microsoft"));

// Fallback: static assets for unmatched GET (Svelte CSR build).
app.get("*", async (c) => {
  if (c.env.ASSETS) {
    try { return await c.env.ASSETS.fetch(c.req.raw); } catch { /* fall through */ }
  }
  return new Response("Not Found", { status: 404 });
});

export default app;
