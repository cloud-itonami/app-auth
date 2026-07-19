import { Hono } from "hono";
import { decodeBase64Url, encodeBase64Url } from "./base64url";
import {
  agentDidPath, createDid, createetzhayyimDid, defaultHumanSubActorPath, didToUrl, ownerHash,
  PerformerType, toDidDocumentJsonld, uncompressedPubkeyB64UrlToMultibase, userDidPath,
  createetzhayyimChildDid, createetzhayyimChildDidSemantic, didDepth, didParent, didParsesAsetzhayyim,
  didParsesAsetzhayyimAny, isValidetzhayyimSegmentValue, verifyDidChain,
  type ChildDidInput, type MaterialKind, type SegmentKind, type SemanticChildDidResult,
} from "./did";
import { verifyDpopProof } from "./dpop";
import { beginAuthentication, beginRegistration, verifyAuthentication, verifyRegistration } from "./passkey";
import { issueSession, refreshSession, verifySession } from "./session";
import { buildJwks, signServiceAuth } from "./service-auth";
import { renderAuthPage, renderLinkResultPage } from "./ui";

interface Env {
  AUTH_DB?: D1Database;
  KEYS_DB?: D1Database;
  ASSETS?: Fetcher;
  PDS_SERVICE?: Fetcher;
  SS_AT_SESSION_SECRET?: string;
  SS_SERVICE_AUTH_PRIVATE_KEY?: string;
  SS_AUTH_PUBLIC_KEY_B64?: string;
  SS_TELNYX_API_KEY?: string;
  SS_TELNYX_MESSAGING_PROFILE_ID?: string;
  SS_TELNYX_PHONE_NUMBER?: string;
  SS_STRIPE_SECRET_KEY?: string | { get(): Promise<string> };
  SS_STRIPE_SECRET_KEY_STORE?: { get(): Promise<string> } | string;
  STRIPE_PUBLISHABLE_KEY?: string | { get(): Promise<string> };
  STRIPE_PUBLISHABLE_KEY_STORE?: { get(): Promise<string> } | string;
  GOOGLE_OAUTH_CLIENT_ID?: string;
  GOOGLE_OAUTH_CLIENT_SECRET?: string;
  MICROSOFT_OAUTH_CLIENT_ID?: string;
  MICROSOFT_OAUTH_CLIENT_SECRET?: string;
  GMAIL_OAUTH_ID?: string;
  GMAIL_OAUTH_SECRET?: string;
  OUTLOOK_SECRET?: string;
  OUTLOOK_SECRET_ID?: string;
  SS_REPO_SIGNING_KEK?: string;  // AES-256 KEK for envelope encryption (base64url, 32 bytes)
  // ADR-0074 sign-up — service binding to authz `/internal/provision-root-identity`.
  AUTHZ_RPC?: Fetcher;
  // Shared HMAC with worker-authz to gate the internal sign-up route (same
  // secret used by the claim-stake settler routes).
  CLAIM_SETTLER_HMAC?: string;
}

let authTablesReady: Promise<void> | null = null;
let keysTablesReady: Promise<void> | null = null;

function nowIso(): string {
  return new Date().toISOString();
}

// ── KEK Envelope Encryption (ADR-0010 Stage 1) ──────────────────────────
// private_key ← data_key (AES-256-GCM, per-DID) ← KEK (SS_REPO_SIGNING_KEK)

async function importKek(kekB64: string): Promise<CryptoKey> {
  const pad = kekB64.length % 4 === 0 ? "" : "=".repeat(4 - (kekB64.length % 4));
  const raw = Uint8Array.from(atob(kekB64.replace(/-/g, "+").replace(/_/g, "/") + pad), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function envelopeEncrypt(kekB64: string, plaintext: Uint8Array): Promise<{ ciphertext: string; wrappedDataKey: string; iv: string }> {
  const kek = await importKek(kekB64);
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const dataKeyCrypto = await crypto.subtle.importKey("raw", dataKey, { name: "AES-GCM" }, false, ["encrypt"]);
  const ciphertextBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dataKeyCrypto, plaintext);
  const wrappedBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, dataKey);
  const b64 = (buf: ArrayBuffer) => {
    const bytes = new Uint8Array(buf);
    let s = ""; for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
  return { ciphertext: b64(ciphertextBuf), wrappedDataKey: b64(wrappedBuf), iv: b64(iv) };
}

async function envelopeDecrypt(kekB64: string, ciphertext: string, wrappedDataKey: string, ivB64: string): Promise<Uint8Array> {
  const decode = (s: string) => {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  };
  const kek = await importKek(kekB64);
  const iv = decode(ivB64);
  const dataKeyBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, kek, decode(wrappedDataKey));
  const dataKeyCrypto = await crypto.subtle.importKey("raw", dataKeyBuf, { name: "AES-GCM" }, false, ["decrypt"]);
  const plaintextBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, dataKeyCrypto, decode(ciphertext));
  return new Uint8Array(plaintextBuf);
}

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
      // ── did:etzhayyim auth control plane (GraphAr schema in D1) ──
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
        CREATE TABLE IF NOT EXISTS vertex_etzhayyim_auth_credential (
          vertex_id TEXT PRIMARY KEY,
          sensitivity_ord INTEGER NOT NULL DEFAULT 3,
          owner_did TEXT,
          did TEXT NOT NULL,
          handle TEXT NOT NULL,
          public_key_b64 TEXT NOT NULL,
          sign_count INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
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
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS vertex_etzhayyim_auth_otp (
          vertex_id TEXT PRIMARY KEY,
          sensitivity_ord INTEGER NOT NULL DEFAULT 3,
          owner_did TEXT,
          account_did TEXT NOT NULL,
          email TEXT NOT NULL,
          code TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          created_at TEXT NOT NULL
        )
      `),
      env.AUTH_DB.prepare(`
        CREATE TABLE IF NOT EXISTS edge_etzhayyim_auth_linked (
          edge_id TEXT PRIMARY KEY,
          src_vid TEXT NOT NULL,
          dst_vid TEXT NOT NULL,
          sensitivity_ord INTEGER NOT NULL DEFAULT 3,
          owner_did TEXT,
          provider TEXT NOT NULL,
          provider_subject TEXT NOT NULL,
          display_label TEXT NOT NULL,
          verified INTEGER NOT NULL DEFAULT 0,
          metadata_json TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(src_vid, provider, provider_subject)
        )
      `),
    ]).then(() => undefined).catch((error: unknown) => {
      authTablesReady = null;
      throw error;
    });
  }
  await authTablesReady;
}

async function ensureKeysTables(env: Env): Promise<void> {
  if (!env.KEYS_DB) return;
  if (!keysTablesReady) {
    keysTablesReady = env.KEYS_DB.batch([
      // ── did:etzhayyim key custody (GraphAr schema, KEK envelope) ──
      env.KEYS_DB.prepare(`DROP TABLE IF EXISTS vertex_etzhayyim_key_signing`),
      env.KEYS_DB.prepare(`
        CREATE TABLE IF NOT EXISTS vertex_etzhayyim_key_signing (
          vertex_id TEXT PRIMARY KEY,
          sensitivity_ord INTEGER NOT NULL DEFAULT 3,
          owner_did TEXT,
          did TEXT NOT NULL,
          encrypted_private_key TEXT NOT NULL,
          wrapped_data_key TEXT NOT NULL,
          iv TEXT NOT NULL,
          performer_type TEXT NOT NULL,
          public_key_multibase TEXT NOT NULL,
          created_at TEXT NOT NULL
        )
      `),
      env.KEYS_DB.prepare(`
        CREATE TABLE IF NOT EXISTS vertex_etzhayyim_key_revoked_session (
          vertex_id TEXT PRIMARY KEY,
          sensitivity_ord INTEGER NOT NULL DEFAULT 3,
          owner_did TEXT,
          jti TEXT NOT NULL,
          did TEXT NOT NULL,
          revoked_at TEXT NOT NULL,
          sid TEXT
        )
      `),
      env.KEYS_DB.prepare(`
        CREATE TABLE IF NOT EXISTS vertex_etzhayyim_key_otp (
          vertex_id TEXT PRIMARY KEY,
          sensitivity_ord INTEGER NOT NULL DEFAULT 3,
          owner_did TEXT,
          phone TEXT NOT NULL,
          code TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          created_at TEXT NOT NULL
        )
      `),
      env.KEYS_DB.prepare(`
        CREATE TABLE IF NOT EXISTS vertex_etzhayyim_key_api_key (
          vertex_id TEXT PRIMARY KEY,
          owner_did TEXT NOT NULL,
          key_hash TEXT NOT NULL UNIQUE,
          key_prefix TEXT NOT NULL DEFAULT 'sk_live_',
          name TEXT NOT NULL DEFAULT 'default',
          scopes TEXT NOT NULL DEFAULT 'read,write',
          status TEXT NOT NULL DEFAULT 'active',
          product_scope TEXT,
          created_at TEXT NOT NULL,
          last_used_at TEXT
        )
      `),
    ]).then(async () => {
      // ADR-2604240914 Y2 B3: pre-existing deployments predate `sid`. D1/SQLite
      // ALTER TABLE ADD COLUMN is idempotent via the duplicate-column error
      // we catch and ignore.
      try {
        await env.KEYS_DB.prepare(
          "ALTER TABLE vertex_etzhayyim_key_revoked_session ADD COLUMN sid TEXT",
        ).run();
      } catch (_e) { /* column already exists — first run after fresh CREATE */ }
      try {
        await env.KEYS_DB.prepare(
          "CREATE INDEX IF NOT EXISTS idx_revoked_session_sid ON vertex_etzhayyim_key_revoked_session (sid)",
        ).run();
      } catch (e) { console.warn("[keys/init] sid index create failed:", e); }
      return undefined;
    }).catch((error: unknown) => {
      keysTablesReady = null;
      throw error;
    });
  }
  await keysTablesReady;
}

interface OAuthAuthorizationCode {
  code: string;
  'clientId': string;
  'redirectUri': string;
  'codeChallenge': string;
  'codeChallengeMethod': string;
  state: string;
  did: string;
  handle: string;
  'expiresAt': number;
}

interface LinkedAuthMethod {
  provider: string;
  providerSubject: string;
  displayLabel: string;
  verified: boolean;
  createdAt: string;
  updatedAt: string;
  metadata?: Record<string, unknown>;
}

interface SessionAccount {
  accountDid: string;
  activeDid: string;
  handle: string;
  token: string;
  payload: Record<string, unknown>;
}

interface AuthScoreSummary {
  score: number;
  verifiedMethodCount: number;
  methods: Array<{ provider: string; verified: boolean; label: string }>;
}

const usedDpopJtis = new Set<string>();

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

/** Build Set-Cookie header value for cross-subdomain session sharing on *.etzhayyim.com. */
function sessionCookie(accessJwt: string): string {
  return `etzhayyim_session=${accessJwt}; Domain=.etzhayyim.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=604800`;
}

/** Build Set-Cookie header that clears the session cookie across *.etzhayyim.com. */
function clearSessionCookie(): string {
  return "etzhayyim_session=; Domain=.etzhayyim.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0";
}

/** Return JSON response with session cookie set for cross-subdomain auth. */
function jsonWithSession(body: unknown, accessJwt: string, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
      // no-cookie: allow legacy cross-subdomain auth bridge pending DID/WebAuthn-only cutover
      "Set-Cookie": sessionCookie(accessJwt),
      ...extraHeaders,
    },
  });
}

function jsonErr(status: number, error: string, message: string): Response {
  return json({ error, message }, status);
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

function accountHandleFromPath(path: string): string {
  const nanoid = path.replace(/^user:/, "");
  return `${nanoid}.etzhayyim.com`;
}

function deriveDefaultHumanDid(accountDid: string): string {
  return accountDid.startsWith("did:web:authn.etzhayyim.com:")
    ? `${accountDid}:person:default`
    : accountDid;
}

function orgIdFromAccountDid(accountDid: string): string {
  const match = accountDid.match(/^did:web:authn\.etzhayyim\.ai:user:([a-zA-Z0-9._:-]+)/);
  return match ? `user:${match[1]}` : accountDid;
}

function formDecode(value: string): string {
  return decodeURIComponent(value.replace(/\+/g, " "));
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

function getAccessTokenFromRequest(request: Request): string {
  const authorization = request.headers.get("Authorization") || "";
  if (authorization.startsWith("Bearer ")) return authorization.slice("Bearer ".length);
  const cookies = parseCookieHeader(request.headers.get("Cookie") || "");
  return cookies.etzhayyim_session || "";
}

async function handleVerifySession(request: Request, env: Env): Promise<Response> {
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  try {
    const account = await requireSessionAccount(request, env);
    return json({
      valid: true,
      did: account.accountDid,
      accountDid: account.accountDid,
      activeDid: account.activeDid,
      handle: account.handle,
    });
  } catch (err) {
    return json({ valid: false, error: err instanceof Error ? err.message : "verify failed" });
  }
}

async function requireSessionAccount(request: Request, env: Env): Promise<SessionAccount> {
  const token = getAccessTokenFromRequest(request);
  if (!token) throw new Error("missing session");
  const payload = await verifySession(getSessionSecret(env), token, "com.atproto.access");
  const accountDid = String(payload.accountDid ?? payload.sub ?? "");
  if (!accountDid) throw new Error("missing accountDid");
  const activeDid = String(payload.activeDid ?? deriveDefaultHumanDid(accountDid));
  const handle = String(payload.handle ?? accountDid);
  const jti = String(payload.jti ?? "");
  if (jti && env.KEYS_DB) {
    const revoked = await env.KEYS_DB.prepare("SELECT 1 FROM revoked_sessions WHERE jti = ? LIMIT 1").bind(jti).first();
    if (revoked) throw new Error("session revoked");
  }
  return { accountDid, activeDid, handle, token, payload };
}

function providerDisplayLabel(provider: string, subject: string, metadata?: Record<string, unknown>): string {
  if (provider === "passkey") return "Passkey";
  if (provider === "email") return subject;
  if (provider === "google") return String(metadata?.email || subject);
  if (provider === "microsoft") return String(metadata?.email || subject);
  return subject;
}

function normalizeProvider(provider: string): "email" | "google" | "microsoft" | null {
  const value = provider.trim().toLowerCase();
  if (value === "email") return "email";
  if (value === "google" || value === "gmail") return "google";
  if (value === "microsoft" || value === "azure" || value === "outlook") return "microsoft";
  return null;
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
  const now = nowIso();
  await env.AUTH_DB.prepare(`
    INSERT INTO linked_auth_methods (
      account_did, provider, provider_subject, display_label, verified, metadata_json, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(account_did, provider, provider_subject) DO UPDATE SET
      display_label=excluded.display_label,
      verified=excluded.verified,
      metadata_json=excluded.metadata_json,
      updated_at=excluded.updated_at
  `).bind(
    accountDid,
    provider,
    providerSubject,
    displayLabel,
    verified ? 1 : 0,
    metadata ? JSON.stringify(metadata) : null,
    now,
    now,
  ).run();
}

async function deleteLinkedAuthMethod(env: Env, accountDid: string, provider: string, providerSubject: string): Promise<void> {
  if (!env.AUTH_DB) return;
  await ensureAuthTables(env);
  await env.AUTH_DB.prepare(`
    DELETE FROM linked_auth_methods
    WHERE account_did = ? AND provider = ? AND provider_subject = ?
  `).bind(accountDid, provider, providerSubject).run();
}

async function countPasskeysForAccount(env: Env, accountDid: string): Promise<number> {
  if (!env.AUTH_DB) return 0;
  await ensureAuthTables(env);
  const row = await env.AUTH_DB.prepare(`
    SELECT COUNT(*) AS count
    FROM passkey_credentials
    WHERE did = ?
  `).bind(accountDid).first<{ count: number }>();
  return Number(row?.count || 0);
}

async function listLinkedAuthMethods(env: Env, accountDid: string): Promise<LinkedAuthMethod[]> {
  const methods: LinkedAuthMethod[] = [];
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
  `).bind(accountDid).all();
  for (const row of (rows.results || []) as Array<{
    provider: string;
    providerSubject: string;
    displayLabel: string;
    verified: number;
    metadataJson?: string | null;
    createdAt: string;
    updatedAt: string;
  }>) {
    let metadata: Record<string, unknown> | undefined;
    if (row.metadataJson) {
      try {
        metadata = JSON.parse(row.metadataJson) as Record<string, unknown>;
      } catch {
        metadata = undefined;
      }
    }
    methods.push({
      provider: row.provider,
      providerSubject: row.providerSubject,
      displayLabel: row.displayLabel,
      verified: Boolean(row.verified),
      metadata,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  }
  return methods;
}

function buildActorScoreSummary(methods: LinkedAuthMethod[]): AuthScoreSummary {
  const uniqueVerifiedProviders = new Map<string, { provider: string; verified: boolean; label: string }>();
  for (const method of methods) {
    const key = method.provider;
    if (!method.verified) continue;
    uniqueVerifiedProviders.set(key, {
      provider: method.provider,
      verified: method.verified,
      label: method.displayLabel,
    });
  }
  const verifiedMethodCount = uniqueVerifiedProviders.size;
  return {
    score: Math.max(0, Math.min(100, verifiedMethodCount * 25)),
    verifiedMethodCount,
    methods: methods.map((method) => ({
      provider: method.provider,
      verified: method.verified,
      label: method.displayLabel,
    })),
  };
}

function oauthLinkRedirectUri(request: Request, provider: "google" | "microsoft"): string {
  return `${new URL(request.url).origin}/oauth/link/${provider}/callback`;
}


/** HMAC-signed self-contained OAuth code (stateless, no KV/DO). */
async function encodeOAuthCode(secret: string, payload: OAuthAuthorizationCode): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const data = new TextEncoder().encode(JSON.stringify(payload));
  const sig = await crypto.subtle.sign("HMAC", key, data);
  return `${encodeBase64Url(new Uint8Array(data))}.${encodeBase64Url(new Uint8Array(sig))}`;
}

async function decodeOAuthCode(secret: string, token: string): Promise<OAuthAuthorizationCode | null> {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  try {
    const data = decodeBase64Url(parts[0]);
    const sig = decodeBase64Url(parts[1]);
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify("HMAC", key, sig, data);
    if (!valid) return null;
    return JSON.parse(new TextDecoder().decode(data)) as OAuthAuthorizationCode;
  } catch {
    return null;
  }
}

async function parseJson<T>(request: Request): Promise<T> {
  return request.json<T>();
}

async function parseOAuthTokenRequest(request: Request): Promise<Record<string, string>> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return parseJson<Record<string, string>>(request);
  }
  const text = await request.text();
  const parsed: Record<string, string> = {};
  for (const pair of text.split("&")) {
    const [key, value] = pair.split("=", 2);
    if (!key) continue;
    parsed[key] = formDecode(value || "");
  }
  // Mirror OAuth 2.0 (RFC 6749) snake_case keys to camelCase aliases so
  // downstream handlers can read either spelling.
  const aliases: Record<string, string> = {
    grant_type: "grantType",
    client_id: "clientId",
    redirect_uri: "redirectUri",
    code_verifier: "codeVerifier",
    code_challenge: "codeChallenge",
    code_challenge_method: "codeChallengeMethod",
    refresh_token: "refreshToken",
  };
  for (const [snake, camel] of Object.entries(aliases)) {
    if (parsed[snake] !== undefined && parsed[camel] === undefined) parsed[camel] = parsed[snake];
  }
  return parsed;
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  const bytes = new Uint8Array(digest);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function handleAuthenticate(request: Request, env: Env): Promise<Response> {
  const body = await parseJson<Record<string, unknown>>(request);
  if (body.xKotodamaVerified === true) {
    return json({
      level: "internal",
      did: null,
      'orgId': String(body.xetzhayyimOrgId || "service"),
      clearance: "restricted",
      sub: null,
      'tokenScopes': [],
    });
  }
  const authorization = typeof body.authorization === "string" ? body.authorization : "";
  if (!authorization) {
    return json({
      level: "public",
      did: null,
      'orgId': "public",
      clearance: "public",
      sub: null,
      'tokenScopes': [],
    });
  }
  try {
    const token = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : authorization;
    const payload = await verifySession(getSessionSecret(env), token, "com.atproto.access");
    const accountDid = String(payload.accountDid ?? payload.sub ?? "");
    const requestedActiveDid = typeof body.xActiveDid === "string" ? body.xActiveDid.trim() : "";
    const tokenActiveDid = String(payload.activeDid ?? deriveDefaultHumanDid(accountDid));
    const activeDid = requestedActiveDid && (requestedActiveDid === accountDid || requestedActiveDid.startsWith(`${accountDid}:`))
      ? requestedActiveDid
      : tokenActiveDid;
    const jti = String(payload.jti ?? "");
    if (jti && env.KEYS_DB) {
      const revoked = await env.KEYS_DB.prepare("SELECT 1 FROM revoked_sessions WHERE jti = ? LIMIT 1").bind(jti).first();
      if (revoked) throw new Error("session revoked");
    }
    const scopes = String(payload.scope ?? "").split(" ").filter(Boolean);
    if (!scopes.includes("com.atproto.access")) scopes.push("com.atproto.access");
    return json({
      level: "session",
      did: activeDid,
      accountDid,
      activeDid,
      'orgId': orgIdFromAccountDid(accountDid),
      clearance: "internal",
      sub: accountDid,
      'tokenScopes': scopes,
    });
  } catch {
    return json({
      level: "public",
      did: null,
      'orgId': "public",
      clearance: "public",
      sub: null,
      'tokenScopes': [],
    });
  }
}

async function handleCreateSession(request: Request, env: Env): Promise<Response> {
  // ADR-2604240914 Y1 A2: caller MAY pass `cnfJkt` when the session is issued
  // on behalf of a DPoP-bound OAuth token exchange. The thumbprint ends up in
  // the access token's `cnf.jkt` claim so the Resource Server can verify the
  // proof key matches (RFC 9449 §6).
  const body = await parseJson<{
    did?: string;
    handle: string;
    accountDid?: string;
    activeDid?: string;
    cnfJkt?: string;
  }>(request);
  const accountDid = String(body.accountDid ?? body.did ?? "");
  const activeDid = String(body.activeDid ?? deriveDefaultHumanDid(accountDid));
  const cnfJkt = typeof body.cnfJkt === "string" && body.cnfJkt.length > 0 ? body.cnfJkt : undefined;
  const tokens = await issueSession(getSessionSecret(env), { accountDid, activeDid, handle: body.handle, cnfJkt });
  return jsonWithSession(tokens, tokens.accessJwt);
}

/**
 * ADR-2604240914 Phase B (Y2): internal RPC backing the PDS `/oauth/revoke`
 * endpoint. Extracts {jti, sub, exp} from the provided token (no signature
 * verify — we do not want revocation to depend on a live secret) and writes
 * a row to `vertex_etzhayyim_key_revoked_session`. RFC 7009 §2.2 requires the
 * caller to return 200 for both success and unknown tokens — this handler
 * therefore tolerates malformed tokens silently.
 *
 * Expected body: `{ token: string, token_type_hint?: "access_token" | "refresh_token" }`.
 */
async function handleRevokeToken(request: Request, env: Env): Promise<Response> {
  const body = await parseJson<{ token?: string; token_type_hint?: string; tokenTypeHint?: string }>(request);
  const token = String(body.token ?? "").trim();
  if (!token) return json({ ok: true });
  // Best-effort JWT decode. Non-JWT tokens or garbage → treat as unknown.
  const parts = token.split(".");
  if (parts.length !== 3) return json({ ok: true });
  let payload: Record<string, unknown> = {};
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/").padEnd(parts[1].length + (4 - parts[1].length % 4) % 4, "=");
    payload = JSON.parse(atob(b64)) as Record<string, unknown>;
  } catch {
    return json({ ok: true });
  }
  const jti = typeof payload.jti === "string" ? payload.jti : "";
  const sid = typeof payload.sid === "string" ? payload.sid : "";
  // Tokens issued before Y2 B3 have jti but no sid. Revoking such a legacy
  // token can only blacklist the single jti — its refresh counterpart stays
  // valid until its own jti is revoked. New issuance always sets sid, so
  // the cascade kicks in automatically going forward.
  if (!jti && !sid) return json({ ok: true });
  const did = typeof payload.sub === "string"
    ? payload.sub
    : (typeof payload.did === "string" ? payload.did : "");
  const revokedAt = new Date().toISOString();
  await ensureKeysTables(env);
  try {
    // One row keyed on jti (unchanged) — carries the family `sid` too so the
    // RS check can match either column without a second INSERT.
    if (jti) {
      const vertexId = `at://did:web:authn.etzhayyim.com/com.etzhayyim.auth.revokedSession/${jti}`;
      await env.KEYS_DB.prepare(
        "INSERT OR IGNORE INTO vertex_etzhayyim_key_revoked_session (vertex_id, sensitivity_ord, owner_did, jti, did, revoked_at, sid) VALUES (?, 3, ?, ?, ?, ?, ?)",
      ).bind(vertexId, did, jti, did, revokedAt, sid || null).run();
    }
    // Family-scoped row so the paired refresh/access token (same sid) is
    // caught on lookup even when the revoked_at request only carried one
    // jti. RFC 7009 §2.1 SHOULD cascade.
    if (sid) {
      const sidVertexId = `at://did:web:authn.etzhayyim.com/com.etzhayyim.auth.revokedFamily/${sid}`;
      await env.KEYS_DB.prepare(
        "INSERT OR IGNORE INTO vertex_etzhayyim_key_revoked_session (vertex_id, sensitivity_ord, owner_did, jti, did, revoked_at, sid) VALUES (?, 3, ?, ?, ?, ?, ?)",
      ).bind(sidVertexId, did, jti || `family:${sid}`, did, revokedAt, sid).run();
    }
  } catch (e) {
    console.warn("[oauth/revoke-token] D1 INSERT failed (non-fatal per RFC 7009 §2.2):", e);
  }
  return json({ ok: true });
}

/**
 * ADR-2604240914 Y2 B2: RS-side blacklist lookup. atproto calls this from
 * `isJtiRevoked` when its 60s in-memory cache misses. Returns
 * `{ revoked: boolean, revoked_at?: string }`.
 *
 * Expected body: `{ jti: string }`.
 */
async function handleCheckRevoked(request: Request, env: Env): Promise<Response> {
  // ADR-2604240914 Y2 B2 + B3: lookup by either jti or sid. Caller sends
  // both so revoking via family (sid) also matches access tokens that were
  // issued with only jti-keyed revocation rows.
  const body = await parseJson<{ jti?: string; sid?: string }>(request);
  const jti = typeof body.jti === "string" ? body.jti.trim() : "";
  const sid = typeof body.sid === "string" ? body.sid.trim() : "";
  if (!jti && !sid) return json({ revoked: false });
  try {
    // Build WHERE dynamically so we don't spend a lookup on an empty placeholder.
    const conds: string[] = [];
    const binds: string[] = [];
    if (jti) { conds.push("jti = ?"); binds.push(jti); }
    if (sid) { conds.push("sid = ?"); binds.push(sid); }
    const sql = `SELECT revoked_at FROM vertex_etzhayyim_key_revoked_session WHERE ${conds.join(" OR ")} LIMIT 1`;
    const row = await env.KEYS_DB.prepare(sql).bind(...binds).first<{ revoked_at?: string }>();
    if (row?.revoked_at) return json({ revoked: true, revoked_at: row.revoked_at });
    return json({ revoked: false });
  } catch (e) {
    console.warn("[oauth/check-revoked] D1 lookup failed:", e);
    return json({ revoked: false });
  }
}

async function handleRefreshSession(request: Request, env: Env): Promise<Response> {
  // ADR-2604240914 Y1 A2: DPoP-bound refresh rotates the access token's
  // proof-key thumbprint. Caller forwards the new DPoP jkt; if absent the
  // refreshSession helper retains whatever cnf was embedded in the old token.
  const body = await parseJson<{ 'refreshToken': string; 'cnfJkt'?: string }>(request);
  const cnfJkt = typeof body.cnfJkt === "string" && body.cnfJkt.length > 0 ? body.cnfJkt : undefined;
  try {
    const tokens = await refreshSession(getSessionSecret(env), body.refreshToken, { cnfJkt });
    return jsonWithSession(tokens, tokens.accessJwt);
  } catch (error) {
    return jsonErr(401, "InvalidToken", error instanceof Error ? error.message : "invalid token");
  }
}

/**
 * POST /xrpc/com.etzhayyim.auth.switchActiveDid
 * Body: { activeDid }
 * Re-issues the session JWT with a different activeDid (sub-actor persona).
 * The requested DID must equal the accountDid or start with "{accountDid}:".
 * Requires a valid session (Authorization Bearer or etzhayyim_session cookie).
 */
async function handleSwitchActiveDid(request: Request, env: Env): Promise<Response> {
  try {
    const token = getAccessTokenFromRequest(request);
    if (!token) return jsonErr(401, "AuthRequired", "missing session");
    const payload = await verifySession(getSessionSecret(env), token, "com.atproto.access");
    const accountDid = String(payload.accountDid ?? payload.sub ?? "");
    if (!accountDid) return jsonErr(401, "AuthRequired", "missing accountDid");
    const handle = String(payload.handle ?? accountDid);
    const body = await parseJson<{ activeDid: string }>(request);
    const requested = String(body.activeDid || "").trim();
    if (!requested) return jsonErr(400, "BadRequest", "activeDid is required");
    const isSelf = requested === accountDid;
    const isSubActor = requested.startsWith(`${accountDid}:`);
    if (!isSelf && !isSubActor) {
      return jsonErr(403, "Forbidden", "activeDid must be accountDid or a sub-actor path");
    }
    const tokens = await issueSession(getSessionSecret(env), {
      accountDid,
      activeDid: requested,
      handle,
    });
    return jsonWithSession({ ok: true, accountDid, activeDid: requested, handle, tokens }, tokens.accessJwt);
  } catch (error) {
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function handleResolveDid(request: Request): Promise<Response> {
  const body = await parseJson<{ did: string }>(request);
  const url = didToUrl(body.did);
  if (!url) return jsonErr(400, "InvalidDID", "cannot parse did:web");
  return json({ did: body.did, url });
}

async function handleCreateDid(request: Request, env: Env): Promise<Response> {
  const body = await parseJson<{ path: string; 'performerType': PerformerType }>(request);
  const { privateKeyB64url, didDocument } = await createDid(body.path, body.performerType);
  if (env.KEYS_DB) {
    await ensureKeysTables(env);
    await env.KEYS_DB.prepare(
      "INSERT OR REPLACE INTO did_keys (did, private_key_b64, performer_type, public_key_multibase, created_at) VALUES (?, ?, ?, ?, ?)"
    ).bind(didDocument.did, privateKeyB64url, body.performerType, didDocument.publicKeyMultibase, didDocument.createdAt).run();
  }
  return json({
    didDocument,
    'didDocumentJsonld': toDidDocumentJsonld(didDocument),
    privateKeyB64url,
    'ownerHash': ownerHash(didDocument.did),
  });
}

async function handleCreateAgentSession(request: Request, env: Env): Promise<Response> {
  const body = await parseJson<{ appNanoid?: string; subPath?: string; performerType?: PerformerType }>(request);
  const appNanoid = String(body.appNanoid || "");
  const subPath = typeof body.subPath === "string" ? body.subPath : undefined;
  const performerType = body.performerType || "service";
  if (!appNanoid) return jsonErr(400, "BadRequest", "appNanoid is required");
  const path = agentDidPath(appNanoid, subPath);
  const { privateKeyB64url, didDocument } = await createDid(path, performerType);
  if (env.KEYS_DB) {
    await ensureKeysTables(env);
    await env.KEYS_DB.prepare(
      "INSERT OR REPLACE INTO did_keys (did, private_key_b64, performer_type, public_key_multibase, created_at) VALUES (?, ?, ?, ?, ?)"
    ).bind(didDocument.did, privateKeyB64url, performerType, didDocument.publicKeyMultibase, didDocument.createdAt).run();
  }
  const handle = `${appNanoid}.etzhayyim.com`;
  return json({
    did: didDocument.did,
    didDocument,
    'didDocumentJsonld': toDidDocumentJsonld(didDocument),
    privateKeyB64url,
    'ownerHash': ownerHash(didDocument.did),
    'sessionTokens': await issueSession(getSessionSecret(env), {
      accountDid: didDocument.did,
      activeDid: didDocument.did,
      handle,
    }),
    'keyId': `${didDocument.did}#key-${crypto.randomUUID().replace(/-/g, "")}`,
    'keyCustodyTier': "serverAssisted",
  });
}

async function handleRotateAgentKey(request: Request): Promise<Response> {
  const body = await parseJson<{ did: string }>(request);
  const path = body.did.replace(/^did:web:authn\.etzhayyim\.ai:/, "");
  const { privateKeyB64url, didDocument } = await createDid(path, "service");
  return json({
    did: body.did,
    'newKeyId': `${body.did}#key-${crypto.randomUUID().replace(/-/g, "")}`,
    'newPublicKeyMultibase': didDocument.publicKeyMultibase,
    'newPrivateKeyB64url': privateKeyB64url,
    'oldKeyRevokedAt': new Date().toISOString(),
  });
}

async function handleOAuthIssueCode(request: Request, env: Env): Promise<Response> {
  const body = await parseJson<Record<string, string>>(request);
  if (!body.did || !body.clientId) return jsonErr(400, "BadRequest", "did and clientId are required");
  const authCode: OAuthAuthorizationCode = {
    code: "",
    'clientId': body.clientId,
    'redirectUri': body.redirectUri || "",
    'codeChallenge': body.codeChallenge || "",
    'codeChallengeMethod': body.codeChallengeMethod || "S256",
    state: body.state || "",
    did: body.did,
    handle: body.handle || "",
    'expiresAt': Math.floor(Date.now() / 1000) + 300,
  };
  const code = await encodeOAuthCode(getSessionSecret(env) || "fallback", authCode);
  return json({ code });
}

async function handleOAuthToken(request: Request, env: Env): Promise<Response> {
  const body = await parseOAuthTokenRequest(request);
  if (body.grantType !== "authorizationCode" && body.grantType !== "authorization_code") {
    return jsonErr(400, "UnsupportedGrantType", "only authorization_code is supported");
  }
  const authCode = await decodeOAuthCode(getSessionSecret(env) || "fallback", body.code || "");
  if (!authCode) return jsonErr(400, "InvalidGrant", "invalid or expired authorization code");
  if (authCode.expiresAt < Math.floor(Date.now() / 1000)) {
    return jsonErr(400, "InvalidGrant", "authorization code expired");
  }
  if (authCode.clientId !== body.clientId) {
    return jsonErr(400, "InvalidClient", "clientId mismatch");
  }
  if (authCode.redirectUri !== body.redirectUri) {
    return jsonErr(400, "InvalidGrant", "redirectUri mismatch");
  }
  if (authCode.codeChallengeMethod !== "S256") {
    return jsonErr(400, "InvalidRequest", "only S256 codeChallengeMethod is supported");
  }
  if (await sha256Base64Url(body.codeVerifier || "") !== authCode.codeChallenge) {
    return jsonErr(400, "InvalidGrant", "PKCE codeVerifier does not match codeChallenge");
  }
  const tokens = await issueSession(getSessionSecret(env), {
    accountDid: authCode.did,
    activeDid: deriveDefaultHumanDid(authCode.did),
    handle: authCode.handle,
  });

  // ADR-0022 bootstrap: mint canonical sk_live_* API key server-side by delegating
  // to PDS createApiKey via service binding. HS256 session JWT is no longer accepted
  // by PDS authenticate() (step 7), so the API key is issued under internal-trust
  // (x-kotodama-verified) instead of via CLI round-trip.
  const apiKey = await mintBootstrapApiKey(env, authCode.did).catch((err) => {
    console.warn("[oauth/token] mintBootstrapApiKey failed:", err);
    return "";
  });

  // ADR-2604231821 S5: OAuth /oauth/token response snake_case per RFC 6749 §5.1 + RFC 9207 (iss).
  // access_token TTL capped at 900s (spec). Cookie still set — authn doubles as
  // the browser session host; proper separation is Phase 4/5 follow-up work.
  return jsonWithSession(
    {
      'access_token': tokens.accessJwt,
      'token_type': "Bearer",
      'expires_in': 900,
      'id_token': tokens.accessJwt,
      'refresh_token': tokens.refreshJwt,
      'iss': "https://authn.etzhayyim.com",
      ...(apiKey ? { 'api_key': apiKey } : {}),
    },
    tokens.accessJwt,
    200,
    { "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" },
  );
}

/** Generate a cryptographically random API key with sk_live_ prefix. */
function generateApiKeyLocal(): string {
  const buf = new Uint8Array(24);
  crypto.getRandomValues(buf);
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let key = "sk_live_";
  for (const b of buf) key += chars[b % chars.length];
  return key;
}

async function sha256HexLocal(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/** Create an API key in KEYS_DB D1 and return the raw key. */
async function localCreateApiKey(
  env: Env,
  ownerDid: string,
  name: string = "default",
  scopes: string = "read,write",
): Promise<{ key: string; keyId: string }> {
  if (!env.KEYS_DB) throw new Error("KEYS_DB not available");
  await ensureKeysTables(env);
  const rawKey = generateApiKeyLocal();
  const keyHash = await sha256HexLocal(rawKey);
  const keyId = `apikey:${keyHash.slice(0, 16)}`;
  await env.KEYS_DB.prepare(
    `INSERT INTO vertex_etzhayyim_key_api_key
     (vertex_id, owner_did, key_hash, key_prefix, name, scopes, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
  ).bind(keyId, ownerDid, keyHash, "sk_live_", name.slice(0, 256) || "default", scopes, nowIso()).run();
  return { key: rawKey, keyId };
}

async function mintBootstrapApiKey(env: Env, accountDid: string): Promise<string> {
  if (!env.KEYS_DB) return "";
  console.info("[oauth/token] mintBootstrapApiKey via local KEYS_DB D1", { accountDid });
  const { key } = await localCreateApiKey(env, accountDid, "etzhayyim-cli-login", "read,write");
  return key;
}

async function buildPdsApiKeyProxyHeaders(
  env: Env,
  accountDid: string,
  lxm: "com.etzhayyim.auth.listApiKeys" | "com.etzhayyim.auth.revokeApiKey",
): Promise<Record<string, string>> {
  const privateKeyB64 = getVar(env, "SS_SERVICE_AUTH_PRIVATE_KEY");
  const publicKeyB64 = getVar(env, "SS_AUTH_PUBLIC_KEY_B64");
  const useEs256 = Boolean(privateKeyB64 && publicKeyB64);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "x-active-did": accountDid,
    "x-etzhayyim-org-id": "auth-manage",
  };
  if (useEs256 && privateKeyB64) {
    const jwt = await signServiceAuth(
      privateKeyB64,
      "did:web:authn.etzhayyim.com",
      "did:web:atproto.etzhayyim.com",
      lxm,
      accountDid,
    );
    headers.Authorization = `Bearer ${jwt}`;
  } else {
    headers["x-kotodama-verified"] = "true";
  }
  return headers;
}

/** Handle com.etzhayyim.auth.createApiKey locally using KEYS_DB D1. */
async function handleCreateApiKeyLocal(request: Request, env: Env): Promise<Response> {
  if (!env.KEYS_DB) return jsonErr(503, "ConfigError", "KEYS_DB is required");
  try {
    const session = await requireSessionAccount(request, env);
    const body = await parseJson<{ name?: string; scopes?: string }>(request).catch(() => ({} as { name?: string; scopes?: string }));
    const name = String(body.name ?? "default").slice(0, 256) || "default";
    const scopes = String(body.scopes ?? "read,write").slice(0, 1024) || "read,write";
    const { key, keyId } = await localCreateApiKey(env, session.accountDid, name, scopes);
    return json({ key, keyId, name, scopes, ownerDid: session.accountDid });
  } catch (error) {
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

/** Internal endpoint: verify an API key hash, used by PDS verify.ts delegation. */
async function handleInternalVerifyApiKey(request: Request, env: Env): Promise<Response> {
  if (!env.KEYS_DB) return jsonErr(503, "ConfigError", "KEYS_DB is required");
  try {
    const body = await parseJson<{ keyHash?: string; rawKey?: string }>(request);
    let keyHash = String(body.keyHash ?? "").trim();
    if (!keyHash && body.rawKey) {
      keyHash = await sha256HexLocal(String(body.rawKey));
    }
    if (!keyHash) return jsonErr(400, "InvalidRequest", "keyHash or rawKey required");
    await ensureKeysTables(env);
    const row = await env.KEYS_DB.prepare(
      `SELECT owner_did, scopes, product_scope FROM vertex_etzhayyim_key_api_key
       WHERE key_hash = ? AND status = 'active' LIMIT 1`,
    ).bind(keyHash).first<{ owner_did: string; scopes: string; product_scope: string | null }>();
    if (!row) return jsonErr(404, "NotFound", "api key not found");
    // Fire-and-forget last_used_at update
    env.KEYS_DB.prepare(
      `UPDATE vertex_etzhayyim_key_api_key SET last_used_at = ? WHERE key_hash = ?`,
    ).bind(nowIso(), keyHash).run().catch(() => undefined);
    return json({ ownerDid: row.owner_did, scopes: row.scopes, productScope: row.product_scope ?? null });
  } catch (error) {
    return jsonErr(500, "InternalServerError", error instanceof Error ? error.message : "verify failed");
  }
}

async function proxyApiKeyManagement(
  request: Request,
  env: Env,
  nsid: "com.etzhayyim.auth.listApiKeys" | "com.etzhayyim.auth.revokeApiKey",
): Promise<Response> {
  if (!env.PDS_SERVICE || typeof env.PDS_SERVICE.fetch !== "function") {
    return jsonErr(503, "ConfigError", "PDS_SERVICE is required");
  }
  try {
    const session = await requireSessionAccount(request, env);
    const body = await request.text();
    const headers = await buildPdsApiKeyProxyHeaders(env, session.accountDid, nsid);
    const resp = await env.PDS_SERVICE.fetch(`https://atproto.etzhayyim.com/xrpc/${nsid}`, {
      method: "POST",
      headers,
      body: body || "{}",
    });
    const text = await resp.text();
    return new Response(text, {
      status: resp.status,
      headers: {
        "Content-Type": resp.headers.get("content-type") || "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Access-Control-Allow-Origin": "*",
      },
    });
  } catch (error) {
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function handleLinkEmailBegin(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB is required");
  try {
    const session = await requireSessionAccount(request, env);
    const body = await parseJson<{ email: string }>(request);
    const email = String(body.email || "").trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return jsonErr(400, "BadRequest", "valid email is required");
    await ensureAuthTables(env);
    const code = generateOtp();
    const expiresAt = nowSecs() + 600;
    await env.AUTH_DB.prepare(`
      INSERT OR REPLACE INTO email_link_codes (account_did, email, code, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(session.accountDid, email, code, expiresAt, nowIso()).run();
    console.log(`EMAIL LINK CODE ${session.accountDid} ${email} -> ${code}`);
    return json({
      sent: true,
      email,
      expiresIn: 600,
      // Until an outbound mail provider is configured, surface the code only in non-production flows.
      debugCode: code,
    });
  } catch (error) {
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function handleLinkEmailVerify(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) return jsonErr(503, "ConfigError", "AUTH_DB is required");
  try {
    const session = await requireSessionAccount(request, env);
    const body = await parseJson<{ email: string; code: string }>(request);
    const email = String(body.email || "").trim().toLowerCase();
    const code = String(body.code || "").trim();
    await ensureAuthTables(env);
    const row = await env.AUTH_DB.prepare(`
      SELECT code, expires_at AS expiresAt
      FROM email_link_codes
      WHERE account_did = ? AND email = ?
      LIMIT 1
    `).bind(session.accountDid, email).first<{ code: string; expiresAt: number }>();
    if (!row || row.code !== code || Number(row.expiresAt || 0) < nowSecs()) {
      return jsonErr(401, "InvalidCode", "invalid or expired code");
    }
    await env.AUTH_DB.prepare(`
      DELETE FROM email_link_codes
      WHERE account_did = ? AND email = ?
    `).bind(session.accountDid, email).run();
    await upsertLinkedAuthMethod(env, session.accountDid, "email", email, email, true, { email, verifiedAt: nowIso() });
    await syncAuthMethodToetzhayyimIdentity(env, session.accountDid, "email", email, true);
    const methods = await listLinkedAuthMethods(env, session.accountDid);
    return json({
      ok: true,
      linkedMethods: methods,
      actorScore: buildActorScoreSummary(methods),
    });
  } catch (error) {
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function handleUnlinkMethod(request: Request, env: Env): Promise<Response> {
  try {
    const session = await requireSessionAccount(request, env);
    const body = await parseJson<{ provider: string; providerSubject: string }>(request);
    if (body.provider === "passkey") return jsonErr(400, "BadRequest", "passkey cannot be removed here");
    await deleteLinkedAuthMethod(env, session.accountDid, String(body.provider || ""), String(body.providerSubject || ""));
    const methods = await listLinkedAuthMethods(env, session.accountDid);
    return json({ ok: true, linkedMethods: methods, actorScore: buildActorScoreSummary(methods) });
  } catch (error) {
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function handleLinkOAuthStart(request: Request, env: Env): Promise<Response> {
  try {
    const session = await requireSessionAccount(request, env);
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
      did: session.accountDid,
      handle: session.handle,
      expiresAt: nowSecs() + 600,
    });

    const authorizationUrl = provider === "google"
      ? `https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent("openid email profile")}&state=${encodeURIComponent(state)}&access_type=offline&prompt=consent`
      : `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent("openid email profile User.Read")}&response_mode=query&state=${encodeURIComponent(state)}`;

    return json({ ok: true, authorizationUrl, provider });
  } catch (error) {
    return jsonErr(401, "AuthRequired", error instanceof Error ? error.message : "auth required");
  }
}

async function exchangeOAuthCode(provider: "google" | "microsoft", request: Request, env: Env, code: string): Promise<Record<string, unknown>> {
  const redirectUri = oauthLinkRedirectUri(request, provider);
  const clientId = provider === "google" ? getGoogleOauthClientId(env) : getMicrosoftOauthClientId(env);
  const clientSecret = provider === "google" ? getGoogleOauthClientSecret(env) : getMicrosoftOauthClientSecret(env);
  if (!clientId || !clientSecret) throw new Error(`${provider} OAuth is not configured`);
  const tokenUrl = provider === "google"
    ? "https://oauth2.googleapis.com/token"
    : "https://login.microsoftonline.com/common/oauth2/v2.0/token";
  const params = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code,
    grant_type: "authorization_code",
    redirect_uri: redirectUri,
  });
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
    const profileResp = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!profileResp.ok) throw new Error("google profile fetch failed");
    return profileResp.json();
  }

  const profileResp = await fetch("https://graph.microsoft.com/v1.0/me", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!profileResp.ok) throw new Error("microsoft profile fetch failed");
  return profileResp.json();
}

async function handleOAuthLinkCallback(request: Request, env: Env, provider: "google" | "microsoft"): Promise<Response> {
  const url = new URL(request.url);
  const stateToken = url.searchParams.get("state") || "";
  const code = url.searchParams.get("code") || "";
  if (!stateToken || !code) return html(renderLinkResultPage(false, provider, "missing code or state"));
  try {
    const state = await decodeOAuthCode(getSessionSecret(env) || "fallback", stateToken);
    if (!state || !state.did || Number(state.expiresAt || 0) < nowSecs()) {
      return html(renderLinkResultPage(false, provider, "state is invalid or expired"));
    }
    const profile = await exchangeOAuthCode(provider, request, env, code);
    const subject = provider === "google"
      ? String(profile.sub || profile.email || "")
      : String(profile.id || profile.userPrincipalName || profile.mail || "");
    const email = provider === "google"
      ? String(profile.email || "")
      : String(profile.mail || profile.userPrincipalName || "");
    if (!subject) return html(renderLinkResultPage(false, provider, "provider account id missing"));
    const verified = provider === "google"
      ? Boolean(profile.email_verified ?? true)
      : true;
    await upsertLinkedAuthMethod(
      env,
      state.did,
      provider,
      subject,
      providerDisplayLabel(provider, subject, { email }),
      verified,
      { email, profile },
    );
    await syncAuthMethodToetzhayyimIdentity(env, state.did, provider, email, verified);
    return html(renderLinkResultPage(true, provider));
  } catch (error) {
    return html(renderLinkResultPage(false, provider, error instanceof Error ? error.message : "link failed"));
  }
}

/**
 * Resolve a did:etzhayyim DID Document.
 * Auth data (signing key) from D1 KEYS_DB.
 * Governance data (RBAC, capability, consent) from RisingWave via PDS_SERVICE.
 * Falls back to D1-only minimal DID Doc if graph is unavailable.
 */
// ── ADR-0029 recursive did:etzhayyim resolver helpers ───────────────────────

async function queryIdentityGraphRow(env: Env, did: string): Promise<Record<string, unknown> | null> {
  if (!env.PDS_SERVICE) return null;
  try {
    const resp = await env.PDS_SERVICE.fetch(
      `https://atproto.etzhayyim.com/xrpc/com.etzhayyim.graph.query?table=vertex_etzhayyim_identity&did=${encodeURIComponent(did)}`,
      { headers: { "x-kotodama-verified": "true" } },
    );
    if (!resp.ok) return null;
    const result = await resp.json() as { rows?: Record<string, unknown>[] };
    return result.rows?.[0] ?? null;
  } catch (e) {
    console.warn(`[queryIdentityGraphRow] ${did}:`, e);
    return null;
  }
}

async function ancestorChainRevoked(env: Env, did: string): Promise<string | null> {
  let cursor: string | null = didParent(did);
  let hops = 0;
  while (cursor && hops < 6) {
    const row = await queryIdentityGraphRow(env, cursor);
    const revokedAt = row?.revoked_at as string | undefined;
    if (revokedAt) return `${cursor} revoked at ${revokedAt}`;
    cursor = didParent(cursor);
    hops += 1;
  }
  return null;
}

async function findNearestKeyedAncestor(env: Env, did: string): Promise<{ did: string; publicKeyMultibase: string; performerType: string } | null> {
  if (!env.KEYS_DB) return null;
  let cursor: string | null = did;
  let hops = 0;
  while (cursor && hops < 6) {
    const keyRow = await env.KEYS_DB.prepare(
      "SELECT public_key_multibase, performer_type FROM vertex_etzhayyim_key_signing WHERE vertex_id = ? LIMIT 1"
    ).bind(cursor).first<{ public_key_multibase: string; performer_type: string }>();
    if (keyRow) return { did: cursor, publicKeyMultibase: keyRow.public_key_multibase, performerType: keyRow.performer_type };
    cursor = didParent(cursor);
    hops += 1;
  }
  return null;
}

async function handleResolveetzhayyimDid(request: Request, env: Env): Promise<Response> {
  const body = await parseJson<{ did: string }>(request);
  const did = body.did;
  if (!did?.startsWith("did:etzhayyim:")) return jsonErr(400, "InvalidDID", "did must start with did:etzhayyim:");
  if (!didParsesAsetzhayyim(did)) return jsonErr(400, "InvalidDID", "did:etzhayyim syntax invalid (max depth 6, 24-hex segments)");
  if (!env.KEYS_DB) return jsonErr(503, "ConfigError", "KEYS_DB required");
  await ensureKeysTables(env);

  const depth = didDepth(did);
  const parent = didParent(did);

  // D1 KEYS_DB lookup (present for root + pubkey kind; absent for keyless children)
  const keyRow = await env.KEYS_DB.prepare(
    "SELECT public_key_multibase, performer_type FROM vertex_etzhayyim_key_signing WHERE vertex_id = ? LIMIT 1"
  ).bind(did).first<{ public_key_multibase: string; performer_type: string }>();

  // Graph row (authoritative for recursion metadata + governance)
  const graphRow = await queryIdentityGraphRow(env, did);

  // Recursive keyless child: no local key, no graph row either → 404
  if (!keyRow && !graphRow) return jsonErr(404, "NotFound", `${did} not found`);

  // Self revocation
  const selfRevoked = graphRow?.revoked_at as string | undefined;
  if (selfRevoked) {
    return json({
      id: did,
      revoked: true,
      revokedAt: selfRevoked,
      revokedBy: graphRow?.controller_did ?? null,
    }, 410, { "Cache-Control": "no-store" });
  }

  // Ancestor revocation cascade (recursive DIDs only)
  if (depth > 1) {
    const cascadeReason = await ancestorChainRevoked(env, did);
    if (cascadeReason) {
      return json({ id: did, revoked: true, reason: cascadeReason }, 410, { "Cache-Control": "no-store" });
    }
  }

  // Hash chain verification (recursive DIDs with material_hash_proof only)
  let chainVerified: boolean | null = null;
  if (depth > 1 && parent && graphRow?.material_hash_proof) {
    try {
      chainVerified = await verifyDidChain(did, parent, String(graphRow.material_hash_proof));
    } catch {
      chainVerified = false;
    }
    if (chainVerified === false) return jsonErr(409, "ChainBroken", `hash chain verification failed for ${did}`);
  }

  // AUTH_DB lookup (only root DIDs have a row; children may not)
  let authAccount: { handle?: string; legacy_did?: string; controller_did?: string; actor_score?: number } | null = null;
  if (env.AUTH_DB) {
    await ensureAuthTables(env);
    authAccount = await env.AUTH_DB.prepare(
      "SELECT handle, legacy_did, controller_did, actor_score FROM vertex_etzhayyim_auth_account WHERE vertex_id = ? LIMIT 1"
    ).bind(did).first();
  }

  // Verification method: self key if present, else nearest keyed ancestor
  let verifyDid = did;
  let verifyKey = keyRow?.public_key_multibase;
  let verifyPerformer = keyRow?.performer_type;
  if (!verifyKey) {
    const ancestor = await findNearestKeyedAncestor(env, parent ?? did);
    if (!ancestor) return jsonErr(404, "NoKeyInChain", `no keyed ancestor for ${did}`);
    verifyDid = ancestor.did;
    verifyKey = ancestor.publicKeyMultibase;
    verifyPerformer = ancestor.performerType;
  }

  const entityType = (graphRow?.entity_type as string) ?? (verifyPerformer === "organization" ? "Organization" : "Person");
  const doc: Record<string, unknown> = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://did.etzhayyim.com/context/v1"],
    id: did,
    type: [entityType, verifyPerformer === "organization" ? "DoDAFPerformer" : "DoDAFSystem"],
    controller: authAccount?.controller_did ?? (graphRow?.controller_did as string) ?? did,
    verificationMethod: [{
      id: `${verifyDid}#signingKey`,
      type: "EcdsaSecp256r1VerificationKey2019",
      controller: verifyDid,
      publicKeyMultibase: verifyKey,
    }],
  };

  // ADR-0029 recursive metadata
  doc.depth = depth;
  if (parent) doc.parentDid = parent;
  if (graphRow?.material_kind) doc.materialKind = graphRow.material_kind;
  if (graphRow?.material_hash_proof) doc.materialHashProof = graphRow.material_hash_proof;
  if (chainVerified !== null) doc.chainVerified = chainVerified;
  if (verifyDid !== did) doc.signingDid = verifyDid;

  // Governance (graph authoritative)
  if (graphRow) {
    const parseArr = (v: unknown) => { try { return JSON.parse(String(v || "[]")); } catch { return []; } };
    doc.capabilityInvocation = parseArr(graphRow.capability_scopes).map((s: string) => ({
      scope: [s], maxLifetime: 60, consentRequired: (graphRow!.consent_model as string) === "gnap-vp",
    }));
    doc.rbac = { roles: parseArr(graphRow.rbac_roles), grants: parseArr(graphRow.rbac_grants) };
    doc.consent = { model: graphRow.consent_model, piiTier: graphRow.pii_tier };
    doc.authentication = parseArr(graphRow.authentication_methods);
    if (graphRow.dodaf_viewpoint) doc.dodaf = { viewpoint: graphRow.dodaf_viewpoint, performerBinding: graphRow.dodaf_performer_binding };
    if (graphRow.federation_did) doc.federationDID = graphRow.federation_did;
  }

  if (authAccount?.legacy_did) {
    const aka = (doc.alsoKnownAs as string[] | undefined) ?? [];
    aka.push(authAccount.legacy_did);
    doc.alsoKnownAs = aka;
  }
  if (authAccount?.handle) {
    const aka = (doc.alsoKnownAs as string[] | undefined) ?? [];
    aka.push(`at://${authAccount.handle}`);
    doc.alsoKnownAs = aka;
  }
  doc.actorScore = authAccount?.actor_score ?? (graphRow?.actor_score as number) ?? (depth === 1 ? 25 : 0);

  return json(doc, 200, { "Cache-Control": "public, max-age=60" });
}

// ── ADR-0029 mintChildDid ──────────────────────────────────────────────

async function handleMintChildDid(request: Request, env: Env): Promise<Response> {
  // 1. Session auth — caller must present Bearer access JWT
  const authHeader = request.headers.get("authorization") ?? "";
  if (!authHeader.toLowerCase().startsWith("bearer ")) {
    return jsonErr(401, "Unauthorized", "Bearer access token required");
  }
  const token = authHeader.slice("bearer ".length).trim();
  const sessionSecret = getVar(env, "SS_AT_SESSION_SECRET");
  if (!sessionSecret) return jsonErr(503, "ConfigError", "SS_AT_SESSION_SECRET required");

  let claims: Record<string, unknown>;
  try {
    claims = await verifySession(sessionSecret, token, "atproto");
  } catch (e) {
    return jsonErr(401, "InvalidToken", e instanceof Error ? e.message : "session verify failed");
  }
  const callerAccount = (claims.accountDid as string) ?? (claims.did as string);
  if (!callerAccount?.startsWith("did:etzhayyim:")) {
    return jsonErr(403, "Forbidden", "caller session lacks did:etzhayyim account");
  }

  // 2. Parse + validate input. ADR-0029 revision (2026-04-19) introduces a
  //    semantic-path form (segmentKind + segmentValue). Legacy hash form
  //    (materialKind + material) is kept for Phase 1 callers until ADR-0030
  //    Phase 4 migrates per-app adopters. The handler dispatches on shape.
  const body = await parseJson<{
    parentDid: string;
    // Semantic form (preferred, ADR-0029 revised)
    segmentKind?: Exclude<SegmentKind, "root">;
    segmentValue?: string;
    // Legacy hash form (Phase 1 grandfather path)
    materialKind?: Exclude<MaterialKind, "root">;
    material?: Record<string, string>;
    handle?: string;
    performerType?: PerformerType;
  }>(request);

  if (!didParsesAsetzhayyimAny(body.parentDid)) {
    return jsonErr(400, "InvalidParent", "parentDid must be a valid did:etzhayyim (max depth 6, legacy hex or semantic form)");
  }

  const useSemantic = typeof body.segmentKind === "string" && typeof body.segmentValue === "string";
  if (useSemantic) {
    if (!["sub", "id", "lexicon", "role", "pubkey", "grant"].includes(body.segmentKind as string)) {
      return jsonErr(400, "InvalidMaterial", `unknown segmentKind '${body.segmentKind}'`);
    }
    if (!isValidetzhayyimSegmentValue(body.segmentValue as string)) {
      return jsonErr(400, "InvalidMaterial", `invalid segmentValue '${body.segmentValue}'`);
    }
  } else {
    if (!body.materialKind) {
      return jsonErr(400, "InvalidMaterial", "either (segmentKind+segmentValue) or (materialKind+material) required");
    }
    if (!["pubkey", "role", "matter", "doc", "grant", "session"].includes(body.materialKind)) {
      return jsonErr(400, "InvalidMaterial", `unknown materialKind '${body.materialKind}'`);
    }
  }

  // 3. Authorize — caller account must equal or be a prefix ancestor of parent
  if (body.parentDid !== callerAccount && !body.parentDid.startsWith(`${callerAccount}:`)) {
    return jsonErr(403, "Forbidden", "caller does not control parentDid");
  }

  // 4. Check parent exists + revocation + depth headroom
  const parentRow = await queryIdentityGraphRow(env, body.parentDid);
  if (parentRow?.revoked_at) return jsonErr(410, "ParentRevoked", String(parentRow.revoked_at));
  const cascade = await ancestorChainRevoked(env, body.parentDid);
  if (cascade) return jsonErr(410, "ParentRevoked", cascade);

  const parentDepth = parentRow?.depth ? Number(parentRow.depth) : didDepth(body.parentDid);
  if (parentDepth >= 6) return jsonErr(400, "DepthLimit", "parent already at max depth 6");

  // 5. Mint child (dispatch on shape)
  type MintResult = {
    did: string;
    parentDid: string;
    // legacy fields (only populated when input used legacy form)
    materialHashProof?: string;
    // semantic fields (only populated when input used semantic form)
    segmentKind?: Exclude<SegmentKind, "root">;
    segmentValue?: string;
    // common
    privateKeyB64url?: string;
    publicKeyMultibase?: string;
  };

  let child: MintResult;
  try {
    if (useSemantic) {
      const semantic: SemanticChildDidResult = await createetzhayyimChildDidSemantic({
        parentDid: body.parentDid,
        segmentKind: body.segmentKind as Exclude<SegmentKind, "root">,
        segmentValue: body.segmentValue as string,
      });
      child = semantic;
    } else {
      const legacy = await createetzhayyimChildDid({
        parentDid: body.parentDid,
        kind: body.materialKind as Exclude<MaterialKind, "root">,
        roleName: body.material?.roleName,
        holderDid: body.material?.holderDid,
        matterTid: body.material?.matterTid,
        docCid: body.material?.docCid,
        granteeDid: body.material?.granteeDid,
        grantExpiresAt: body.material?.grantExpiresAt,
        grantNonceHex: body.material?.grantNonceHex,
        parentSessionJti: body.material?.parentSessionJti,
        sessionNonceHex: body.material?.sessionNonceHex,
      });
      child = legacy;
    }
  } catch (e) {
    return jsonErr(400, "InvalidMaterial", e instanceof Error ? e.message : "material encode failed");
  }

  const depth = parentDepth + 1;
  const now = nowIso();
  const effectiveKind: string = useSemantic ? (body.segmentKind as string) : (body.materialKind as string);
  const performerType: PerformerType = body.performerType ?? (effectiveKind === "pubkey" ? "service" : "system");

  // 6. Persist signing key (pubkey kind only)
  if (child.privateKeyB64url && child.publicKeyMultibase) {
    if (!env.KEYS_DB) return jsonErr(503, "ConfigError", "KEYS_DB required for pubkey kind");
    await ensureKeysTables(env);
    const kek = getVar(env, "SS_REPO_SIGNING_KEK");
    if (!kek) return jsonErr(503, "ConfigError", "SS_REPO_SIGNING_KEK required");
    const envelope = await envelopeEncrypt(kek, new TextEncoder().encode(child.privateKeyB64url));
    await env.KEYS_DB.prepare(
      `INSERT OR REPLACE INTO vertex_etzhayyim_key_signing
       (vertex_id, sensitivity_ord, owner_did, did, encrypted_private_key, wrapped_data_key, iv, performer_type, public_key_multibase, created_at)
       VALUES (?, 3, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      child.did, callerAccount, child.did,
      envelope.ciphertext, envelope.wrappedDataKey, envelope.iv,
      performerType, child.publicKeyMultibase, now,
    ).run();
  }

  // 7. Graph write (fire-and-forget projection)
  if (env.PDS_SERVICE) {
    // entity_type derived from effective kind (legacy maps {matter→DomainEntity,
    // doc→Document, grant→ConsentGrant, session→Session, pubkey→Agent, role→Capability};
    // semantic kinds follow the same mapping with sub/id/lexicon → Capability).
    const entityType =
      effectiveKind === "pubkey" ? "Agent" :
      effectiveKind === "matter" ? "DomainEntity" :
      effectiveKind === "doc" ? "Document" :
      effectiveKind === "grant" ? "ConsentGrant" :
      effectiveKind === "session" ? "Session" : "Capability";

    const graphPayload = {
      vertices: [{
        table: "vertex_etzhayyim_identity",
        vertex_id: child.did,
        did: child.did,
        entity_type: entityType,
        performer_type: performerType,
        handle: body.handle ?? null,
        controller_did: callerAccount,
        parent_did: body.parentDid,
        depth,
        // ADR-0029 revised columns (semantic path form) — populated only when
        // the caller used the semantic shape. Legacy hash callers leave these NULL.
        segment_kind: useSemantic ? (body.segmentKind as string) : null,
        segment_value: useSemantic ? (body.segmentValue as string) : null,
        pubkey_multibase: child.publicKeyMultibase ?? null,
        // Legacy hash columns (ADR-0029 草案). Populated only when the caller
        // used the legacy shape. Drops in a follow-up migration post ADR-0030 Phase 4.
        material_kind: useSemantic ? null : body.materialKind,
        material_hash_proof: useSemantic ? null : child.materialHashProof,
        actor_score: 0,
        rbac_roles: "[]",
        rbac_grants: "[]",
        capability_scopes: "[]",
        consent_model: "scoped",
        pii_tier: 3,
        public_key_multibase: child.publicKeyMultibase ?? "",
        authentication_methods: "[]",
        status: "active",
        created_at: now,
        updated_at: now,
      }],
      edges: [{
        table: "edge_etzhayyim_controls",
        edge_id: `${body.parentDid}:derives:${child.did}`,
        src_vid: body.parentDid,
        dst_vid: child.did,
        relationship: useSemantic ? "semantic-child" : "merkle-child",
        created_at: now,
      }],
    };
    env.PDS_SERVICE.fetch("https://atproto.etzhayyim.com/xrpc/com.etzhayyim.graph.batchInsert", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-kotodama-verified": "true" },
      body: JSON.stringify(graphPayload),
    }).catch((e: unknown) => console.warn("[mintChildDid] graph write failed (non-fatal):", e));
  }

  return json({
    did: child.did,
    parentDid: body.parentDid,
    depth,
    // Echo back both shapes so dual-mode callers can pick their fields:
    // semantic callers read segmentKind/segmentValue; legacy callers read
    // materialKind/materialHashProof. Either side is undefined when the
    // input form did not supply it.
    segmentKind: useSemantic ? body.segmentKind : undefined,
    segmentValue: useSemantic ? body.segmentValue : undefined,
    materialKind: useSemantic ? undefined : body.materialKind,
    materialHashProof: useSemantic ? undefined : child.materialHashProof,
    publicKeyMultibase: child.publicKeyMultibase,
  });
}

/** Update D1 auth control (actor_score, auth summary) + graph (edge_etzhayyim_authenticates) on linked auth method change. */
async function syncAuthMethodToetzhayyimIdentity(env: Env, accountDid: string, provider: string, email: string, verified: boolean): Promise<void> {
  if (!accountDid.startsWith("did:etzhayyim:")) return;

  // D1: update auth control plane (actor score + method summary, no PII)
  if (env.AUTH_DB) {
    await ensureAuthTables(env);
    const row = await env.AUTH_DB.prepare(
      "SELECT auth_methods_summary, actor_score FROM vertex_etzhayyim_auth_account WHERE vertex_id = ? LIMIT 1"
    ).bind(accountDid).first<{ auth_methods_summary: string; actor_score: number }>();
    if (!row) return;

    const methods: Array<Record<string, unknown>> = JSON.parse(row.auth_methods_summary || "[]");
    const existing = methods.findIndex((m) => m.provider === provider || m.id === `#${provider}`);
    const entry: Record<string, unknown> = { id: `#${provider}`, type: provider === "email" ? "EmailVerification" : "OIDCProvider", provider, verified };
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
    ).bind(JSON.stringify(methods), score, nowIso(), accountDid).run();
  }

  // RisingWave: write edge_etzhayyim_authenticates + update vertex actor_score (fire-and-forget)
  if (env.PDS_SERVICE) {
    const now = nowIso();
    const graphPayload = {
      edges: [{
        table: "edge_etzhayyim_authenticates",
        edge_id: `${accountDid}:auth:${provider}`,
        src_vid: accountDid,
        dst_vid: `${provider}:${accountDid}`,
        auth_type: provider === "email" ? "EmailVerification" : "OIDCProvider",
        provider,
        email,
        verified: verified ? 1 : 0,
        is_primary: 0,
        linked_at: now,
      }],
    };
    env.PDS_SERVICE.fetch("https://atproto.etzhayyim.com/xrpc/com.etzhayyim.graph.batchInsert", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-kotodama-verified": "true" },
      body: JSON.stringify(graphPayload),
    }).catch((e: unknown) => console.warn("[syncAuthMethod] graph write failed (non-fatal):", e));
  }
}

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

function generateOtp(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  const value = new DataView(bytes.buffer).getUint32(0, true) % 1_000_000;
  return value.toString().padStart(6, "0");
}

function phoneToDidPath(phone: string): string {
  return `tel:${phone.replace(/\D/g, "")}`;
}

async function postJson(url: string, body: unknown, headers?: Record<string, string>): Promise<Response> {
  return fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

// Phase 3B (ADR-2605152100): allowlist of iss values permitted to obtain JWTs.
// Service-binding callers (PDS, email-relay, plc-directory, browser-host) are
// network-isolated by Cloudflare — no HMAC required for them.
const _SVC_AUTH_ISS_ALLOWLIST = new Set([
  "did:web:kotodama.etzhayyim.com",
  "did:web:authn.etzhayyim.com",
  "did:web:atproto.etzhayyim.com",
  "did:web:ml1nb0nd.etzhayyim.com",           // email-relay (etzhayyim-email-relay)
  "did:web:plc.etzhayyim.com",                 // plc-directory
  "did:web:authn.etzhayyim.com:svc:browser-host", // browser-host
]);

// HMAC gate — only for kotodama (public-facing caller, not a service binding).
// All other allowlisted callers come in via CF service bindings.
const _SVC_AUTH_HMAC_ISS = new Set([
  "did:web:kotodama.etzhayyim.com",
]);

async function handleGetServiceAuth(request: Request, env: Env): Promise<Response> {
  try {
    const rawBody = await request.text();
    let body: { iss: string; aud: string; lxm?: string; sub?: string };
    try { body = JSON.parse(rawBody) as { iss: string; aud: string; lxm?: string; sub?: string }; }
    catch { return jsonErr(400, "InvalidRequest", "invalid json body"); }
    const sub = body.sub || body.iss;

    // Phase 3B allowlist gate
    if (!_SVC_AUTH_ISS_ALLOWLIST.has(body.iss) && !body.iss.startsWith("did:etzhayyim:")) {
      console.warn("[svc-auth] rejected iss not in allowlist:", body.iss);
      return jsonErr(403, "Forbidden", "iss not in service auth allowlist");
    }

    // Phase 3B HMAC gate — only for kotodama
    if (_SVC_AUTH_HMAC_ISS.has(body.iss)) {
      const hmacKey = (env.CLAIM_SETTLER_HMAC || "").trim();
      if (hmacKey) {
        const authHeader = request.headers.get("x-claim-settler-auth") || "";
        const expected = await provisionHmacSha256Hex(hmacKey, new TextEncoder().encode(rawBody));
        if (!authHeader || authHeader !== expected) {
          console.warn("[svc-auth] HMAC mismatch for iss:", body.iss);
          return jsonErr(401, "Unauthorized", "HMAC verification failed");
        }
      }
    }

    // did:etzhayyim issuer: envelope-decrypt signing key from vertex_etzhayyim_key_signing
    if (body.iss.startsWith("did:etzhayyim:") && env.KEYS_DB) {
      await ensureKeysTables(env);
      const keyRow = await env.KEYS_DB.prepare(
        "SELECT encrypted_private_key, wrapped_data_key, iv FROM vertex_etzhayyim_key_signing WHERE vertex_id = ?"
      ).bind(body.iss).first<{ encrypted_private_key: string; wrapped_data_key: string; iv: string }>();

      if (keyRow) {
        const kek = getVar(env, "SS_REPO_SIGNING_KEK");
        if (!kek) return jsonErr(503, "ConfigError", "SS_REPO_SIGNING_KEK required");
        const plaintext = await envelopeDecrypt(kek, keyRow.encrypted_private_key, keyRow.wrapped_data_key, keyRow.iv);
        const privateKeyB64 = new TextDecoder().decode(plaintext);
        return json({ token: await signServiceAuth(privateKeyB64, body.iss, body.aud, body.lxm, sub) });
      }
    }

    // Fallback: auth Worker's own signing key (did:web:authn.etzhayyim.com)
    const privateKey = getVar(env, "SS_SERVICE_AUTH_PRIVATE_KEY");
    if (!privateKey) return jsonErr(503, "ServiceUnavailable", "service auth private key missing");
    return json({ token: await signServiceAuth(privateKey, body.iss, body.aud, body.lxm, sub) });
  } catch (error) {
    return jsonErr(500, "SigningError", error instanceof Error ? error.message : "service auth signing failed");
  }
}

async function handleJwks(env: Env): Promise<Response> {
  const resp = json(buildJwks(getVar(env, "SS_AUTH_PUBLIC_KEY_B64")), 200, {
    "Cache-Control": "public, max-age=3600",
    "Access-Control-Allow-Origin": "*",
  });
  return resp;
}

// ADR-0023 P4: did:web resolution endpoint. PDS resolveDIDSigningKey (verify.ts)
// fetches `https://authn.etzhayyim.com/.well-known/did.json` to verify ES256 JWTs
// issued by auth Worker itself (e.g. bootstrap createApiKey calls).
async function handleWellKnownDidJson(env: Env): Promise<Response> {
  // ADR-0023 P4: multi-key did:web document supports key rotation grace.
  //   SS_AUTH_PUBLIC_KEY_B64        → current signing key (verificationMethod #atproto, assertionMethod)
  //   SS_AUTH_PUBLIC_KEY_B64_NEXT   → incoming key during Phase 1 rotation (published but not yet signing)
  //   SS_AUTH_PUBLIC_KEY_B64_PREV   → sunset key during Phase 2 rotation (still verifies in-flight JWTs)
  // Rotation procedure:
  //   Phase 0: cur=A, next=-, prev=-. Sign with A.
  //   Phase 1: cur=A, next=B.          Verifiers start caching [A, B].
  //   Phase 2: cur=B, prev=A.          Sign with B. Old A-signed JWTs still verify.
  //   Phase 3: cur=B, prev=-.          A fully retired. Rotation complete.
  const cur = getVar(env, "SS_AUTH_PUBLIC_KEY_B64");
  const next = getVar(env, "SS_AUTH_PUBLIC_KEY_B64_NEXT");
  const prev = getVar(env, "SS_AUTH_PUBLIC_KEY_B64_PREV");
  if (!cur) return jsonErr(503, "ConfigError", "SS_AUTH_PUBLIC_KEY_B64 not set");

  const did = "did:web:authn.etzhayyim.com";
  const vms: Array<{ id: string; type: string; controller: string; publicKeyMultibase: string }> = [];
  const idSuffix = (label: string) => label === "current" ? "#atproto" : `#atproto-${label}`;

  const encoders: Array<{ label: string; b64: string }> = [
    { label: "current", b64: cur },
  ];
  if (next) encoders.push({ label: "next", b64: next });
  if (prev) encoders.push({ label: "prev", b64: prev });

  for (const { label, b64 } of encoders) {
    try {
      const publicKeyMultibase = uncompressedPubkeyB64UrlToMultibase(b64);
      vms.push({
        id: `${did}${idSuffix(label)}`,
        type: "Multikey",
        controller: did,
        publicKeyMultibase,
      });
    } catch (e) {
      console.warn(`[did.json] skipping ${label} key: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (!vms.length) return jsonErr(500, "ConfigError", "no valid public keys to publish");

  const doc = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: did,
    verificationMethod: vms,
    assertionMethod: [vms[0].id],
    authentication: [vms[0].id],
  };
  return json(doc, 200, {
    "Cache-Control": "public, max-age=60",
    "Access-Control-Allow-Origin": "*",
  });
}

// Phase 3B: DID document for did:web:authn.etzhayyim.com:svc:browser-host.
// Served at /svc/browser-host/did.json. Uses the same signing key as the
// auth Worker since the auth Worker signs JWTs on behalf of browser-host.
async function handleSvcBrowserHostDidJson(env: Env): Promise<Response> {
  const cur = getVar(env, "SS_AUTH_PUBLIC_KEY_B64");
  if (!cur) return jsonErr(503, "ConfigError", "SS_AUTH_PUBLIC_KEY_B64 not set");
  const did = "did:web:authn.etzhayyim.com:svc:browser-host";
  let publicKeyMultibase: string;
  try { publicKeyMultibase = uncompressedPubkeyB64UrlToMultibase(cur); }
  catch { return jsonErr(503, "ConfigError", "invalid SS_AUTH_PUBLIC_KEY_B64"); }
  return json({
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: did,
    controller: "did:web:authn.etzhayyim.com",
    verificationMethod: [{ id: `${did}#atproto`, type: "EcdsaSecp256r1VerificationKey2019",
      controller: did, publicKeyMultibase }],
    assertionMethod: [`${did}#atproto`],
  }, 200, { "Cache-Control": "public, max-age=3600", "Access-Control-Allow-Origin": "*" });
}

async function handleSmsOtpSend(request: Request, env: Env): Promise<Response> {
  const body = await parseJson<{ phone: string }>(request);
  const phone = body.phone.trim();
  if (phone.length < 8) return jsonErr(400, "BadRequest", "invalid phone number");

  const code = generateOtp();
  const expiresAt = nowSecs() + 300;

  if (env.KEYS_DB) {
    await ensureKeysTables(env);
    await env.KEYS_DB.prepare(
      "INSERT OR REPLACE INTO otp_codes (phone, code, expires_at, created_at) VALUES (?, ?, ?, ?)"
    ).bind(phone, code, expiresAt, nowIso()).run();
    await env.KEYS_DB.prepare("DELETE FROM otp_codes WHERE expires_at < ?").bind(nowSecs()).run();
  }

  const telnyxKey = getVar(env, "SS_TELNYX_API_KEY");
  const messagingProfile = getVar(env, "SS_TELNYX_MESSAGING_PROFILE_ID");
  const fromNumber = getVar(env, "SS_TELNYX_PHONE_NUMBER");
  if (telnyxKey) {
    await postJson(
      "https://api.telnyx.com/v2/messages",
      {
        from: fromNumber,
        to: phone,
        text: `etzhayyim verification code: ${code}. Expires in 5 minutes.`,
        'messagingProfileId': messagingProfile,
      },
      { Authorization: `Bearer ${telnyxKey}` },
    ).catch((_err) => undefined);
  } else {
    console.log(`SMS OTP (dev mode, no Telnyx key): ${phone} -> ${code}`);
  }

  return json({ sent: true, phone, 'expiresIn': 300 });
}

async function handleSmsOtpVerify(request: Request, env: Env): Promise<Response> {
  const body = await parseJson<{ phone: string; code: string }>(request);
  const phone = body.phone.trim();
  const code = body.code.trim();

  if (!env.KEYS_DB) return jsonErr(503, "ConfigError", "KEYS_DB required for OTP verification");
  await ensureKeysTables(env);
  const entry = await env.KEYS_DB.prepare(
    "SELECT code, expires_at AS expiresAt FROM otp_codes WHERE phone = ? LIMIT 1"
  ).bind(phone).first<{ code: string; expiresAt: number }>();
  const valid = !!entry && entry.expiresAt > nowSecs() && entry.code === code;
  if (!valid) return jsonErr(401, "InvalidOTP", "invalid or expired verification code");
  await env.KEYS_DB.prepare("DELETE FROM otp_codes WHERE phone = ?").bind(phone).run();

  const accountPath = phoneToDidPath(phone);
  const { didDocument } = await createDid(accountPath, "organization");
  const { didDocument: activeDidDocument } = await createDid(`${accountPath}:person:default`, "person");
  const handle = `${phone.replace(/\D/g, "")}.etzhayyim.com`;
  const sessionTokens = await issueSession(getSessionSecret(env), {
    accountDid: didDocument.did,
    activeDid: activeDidDocument.did,
    handle,
  });
  return jsonWithSession({
    verified: true,
    did: didDocument.did,
    accountDid: didDocument.did,
    activeDid: activeDidDocument.did,
    'sessionTokens': sessionTokens,
    'isNewUser': true,
  }, sessionTokens.accessJwt);
}

async function handleEsimProvision(request: Request, env: Env): Promise<Response> {
  const body = await parseJson<{ phone: string }>(request);
  const phone = body.phone?.trim();
  const telnyxKey = getVar(env, "SS_TELNYX_API_KEY");
  if (!telnyxKey) return jsonErr(503, "ServiceUnavailable", "eSIM provisioning not configured");

  const resp = await postJson(
    "https://api.telnyx.com/v2/simCards",
    { 'simCardGroupId': null, tags: [`etzhayyim:${phone}`] },
    { Authorization: `Bearer ${telnyxKey}` },
  ).catch((_err) => null);
  if (!resp) return jsonErr(502, "TelnyxError", "Telnyx API call failed");
  if (resp.status !== 200 && resp.status !== 201) {
    return jsonErr(502, "TelnyxError", `eSIM provision failed: ${await resp.text()}`);
  }

  const data = await resp.json() as { data?: { iccid?: string; msisdn?: string } };
  const iccid = data.data?.iccid || "";
  const msisdn = data.data?.msisdn || phone;
  const accountPath = phoneToDidPath(msisdn || "");
  const { didDocument } = await createDid(accountPath, "organization");
  const { didDocument: activeDidDocument } = await createDid(`${accountPath}:person:default`, "person");
  const handle = `${(msisdn || "").replace(/\D/g, "")}.etzhayyim.com`;
  const sessionTokens = await issueSession(getSessionSecret(env), {
    accountDid: didDocument.did,
    activeDid: activeDidDocument.did,
    handle,
  });
  return jsonWithSession({
    iccid,
    msisdn,
    'activationCode': `LPA:1$rsp.telnyx.com$${iccid}`,
    'qrCodeData': `LPA:1$rsp.telnyx.com$${iccid}`,
    did: didDocument.did,
    accountDid: didDocument.did,
    activeDid: activeDidDocument.did,
    'sessionTokens': sessionTokens,
  }, sessionTokens.accessJwt);
}

async function handleVerifyDpop(request: Request): Promise<Response> {
  try {
    const body = await parseJson<{ proof: string; htm: string; htu: string }>(request);
    const verified = await verifyDpopProof(body.proof, body.htm, body.htu, usedDpopJtis);
    return json({ valid: true, jkt: verified.jkt, claims: verified.claims });
  } catch (error) {
    return jsonErr(400, "DpopVerificationFailed", error instanceof Error ? error.message : "DPoP verification failed");
  }
}

async function handleCreatePlcAlias(request: Request): Promise<Response> {
  const body = await parseJson<{ 'webDid': string; handle: string }>(request);
  if (!body.webDid.startsWith("did:web:")) return jsonErr(400, "BadRequest", "webDid must be did:web");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body.webDid));
  const clean = encodeBase64Url(digest).toLowerCase().replace(/[-_]/g, "");
  return json({
    'webDid': body.webDid,
    'plcDid': `did:plc:${clean.slice(0, 24)}`,
    handle: body.handle,
    'createdAt': new Date().toISOString(),
  });
}

async function handleResolveExternalDid(request: Request): Promise<Response> {
  const body = await parseJson<{ did: string }>(request);
  if (!body.did) return jsonErr(400, "BadRequest", "did is required");
  if (body.did.startsWith("did:plc:")) {
    const resp = await fetch(`https://plc.directory/${body.did}`).catch((_err) => null);
    if (!resp || !resp.ok) return jsonErr(404, "NotFound", "did:plc not found in PLC Directory");
    return json({ did: body.did, 'didDocument': await resp.json(), source: "plcDirectory" });
  }
  if (body.did.startsWith("did:web:")) {
    const stripped = body.did.slice("did:web:".length).replace(/:/g, "/");
    const target = stripped.includes("/")
      ? `https://${stripped}/did.json`
      : `https://${stripped}/.well-known/did.json`;
    const resp = await fetch(target).catch((_err) => null);
    if (!resp || !resp.ok) return jsonErr(404, "NotFound", "did:web resolution failed");
    return json({ did: body.did, 'didDocument': await resp.json(), source: "wellKnown" });
  }
  return jsonErr(400, "UnsupportedDID", "only did:plc and did:web are supported");
}

async function handleTelnyxWebhook(request: Request): Promise<Response> {
  const body = await parseJson<Record<string, unknown>>(request).catch((_err) => ({}));
  console.log("Telnyx webhook", JSON.stringify(body).slice(0, 500));
  return new Response("ok");
}

async function handleCreateGuestAccount(request: Request, env: Env): Promise<Response> {
  const body = await parseJson<{ username?: string; password?: string }>(request);
  const username = (body.username || "").trim().toLowerCase();
  const password = body.password || "";
  if (username.length < 3 || username.length > 30) return jsonErr(400, "InvalidUsername", "Username must be 3-30 characters");
  if (!/^[a-z0-9_-]+$/.test(username)) return jsonErr(400, "InvalidUsername", "Username: letters, numbers, _ and - only");
  if (password.length < 8) return jsonErr(400, "WeakPassword", "Password must be at least 8 characters");
  const handle = `${username}.etzhayyim.com`;
  const legacyDid = `did:web:authn.etzhayyim.com:user:${username}`;

  // ADR-0074 — mint an ERC725 root identity contract for the new account.
  // Sealer pays for the deploy; ~5-10s synchronous on chain 260425.
  // Falls back to legacy did:web for graceful degradation when authz binding
  // or HMAC isn't configured (dev / pre-deploy).
  const provisioned = await provisionErc725Identity(env, {
    stableId: `guest:${username}`,
    label: legacyDid,
    facadeDids: [legacyDid],
  }).catch((e) => {
    console.warn("provisionErc725Identity failed, falling back to legacy did:web:", e?.message ?? e);
    return null;
  });
  const accountDid = provisioned?.rootDid ?? legacyDid;
  const activeDid = `${accountDid}:person:default`;
  const tokens = await issueSession(getSessionSecret(env), { accountDid, activeDid, handle });
  return jsonWithSession({
    did: tokens.did,
    accountDid: tokens.accountDid,
    activeDid: tokens.activeDid,
    handle: tokens.handle,
    'accessJwt': tokens.accessJwt,
    'refreshJwt': tokens.refreshJwt,
    tier: "guest",
    rootIdentity: provisioned?.identityAddress ?? null,
    rootDidProvisioned: Boolean(provisioned),
    legacyDid,
  }, tokens.accessJwt);
}

interface ProvisionErc725Request {
  stableId: string;
  label: string;
  facadeDids?: string[];
}

interface ProvisionErc725Response {
  ok: boolean;
  rootDid: string;
  rootDidHash: string;
  identityAddress: string;
  txHash: string;
  receiptStatus: "0x1" | "0x0" | null;
}

async function provisionErc725Identity(
  env: Env,
  req: ProvisionErc725Request,
): Promise<ProvisionErc725Response> {
  if (!env.AUTHZ_RPC) throw new Error("AUTHZ_RPC binding not configured");
  const hmacKey = (env.CLAIM_SETTLER_HMAC || "").trim();
  if (!hmacKey) throw new Error("CLAIM_SETTLER_HMAC not configured");
  const body = JSON.stringify({ stableId: req.stableId, label: req.label, facadeDids: req.facadeDids });
  const sig = await provisionHmacSha256Hex(hmacKey, new TextEncoder().encode(body));
  const resp = await env.AUTHZ_RPC.fetch(new Request("https://accounts.etzhayyim.com/internal/provision-root-identity", {
    method: "POST",
    headers: { "content-type": "application/json", "x-claim-settler-auth": sig },
    body,
  }));
  const text = await resp.text();
  if (!resp.ok) throw new Error(`provision-root-identity HTTP ${resp.status}: ${text.slice(0, 200)}`);
  return JSON.parse(text) as ProvisionErc725Response;
}

async function provisionHmacSha256Hex(key: string, body: Uint8Array): Promise<string> {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, body);
  const bytes = new Uint8Array(sig);
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

/** Resolve a Cloudflare Secrets Store binding (object with `.get()`) or fall
 *  back to a plain string var. Returns "" on any failure. */
async function resolveSecret(source: unknown): Promise<string> {
  if (typeof source === "string") return source;
  if (source && typeof (source as { get?: () => Promise<string> }).get === "function") {
    try { return await (source as { get: () => Promise<string> }).get(); }
    catch { return ""; }
  }
  return "";
}

// CHARTER RIDER §2 (ADR-2605192115) — Stripe payment helpers removed.
// External fiat subscription is prohibited. Telecom-tier provisioning
// now requires a USDC donation on Base L2 with
// purpose='internal-subscription' via @etzhayyim/sdk donate(); see the
// donate flow on the yatabase Studio / yoro membership UI.
//
// The legacy XRPC surface com.etzhayyim.auth.createSetupIntent is permanently
// removed below (route is unregistered, not stubbed). Clients still
// calling it will receive the Worker's 404 fallback.
//
// `getConfig` no longer exposes a `stripePk`. Frontends must request
// the USDC treasury address + Base L2 RPC URL via the new SDK config
// endpoint when that lands.

async function storeCredential(env: Env, credentialId: string, value: Record<string, unknown>): Promise<void> {
  if (!env.AUTH_DB) return;
  await ensureAuthTables(env);
  await env.AUTH_DB.prepare(`
    INSERT INTO passkey_credentials (
      credential_id, did, handle, public_key_b64, sign_count, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(credential_id) DO UPDATE SET
      did=excluded.did,
      handle=excluded.handle,
      public_key_b64=excluded.public_key_b64,
      sign_count=excluded.sign_count,
      created_at=excluded.created_at,
      updated_at=excluded.updated_at
  `).bind(
    credentialId,
    String(value.did || ""),
    String(value.handle || ""),
    String(value.publicKeyB64 || ""),
    Number(value.signCount || 0),
    String(value.createdAt || nowIso()),
    nowIso(),
  ).run();
}

async function loadCredential(
  env: Env,
  credentialId: string,
): Promise<{ accountDid: string; activeDid: string; handle: string; 'publicKeyB64': string; 'signCount': number; 'createdAt': string } | null> {
  if (!env.AUTH_DB) return null;
  await ensureAuthTables(env);
  const row = await env.AUTH_DB.prepare(`
    SELECT did, handle, public_key_b64 AS publicKeyB64, sign_count AS signCount, created_at AS createdAt
    FROM passkey_credentials
    WHERE credential_id = ?
    LIMIT 1
  `).bind(credentialId).first<{ did: string; handle: string; publicKeyB64: string; signCount: number; createdAt: string }>();
  if (!row) return null;
  return {
    accountDid: row.did,
    activeDid: deriveDefaultHumanDid(row.did),
    handle: row.handle,
    'publicKeyB64': row.publicKeyB64,
    'signCount': Number(row.signCount || 0),
    'createdAt': row.createdAt,
  };
}

async function createPasskeyAccount(env: Env): Promise<{
  accountDid: string;
  activeDid: string;
  handle: string;
}> {
  const accountetzhayyim = await createetzhayyimDid("organization");
  const activeetzhayyim = await createetzhayyimDid("person");
  const accountPath = userDidPath();
  const handle = accountHandleFromPath(accountPath);
  const now = nowIso();

  // KEYS_DB: envelope-encrypted signing key custody
  if (env.KEYS_DB) {
    await ensureKeysTables(env);
    const kek = getVar(env, "SS_REPO_SIGNING_KEK");
    if (!kek) throw new Error("SS_REPO_SIGNING_KEK is required for signing key custody");

    const stmts: D1PreparedStatement[] = [];
    for (const { etzhayyimDid, privateKey, perfType, ownerDid } of [
      { etzhayyimDid: accountetzhayyim.did, privateKey: accountetzhayyim.privateKeyB64url, perfType: "organization" as const, ownerDid: accountetzhayyim.did },
      { etzhayyimDid: activeetzhayyim.did, privateKey: activeetzhayyim.privateKeyB64url, perfType: "person" as const, ownerDid: accountetzhayyim.did },
    ]) {
      const envelope = await envelopeEncrypt(kek, new TextEncoder().encode(privateKey));
      stmts.push(env.KEYS_DB.prepare(
        `INSERT OR REPLACE INTO vertex_etzhayyim_key_signing
         (vertex_id, sensitivity_ord, owner_did, did, encrypted_private_key, wrapped_data_key, iv, performer_type, public_key_multibase, created_at)
         VALUES (?, 3, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(etzhayyimDid, ownerDid, etzhayyimDid, envelope.ciphertext, envelope.wrappedDataKey, envelope.iv, perfType,
        etzhayyimDid === accountetzhayyim.did ? accountetzhayyim.publicKeyMultibase : activeetzhayyim.publicKeyMultibase, now));
    }
    await env.KEYS_DB.batch(stmts);
  }

  // AUTH_DB: auth control plane
  if (env.AUTH_DB) {
    await ensureAuthTables(env);
    const authSummary = JSON.stringify([{ id: "#passkey-1", type: "WebAuthnAuthenticator", primary: true }]);
    await env.AUTH_DB.batch([
      env.AUTH_DB.prepare(
        `INSERT OR REPLACE INTO vertex_etzhayyim_auth_account
         (vertex_id, sensitivity_ord, owner_did, did, handle, performer_type, controller_did, actor_score, auth_methods_summary, status, created_at, updated_at)
         VALUES (?, 3, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(accountetzhayyim.did, accountetzhayyim.did, accountetzhayyim.did, handle, "organization", accountetzhayyim.did, 25, authSummary, "active", now, now),
      env.AUTH_DB.prepare(
        `INSERT OR REPLACE INTO vertex_etzhayyim_auth_account
         (vertex_id, sensitivity_ord, owner_did, did, handle, performer_type, controller_did, actor_score, auth_methods_summary, status, created_at, updated_at)
         VALUES (?, 3, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(activeetzhayyim.did, accountetzhayyim.did, activeetzhayyim.did, handle, "person", accountetzhayyim.did, 25, authSummary, "active", now, now),
    ]);
  }

  // RisingWave: governance data plane (RBAC, capability, consent, DoDAF)
  // Written via PDS_SERVICE → graph INSERT (fire-and-forget, non-blocking)
  if (env.PDS_SERVICE) {
    const graphPayload = {
      vertices: [
        {
          table: "vertex_etzhayyim_identity",
          vertex_id: accountetzhayyim.did,
          did: accountetzhayyim.did,
          entity_type: "Organization",
          performer_type: "organization",
          handle,
          controller_did: accountetzhayyim.did,
          actor_score: 25,
          rbac_roles: '["owner"]',
          rbac_grants: '["com.etzhayyim.apps.*"]',
          capability_scopes: '["com.etzhayyim.apps.*"]',
          consent_model: "gnap-vp",
          pii_tier: 3,
          public_key_multibase: accountetzhayyim.publicKeyMultibase,
          authentication_methods: JSON.stringify([{ id: "#passkey-1", type: "WebAuthnAuthenticator", primary: true, registeredAt: now }]),
          status: "active",
          created_at: now,
          updated_at: now,
        },
        {
          table: "vertex_etzhayyim_identity",
          vertex_id: activeetzhayyim.did,
          did: activeetzhayyim.did,
          entity_type: "Person",
          performer_type: "person",
          handle,
          controller_did: accountetzhayyim.did,
          actor_score: 25,
          rbac_roles: "[]",
          rbac_grants: "[]",
          capability_scopes: '["com.etzhayyim.apps.*.query"]',
          consent_model: "gnap-vp",
          pii_tier: 1,
          public_key_multibase: activeetzhayyim.publicKeyMultibase,
          authentication_methods: JSON.stringify([{ id: "#passkey-1", type: "WebAuthnAuthenticator", primary: true, registeredAt: now }]),
          status: "active",
          created_at: now,
          updated_at: now,
        },
      ],
      edges: [
        {
          table: "edge_etzhayyim_controls",
          edge_id: `${accountetzhayyim.did}:controls:${activeetzhayyim.did}`,
          src_vid: accountetzhayyim.did,
          dst_vid: activeetzhayyim.did,
          relationship: "controller",
          created_at: now,
        },
        {
          table: "edge_etzhayyim_authenticates",
          edge_id: `${accountetzhayyim.did}:auth:passkey-1`,
          src_vid: accountetzhayyim.did,
          dst_vid: `passkey:${accountetzhayyim.did}`,
          auth_type: "WebAuthnAuthenticator",
          provider: "passkey",
          verified: 1,
          is_primary: 1,
          linked_at: now,
        },
      ],
    };
    // Fire-and-forget: graph write is async projection, not auth-critical
    env.PDS_SERVICE.fetch("https://atproto.etzhayyim.com/xrpc/com.etzhayyim.graph.batchInsert", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-kotodama-verified": "true" },
      body: JSON.stringify(graphPayload),
    }).catch((e: unknown) => console.warn("[createPasskeyAccount] graph write failed (non-fatal):", e));
  }

  return {
    accountDid: accountetzhayyim.did,
    activeDid: activeetzhayyim.did,
    handle,
  };
}

async function handlePasskeyBeginRegister(request: Request): Promise<Response> {
  const body = await parseJson<{ userId?: string; userName?: string }>(request).catch((_err) => ({}));
  return json(beginRegistration(body.userId, body.userName));
}

async function handlePasskeyVerifyRegister(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) {
    return jsonErr(503, "ConfigError", "AUTH_DB D1 binding is required for passkey registration");
  }
  const sessionSecret = getSessionSecret(env);
  if (!sessionSecret) {
    return jsonErr(503, "ConfigError", "SS_AT_SESSION_SECRET required");
  }
  try {
    const body = await parseJson<{ challenge: string; 'clientDataJson': string; 'attestationObject': string }>(request);
    const credential = await verifyRegistration(body.challenge, body.clientDataJson, body.attestationObject);
    const identity = await createPasskeyAccount(env);
    // ADR-0074 — promote to ERC725 root identity. credentialId is stable per
    // passkey, so re-registering the same authenticator is idempotent (returns
    // the existing rootDid). The legacy did:web stays in the credential row +
    // as the on-chain label.
    const provisioned = await provisionErc725Identity(env, {
      stableId: `passkey:${credential.credentialId}`,
      label: identity.accountDid,
      facadeDids: [identity.accountDid],
    }).catch((e) => {
      console.warn("provisionErc725Identity failed during passkey register:", e?.message ?? e);
      return null;
    });
    const accountDid = provisioned?.rootDid ?? identity.accountDid;
    const activeDid = provisioned ? `${accountDid}:person:default` : identity.activeDid;
    // Store the credential under the ROOT did so loadCredential during
    // sign-in returns it tied to the canonical accountDid.
    await storeCredential(env, credential.credentialId, {
      did: accountDid,
      handle: identity.handle,
      'publicKeyB64': credential.publicKeyB64,
      'signCount': credential.signCount,
      'createdAt': credential.createdAt,
    });
    const tokens = await issueSession(sessionSecret, { accountDid, activeDid, handle: identity.handle });
    return jsonWithSession({
      credential,
      did: accountDid,
      accountDid,
      activeDid,
      handle: identity.handle,
      'accessJwt': tokens.accessJwt,
      'refreshJwt': tokens.refreshJwt,
      tier: "guest",
      rootIdentity: provisioned?.identityAddress ?? null,
      rootDidProvisioned: Boolean(provisioned),
      legacyDid: identity.accountDid,
    }, tokens.accessJwt);
  } catch (error) {
    return jsonErr(400, "PasskeyRegistrationFailed", error instanceof Error ? error.message : "registration failed");
  }
}

async function handlePasskeyBeginAuth(): Promise<Response> {
  return json(beginAuthentication());
}

async function handlePasskeyVerifyAuth(request: Request, env: Env): Promise<Response> {
  if (!env.AUTH_DB) {
    return jsonErr(503, "ConfigError", "AUTH_DB D1 binding is required for passkey authentication");
  }
  try {
    const body = await parseJson<{
      challenge: string;
      'credentialId': string;
      'clientDataJson': string;
      'authenticatorData': string;
      signature: string;
    }>(request);
    const stored = await loadCredential(env, body.credentialId);
    if (!stored || !stored.accountDid || !stored.publicKeyB64) {
      return jsonErr(404, "CredentialNotFound", "passkey credential not found - sign up first");
    }
    const newSignCount = await verifyAuthentication(
      body.challenge,
      body.clientDataJson,
      body.authenticatorData,
      body.signature,
      stored.publicKeyB64,
      stored.signCount,
    );
    await storeCredential(env, body.credentialId, {
      did: stored.accountDid,
      handle: stored.handle,
      'publicKeyB64': stored.publicKeyB64,
      'signCount': newSignCount,
      'createdAt': stored.createdAt,
    });
    const sessionTokens = await issueSession(getSessionSecret(env), {
      accountDid: stored.accountDid,
      activeDid: stored.activeDid,
      handle: stored.handle,
    });
    return jsonWithSession({
      did: stored.accountDid,
      accountDid: stored.accountDid,
      activeDid: stored.activeDid,
      'sessionTokens': sessionTokens,
      'credentialId': body.credentialId,
      'newSignCount': newSignCount,
    }, sessionTokens.accessJwt);
  } catch (error) {
    return jsonErr(401, "AuthenticationFailed", error instanceof Error ? error.message : "authentication failed");
  }
}

function html(body: string): Response {
  return new Response(body, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-cache",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "Content-Type, Authorization, X-Requested-With",
    },
  });
}

// Session-aware UI routing for authn.etzhayyim.com (host-gated).
// Returns Response to short-circuit, or null to let the router continue.
async function sessionAwareUiRoute(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.hostname !== "authn.etzhayyim.com" && url.hostname !== "auth.etzhayyim.com") return null;
  const pathname = url.pathname;

  const sessionToken = parseCookieHeader(request.headers.get("Cookie") || "").etzhayyim_session;
  let sessionValid = false;
  let sessionAccount: { accountDid: string; activeDid: string; handle: string } | null = null;
  if (sessionToken) {
    try {
      const payload = await verifySession(getSessionSecret(env), sessionToken, "com.atproto.access");
      const accountDid = String(payload.accountDid ?? payload.sub ?? "");
      if (accountDid) {
        sessionValid = true;
        sessionAccount = {
          accountDid,
          activeDid: String(payload.activeDid ?? accountDid),
          handle: String(payload.handle ?? ""),
        };
      }
    } catch { /* expired or invalid — treat as unauthenticated */ }
  }

  if (sessionValid && (pathname === "/" || pathname === "/sign-in" || pathname === "/sign-in/" || pathname === "/sign-up" || pathname === "/sign-up/")) {
    return Response.redirect("https://accounts.etzhayyim.com/manage", 302);
  }
  if (pathname === "/" || pathname === "/oauth/authorize" || pathname === "/oauth" || pathname === "/oauth/") {
    const target = new URL("/sign-in", url.origin);
    target.search = url.search;
    return Response.redirect(target.toString(), 302);
  }
  if (pathname === "/manage") {
    return Response.redirect("https://accounts.etzhayyim.com/manage", 302);
  }
  if (pathname === "/xrpc/com.etzhayyim.auth.getSession" || pathname === "/xrpc/com.etzhayyim.authz.getSession") {
    if (sessionValid && sessionAccount) {
      return json({
        ok: true,
        authenticated: true,
        accountDid: sessionAccount.accountDid,
        activeDid: sessionAccount.activeDid,
        handle: sessionAccount.handle,
      });
    }
    return json({ ok: false, authenticated: false }, 200);
  }
  if (pathname === "/sign-in" || pathname === "/sign-in/" || pathname === "/sign-up" || pathname === "/sign-up/" || pathname === "/manage" || pathname === "/manage/") {
    if (pathname.startsWith("/manage") && !sessionValid) {
      return Response.redirect("https://auth.etzhayyim.com/sign-in?redirectUrl=https://accounts.etzhayyim.com/manage", 302);
    }
    if (env.ASSETS) {
      try {
        return await env.ASSETS.fetch(new Request(url.toString(), request));
      } catch { /* fall through to server-rendered HTML */ }
    }
    if (pathname.startsWith("/manage")) {
      return html("<!doctype html><html><body><script>location.replace('/manage')</script></body></html>");
    }
    return html(renderAuthPage(pathname.startsWith("/sign-up") ? "sign-up" : "sign-in", request));
  }
  return null;
}

// ── Hono router (Phase A edge HTTP migration, 2026-04-23) ──
// Business logic (session/did/passkey/service-auth/dpop/ui) is unchanged —
// only the dispatch layer moves from if-else chain to Hono route declarations.
const app = new Hono<{ Bindings: Env }>();

// ADR-2605152100: auth.etzhayyim.com is canonical. Redirect authn.etzhayyim.com → auth.etzhayyim.com (301).
// Exempt: /.well-known/* and /users/*/did.json — PDS service-binding resolution fetches
// these directly (CF Worker-to-Worker doesn't follow 301s), so both hostnames must serve
// the same content without redirect.
app.use("*", (c, next) => {
  const url = new URL(c.req.url);
  if (
    url.hostname === "authn.etzhayyim.com" &&
    !url.pathname.startsWith("/.well-known/") &&
    !/^\/users\/[^/]+\/did\.json$/.test(url.pathname)
  ) {
    url.hostname = "auth.etzhayyim.com";
    return Response.redirect(url.toString(), 301);
  }
  return next();
});

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
app.get("/.well-known/jwks.json", (c) => handleJwks(c.env));
app.get("/.well-known/did.json", (c) => handleWellKnownDidJson(c.env));
// Phase 3B: service sub-DID documents for path-based service DIDs
app.get("/svc/browser-host/did.json", (c) => handleSvcBrowserHostDidJson(c.env));

// ADR-2605152100 §4: /users/:id/did.json — resolve did:web:authn.etzhayyim.com:user:{id}
// Served on both auth.etzhayyim.com and authn.etzhayyim.com (no redirect) so PDS ROUTING_GATEWAY
// and AUTH_SERVICE service bindings can fetch it without following 301s.
app.get("/users/:id/did.json", async (c) => {
  const id = c.req.param("id");
  if (!id || !/^[a-zA-Z0-9._:-]+$/.test(id)) return jsonErr(400, "InvalidId", "invalid user id");
  const did = `did:web:authn.etzhayyim.com:user:${id}`;
  if (!c.env.KEYS_DB) return jsonErr(503, "ConfigError", "KEYS_DB unavailable");
  const keyRow = await c.env.KEYS_DB.prepare(
    "SELECT public_key_multibase, performer_type FROM vertex_etzhayyim_key_signing WHERE vertex_id = ? LIMIT 1"
  ).bind(did).first<{ public_key_multibase: string; performer_type: string }>();
  if (!keyRow) return jsonErr(404, "NotFound", `${did} not found`);
  const doc = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/multikey-2021/v1"],
    id: did,
    verificationMethod: [{
      id: `${did}#atproto`,
      type: "Multikey",
      controller: did,
      publicKeyMultibase: keyRow.public_key_multibase,
    }],
    assertionMethod: [`${did}#atproto`],
  };
  return new Response(JSON.stringify(doc), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "max-age=60",
      "Access-Control-Allow-Origin": "*",
    },
  });
});
app.get("/xrpc/com.etzhayyim.auth.getConfig", async (c) =>
  // Charter Rider §2 (ADR-2605192115): Stripe is permanently removed.
  // `stripePk: ""` is kept in the response shape only for backward-compat
  // with older Svelte builds that destructure it; new clients should ignore.
  json({
    stripePk: "",
    countryCode: c.req.raw.headers.get("CF-IPCountry") || "JP",
  }),
);

// Session-aware UI paths (authn.etzhayyim.com host).
const sessionAwarePaths = [
  "/",
  "/sign-in", "/sign-in/",
  "/sign-up", "/sign-up/",
  "/manage", "/manage/",
  "/oauth", "/oauth/", "/oauth/authorize",
  "/xrpc/com.etzhayyim.auth.getSession",
  "/xrpc/com.etzhayyim.authz.getSession",
];
for (const p of sessionAwarePaths) {
  app.get(p, async (c) => {
    const hit = await sessionAwareUiRoute(c.req.raw, c.env);
    if (hit) return hit;
    if (c.env.ASSETS) {
      try { return await c.env.ASSETS.fetch(c.req.raw); } catch { /* fall through */ }
    }
    return new Response("Not Found", { status: 404 });
  });
}

// XRPC POST — delegate to existing handler functions (unchanged business logic).
app.post("/xrpc/com.etzhayyim.auth.authenticate", (c) => handleAuthenticate(c.req.raw, c.env));
app.post("/xrpc/com.atproto.server.createSession", (c) => handleCreateSession(c.req.raw, c.env));
app.post("/xrpc/com.atproto.server.refreshSession", (c) => handleRefreshSession(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.auth.switchActiveDid", (c) => handleSwitchActiveDid(c.req.raw, c.env));

app.post("/xrpc/com.atproto.server.deleteSession", async (c) => {
  const request = c.req.raw;
  const env = c.env;
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : "";
  let jti = "";
  let did = "";
  if (token) {
    try {
      const payload = await verifySession(getSessionSecret(env), token, "com.atproto.access");
      jti = String(payload.jti ?? "");
      did = String(payload.sub ?? "");
    } catch { /* allow logout even if token expired */ }
  }
  if (!jti) {
    const body = await parseJson<{ jti?: string }>(request).catch(() => ({}));
    jti = (body as Record<string, string>).jti || "";
  }
  if (jti && env.KEYS_DB) {
    await ensureKeysTables(env);
    await env.KEYS_DB.prepare("INSERT OR IGNORE INTO revoked_sessions (jti, did, revoked_at) VALUES (?, ?, ?)")
      .bind(jti, did, nowIso()).run();
  }
  return new Response(JSON.stringify({ revoked: jti || true }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
      // no-cookie: allow clearing legacy cross-subdomain auth bridge cookie
      "Set-Cookie": clearSessionCookie(),
    },
  });
});

app.get("/xrpc/com.atproto.server.getSession", async (c) => {
  const request = c.req.raw;
  const env = c.env;
  const token = getAccessTokenFromRequest(request);
  if (!token) return jsonErr(401, "AuthRequired", "missing session token");
  try {
    const payload = await verifySession(getSessionSecret(env), token, "com.atproto.access");
    const did = String(payload.sub ?? "");
    const jti = String(payload.jti ?? "");
    if (jti && env.KEYS_DB) {
      const revoked = await env.KEYS_DB.prepare("SELECT 1 FROM revoked_sessions WHERE jti = ? LIMIT 1").bind(jti).first();
      if (revoked) return jsonErr(401, "SessionRevoked", "session has been revoked");
    }
    return json({ did, handle: did, active: true });
  } catch (error) {
    return jsonErr(401, "InvalidToken", error instanceof Error ? error.message : "invalid token");
  }
});

app.post("/xrpc/com.atproto.identity.resolveDid", (c) => handleResolveDid(c.req.raw));
app.post("/xrpc/com.atproto.identity.createDid", (c) => handleCreateDid(c.req.raw, c.env));
app.post("/xrpc/com.atproto.server.getServiceAuth", (c) => handleGetServiceAuth(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.auth.createAgentSession", (c) => handleCreateAgentSession(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.auth.rotateAgentKey", (c) => handleRotateAgentKey(c.req.raw));
app.post("/xrpc/com.etzhayyim.auth.listAgentKeys", async (c) =>
  json({ did: (await parseJson<{ did: string }>(c.req.raw)).did, keys: [] }),
);
app.post("/xrpc/com.etzhayyim.auth.createApiKey", (c) => handleCreateApiKeyLocal(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.auth.listApiKeys", (c) => proxyApiKeyManagement(c.req.raw, c.env, "com.etzhayyim.auth.listApiKeys"));
app.post("/xrpc/com.etzhayyim.auth.revokeApiKey", (c) => proxyApiKeyManagement(c.req.raw, c.env, "com.etzhayyim.auth.revokeApiKey"));
app.post("/internal/verify-api-key", (c) => handleInternalVerifyApiKey(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.auth.passkeyBeginRegister", (c) => handlePasskeyBeginRegister(c.req.raw));
app.post("/xrpc/com.etzhayyim.auth.passkeyVerifyRegister", (c) => handlePasskeyVerifyRegister(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.auth.passkeyBeginAuth", () => handlePasskeyBeginAuth());
app.post("/xrpc/com.etzhayyim.auth.passkeyVerifyAuth", (c) => handlePasskeyVerifyAuth(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.auth.smsOtpSend", (c) => handleSmsOtpSend(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.auth.smsOtpVerify", (c) => handleSmsOtpVerify(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.auth.esimProvision", (c) => handleEsimProvision(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.auth.verifyDpop", (c) => handleVerifyDpop(c.req.raw));
app.post("/xrpc/com.etzhayyim.auth.createPlcAlias", (c) => handleCreatePlcAlias(c.req.raw));
app.post("/xrpc/com.etzhayyim.auth.resolveExternalDid", (c) => handleResolveExternalDid(c.req.raw));
app.post("/xrpc/com.etzhayyim.auth.resolveetzhayyimDid", (c) => handleResolveetzhayyimDid(c.req.raw, c.env));
app.post("/xrpc/com.etzhayyim.auth.mintChildDid", (c) => handleMintChildDid(c.req.raw, c.env));

// Linked methods live on authz Worker — redirect legacy com.etzhayyim.auth.* paths to canonical com.etzhayyim.authz.*.
const authzRedirectMap: Record<string, string> = {
  "/xrpc/com.etzhayyim.auth.linkEmailBegin":  "/xrpc/com.etzhayyim.authz.linkEmailBegin",
  "/xrpc/com.etzhayyim.auth.linkEmailVerify": "/xrpc/com.etzhayyim.authz.linkEmailVerify",
  "/xrpc/com.etzhayyim.auth.linkOAuthStart":  "/xrpc/com.etzhayyim.authz.linkOAuthStart",
  "/xrpc/com.etzhayyim.auth.unlinkMethod":    "/xrpc/com.etzhayyim.authz.unlinkMethod",
};
for (const [oldPath, newPath] of Object.entries(authzRedirectMap)) {
  app.post(oldPath, (c) => {
    const url = new URL(c.req.url);
    return Response.redirect(`https://accounts.etzhayyim.com${newPath}${url.search}`, 307);
  });
}
app.get("/oauth/link/google/callback", (c) => {
  const url = new URL(c.req.url);
  return Response.redirect(`https://accounts.etzhayyim.com${url.pathname}${url.search}`, 302);
});
app.get("/oauth/link/microsoft/callback", (c) => {
  const url = new URL(c.req.url);
  return Response.redirect(`https://accounts.etzhayyim.com${url.pathname}${url.search}`, 302);
});

app.post("/oauth/issue-code", (c) => handleOAuthIssueCode(c.req.raw, c.env));
app.post("/oauth/token", (c) => handleOAuthToken(c.req.raw, c.env));
// ADR-2604240914 Phase B (Y2): token revocation blacklist writer.
// Called by atproto /oauth/revoke via AUTH_SERVICE service binding.
app.post("/rpc/revoke-token", (c) => handleRevokeToken(c.req.raw, c.env));
// ADR-2604240914 Y2 B2: blacklist lookup for the PDS access_token verify path.
app.post("/rpc/check-revoked", (c) => handleCheckRevoked(c.req.raw, c.env));
// Apex chat-shell viewer identity resolution. Caller forwards the inbound
// `Cookie` / `Authorization` headers; we run the same path requireSessionAccount
// uses internally and return the resolved DID + handle. Always 200 — caller
// branches on `valid` so it can leave anonymous traffic flowing.
app.post("/rpc/verify-session", (c) => handleVerifySession(c.req.raw, c.env));
app.post("/webhook/telnyx", (c) => handleTelnyxWebhook(c.req.raw));
app.post("/xrpc/com.etzhayyim.auth.createGuestAccount", (c) => handleCreateGuestAccount(c.req.raw, c.env));
// Charter Rider §2 (ADR-2605192115): com.etzhayyim.auth.createSetupIntent removed.
// Replacement is the USDC donation flow (purpose='internal-subscription').

// Fallback: static assets for unmatched GET (Svelte CSR build).
app.get("*", async (c) => {
  if (c.env.ASSETS) {
    try { return await c.env.ASSETS.fetch(c.req.raw); } catch { /* fall through to 404 */ }
  }
  return new Response("Not Found", { status: 404 });
});

export default app;
