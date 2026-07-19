/**
 * did:etzhayyim D1 auth schema — GraphAr convention (vertex_*/edge_*).
 *
 * Both D1 (auth control plane) and RisingWave (governance data plane)
 * share the same GraphAr naming: vertex_*, edge_*, with vertex_id PK.
 *
 * D1 tables omit _seq and created_date (no firehose ingestion).
 * D1 tables keep sensitivity_ord and owner_did for RLS consistency.
 *
 * Security boundary:
 *   D1 AUTH_DB   = vertex_etzhayyim_auth_*  / edge_etzhayyim_auth_*  (secrets, credentials)
 *   D1 KEYS_DB   = vertex_etzhayyim_key_*                        (private keys, revocation)
 *   RisingWave   = vertex_etzhayyim_identity / edge_etzhayyim_*       (public governance)
 *
 * Design doc: 90-docs/260416-did-schema-dodaf-org-agent-shannon-design.md
 */

// CHARTER-VIOLATION §substrate (ADR-2605172000).
//
// This file currently describes two tables that violate the substrate
// boundary in `/CLAUDE.md`:
//
//   1. `vertex_etzhayyim_auth_*` / `vertex_etzhayyim_key_*` — D1 (Cloudflare's
//      edge SQLite) tables used as auth-credential storage. D1 is
//      centralized-DB-class storage even though it lives at the edge.
//      Migration target: store credential blobs in the MST under a
//      Signal-wrapped, DID-bound encrypted envelope
//      (`com.etzhayyim.encrypted.auth.credential`) per ADR-2605181100,
//      with a Workers KV index for fast lookup. The Kysely *types*
//      themselves are harmless — they describe an off-chain auth-only
//      cache that will eventually be regeneratable from the encrypted
//      MST records.
//
//   2. `vertex_etzhayyim_identity` / `edge_etzhayyim_*` — RisingWave governance
//      tables. Migration target: lexicons under
//      `com.etzhayyim.apps.identity.*` (already partly registered) with the
//      authoritative writes against MST and a kotoba-datomic-projection
//      (`ADR-2605231500`) RisingWave cache that is rebuildable from
//      MST + IPFS.
//
// The `kysely` type-only import below is retained as a transitional
// dependency: D1 auth tables remain in service until the encrypted
// MST envelopes ship. Removing the import would break the type-checker
// without changing behaviour. See `_etzhayyim_substrate.py` in the
// maps bulk-ingest workers for an example of the seam pattern that the
// auth worker should adopt at runtime.
// kotoba-datomic-projection: D1 type-only kysely import — compiles away; runtime still goes through @etzhayyim/sdk seam (ADR-2605231500)
import type { ColumnType, Generated, Insertable, Selectable, Updateable } from "kysely";

// ═══════════════════════════════════════════════════════════════════════════
// D1 AUTH_DB — auth control plane (GraphAr schema)
// ═══════════════════════════════════════════════════════════════════════════

// ── vertex_etzhayyim_auth_account ────────────────────────────────────────────
// Auth control record for each did:etzhayyim. No governance data.
// vertex_id = did:etzhayyim:{hash}

export interface VertexetzhayyimAuthAccountTable {
  vertex_id: string;                // did:etzhayyim:{hash}
  sensitivity_ord: ColumnType<number, number | undefined, number>;
  owner_did: string | null;         // = vertex_id (self)

  did: string;                      // = vertex_id (denorm for query compat)
  legacy_did: string | null;        // did:web:authn.etzhayyim.com:user:{nanoid}
  handle: string | null;            // abc12345.etzhayyim.com
  performer_type: string;           // person | organization | service | system
  controller_did: string | null;    // parent authority did:etzhayyim
  actor_score: ColumnType<number, number | undefined, number>;
  auth_methods_summary: ColumnType<string, string | undefined, string>; // JSON [{id,type,provider,verified}]
  status: ColumnType<string, string | undefined, string>;               // active | suspended | deactivated
  created_at: string;
  updated_at: string;
}

export type VertexetzhayyimAuthAccount = Selectable<VertexetzhayyimAuthAccountTable>;
export type NewVertexetzhayyimAuthAccount = Insertable<VertexetzhayyimAuthAccountTable>;

// ── vertex_etzhayyim_auth_credential ─────────────────────────────────────────
// WebAuthn passkey credential. Replaces legacy passkey_credentials.
// vertex_id = credential_id (base64url)

export interface VertexetzhayyimAuthCredentialTable {
  vertex_id: string;                // credential_id (base64url)
  sensitivity_ord: ColumnType<number, number | undefined, number>;
  owner_did: string | null;         // did:etzhayyim:{hash} of the account

  did: string;                      // did:etzhayyim:{hash}
  handle: string;
  public_key_b64: string;           // uncompressed P-256, 65 bytes, base64url
  sign_count: number;
  created_at: string;
  updated_at: string;
}

export type VertexetzhayyimAuthCredential = Selectable<VertexetzhayyimAuthCredentialTable>;

// ── vertex_etzhayyim_auth_invite ─────────────────────────────────────────────
// Pending org invitation. HMAC token (security-sensitive).
// vertex_id = invite:{id}

export interface VertexetzhayyimAuthInviteTable {
  vertex_id: string;                // invite:{auto_id}
  sensitivity_ord: ColumnType<number, number | undefined, number>;
  owner_did: string | null;         // org_did

  org_did: string;
  email: string;
  role: string;                     // owner | admin | member | viewer | agent-runtime
  invite_token: string | null;      // HMAC token (cleared after acceptance)
  expires_at: number;               // unix seconds
  inviter_did: string;              // did:etzhayyim of inviter
  accepted_did: string | null;      // did:etzhayyim of acceptor
  status: ColumnType<string, string | undefined, string>;  // pending | accepted | expired | revoked
  accepted_at: string | null;
  created_at: string;
  updated_at: string;
}

export type VertexetzhayyimAuthInvite = Selectable<VertexetzhayyimAuthInviteTable>;

// ── vertex_etzhayyim_auth_otp ────────────────────────────────────────────────
// Email OTP code (10min expiry). Replaces legacy email_link_codes.
// vertex_id = otp:{account_did}:{email}

export interface VertexetzhayyimAuthOtpTable {
  vertex_id: string;                // otp:{account_did}:{email}
  sensitivity_ord: ColumnType<number, number | undefined, number>;
  owner_did: string | null;         // account_did

  account_did: string;
  email: string;
  code: string;                     // 6-digit OTP
  expires_at: number;               // unix seconds
  created_at: string;
}

export type VertexetzhayyimAuthOtp = Selectable<VertexetzhayyimAuthOtpTable>;

// ── edge_etzhayyim_auth_linked ───────────────────────────────────────────────
// Linked auth method (OAuth/email). Replaces legacy linked_auth_methods.
// edge_id = {account_did}:auth:{provider}:{provider_subject}

export interface EdgeetzhayyimAuthLinkedTable {
  edge_id: string;                  // {account_did}:auth:{provider}:{provider_subject_hash}
  src_vid: string;                  // account did:etzhayyim
  dst_vid: string;                  // provider:{provider_subject}
  sensitivity_ord: ColumnType<number, number | undefined, number>;
  owner_did: string | null;         // account did:etzhayyim

  provider: string;                 // email | google | microsoft
  provider_subject: string;         // email address or OAuth subject ID
  display_label: string;
  verified: ColumnType<number, number | undefined, number>;
  metadata_json: string | null;     // JSON {email, profile, verifiedAt}
  created_at: string;
  updated_at: string;
}

export type EdgeetzhayyimAuthLinked = Selectable<EdgeetzhayyimAuthLinkedTable>;

// ═══════════════════════════════════════════════════════════════════════════
// D1 KEYS_DB — key custody (GraphAr schema)
// ═══════════════════════════════════════════════════════════════════════════

// ── vertex_etzhayyim_key_signing ─────────────────────────────────────────────
// P-256 signing key custody. Replaces legacy did_keys.
// vertex_id = did:etzhayyim:{hash}

export interface VertexetzhayyimKeySigningTable {
  vertex_id: string;                // did:etzhayyim:{hash}
  sensitivity_ord: ColumnType<number, number | undefined, number>;
  owner_did: string | null;         // = vertex_id

  did: string;                      // = vertex_id

  // KEK envelope encrypted (ADR-0010 Stage 1)
  encrypted_private_key: string;         // AES-256-GCM ciphertext of private_key_b64
  wrapped_data_key: string;              // per-DID data key, wrapped by KEK (AES-256-GCM)
  iv: string;                            // 12-byte AES-GCM IV (base64url)

  performer_type: string;
  public_key_multibase: string;     // z-prefixed base58btc compressed P-256 (always plaintext, public)
  created_at: string;
}

export type VertexetzhayyimKeySigning = Selectable<VertexetzhayyimKeySigningTable>;

// ── vertex_etzhayyim_key_revoked_session ─────────────────────────────────────
// JTI revocation record. Replaces legacy revoked_sessions.
// vertex_id = jti:{uuid}

export interface VertexetzhayyimKeyRevokedSessionTable {
  vertex_id: string;                // jti:{uuid}
  sensitivity_ord: ColumnType<number, number | undefined, number>;
  owner_did: string | null;         // did of session owner

  jti: string;
  did: string;
  revoked_at: string;
}

export type VertexetzhayyimKeyRevokedSession = Selectable<VertexetzhayyimKeyRevokedSessionTable>;

// ── vertex_etzhayyim_key_otp ─────────────────────────────────────────────────
// SMS OTP code. Replaces legacy otp_codes.
// vertex_id = sms:{phone}

export interface VertexetzhayyimKeyOtpTable {
  vertex_id: string;                // sms:{phone_digits}
  sensitivity_ord: ColumnType<number, number | undefined, number>;
  owner_did: string | null;

  phone: string;
  code: string;
  expires_at: number;
  created_at: string;
}

export type VertexetzhayyimKeyOtp = Selectable<VertexetzhayyimKeyOtpTable>;

// ═══════════════════════════════════════════════════════════════════════════
// Database interfaces (Kysely)
// ═══════════════════════════════════════════════════════════════════════════

/** AUTH_DB (D1) — auth control plane, GraphAr convention. */
export interface etzhayyimAuthDatabase {
  vertex_etzhayyim_auth_account: VertexetzhayyimAuthAccountTable;
  vertex_etzhayyim_auth_credential: VertexetzhayyimAuthCredentialTable;
  vertex_etzhayyim_auth_invite: VertexetzhayyimAuthInviteTable;
  vertex_etzhayyim_auth_otp: VertexetzhayyimAuthOtpTable;
  edge_etzhayyim_auth_linked: EdgeetzhayyimAuthLinkedTable;
}

/** KEYS_DB (D1) — key custody, GraphAr convention. */
export interface etzhayyimKeysDatabase {
  vertex_etzhayyim_key_signing: VertexetzhayyimKeySigningTable;
  vertex_etzhayyim_key_revoked_session: VertexetzhayyimKeyRevokedSessionTable;
  vertex_etzhayyim_key_otp: VertexetzhayyimKeyOtpTable;
}
