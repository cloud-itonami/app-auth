/**
 * substrate-mst-credential.ts — encrypted MST seam for auth credentials.
 *
 * Per ADR-2605172000 (kotoba substrate) + ADR-2605181100 (encrypted
 * MST records via Signal-wrapped XChaCha20-Poly1305 envelopes).
 *
 * Auth credentials (passkey, OAuth link, email magic-link verifier, SMS
 * OTP) MUST land on the auth tenant PDS as `com.etzhayyim.encrypted.record`
 * envelopes whose plaintext body matches the `com.etzhayyim.auth.credential`
 * lexicon (see `00-contracts/lexicons/com/etzhayyim/auth/credential.json`).
 *
 * The existing D1 tables (`vertex_etzhayyim_auth_credential` etc.) remain in
 * place as a kotoba-datomic-projection cache (see
 * `60-apps/etzhayyim-project-auth/kotoba-datomic-projection.edn`). This module
 * wires the canonical-write seam; integrating it into the existing
 * `passkeyVerifyRegister` / `linkEmailVerify` / `linkOAuthStart` /
 * `smsOtpSend` handlers in `index.ts` is the Stage 2 task that flips the
 * D1 read path to projection-only.
 *
 * The Stage 1 contract here is a thin wrapper around
 * `@etzhayyim/sdk` `encryptedWriteStandalone()` / `encryptedReadStandalone()`
 * so the auth Worker does not have to know about Signal key wrapping or
 * envelope CBOR encoding — those live in the SDK.
 */

import {
  encryptedWriteStandalone,
  encryptedReadStandalone,
  type EncryptedWriteReceipt,
  type StandaloneWriteDeps,
  type StandaloneReadDeps,
} from "@etzhayyim/sdk/encrypted";

// ─── Plaintext credential shape (mirrors com.etzhayyim.auth.credential) ──

export type AuthCredentialKind = "passkey" | "oauthLink" | "emailLink" | "smsOtp";

export interface PasskeyPlaintext {
  credentialId: string;
  publicKeyB64: string;
  signCount: number;
  transports?: string[];
  handle?: string;
}

export interface OauthLinkPlaintext {
  provider: "google" | "microsoft" | "github" | "apple";
  subject: string;
  email?: string;
}

export interface EmailLinkPlaintext {
  email: string;
  codeHash: string; // sha256 hex of the magic-link code
  expiresAt: string; // ISO 8601
}

export interface SmsOtpPlaintext {
  phone: string; // E.164
  codeHash: string; // sha256 hex of the OTP
  expiresAt: string; // ISO 8601
}

export interface AuthCredentialRecord {
  v: 1;
  subject: string; // DID this credential authenticates
  kind: AuthCredentialKind;
  passkey?: PasskeyPlaintext;
  oauthLink?: OauthLinkPlaintext;
  emailLink?: EmailLinkPlaintext;
  smsOtp?: SmsOtpPlaintext;
  revokedAt?: string;
  createdAt: string;
}

// ─── Public API ────────────────────────────────────────────────────

const COLLECTION_ENVELOPE = "com.etzhayyim.encrypted.record";
const INNER_TYPE = "com.etzhayyim.auth.credential";

/**
 * Persist an auth credential to the auth tenant PDS as an encrypted MST
 * envelope. The plaintext NEVER leaves this Worker boundary.
 *
 * @returns the envelope's at-URI, CID, and the symmetric key id so the
 * D1 projection can store a forward-pointer for fast rehydrate.
 */
export async function writeAuthCredential(
  deps: StandaloneWriteDeps,
  record: AuthCredentialRecord,
  opts: {
    /** Extra DIDs to grant read-cap. The subject is auto-added. */
    additionalRecipients?: string[];
    /** Optional override rkey (default: SDK-generated). */
    rkey?: string;
  } = {},
): Promise<EncryptedWriteReceipt> {
  const recipients = [record.subject, ...(opts.additionalRecipients ?? [])];
  // Dedupe while preserving subject-first ordering.
  const seen = new Set<string>();
  const uniqRecipients = recipients.filter((did) => {
    if (seen.has(did)) return false;
    seen.add(did);
    return true;
  });

  return encryptedWriteStandalone<Record<string, unknown>>(deps, {
    collection: COLLECTION_ENVELOPE,
    innerType: INNER_TYPE,
    record: record as unknown as Record<string, unknown>,
    recipients: uniqRecipients,
    wrapToSelf: false, // subject is already in `recipients`
    rkey: opts.rkey,
  });
}

/**
 * Resolve an encrypted credential envelope back to plaintext. Used by
 * the projection rebuild runbook and (Stage 2) by the live auth flow
 * when the D1 cache misses.
 */
export async function readAuthCredential(
  deps: StandaloneReadDeps,
  envelopeUri: string,
): Promise<AuthCredentialRecord> {
  return encryptedReadStandalone<AuthCredentialRecord>(deps, envelopeUri);
}

// ─── Projection helpers (D1 ↔ MST) ─────────────────────────────────

/**
 * Project a decrypted credential into the legacy D1 row shape used by
 * `vertex_etzhayyim_auth_credential` (passkey-only — other kinds project
 * into `edge_etzhayyim_auth_linked` / `vertex_etzhayyim_auth_otp` / etc.).
 *
 * This is the inverse of the historical D1 → handler path. After
 * Stage 2 ships, the auth Worker reads MST envelopes and projects
 * with this function instead of running a D1 query directly.
 */
export function projectPasskeyToD1Row(record: AuthCredentialRecord): {
  credential_id: string;
  did: string;
  handle: string | null;
  public_key_b64: string;
  sign_count: number;
  created_at: string;
  updated_at: string;
} {
  if (record.kind !== "passkey" || !record.passkey) {
    throw new Error("projectPasskeyToD1Row: record is not a passkey credential");
  }
  return {
    credential_id: record.passkey.credentialId,
    did: record.subject,
    handle: record.passkey.handle ?? null,
    public_key_b64: record.passkey.publicKeyB64,
    sign_count: record.passkey.signCount,
    created_at: record.createdAt,
    updated_at: record.createdAt,
  };
}
