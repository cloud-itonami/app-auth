# Stage C — identity-signing devolution to Council multisig

Per [ADR-2605231525](../../90-docs/adr/2605231525-no-server-key-religious-corp-architecture.md)
(No-Server-Key Religious-Corp Architecture) Stage C, the auth Worker's
identity-signing capability is devolved to:

1. **The Bootstrap Council 5-of-7 Safe** (ADR-2605192300) for protected
   resources (DID Document amendments to `did:web:authn.etzhayyim.com`,
   `did:web:etzhayyim.com`).
2. **The member's own device** (WebAuthn passkey + browser-derived ES256
   keypair) for everything that today is signed by the auth Worker on
   behalf of a member or an AI agent.

After Stage C, the auth Worker no longer holds:

- `did:web:authn.etzhayyim.com` Worker DID private key (macOS Keychain + 1Password mirror)
- `SS_REPO_SIGNING_KEK` (KEK envelope encryption master)
- Per-agent ES256 P-256 keys (715+ keys currently in `KEYS_DB`)

## Why this works

Two ADRs already laid the groundwork:

- **ADR-2605181100** (MST Encrypted Records — Signal KeyWrap): each
  member encrypts with their own Signal identity. The KEK
  envelope-encryption pattern (ADR-0010 Stage 1) becomes per-member,
  not platform-wide.
- **ADR-0074** (Ethereum Identity Bridge — CACAO + WebAuthn):
  `did:erc725:etzhayyim:260425:{identityContract}` is the platform primary
  identity. The auth Worker's `did:web` is a *facade* serving a
  document that is signed *off-line* by the ERC725 root controller.

The auth Worker can therefore publish the DID Document (read-only
serving) without holding the key that signed it.

## Migration plan

### C-1 — DID Document multi-controller spec

The current `did:web:authn.etzhayyim.com/.well-known/did.json` has
a single controller (the auth Worker's P-256 key). After Stage C,
the document is amended to declare:

```jsonc
{
  "id": "did:web:authn.etzhayyim.com",
  "controller": [
    "did:web:etzhayyim.com",
    // Bootstrap Council Safe (Base L2)
    "did:pkh:eip155:8453:0x..."
  ],
  "verificationMethod": [
    // P-256 key — REMOVED in Stage C. The Worker no longer signs.
    // ECDSA secp256k1 verification key derived from the Safe
    // (ERC-1271 isValidSignature) — the Council multisig owns this.
    {
      "id": "did:web:authn.etzhayyim.com#council-safe",
      "type": "EcdsaSecp256k1RecoveryMethod2020",
      "controller": "did:web:authn.etzhayyim.com",
      "blockchainAccountId": "eip155:8453:0x..."
    }
  ],
  "service": [
    // unchanged: PDS endpoint, atproto service
  ]
}
```

Document amendments require a 5-of-7 Council vote; the Safe signs an
attestation that the auth Worker publishes as a Workers Assets static
file. No private key on the Worker.

### C-2 — Per-agent ES256 → device-generated keypair

Today: `com.etzhayyim.auth.createAgentSession` generates a P-256 keypair
inside the auth Worker, persists the private half to `KEYS_DB` (KEK-
wrapped), and returns both halves to the agent's container at
`etzhayyim deploy` time.

After Stage C: the agent's runtime (the operator's own device or the
community-operated pod) generates the keypair locally via WebCrypto
`crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'})`,
exports the public half, and POSTs `com.etzhayyim.auth.registerAgentKey`
with the public key + an attestation (WebAuthn proof of possession
or DPoP-style nonce sign). The auth Worker stores the public key in
the `vertex_etzhayyim_key_signing` projection — never the private key.

`KEYS_DB`'s `private_key_b64` column is dropped in the same
migration. The table becomes a public-keys-only register.

### C-3 — Passkey-derived ES256 for human session JWTs

Today: `com.atproto.server.createSession` issues an HS256 JWT signed
by `SS_REPO_SIGNING_KEK`-derived material.

After Stage C: each member's WebAuthn passkey is used in `userVerification:'preferred'`
mode to derive an ES256 keypair (one per passkey, deterministic from
the passkey's COSE public key + a per-PDS salt). The session token
becomes a DPoP-style PoP token signed by the passkey. The auth
Worker verifies (read-only) by looking up the passkey credential in
its public projection.

### C-4 — `SS_REPO_SIGNING_KEK` removal

Once C-2 and C-3 ship, no auth Worker code reads `SS_REPO_SIGNING_KEK`.
A 30-day overlap window (where the Worker logs all KEK reads and
expects zero) confirms safe removal. The Cloudflare Secrets Store
binding is then deleted.

## Acceptance criteria

- [ ] DID Document update is signed by the Council Safe (Stage C-1) and reachable via curl.
- [ ] `vertex_etzhayyim_key_signing` schema migration drops the `private_key_b64` column.
- [ ] No code path in `worker/src-ts/**` references `env.AUTH_KEYS_KEK` / `SS_REPO_SIGNING_KEK`.
- [ ] `e7m verify --no-server-key` reports zero exemptions in the auth Worker.

## C-3 / C-4 status + execution runbook (2026-06-02)

**Landed in code (additive, non-breaking — verified, see ADR-2606014500):**
- **C-2 server**: `com.etzhayyim.auth.registerSigningKey` stores a client-generated
  public key only (`vertex_etzhayyim_key_signing.key_custody_tier = human_self_custody`,
  empty private columns — no KEK).
- **C-3 verify**: `session-pop.ts::verifySessionPoP` + `POST
  /xrpc/com.etzhayyim.auth.verifySessionPoP` (read-only Ed25519 JWS verification
  against the registered public key; client↔worker interop cross-checked).
- **C-3 issuance (additive login path)**: `POST
  /xrpc/com.etzhayyim.auth.createSessionFromPoP` establishes a session from a
  client PoP — login proof is the member's own signature, no server signing-key
  custody involved. (Issues the standard HS256 session for downstream compat;
  dropping HS256 in favour of downstream PoP verification is the broader migration.)
- **C-4 instrument**: `logKekRead(site)` fires at all 3 `SS_REPO_SIGNING_KEK`
  read sites (`subDid.persistSigningKey`, `signServiceAuth.decryptPrivateKey`,
  `createPasskeyAccount.persistSigningKeys`).

**C-4 execution runbook (OPERATOR action — NOT done in code; irreversible):**
1. Migrate sign-up + agent provisioning to client-self-custody so server-assisted
   paths (the 3 `logKekRead` sites) stop being hit for new identities. **Sign-up is
   wired**: set `SS_KEY_CUSTODY_MODE=client_self_custody` and `createPasskeyAccount`
   persists public-key-only rows (no KEK read). Stage it, confirm sign-up + later
   `registerSigningKey` work, then make it the deployed default. **All 3 KEK sites
   are now gated**: sub-DID persist also honours
   `SS_KEY_CUSTODY_MODE=client_self_custody` (public-only, `agent_self_custody`),
   and service-auth signing returns `409 ClientCustodyKey` (sign client-side) for a
   client-custody key — both skip the KEK read. So a client-self-custody deployment
   reads `SS_REPO_SIGNING_KEK` for no new identity; remaining `[kek-read]` lines
   come only from legacy server-custody rows.
2. Deploy; over a **30-day window**, grep Worker logs for `[kek-read]`. The window
   passes only when the count is **zero** (each line names the offending site).
3. While `[kek-read]` is still non-zero, the KEK MUST stay — those sites fail
   closed without it (`SS_REPO_SIGNING_KEK required`). Do not delete.
4. After 30 days of zero reads: drop the `encrypted_private_key` /
   `wrapped_data_key` / `iv` columns (now always empty) from
   `vertex_etzhayyim_key_signing`, delete the `envelopeEncrypt`/`envelopeDecrypt` code,
   then `wrangler secret delete SS_REPO_SIGNING_KEK`.
5. Confirm `e7m verify --no-server-key` reports zero exemptions in the auth Worker.

## Rollback

Each sub-stage (C-1 / C-2 / C-3 / C-4) is independently revertible.
C-4 (KEK removal) is the only one that destroys state; a 30-day
quarantine window with the KEK still loaded but unused is the
rollback insurance.

## References

- ADR-2605231525 (No-Server-Key Religious-Corp Architecture)
- ADR-2605181100 (MST Encrypted Records — Signal KeyWrap)
- ADR-2605192300 (Bootstrap Council 5-of-7 Safe)
- ADR-0074 (Ethereum Identity Bridge — CACAO + WebAuthn)
- ADR-0029 (did:etzhayyim method specification — legacy migration)
- `kotoba-datomic-projection.edn` — declares `vertex_etzhayyim_*` as L0-rebuildable from MST
