# Migration TODO

**Status**: 🔄 TRANSFORM — seed copied 2026-05-21, codemod pending.

**Codemod required**: RisingWave/Postgres → AT MST + IPFS

## Substrate-boundary checks (per CLAUDE.md)

This seed was copied verbatim from `etzhayyim-root/60-apps/etzhayyim-project-auth`.
The following constitutional invariants are likely violated and MUST be
remediated before this app can be considered etzhayyim-aligned:

- [ ] Replace any `@atproto/api`, `viem`, raw IPFS client, `@noble/ciphers`,
      `@signalapp/libsignal-client` imports with `@etzhayyim/sdk`.
- [ ] Strip RisingWave / Postgres / Kysely / centralized DB code — migrate to
      AT Protocol MST + IPFS + Base L2 anchor.
- [ ] Strip Stripe / PayPal / Square / fiat processors — migrate to USDC on
      Base L2 + ERC-4337 + `etzhayyim-tithe-router` (10% auto-split to
      Public Fund).
- [ ] Remove third-party advertising / AdSense / Meta Pixel / GA4 ad-linkage.
      Only internal-promo for etzhayyim's own religious activity is allowed.
- [ ] Verify identity flow uses did:web:etzhayyim.com + did:plc + WebAuthn
      passkey + Adherent SBT. Remove server-issued JWTs without DID binding.
- [ ] Reclassify payment purposes to: donation / kisha / grant / tithe /
      escrow-refund (external) OR internal-purchase / internal-subscription /
      internal-promo (SBT↔SBT carve-out).
- [ ] Audit against Charter Rider v2.0 §2(a)-(h).

## Reference

- Constitution wave ADRs: ADR-2605192100 / 2605192115 / 2605192130 / 2605192200
- Substrate boundary table: `/CLAUDE.md` § "Substrate boundary"
- Charter Rider: `/CHARTER-RIDER.md`

---

## Codemod scan results (applied 2026-05-21)

Automated annotation pass added `// CHARTER-VIOLATION` comments above each
detected violation line. The imports themselves were NOT removed (would break
the build). Remediation must replace these imports with the substrate-aligned
equivalents listed at the top of this file.

Detected violations:

```
  RW/Kysely/Prisma: /Users/junkawasaki/github/etzhayyim-root/60-apps/etzhayyim-project-auth/worker/src-ts/etzhayyim-identity-schema.ts:18
```

---

## Post-verification gap patch (2026-05-21)

Additional violations detected in re-scan:

```
  - 60-apps/etzhayyim-project-auth/worker/src-ts/etzhayyim-identity-schema.ts
```

Lines annotated with `CHARTER-VIOLATION §substrate` comments.

---

## Stripe → USDC codemod (2026-05-23)

<!-- stripe-usdc-codemod-closure:2605231830 -->

**Status (Stripe layer)**: ✅ codemod applied.

### Applied changes

| File | Change |
|---|---|
| `worker/src-ts/index.ts` | removed `resolveStripeSecretKey`/`resolveStripePublishableKey`/`handleCreateSetupIntent` stubs; `getConfig` now returns empty `stripePk` (legacy field for backward-compat); legacy `com.etzhayyim.auth.createSetupIntent` route removed |
| `worker/svelte/src/routes/sign-up/+page.svelte` | Stripe.js CDN load removed; card element + SetupIntent flow replaced with USDC donation form (POST /api/donate, purpose=`internal-subscription`); eSIM provisioning runs after donation tx confirms |

### Remaining

- CLAUDE.md still describes "Telecom (Stripe)" — needs rewrite to reflect USDC flow.
- A new `auth.getDonationConfig` XRPC surface should expose `donate_treasury_base_l2`; for now the page falls back to a placeholder address.

_Closed by manual codemod 2026-05-23._

---

## RW → MST substrate codemod (2026-05-23)

<!-- rw-mst-codemod-progress:2605231930 -->

**Status**: 🟡 partial — substrate boundary annotated; runtime migration pending.

### Applied

- `worker/src-ts/etzhayyim-identity-schema.ts` — CHARTER-VIOLATION header expanded to
  describe the concrete migration target for both D1 (`vertex_etzhayyim_auth_*` /
  `vertex_etzhayyim_key_*` → encrypted MST envelopes per ADR-2605181100 + Workers KV
  index) and RisingWave (`vertex_etzhayyim_identity` → `com.etzhayyim.apps.identity.*`
  lexicons with kotoba-datomic-projection RW cache per ADR-2605231500).

### Remaining

- Ship `com.etzhayyim.encrypted.auth.credential` lexicon + Signal-wrapped
  envelope encryption for D1 credentials.
- Migrate `vertex_etzhayyim_identity` writes to MST + register kotoba-datomic-projection
  manifest for the RW read cache.
- Remove the type-only `kysely` import once the D1 auth schema is regeneratable
  from the encrypted MST records.

_Closed (Stage 1) by manual codemod 2026-05-23._

---

## Encrypted MST envelope scaffold (Stage 1, 2026-05-23)

<!-- auth-encrypted-mst-stage-1:2605232100 -->

**Status**: ✅ Stage 1 scaffold shipped. Stage 2 (wire into live handlers) pending.

### Applied (this PR)

| File | Purpose |
|---|---|
| `00-contracts/lexicons/com/etzhayyim/auth/credential.json` | Inner-type lexicon describing the plaintext shape of an auth credential envelope (passkey / oauthLink / emailLink / smsOtp). |
| `60-apps/etzhayyim-project-auth/kotoba-datomic-projection.edn` | Declares the D1 `vertex_etzhayyim_auth_*` / `edge_etzhayyim_auth_*` / `vertex_etzhayyim_key_*` tables as L0 projections of `com.etzhayyim.encrypted.record` envelopes per ADR-2605231500. Lints reading this manifest can now exempt the auth Worker's D1 access from the substrate-boundary rule. |
| `60-apps/etzhayyim-project-auth/worker/src-ts/substrate-mst-credential.ts` | TypeScript seam: `writeAuthCredential()` / `readAuthCredential()` / `projectPasskeyToD1Row()`. Uses `@etzhayyim/sdk/encrypted` (`encryptedWriteStandalone` / `encryptedReadStandalone`) — already shipping (XChaCha20-Poly1305 + Signal-wrapped per-recipient keys per ADR-2605181100). |

### Stage 2 (next PR)

- [ ] Add `60-apps/etzhayyim-project-auth/worker/package.json` and register the package in root `pnpm-workspace.yaml` so `@etzhayyim/sdk/encrypted` resolves at build time (currently the auth Worker is outside the pnpm workspace cohort).
- [ ] Replace D1 writes in `passkeyVerifyRegister`, `linkOAuthStart`, `linkEmailVerify`, `smsOtpSend` with `writeAuthCredential(...)`. D1 row is then written from the same flow as a projection-only cache.
- [ ] On revocation paths, emit an `com.etzhayyim.encrypted.tombstone` envelope (existing lexicon) and soft-delete the D1 row.
- [ ] Stand up the rebuild runbook as a one-shot Worker command (`wrangler dev rebuild-projection`) that walks the PDS firehose, decrypts each envelope, and rebuilds D1 + KV from scratch.
- [ ] Drift detector cron (D1 ↔ MST envelope re-derive + alert on divergence) per `promotion_to_l1` in the projection manifest.

_Shipped Stage 1 by manual codemod 2026-05-23._
