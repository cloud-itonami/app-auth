`src-ts/` is the production TypeScript source for `etzhayyim-auth-worker`.

`wrangler.jsonc` `main` points at `src-ts/index.ts`. The previous monolithic
`src/index.ts` (2,111 LOC) was archived (git history preserves it) after
porting D1-backed passkey storage and stateless HMAC OAuth code handling.

## Modules

- `index.ts` — fetch handler / route table
- `session.ts` — AT Protocol session HS256 issue / verify / refresh (WebCrypto HMAC)
- `did.ts` — did:web Document creation + helpers (P-256 keypair via WebCrypto)
- `service-auth.ts` — ES256 Service Auth JWT + JWKS builder
- `passkey.ts` — WebAuthn registration + assertion verification (P-256, custom CBOR)
- `dpop.ts` — RFC 9449 DPoP proof verification + jti replay
- `ui.ts` — `/sign-in`, `/sign-up`, `/oauth/authorize` HTML fallback (SvelteKit static
  build under `../svelte/build/` is preferred when present)
- `base64url.ts`, `security.ts` — small utilities

## Storage

- Passkey credentials: D1 (`AUTH_DB` binding, `passkey_credentials` table, schema
  initialized on demand by `ensurePasskeyCredentialTable`).
- OAuth authorization codes: stateless HMAC-signed self-contained tokens (no KV/DO).
- Session JWT: HS256 with `SS_AT_SESSION_SECRET`.

## Cross-origin session handoff

Successful passkey flows redirect to `yoro.etzhayyim.com#auth=<encoded JSON session>` so
that consumer subdomains can hydrate auth state from the URL fragment.
</content>
</invoke>