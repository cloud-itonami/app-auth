# etzhayyim Auth Platform — T4 Topology (auth + authz split, η=0.91)

DID-native 自前認証基盤。TS infra Workers (2)。AI Agent-First + DID-native + AT Protocol faithful。

## T4 Worker Split (ADR-2605152100)

| Worker | Name | Routes | 責務 |
|---|---|---|---|
| `etzhayyim-auth` | **auth.etzhayyim.com** (canonical) | `auth.etzhayyim.com/*`, `authn.etzhayyim.com/*` (301 redirect) | AuthN: passkey / session JWT / DID / Service Auth |
| `etzhayyim-authz` | **accounts.etzhayyim.com** (canonical) | `accounts.etzhayyim.com/*`, `authz.etzhayyim.com/*` (301 redirect) | AuthZ: linked methods / actor score / org / /manage UI |

**DNS**:
- `auth.etzhayyim.com` → auth Worker (`worker/`) — **canonical**
- `authn.etzhayyim.com` → auth Worker (301 → auth.etzhayyim.com, DNS 廃止予定 2026-10-01)
- `accounts.etzhayyim.com` → authz Worker (`worker-authz/`) — **canonical**
- `authz.etzhayyim.com` → authz Worker (301 → accounts.etzhayyim.com, DNS 廃止予定 TBD)

**301 redirect 例外** (PDS service binding が直接 fetch するため redirect しない):
- `/.well-known/*` — Worker DID document / JWKS
- `/users/:id/did.json` — user DID document (did:web:authn.etzhayyim.com:user:*)

**XRPC NSIDs**:
- `com.etzhayyim.auth.*` — auth Worker (passkey, session, DID, service auth)
- `com.etzhayyim.authz.*` — authz Worker (linked methods, actor score, org) **canonical**
- `com.etzhayyim.auth.link*` on auth Worker → 307 → `accounts.etzhayyim.com/xrpc/com.etzhayyim.authz.*`

### Org Management XRPC (com.etzhayyim.authz.org*)

| NSID | Method | 説明 |
|---|---|---|
| `com.etzhayyim.authz.orgCreate` | POST `{ name, domain?, orgType? }` | org 作成 (caller の accountDid = orgDid) |
| `com.etzhayyim.authz.orgInfo` | GET `?orgDid=` | org 情報取得 |
| `com.etzhayyim.authz.orgList` | GET | caller が所属する org 一覧 |
| `com.etzhayyim.authz.orgMembers` | GET `?orgDid=` | org メンバー一覧 (メンバーのみ) |
| `com.etzhayyim.authz.orgInvite` | POST `{ orgDid?, email, role? }` | メンバー招待 (HMAC token 発行) |
| `com.etzhayyim.authz.orgInviteAccept` | POST `{ token }` | 招待を承認 (caller が新メンバーになる) |
| `com.etzhayyim.authz.orgMemberRemove` | POST `{ orgDid?, memberDid }` | メンバー除外 (owner/admin のみ) |
| `com.etzhayyim.authz.orgLeave` | POST `{ orgDid }` | org を退会 |

**D1 Tables (GraphAr)**:
- `vertex_etzhayyim_auth_org` — org metadata (name, domain, org_type, settings)
- `edge_etzhayyim_auth_member` — membership edge (org_did → member_did, role, status)
- `vertex_etzhayyim_auth_invite` — pending invites (HMAC token, expires_at)

**Auth UI**: `auth.etzhayyim.com/sign-in` + `/sign-up`. `?redirectUrl=` で認証後 `accounts.etzhayyim.com/manage` へリダイレクト。
**Account Management UI**: `accounts.etzhayyim.com/manage` → `auth.etzhayyim.com/manage` (暫定 302。manage UI は将来 accounts.etzhayyim.com に移行予定)。Linked methods / actor score / OAuth link/unlink。

### Sign-Up Flow (Passkey-First, Zero Input, Account = Actor = Org)

```
authn.etzhayyim.com/sign-up
  → [🔒 Create Account] ボタン 1 タップ
  → Touch ID / Face ID / デバイス PIN (WebAuthn FIDO2)
  → Account DID 自動生成: did:web:authn.etzhayyim.com:user:{nanoid} (8 文字, alpha-start, performerType: organization, org_type: personal)
  → Default Human Sub-Actor 自動作成: did:web:authn.etzhayyim.com:user:{nanoid}:person:default (performerType: person)
  → (:AccountDID)-[:CONTROLS]->(:SubActorDID) edge 作成
  → AT Protocol session 発行 (access_jwt + refresh_jwt, account_did=actor=org, active_did=default person sub-actor)
  → yoro.etzhayyim.com にリダイレクト
```

**入力フィールド: ゼロ。** Username/password/email/phone 不要。Passkey = phishing-resistant (FIDO2 Level 2, `user_verification: "preferred"` — Touch ID/Face ID 優先、fallback PIN)。

### Linked Auth Methods (Post Sign-Up Only)

新規登録は **必ず Passkey**。Email / Google / Microsoft は既存 account への追加認証手段としてのみ許可する。

```
accounts.etzhayyim.com/manage
  → session cookie / Authorization Bearer で account 確認
  → linked_auth_methods 一覧表示
  → Email link: code 発行 → verify
  → Google link: OAuth redirect → /oauth/link/google/callback
  → Microsoft link: OAuth redirect → /oauth/link/microsoft/callback
  → unlink (passkey 以外)
```

**actor.score rule**:
- score 評価対象は認証チャネル種別: `passkey`, `email`, `google`, `microsoft`
- verified な 1 種別ごとに `25` 点
- max `100`
- 同種別を複数リンクしても加点は 1 回のみ

### CRITICAL: Account = Actor = Org (DEFAULT)

**全アカウントはデフォルトで actor DID = org DID (`performerType: organization`, `org_type: personal`)。** human / service / team / legal / finance はすべて actor 配下の sub-actor DID とする。

- **Account = Actor = Org DID**: `did:web:authn.etzhayyim.com:user:{nanoid}` — billing/settings/admin/repo ownership/RACI root の主体
- **Human Default Sub-Actor**: `did:web:authn.etzhayyim.com:user:{nanoid}:person:default` — posts/likes/follows/DM の標準 author
- **Session 2 DID**: `account_did` (actor root) + `active_did` (current sub-actor, switchable)
- **Sub-Actor expansion**: `:person:*`, `:service:*`, `:team:*`, `:legal:*`, `:finance:*`, `:moderator:*` を追加可能
- **RACI root**: RACI assignment は actor/account DID 配下 resource に対して sub-actor へ付与する
- **Org 拡張**: `org_type` を `personal` → `company`/`npo`/`community`/`team` に変更しても root actor model は不変
- **設計詳細**: `90-docs/adr/2607193100-doc-only-app-concepts-wave3-retire.edn` の moderator canonical spec

### Membership — 3-Tier Plan

| Plan | 月額 | 認証 | eSIM | 機能 |
|---|---|---|---|---|
| **Free** (Guest) | ¥0 | Passkey ワンタップ | なし | AI Agent と会話 · 制限付き投稿 · WiFi only |
| **Verified** | ¥0 | Passkey + Phone SMS OTP | なし | フル機能 · 投稿無制限 · DM |
| **Telecom** | ¥2,980〜 | Passkey + Phone + Stripe | eSIM 発行 | eSIM 3GB · 通話 · SMS · フル機能 |

**Sign-Up Flow**: Passkey ワンタップ → Membership プラン選択 → Free (即 yoro) / Verified (Phone OTP) / Telecom (Stripe + eSIM)。

### CRITICAL: eSIM は Telecom plan のみ (コスト防御)

**Free/Verified に eSIM を発行しない。** Telnyx eSIM は月額 $2/SIM (アクティブ) の固定コストが発生するため、無課金ユーザーに発行すると赤字。

| Plan | eSIM 発行 | SIM 月額コスト | 根拠 |
|---|---|---|---|
| **Free** | **禁止** | $0 | Passkey のみ。WiFi 前提 |
| **Verified** | **禁止** | $0 | Phone OTP で本人確認済みだが無課金 |
| **Telecom** | **Stripe 決済後に発行** | $2/SIM + データ従量 | 月額課金でコスト回収 |

### Telecom Membership Pricing (Telnyx 原価ベース)

**Telnyx 原価** (従量課金、無制限プランなし):

| 項目 | コスト |
|---|---|
| eSIM 発行 (OTA) | $0.70/枚 (初回のみ) |
| SIM 月額 (アクティブ) | $2.00/SIM |
| SIM 月額 (休止) | $0.20/SIM |
| データ (日本 Zone, 5GB+) | ~$0.040/MB = **~$41/GB** |
| データ (US Zone 1, 5GB+) | $0.0125/MB = **~$13/GB** |

**etzhayyim Telecom プラン設計 (案)**:

| Membership Plan | 月額 | データ容量 | Telnyx 原価 (JP) | マージン |
|---|---|---|---|---|
| Telecom Light | ¥2,980 | 3GB | ~$15 + $2 SIM | ~65% |
| Telecom Standard | ¥4,980 | 20GB | ~$50 + $2 SIM | ~60% |
| Telecom Heavy | ¥7,980 | 50GB (超過後 1Mbps) | ~$100 + $2 SIM | ~55% |

**「無制限」は Telnyx 上で不可能。** 大容量 + 速度制限で擬似無制限を実現。アカウント全体の累積使用量が増えるほどティアが下がる (ボリュームディスカウント)。

### 法定公開ドキュメント

| ドキュメント | 法的根拠 | URL |
|---|---|---|
| 特定商取引法に基づく表示 | 特商法 11条 | `yoro.etzhayyim.com/support/tokushoho` |
| 電気通信事業届出 | 電気通信事業法 16条 | `yoro.etzhayyim.com/support/telecom-registration` |
| 本人確認ポリシー (KYC) | 犯収法 + 携帯電話不正利用防止法 | `yoro.etzhayyim.com/support/kyc-policy` |
| AML/CTF ポリシー | 犯収法 + FATF | `yoro.etzhayyim.com/support/aml-policy` |
| 利用規約 | 民法 + 電気通信事業法 | `yoro.etzhayyim.com/terms` |
| プライバシーポリシー | 個人情報保護法 + GDPR | `yoro.etzhayyim.com/privacy` |

## CRITICAL: Identity Model — did:web + Server-Assisted Custody (3-Tier)

→ `etzhayyim dodaf tv1 query --id etzhayyim-project-auth-identity-model-didweb-+-server-assisted` / MCP `etzhayyim.dodaf.tv1.query`

## Why (Clerk からの移行根拠)

Clerk は全認証の ~15% (Browser JWT) のみカバー。残り 85% は既に自前実装。

| 不整合 | 詳細 |
|---|---|
| **Ephemeral DID** | Clerk sub → `did:web:atproto.etzhayyim.com:user:${sub}` を毎回生成。DID Document 未登録 |
| **Agent 認証不能** | 715+ AI Agent は人間ではない。Clerk は human-first |
| **Org-in-Org 不能** | Clerk = flat org_id。DID path 階層 (L1-L5) 表現不可 |
| **AT Protocol bypass** | `issueAtprotoSession()` が dead code。Clerk JWT が直接 XRPC を通過 |
| **Bearer vs PoP** | Clerk = bearer token (盗まれたら終わり)。W Protocol = PoP (DID 秘密鍵署名) |
| **Consent 不在** | Clerk = authN のみ。GNAP/UMA consent は全て自前 |
| **MAU コスト** | Agent が MAU カウントされると費用破綻 |

## Runtime: TypeScript on Cloudflare Workers (infra Worker)

App ではない。PDS/dispatcher と同列の **infra Worker**。**Rust workers-rs → モノリシック TS → モジュール TS** の 2 段階で移行済み。現在の本流は `worker/src-ts/` (modular)。zero npm deps、WebCrypto API のみ。

```
┌─ Deployment Topology ─────────────────────────────────────┐
│                                                            │
│  Browser ──→ authn.etzhayyim.com ──dispatcher──→ AUTH_SERVICE     │
│                                                  (TS)      │
│  PDS ──service binding──→ AUTH_SERVICE                      │
│   │                                                        │
│   └──service binding──→ YATA_RPC                            │
│                                                            │
│  External: dispatcher SERVICE_BINDING_DOMAINS routing       │
│  Internal: PDS → AUTH_SERVICE service binding               │
└────────────────────────────────────────────────────────────┘
```

| 判断 | 理由 |
|---|---|
| **TypeScript (zero npm deps)** | WebCrypto subtle で P-256 ECDSA + HS256 + SHA-256 を完結。Rust → TS 移行で Cargo build / wasm-bindgen 中間層を撤廃。`@atproto/crypto` 等の SDK 注入も Plan A で評価中 |
| **NOT App** | infra Worker として account-level deploy |
| **NOT Container** | auth は stateless token 操作。128MB Worker で十分。Container の latency 不要 |
| **Service Binding RPC** | PDS → `AUTH_RPC` (WorkerEntrypoint 相当)。HTTP fallback 不要 |

## Project Structure

```
60-apps/etzhayyim-project-auth/
├── CLAUDE.md
├── PROJECT.jsonld
├── worker/                     # etzhayyim-auth → authn.etzhayyim.com (AuthN)
│   ├── wrangler.jsonc          # routes: authn.etzhayyim.com/*, authn.etzhayyim.com/*
│   ├── svelte/                 # Shared CSR build (sign-in / sign-up / manage)
│   └── src-ts/
│       ├── index.ts            # AuthN router: passkey/session/DID/service-auth/PKCE
│       ├── session.ts          # AT Protocol session (HS256 issue/verify/refresh)
│       ├── did.ts              # DID Document CRUD + did:etzhayyim + P-256 keypair
│       ├── service-auth.ts     # Service Auth JWT (ES256, DID-signed)
│       ├── passkey.ts          # WebAuthn registration + assertion verification
│       ├── dpop.ts             # DPoP PoP binding (RFC 9449)
│       ├── ui.ts               # /sign-in, /sign-up HTML pages
│       ├── base64url.ts        # Base64url encode/decode
│       └── security.ts         # fnv1a32 hash
└── worker-authz/               # etzhayyim-authz → accounts.etzhayyim.com (AuthZ, canonical)
    ├── wrangler.jsonc          # routes: accounts.etzhayyim.com/*, authz.etzhayyim.com/* (301 redirect)
    └── src-ts/
        └── index.ts            # AuthZ router: linked methods/actor score/org/manage UI
```

旧モノリシック `worker/src/index.ts` (2,111 LOC) は archive 済み。git 履歴が保持。

## Dependencies

zero npm packages. WebCrypto API + Cloudflare Workers runtime のみ:

| 機能 | 実装 |
|---|---|
| P-256 ECDSA (sign / verify / keygen) | `crypto.subtle.generateKey` / `sign` / `verify` (`{name: "ECDSA", namedCurve: "P-256"}`) |
| HS256 (session JWT) | `crypto.subtle.importKey` (HMAC) + `sign` |
| SHA-256 (digest) | `crypto.subtle.digest` |
| CBOR (WebAuthn attestation) | 手書き minimal decoder (`passkey.ts`) |
| Base58btc (multibase) | 手書き encoder (`did.ts`) |
| Random | `crypto.getRandomValues` |
| D1 SQL | `env.AUTH_DB.prepare(...).bind(...).run()` |

将来的に `@atproto/crypto` (P-256 / secp256k1 / did:key 標準実装) を `did.ts` + `service-auth.ts` に注入可能 (Plan A, root TODO)。

## Deployment

```bash
cd 60-apps/etzhayyim-project-auth/worker
etzhayyim deploy        # or: wrangler deploy
```

**Public URL**:
- `https://authn.etzhayyim.com/*` — sign-in / sign-up / CLI OAuth PKCE
- `https://accounts.etzhayyim.com/*` — account management / linked auth methods

**PDS integration**: PDS `wrangler.jsonc` に `{ "binding": "AUTH_RPC", "service": "etzhayyim-auth" }` 追加 → `authenticate()` を `env.AUTH_RPC.fetch("/rpc/authenticate")` に委譲

**DNS note**: `authn.etzhayyim.com` / `accounts.etzhayyim.com` ともに CF proxied → dispatcher → AUTH_SERVICE。OAuth2 PKCE: `/oauth/authorize` + `/oauth/token` で `etzhayyim authn signin` をサポート。`/oauth/token` は `application/x-www-form-urlencoded` (OAuth2 RFC 6749 標準) と `application/json` の両方を受付。

**OAuth provider env**:
- Google: `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET`
- Microsoft: `MICROSOFT_OAUTH_CLIENT_ID` / `MICROSOFT_OAUTH_CLIENT_SECRET`
- backward compat aliases: `GMAIL_OAUTH_ID` / `GMAIL_OAUTH_SECRET`, `OUTLOOK_SECRET` / `OUTLOOK_SECRET_ID`

## Architecture

```
┌─ auth Worker (TypeScript, WebCrypto-only) ──────────────┐
│                                                         │
│  Identity Layer                                         │
│  ├─ Human: WebAuthn/Passkey → DID Document 生成 ✓      │
│  ├─ Agent: DID 直接生成 (performerType=service/system) ✓│
│  ├─ Org: Multi-DID 階層 (DID path) ✓                    │
│  └─ Session: AT Protocol session token (HS256) ✓        │
│                                                         │
│  Token Layer                                            │
│  ├─ Session JWT: HS256 (WebCrypto HMAC + SHA-256) ✓     │
│  ├─ Service Auth JWT: ES256 (WebCrypto P-256 ECDSA) ✓   │
│  └─ DPoP: ES256 PoP binding (RFC 9449) ✓                │
│                                                         │
│  Storage                                                │
│  ├─ DID Document: yata graph (:DIDDocument node) ✓      │
│  ├─ AgentKey: yata graph (:AgentKey node) ✓             │
│  ├─ Session: yata graph (:Session node, TTL)            │
│  ├─ Passkey: D1 (passkey_credentials table) ✓           │
│  ├─ Linked auth methods: D1 (linked_auth_methods) ✓     │
│  ├─ Email link codes: D1 (email_link_codes) ✓           │
│  └─ DID Document cache: R2 (did:web resolution)         │
│                                                         │
│  RPC Interface (XRPC, NSID-aligned)                     │
│  ├─ /xrpc/com.atproto.server.createSession              │
│  ├─ /xrpc/com.atproto.server.refreshSession             │
│  ├─ /xrpc/com.atproto.server.deleteSession              │
│  ├─ /xrpc/com.atproto.identity.resolveDid               │
│  ├─ /xrpc/com.atproto.identity.createDid                │
│  ├─ /xrpc/com.atproto.server.getServiceAuth             │
│  ├─ /xrpc/com.etzhayyim.auth.passkeyBeginRegister             │
│  ├─ /xrpc/com.etzhayyim.auth.passkeyVerifyRegister            │
│  ├─ /xrpc/com.etzhayyim.auth.passkeyBeginAuth                 │
│  ├─ /xrpc/com.etzhayyim.auth.passkeyVerifyAuth                │
│  ├─ /xrpc/com.etzhayyim.auth.linkEmailBegin                   │
│  ├─ /xrpc/com.etzhayyim.auth.linkEmailVerify                  │
│  ├─ /xrpc/com.etzhayyim.auth.linkOAuthStart                   │
│  ├─ /xrpc/com.etzhayyim.auth.unlinkMethod                     │
│  ├─ /xrpc/com.etzhayyim.auth.smsOtpSend                       │
│  ├─ /xrpc/com.etzhayyim.auth.smsOtpVerify                     │
│  ├─ /xrpc/com.etzhayyim.auth.esimProvision                    │
│  ├─ /xrpc/com.etzhayyim.auth.verifyDpop                       │
│  ├─ /xrpc/com.etzhayyim.auth.createGuestAccount               │
│  ├─ GET  /.well-known/jwks.json (ES256 public key)      │
│  ├─ GET  /oauth/authorize  (CLI PKCE flow)              │
│  ├─ GET  /oauth/link/google/callback                    │
│  ├─ GET  /oauth/link/microsoft/callback                 │
│  ├─ POST /oauth/issue-code                              │
│  ├─ POST /oauth/token  (form-urlencoded + JSON)         │
│  ├─ GET  /api/accounts/session                          │
│  └─ GET  /sign-in / /sign-up / /manage / /api/auth-config│
└─────────────────────────────────────────────────────────┘
```

**NSID 移行**: Rust 時代の `com.etzhayyim.auth.{resolveDid,createDid}` は廃止。`com.atproto.identity.{resolveDid,createDid}` に統一 (AT Protocol 準拠)。caller はゼロだったため alias 不要。

## RPC Interface (TypeScript)

PDS/dispatcher が `env.AUTH_SERVICE.fetch()` または public HTTPS で呼び出す。Router は `(method, pathname)` の string match。

```ts
// src-ts/index.ts — fetch handler
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    if (method === "GET" && pathname === "/health") return new Response("ok");

    // AT Protocol session
    if (method === "POST" && pathname === "/xrpc/com.atproto.server.createSession") return handleCreateSession(request, env);
    if (method === "POST" && pathname === "/xrpc/com.atproto.server.refreshSession") return handleRefreshSession(request, env);
    if (method === "POST" && pathname === "/xrpc/com.atproto.server.deleteSession") return handleDeleteSession(request, env);

    // DID resolution / creation
    if (method === "POST" && pathname === "/xrpc/com.atproto.identity.resolveDid") return handleResolveDid(request);
    if (method === "POST" && pathname === "/xrpc/com.atproto.identity.createDid") return handleCreateDid(request);

    // Service Auth JWT (ES256)
    if (method === "POST" && pathname === "/xrpc/com.atproto.server.getServiceAuth") return handleSignServiceAuth(request, env);

    // WebAuthn / Passkey
    if (method === "POST" && pathname === "/xrpc/com.etzhayyim.auth.passkeyBeginRegister") return handlePasskeyBeginRegister(request);
    if (method === "POST" && pathname === "/xrpc/com.etzhayyim.auth.passkeyVerifyRegister") return handlePasskeyVerifyRegister(request, env);
    if (method === "POST" && pathname === "/xrpc/com.etzhayyim.auth.passkeyBeginAuth") return handlePasskeyBeginAuth();
    if (method === "POST" && pathname === "/xrpc/com.etzhayyim.auth.passkeyVerifyAuth") return handlePasskeyVerifyAuth(request, env);

    // Telecom tier (SMS OTP / eSIM / Stripe)
    if (method === "POST" && pathname === "/xrpc/com.etzhayyim.auth.smsOtpSend") return handleSmsOtpSend(request, env);
    if (method === "POST" && pathname === "/xrpc/com.etzhayyim.auth.smsOtpVerify") return handleSmsOtpVerify(request, env);
    if (method === "POST" && pathname === "/xrpc/com.etzhayyim.auth.esimProvision") return handleEsimProvision(request, env);
    if (method === "POST" && pathname === "/xrpc/com.etzhayyim.auth.createSetupIntent") return handleCreateSetupIntent(request, env);

    // DPoP
    if (method === "POST" && pathname === "/xrpc/com.etzhayyim.auth.verifyDpop") return handleVerifyDpop(request);

    // Guest account (Passkey)
    if (method === "POST" && pathname === "/xrpc/com.etzhayyim.auth.createGuestAccount") return handleCreateGuestAccount(request, env);

    // JWKS
    if (method === "GET" && pathname === "/.well-known/jwks.json") return handleJwks(env);

    // OAuth2 Auth Code + PKCE
    if (method === "GET" && pathname === "/oauth/authorize") return handleOAuthAuthorize(url);
    if (method === "POST" && pathname === "/oauth/issue-code") return handleOAuthIssueCode(request);
    if (method === "POST" && pathname === "/oauth/token") return handleOAuthToken(request, env);

    // UI pages
    if (method === "GET" && pathname === "/sign-in") return renderSignInPage();
    if (method === "GET" && pathname === "/sign-up") return renderSignUpPage();
    if (method === "GET" && pathname === "/api/auth-config") return handleAuthConfig(env);

    return new Response("Not Found", { status: 404 });
  }
};
```

## Core Types (TypeScript)

```ts
// src-ts/types — inline interfaces

type AuthLevel = "public" | "session" | "internal";

interface AuthResult {
  level: AuthLevel;
  did: string | null;             // did:web:...
  orgId: string;
  clearance: string;
  tokenScopes: string[];
}

interface DIDDocument {
  did: string;                    // did:web:authn.etzhayyim.com:user:{nanoid}
  controller: string;             // root actor DID (self for account DID)
  publicKeyMultibase: string;     // z-prefixed base58btc P-256
  performerType: PerformerType;   // service | system | person | organization
  createdAt: string;              // ISO 8601
  updatedAt: string;
}

interface SessionTokens {
  accessJwt: string;     // HS256, 1 week expiry
  refreshJwt: string;    // HS256, 90d expiry
  did: string;           // legacy compat (= accountDid)
  accountDid: string;    // account = actor = org DID (root authority)
  activeDid: string;     // current sub-actor DID (default: person:default)
  handle: string;
}

interface ServiceAuthClaims {
  iss: string;   // sender DID
  aud: string;   // receiver DID
  exp: number;
  lxm?: string;  // lexicon method
}
```

## Migration Phases

### P1: AT Protocol Session + Clerk Bridge

PDS `authenticate()` を AUTH_SERVICE service binding に委譲。Clerk JWT は auth Worker 内で検証し AT Protocol session に変換。PDS 内の inline Clerk JWT 検証コード (`fetchClerkJWKS`, `verifyClerkJWT`) は削除。Clerk は UI/UX (`@clerk/clerk-js`) として維持。

**auth Worker 実装**:
- `session.ts` — HS256 JWT issue/verify/refresh (WebCrypto HMAC + SHA-256)
- `did.ts` — DID Document 生成 + yata MERGE。account/actor root = `did:web:authn.etzhayyim.com:user:{nanoid}`、sub-actor = `did:web:authn.etzhayyim.com:user:{nanoid}:{kind}:{name}`
- `service-auth.ts` — ES256 sign/verify (WebCrypto P-256 ECDSA)
- (Clerk bridge は P3 で完全除去済み)

**PDS 変更**:
- `wrangler.jsonc` に `AUTH_SERVICE` service binding 追加 (`etzhayyim-auth`)
- `authenticate()` を `env.AUTH_SERVICE.fetch("/rpc/authenticate", ...)` に委譲
- `ComAtprotoServerCreateSession` → AUTH_SERVICE `/rpc/issue-session` に委譲 (fallback あり)
- `ComAtprotoServerRefreshSession` → AUTH_SERVICE `/rpc/refresh-session` に委譲 (fallback あり)
- `ComAtprotoServerGetServiceAuth` → AUTH_SERVICE `/rpc/sign-service-auth` に委譲 (fallback あり)
- PDS inline Clerk 検証 (`fetchClerkJWKS`, `verifyClerkJWT`, JWKS cache) 削除
- `50-infra/cloudflare/workers/atproto/src/auth.ts` の `verifyClerkJwt()` は export 維持 (呼出元なし)

**効果**:
- 内部は全て DID-native (Clerk sub は auth Worker boundary で消える)
- AT Protocol session semantics 復活 (access + refresh token)
- auth 処理が auth Worker に集約 (PDS の bundle size 削減)

### P2: Agent Credential Flow

Agent (performerType=service/system) 用の DID credential flow。T1 (server-assisted) key custody。

**auth Worker 実装**:
- `did.ts` — `createAgentSession()`: Agent DID 生成 + P-256 ES256 keypair (WebCrypto) + AT Protocol session 一括発行
- `did.ts` — `rotateAgentKey()`: 新 keypair 生成 + 旧 key revocation timestamp 返却
- `did.ts` — `activeKeyInfo()`: AgentKeyInfo builder
- 3 XRPC routes: `/xrpc/com.etzhayyim.auth.createAgentSession`, `/xrpc/com.etzhayyim.auth.rotateAgentKey`, `/xrpc/com.etzhayyim.auth.listAgentKeys`

**PDS 変更**:
- `registerApp` (`com.atproto.admin.registerApp`): `etzhayyim deploy` 時に AUTH_SERVICE → agent session 作成 → `:DIDDocument` + `:AgentKey` yata graph MERGE + edges (`HAS_KEY`, `HAS_DID`)。response に `agent_did`, `agent_key_id`, `agent_session` を含む
- `authenticate()`: Service Auth (ES256) で `user_did` を設定 → JWT forwarded to yata, SecurityScope compiled from CSR
- `ComAtprotoIdentityRotateKey`: AUTH_SERVICE に委譲 → 新 keypair 生成 + 旧 AgentKey revoke + 新 AgentKey persist + DIDDocument 更新

**データフロー (P2)**:
```
etzhayyim deploy
  → PDS /xrpc/com.atproto.admin.registerApp
    → AUTH_SERVICE /rpc/create-agent-session
      ← {did, did_document, private_key_b64url, session_tokens, key_id}
    → YATA_RPC.mergeRecord(:DIDDocument) + mergeRecord(:AgentKey)
    → YATA_RPC.mutate(:DIDDocument)-[:HAS_KEY]->(:AgentKey)
    → YATA_RPC.mutate(:App)-[:HAS_DID]->(:DIDDocument)
  ← {registered, agent_did, agent_key_id, agent_session}

Agent request (ES256 Service Auth JWT)
  → PDS authenticate()
    → verifyServiceAuthJWT() → JWT forwarded to yata
  ← AuthContext {level: 'internal', user_did, rbac_roles, consent_grants}
```

**効果**:
- 715+ Agent が個別 DID + ES256 keypair で認証
- `SS_KOTODAMA_INTERNAL_TOKEN` (shared secret) 除去 — ES256 Service Auth JWT に完全移行
- Agent DID が yata graph に永続化 (`:DIDDocument` + `:AgentKey` + edges)
- `etzhayyim deploy` が自動で agent credential を発行・登録

### P3: WebAuthn/Passkey

人間の sign-up/sign-in を自前化。Clerk 完全除去。

**auth Worker 実装**:
- `passkey.ts` — WebAuthn registration (attestation verification) + authentication (assertion verification)。P-256 ECDSA (WebCrypto subtle) + CBOR parsing (custom minimal decoder)。RP ID = `etzhayyim.com`
- 4 XRPC routes: `/xrpc/com.etzhayyim.auth.passkeyBeginRegister`, `/xrpc/com.etzhayyim.auth.passkeyVerifyRegister`, `/xrpc/com.etzhayyim.auth.passkeyBeginAuth`, `/xrpc/com.etzhayyim.auth.passkeyVerifyAuth`
- `GET /.well-known/jwks.json` — ES256 公開鍵 JWKS endpoint (Cache-Control: 1h, CORS: *)
- Clerk bridge コード **削除** — RS256 JWKS 検証ロジック除去
- `authenticate()` から Clerk JWT layer 除去 — Layer 1 (service binding) → Layer 2 (AT session HS256) → public
- Passkey credential 永続化: D1 (`AUTH_DB` binding, `passkey_credentials` table)

**Frontend (yoro) 変更**:
- `passkey.ts` **新規** — `clerk.ts` と同一 interface (drop-in replacement)。`navigator.credentials.create/get` (WebAuthn browser API) + AUTH_SERVICE RPC
- `index.ts` — import 先を `clerk` → `passkey` に切替
- `@clerk/clerk-js` npm 依存は不要 (WebAuthn は browser 標準 API)

**PDS 変更**:
- `wrangler.jsonc` — `SS_PUBLIC_CLERK_PUBLISHABLE_KEY`, `SS_CLERK_SECRET_KEY` 削除
- `index.ts` Env 型 — Clerk secret 型宣言削除
- テスト — Clerk secret mock 削除 (302 tests pass)

**効果**:
- **Clerk 完全除去** — npm 依存・DNS CNAME・Secrets Store・auth Worker bridge 全削除
- Passkey = phishing-resistant (FIDO2 Level 2, `user_verification: "preferred"` — Touch ID/Face ID 優先、fallback PIN)
- TS-only 化により Cargo build / wasm-bindgen 中間層を撤廃
- `authn.etzhayyim.com` CNAME を Clerk から解放可能

### P4: AT Protocol Federation + DPoP

AT Protocol 完全準拠 + federation 対応。

**Federation (did:plc)**:
- `did:plc` resolution — PLC Directory (`plc.directory`) query + 5min cache。auth Worker `/rpc/resolve-external-did` + PDS `resolveDIDSigningKey()` 3-layer
- External PDS DID key resolution — HTTPS `.well-known/did.json` (non-etzhayyim.com did:web)
- PDS 3-layer DID resolution: (1) yata graph → (2) PLC Directory → (3) HTTPS .well-known

**OAuth hardening**:
- DPoP jti replay protection — `_dpopJtiCache` Set (10K entries, FIFO cleanup)
- Redirect URI validation — HTTPS 必須 + PAR 登録 URI との一致検証
- VC/VP PoP binding (P4+)

### AT Protocol Compliance

| 項目 | AT Protocol Spec | 実装状態 |
|---|---|---|
| Session JWT (HS256) | REQUIRED | ✅ |
| Service Auth JWT (ES256) | REQUIRED | ✅ |
| OAuth 2.0 + PKCE + PAR | REQUIRED | ✅ (`/oauth/token` accepts form-urlencoded per RFC 6749 §4.1.3) |
| DPoP binding + jti replay | RECOMMENDED | ✅ (`dpop.ts` WebCrypto verify + PDS TS jti cache) |
| Redirect URI validation | REQUIRED | ✅ |
| did:web support | OPTIONAL | ✅ |
| did:plc federation | REQUIRED for federation | ✅ (PLC Directory 経由) |
| External did:web resolution | REQUIRED for federation | ✅ (HTTPS .well-known) |
| XRPC Lexicon routing | REQUIRED | ✅ |
| PDS signing key custody | PDS holds keys | ⚠️ AUTH_SERVICE 委譲 (T1 — セキュリティ強化) |
| Auth UI (sign-in/sign-up) | REQUIRED | ✅ (3-tier: Guest Passkey / Verified Phone OTP / Telecom eKYC+eSIM) |
| WebAuthn `pubKeyCredParams` | RECOMMENDED both ES256+RS256 | ✅ `[{alg:-7},{alg:-257}]` (`passkey.ts` `beginRegistration`) — Chrome warns if RS256 omitted |
- VC/VP PoP binding

## Data Model (SQL)

```sql
// DID Document (永続, did:web)
(:DIDDocument {did, controller_did, public_key_multibase, performer_type, key_custody_tier, created_at, updated_at})
// key_custody_tier: "server_assisted" (T1) | "agent_self_custody" (T2) | "human_self_custody" (T3)

(:Session {jti, did, scope, exp, created_at})
(:DIDDocument)-[:HAS_SESSION]->(:Session)

(:AgentKey {key_id, algorithm, public_key_multibase, created_at, revoked_at})
(:DIDDocument)-[:HAS_KEY]->(:AgentKey)

(:PasskeyCredential {credential_id, public_key, sign_count, transports, created_at})
(:DIDDocument)-[:HAS_PASSKEY]->(:PasskeyCredential)

// Signal Protocol keys (T1: auth Worker 管理, T2: Agent 自己管理)
(:SignalIdentityKey {did, public_key, signed_by_did_key, created_at})
(:DIDDocument)-[:HAS_SIGNAL_IDENTITY]->(:SignalIdentityKey)

(:SignalPreKey {key_id, did, public_key, signature, created_at, expires_at})
(:SignalIdentityKey)-[:HAS_PREKEY]->(:SignalPreKey)

// Bluesky federation bridge (将来)
(:PLCAlias {plc_did, web_did, created_at})
(:DIDDocument)-[:HAS_PLC_ALIAS]->(:PLCAlias)
```

## CRITICAL: Secret Architecture (P3 final)

→ `etzhayyim dodaf tv1 query --id etzhayyim-project-auth-secret-architecture-p3-final` / MCP `etzhayyim.dodaf.tv1.query`

## CRITICAL: 3-System Integration (auth → PDS → yata)

→ `etzhayyim dodaf tv1 query --id etzhayyim-project-auth-3-system-integration-auth-pds-yata` / MCP `etzhayyim.dodaf.tv1.query`

## Cross-Project Dependencies

| Project | 関係 |
|---|---|
| pds | auth の唯一の消費者 (service binding AUTH_RPC) |
| yoro | frontend auth UI (sign-in/sign-up/passkey) |
| trust | DID Trust Score が DIDDocument 品質に依存 |
| society6 | Kyu/Dan が auth identity に依存 |

## CRITICAL: ERC725 Root Identity = Platform Primary Identity (ADR-0074, 2026-04-26)

**`did:erc725:etzhayyim:260425:{identityContract}` が etzhayyim platform の primary identity。** 認証 (AuthN) + 認可 (AuthZ) + governance は ERC725 root を正とし、Coinbase Smart Wallet は execution account として root から参照する。

- **JWT.iss = did:erc725:etzhayyim:260425:{identityContract}** — migration 完了後の platform 内 XRPC call
- **did:etzhayyim = legacy/internal compatibility** — 既存 account と path-form sub-DID の migration 期間のみ primary issuer として受理
- **did:plc = federation adapter のみ** — Bluesky 等の外部連携時のみ `federationDID` 経由で参照
- **did:web = legacy/service facade** — 新規 root 発行停止。既存は migration 期間のみ
- **did:pkh = wallet alias** — SIWE/ERC-1271 で証明した EOA / Coinbase Smart Wallet address
- **KEK envelope encryption (ADR-0010 Stage 1, LIVE)**: `private_key ← data_key (AES-256-GCM) ← KEK (SS_REPO_SIGNING_KEK)`。D1 に plaintext private key は一切存在しない
- **GraphAr schema**: D1 auth control (vertex_etzhayyim_auth_*) と RisingWave governance (vertex_etzhayyim_identity) が同一 GraphAr 命名規則
- **Design doc**: `90-docs/260416-did-schema-dodaf-org-agent-shannon-design.md`
- **Root topology (CRITICAL, ADR-0074)**: `90-docs/adr/0074-ethereum-identity-bridge-cacao-webauthn.md` — ERC725 root + Coinbase Smart Wallet execution + `did:pkh` wallet alias + `did:plc`/`did:web` AT facade。SIWE は link ceremony、CACAO は portable delegated capability。
- **Legacy method spec (ADR-0029)**: `90-docs/adr/0029-did-etzhayyim-method-specification.md` — W3C DID Core 1.0 + DID Resolution v0.3 準拠。CIDv1 (`b` base32 + `raw` codec + sha2-256 multihash) + DAG-CBOR canonical genesis op + path-form sub-DID (max depth 6)。独自 top-level field なし。Reference impl: `10-protocol/did-etzhayyim/`。Resolver: `did.etzhayyim.com` (`10-protocol/did-etzhayyim/resolver/`)。Op submit: PDS XRPC `com.etzhayyim.identity.submitOp` (create/update/deactivate)。`did.ts` 既存 hex-truncated 形式は legacy として grandfather (auto-migration 経路は `etzhayyim identity migrate-paths` で提供予定)

### D1 Tables (GraphAr schema, auth control plane)

| Table | DB | Content |
|---|---|---|
| `vertex_etzhayyim_auth_account` | AUTH_DB | ERC725 root DID 認証制御 (handle, actor_score, status)。table name is legacy GraphAr namespace |
| `vertex_etzhayyim_auth_credential` | AUTH_DB | WebAuthn passkey |
| `vertex_etzhayyim_auth_invite` | AUTH_DB | org 招待 (HMAC token) |
| `vertex_etzhayyim_auth_otp` | AUTH_DB | Email OTP |
| `edge_etzhayyim_auth_linked` | AUTH_DB | OAuth/Email リンク |
| `vertex_etzhayyim_key_signing` | KEYS_DB | **KEK envelope encrypted** signing key |
| `vertex_etzhayyim_key_revoked_session` | KEYS_DB | session 無効化 |
| `vertex_etzhayyim_key_otp` | KEYS_DB | SMS OTP |

## Prohibited Patterns

- **ERC725 root 以外の DID を新規 platform primary identity に使用禁止** — did:erc725 が canonical。did:etzhayyim / did:plc / did:web は facade lookup input のみ。onchain authority path で直接 hash 禁止
- **D1 に plaintext private key を保存禁止** — `server_assisted` (T1) custody では KEK envelope encryption 必須 (SS_REPO_SIGNING_KEK)。legacy `did_keys` テーブル pruned。**zero-access (`human_self_custody`/`agent_self_custody`, ADR-2606014500) では private key を一切受け取らない** — `vertex_etzhayyim_key_signing` の private 列は空、public 半分のみ登録 (`com.etzhayyim.auth.registerSigningKey`)
- **SS_REPO_SIGNING_KEK なしでの sign-up 禁止 (AMENDED, ADR-2606014500)** — `server_assisted` 経路では従来どおり KEK 必須で fail-closed。**ただし client-self-custody (public-key-only 登録) 経路は KEK 不要で許可** (Proton 系 zero-access; `SS_KEY_CUSTODY_MODE=client_self_custody`)。KEK 物理削除は Stage C-4 (30日 zero-read quarantine) で gated
- **Zero-knowledge key custody を Agent に適用禁止** — Agent は server-assisted (T1) or self-custody (T2)。Master Password 方式は不成立
- **Signal Identity Key を DID Signing Key から独立生成禁止** — Signal Identity Key は DID Signing Key で署名される (key hierarchy 遵守)
- **Clerk / 外部 auth SaaS の再導入禁止** — P3 で完全除去済み
- **Shared secret token (`SS_KOTODAMA_INTERNAL_TOKEN`) の再導入禁止** — 除去済み。service-to-service auth は ES256 Service Auth JWT のみ
- **PDS に private key を保持禁止** — T1 custody: 全 signing key は auth Worker が保持 (KEK envelope)
- **Legacy テーブル (did_keys / revoked_sessions / otp_codes) の再導入禁止** — pruned 済み。GraphAr vertex_etzhayyim_key_* テーブルに統合
- **WebAuthn `user_verification: "preferred"`** — registration/authentication 両方 `"preferred"`。`"discouraged"` は禁止
