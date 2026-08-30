# ADR-0001: Human authentication is Passkey-only and never downgrades

Status: accepted, implemented
Date: 2026-08-30

## Context

`auth.itonami.cloud` is an Internet-facing human authentication authority. Any
additional way to create a session is another trust root. Email and telephone
accounts can be reassigned or recovered by an upstream operator; SMS is exposed
to number-porting and carrier support; passwords and OTPs are phishable and
replayable; federated SSO inherits the provider's login, recovery, help-desk,
tenant-administration, and account-linking decisions. Hiding these choices in
the page does not remove the server-side attack path.

Availability is still a security property. A Passkey-only service therefore
needs recovery that does not silently become a lower-assurance authenticator.
The recovery mechanism must provide time for the existing owner to react and
must end in a fresh WebAuthn credential rather than a recovery session.

## Decision

### 1. The only human authenticator is WebAuthn

The authority accepts a WebAuthn assertion with RP ID `itonami.cloud`, an exact
allowed Origin, user verification, a server-issued challenge, and replay
protection. A successful assertion may create a bounded opaque session.

The following are permanently excluded as human authentication, Passkey
enrolment authority, session issuance, or account recovery:

- email links, email OTPs, email addresses, and passwords;
- SMS or voice OTPs and telephone-number ownership;
- social or enterprise SSO through OIDC, OAuth, SAML, or proprietary providers;
- security questions, device fingerprints, support-agent identity judgments,
  administrator resets, and other knowledge or operator overrides;
- bearer credentials whose possession alone can become a durable human session.

Email, SMS, and federation metadata may be used after Passkey authentication
for notifications, contact, data connection, or account linking. Those uses
must never mint or upgrade a human session and must never become a fallback.

If WebAuthn is unavailable, the service fails closed. It does not select a
weaker method based on browser capability, platform, locale, tenant setting,
installed secrets, provider configuration, or an incident flag.

### 2. Recovery is a delayed credential replacement ceremony

Recovery is the sole exception to presenting an existing Passkey, but it is not
a login method:

1. A recently Passkey-authenticated owner generates ten independent 160-bit
   one-time recovery keys. Plaintext is shown once; only SHA-256 digests are
   stored.
2. Spending one key atomically consumes it and creates an opaque continuation.
   It creates no session and reveals no account identifier.
3. The server enforces an exact 48-hour delay. During the delay, an owner with
   an existing Passkey may cancel the request.
4. After the delay, a 15-minute, single-purpose ticket authorizes only creation
   of a replacement WebAuthn credential for the already-bound Stable Principal
   and account DID.
5. Completion revokes every former Passkey and session, consumes the request,
   and invalidates the remaining recovery-key set. Partial cleanup must leave
   former credentials marked unusable.

Recovery requests expire seven days after becoming eligible. Help desk,
operator, email, SMS, SSO, and database edits cannot shorten or bypass the
delay. Operations may freeze an account or service but cannot grant identity.

### 3. Closed routes stay closed

The Worker uses an allowlist of routes. Retired `/v1/email/*`, `/v1/sso/*`,
`/v1/methods*`, SMS, password, and provider callback paths return `404` without
redirecting, even when legacy secrets or records still exist. Legacy data is
inert migration data, not latent configuration.

The built-Worker smoke suite must exercise the negative routes with plausible
legacy provider secrets installed. Any response that starts a ceremony,
redirects, issues a token/session, or differs because a provider secret exists
is a release-blocking security regression.

No runtime flag may re-enable an excluded route. A future federation product
must use a separate hostname, RP/trust boundary, session namespace, and ADR; it
must not be introduced as an `auth.itonami.cloud` fallback. This ADR cannot be
weakened for backward compatibility with dormant credentials.

## Security invariants

- One account has one human authentication root: WebAuthn credentials bound to
  its Stable Principal.
- Notification and integration identifiers never prove identity.
- Recovery-key possession alone never creates a session.
- Delay and expiry are enforced by durable server state, not browser time.
- Credential replacement is fail-closed: former credentials remain revoked
  across retry, partial deletion, and stale replicas.
- Authentication failure is indistinguishable enough to prevent account and
  recovery-key enumeration.
- No operator can convert an availability incident into an identity grant.

## Consequences

Losing all Passkeys and all recovery keys means the identity cannot be
recovered. This is intentional: a convenient manual exception would be the
weakest authentication route and therefore the effective security level of the
whole account. Users are instead guided to register multiple Passkeys and keep
offline recovery keys in separate custody.

Third-party federation may still be useful for importing data or associating an
external account after Passkey authentication. It is not accepted as evidence
that the person controls the Itonami identity.

## Rejected alternatives

### Keep Email or SSO hidden as emergency fallback

A hidden route remains reachable and is less likely to receive routine testing.
It also inherits upstream recovery and operator powers. Rejected.

### Let support bypass the 48-hour delay

This turns social engineering or an operator compromise into immediate account
takeover. Support may explain, observe, freeze, or help cancel; it cannot grant
identity. Rejected.

### Allow tenant administrators to select weaker methods

The weakest tenant option becomes the attacker's target and makes assurance
depend on mutable configuration. Authentication assurance is a service
invariant, not a tenant preference. Rejected.

