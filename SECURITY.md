# Security Policy

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** on this repository — the
*Security* tab, *Report a vulnerability*. It is enabled, so the button is
really there; if it ever is not, that is itself worth reporting.

Do not open a public issue for a suspected vulnerability, credential leak or
privacy incident.

Include the affected revision, reproduction steps, and observed impact. **Do
not include real credentials, tokens, keys or personal data** in a report — a
path and a description are enough, and a report is not a safe place to put the
thing you are reporting about.

## What is in scope

`auth.itonami.cloud` — passkey (WebAuthn) sign-in and native-app authorization.
The interesting surfaces are the ceremony crypto, origin and RP-ID binding,
challenge replay, and anything that would let one caller obtain authorization
issued for another.

Out of scope: the relying applications behind this Worker, each of which has
its own repository and its own policy.

## Workspace human-authentication boundary (ADR-2608302125)

This project is a declared first-party human-authentication authority. The
workspace root `SECURITY.md` and ADR-2608302125 are mandatory and this file may
not weaken them.

- The only active human-authentication method is a WebAuthn Passkey with exact
  RP ID and Origin binding, server-issued single-use challenge, replay
  protection, and user verification.
- Email, password, SMS/voice, OAuth/OIDC/SAML/social/enterprise SSO, support
  decisions, operator resets, and administrator overrides must not
  authenticate, bootstrap, step up, register or replace a credential, recover
  an account, or mint/upgrade a human session.
- If Passkey authentication is unavailable, fail closed. Provider secrets,
  legacy records, flags, or tenant settings must not enable a fallback.
- Recovery replaces a credential and never directly creates a session. It
  requires a one-time offline recovery secret, verifier-only storage, at least
  48 hours of server-enforced delay, and a fresh Passkey. Operators may freeze
  an account but cannot bypass the delay or grant identity.
- Closed legacy routes return 404 or 410 without ceremony, redirect, token,
  session, or credential issuance. Source, built Worker, and live-route
  negative tests must include plausible legacy configuration.

The current conformant claim is limited to the built Worker negative tests and
the deployed `auth.itonami.cloud` route probes recorded by the workspace. It
does not make other Itonami surfaces conformant.

## What is not claimed

This repository carries **no third-party security certification**. There is no
SOC 2 report, no ISO/IEC 27001 certificate and no ISMAP registration covering
it, and none is implied by whatever checks run here.

The workspace-level assurance position — which controls have design evidence,
which have implementation evidence, and which have no operating evidence at all
— is recorded in [`kotoba-lang/security`](https://github.com/kotoba-lang/security).
Read the current figures there with

```sh
kbb --backend sci --classpath src scripts/check-crosswalk.cljs
```

rather than quoting a number from this file, which would be stale the moment it
was written.
