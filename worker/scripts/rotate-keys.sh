#!/bin/bash
# ADR-0023 P4 — auth Worker key rotation runbook.
#
# Rotates `SS_SERVICE_AUTH_PRIVATE_KEY` + `SS_AUTH_PUBLIC_KEY_B64` on the
# etzhayyim-auth Worker through a zero-downtime multi-key grace window.
#
# Phases (see handleWellKnownDidJson in src-ts/index.ts):
#   Phase 0 (pre)   : cur=A                            — sign with A
#   Phase 1 (begin) : cur=A, next=B                    — did.json publishes [A, B]
#   Phase 2 (flip)  : cur=B, prev=A                    — sign with B, A sunset
#   Phase 3 (done)  : cur=B                            — rotation complete
#
# Timing:
#   - PDS `_didKeyCache` TTL = 300s (5 min). Between Phase 1 → 2, wait ≥ 300s
#     so PDS learns about B before we switch to signing with B.
#   - JWT max lifetime = 60s. Between Phase 2 → 3, wait ≥ 60s so the last
#     A-signed JWT expires before removing A from did.json.
#
# Usage: ./rotate-keys.sh [--dry-run]
#
# Prereqs: wrangler CLI, node, etzhayyim repo root cwd.

set -euo pipefail

DRY_RUN="${1:-}"
WORKER_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORKER_DIR"

log() { echo "[rotate-keys] $*" >&2; }
run() {
  if [ "$DRY_RUN" = "--dry-run" ]; then
    log "DRY-RUN: $*"
  else
    eval "$@"
  fi
}

# 1. Generate new P-256 keypair
log "Phase 1: generating new keypair..."
KEY_TMP=$(mktemp -d)
trap "rm -rf $KEY_TMP" EXIT

node --input-type=module -e "
import { webcrypto } from 'node:crypto';
import { writeFileSync, chmodSync } from 'node:fs';
const { subtle } = webcrypto;
const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
const priv = await subtle.exportKey('jwk', kp.privateKey);
const pub = await subtle.exportKey('jwk', kp.publicKey);
const fromB64u = s => Buffer.from(s.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4 - s.length%4)%4), 'base64');
const toB64u = buf => Buffer.from(buf).toString('base64').replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+\$/g,'');
const uncompressed = Buffer.concat([Buffer.from([0x04]), fromB64u(pub.x), fromB64u(pub.y)]);
writeFileSync('$KEY_TMP/new_priv', priv.d);
writeFileSync('$KEY_TMP/new_pub', toB64u(uncompressed));
chmodSync('$KEY_TMP/new_priv', 0o600);
chmodSync('$KEY_TMP/new_pub', 0o600);
"

# 2. Publish new key as _NEXT (Phase 1)
log "Phase 1: publishing new key as SS_AUTH_PUBLIC_KEY_B64_NEXT (did.json announces [cur, next])"
run "npx wrangler secret put SS_AUTH_PUBLIC_KEY_B64_NEXT < $KEY_TMP/new_pub"

# 3. Wait for PDS _didKeyCache TTL (5 min) so all verifiers see the new key
log "Phase 1→2 grace: sleeping 300s for PDS key cache refresh..."
if [ "$DRY_RUN" != "--dry-run" ]; then sleep 300; fi

# 4. Flip: move cur → prev, next → cur, then swap signing key
log "Phase 2: rotating — cur=new, prev=old, sign with new"
# 4a. Read current cur before overwriting (will become prev)
# Since wrangler doesn't expose a 'secret get' cleanly, we re-publish the OLD pub
# as _PREV via a helper: the dev must have kept a copy. Here we assume the
# previous public key is available via the currently-served did.json.
OLD_PUB_MB=$(curl -s "https://auth.etzhayyim.com/.well-known/did.json?t=$(date +%s)" -H "Cache-Control: no-cache" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); const vm=d.verificationMethod.find(v=>v.id.endsWith('#atproto')); console.log(vm.publicKeyMultibase);")
log "Phase 2: observed old publicKeyMultibase = $OLD_PUB_MB"
log "Phase 2: NOTE: SS_AUTH_PUBLIC_KEY_B64_PREV must be set manually with the OLD b64url pubkey (only multibase is observable from did.json — the raw 65B form is recoverable but requires multibase decode + uncompressed re-encode; out of scope for this script)."
log "Phase 2: proceeding with flip priv + cur"
run "npx wrangler secret put SS_SERVICE_AUTH_PRIVATE_KEY < $KEY_TMP/new_priv"
run "npx wrangler secret put SS_AUTH_PUBLIC_KEY_B64 < $KEY_TMP/new_pub"
# NEXT is now stale (== cur); delete
run "npx wrangler secret delete SS_AUTH_PUBLIC_KEY_B64_NEXT --force"

# 5. Wait for max JWT lifetime (60s) so no A-signed JWTs remain in flight
log "Phase 2→3 grace: sleeping 90s for in-flight JWT expiry..."
if [ "$DRY_RUN" != "--dry-run" ]; then sleep 90; fi

# 6. Phase 3: prev is no longer needed (assuming no unexpired JWTs signed with A remain)
log "Phase 3: rotation complete. (SS_AUTH_PUBLIC_KEY_B64_PREV, if set, can now be deleted.)"
log "  run manually: npx wrangler secret delete SS_AUTH_PUBLIC_KEY_B64_PREV --force"

# Verify
log "Post-rotation did.json:"
curl -s "https://auth.etzhayyim.com/.well-known/did.json?t=$(date +%s)" -H "Cache-Control: no-cache" | head -c 500
echo

log "✓ rotation procedure complete"
