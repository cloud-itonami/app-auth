CREATE TABLE IF NOT EXISTS accounts (
  id         TEXT PRIMARY KEY,
  handle     TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS passkey_credentials (
  credential_id   TEXT PRIMARY KEY,
  account_id      TEXT NOT NULL REFERENCES accounts(id),
  public_key_b64  TEXT NOT NULL,
  sign_count      INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
  id            TEXT PRIMARY KEY,
  challenge     TEXT NOT NULL,
  account_id    TEXT,
  credential_id TEXT,
  expires_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_passkey_account ON passkey_credentials(account_id);
CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges(expires_at);
