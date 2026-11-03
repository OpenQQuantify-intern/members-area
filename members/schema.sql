-- Initial schema only. Use versioned migrations for later schema changes.
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    is_blocked INTEGER NOT NULL DEFAULT 0 CHECK (is_blocked IN (0, 1)),
    session_version INTEGER NOT NULL DEFAULT 1 CHECK (session_version >= 1),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Store only a SHA-256 digest of each randomly generated reset token.
-- Times are UTC Unix seconds; used_at is NULL until the token is consumed.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_reset_tokens_user
ON password_reset_tokens(user_id);

-- An opaque random session token lives in the signed browser cookie.
-- Only its digest lives here. Logout deletes this record, preventing replay.
CREATE TABLE IF NOT EXISTS member_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_version INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_member_sessions_user ON member_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_member_sessions_expiry ON member_sessions(expires_at);

-- Durable rate limits are shared by application processes and survive reloads.
-- Bucket keys are HMAC digests, not plaintext emails or IP addresses.
CREATE TABLE IF NOT EXISTS auth_rate_limits (
    bucket_key TEXT PRIMARY KEY,
    window_start INTEGER NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts > 0),
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_limits_expiry ON auth_rate_limits(expires_at);
