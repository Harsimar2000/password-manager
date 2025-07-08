PRAGMA foreign_keys = ON;

/* ---------- users (account details per user) ---------- */
CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,                    -- UUID
  email       TEXT UNIQUE NOT NULL,
  salt        BLOB NOT NULL,                       -- 16-byte Argon2 salt
  pwd_hash    BLOB NOT NULL,                       -- auth hash
  vk_enc      BLOB NOT NULL,                       -- encrypted Vault Key
  created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

/* ---------- items (encrypted vault records) ---------- */
CREATE TABLE IF NOT EXISTS items (
  id          TEXT PRIMARY KEY,                    -- UUID
  user_id     TEXT NOT NULL,
  enc_blob    BLOB NOT NULL,                       -- nonce ‖ cipher ‖ tag
  version     INTEGER NOT NULL,                    -- optimistic-lock counter
  deleted     INTEGER NOT NULL DEFAULT 0,          -- 0 = active, 1 = deleted 
  updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_items_user      ON items(user_id);
CREATE INDEX IF NOT EXISTS idx_items_user_ver  ON items(user_id, version);

/* ---------- refresh_tokens (rotating session cookies) ---------- */
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token       TEXT PRIMARY KEY,                    -- 128-bit random string
  user_id     TEXT NOT NULL, 
  expires_at  INTEGER NOT NULL,                    -- Unix seconds
  created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_rt_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_rt_exp  ON refresh_tokens(expires_at);

