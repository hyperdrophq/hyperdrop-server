package metadb

// schemaSQL is the whole schema: every table, its indexes, and the triggers
// that keep owner_stats and the shares row totals in O(1). Applied once to an
// empty database, inside the same transaction that stamps PRAGMA
// user_version = SchemaVersion.
const schemaSQL = `
CREATE TABLE users (
  username           TEXT PRIMARY KEY,
  password_hash      TEXT NOT NULL,
  role               TEXT NOT NULL,              -- 'admin' | 'user'
  created_at         INTEGER NOT NULL,
  disabled           INTEGER NOT NULL DEFAULT 0,
  account_expires_at INTEGER,
  quota_bytes        INTEGER NOT NULL DEFAULT 0, -- 0 = unlimited
  no_embed           INTEGER NOT NULL DEFAULT 0,
  totp_secret        TEXT,                       -- NULL = 2FA off
  totp_confirmed_at  INTEGER,                    -- NULL = enrolment unfinished, reads as off
  totp_last_step     INTEGER NOT NULL DEFAULT 0,
  invite_hash        TEXT,                       -- the one-time sign-in's hash; NULL = none
  invite_expires_at  INTEGER
) STRICT, WITHOUT ROWID;

CREATE TABLE user_source_roots (                 -- admin-set linked-share allowlist
  username TEXT NOT NULL REFERENCES users ON DELETE CASCADE,
  root     TEXT NOT NULL,
  PRIMARY KEY (username, root)
) STRICT, WITHOUT ROWID;

CREATE TABLE tokens (                            -- device tokens; the raw token is never stored
  id              TEXT PRIMARY KEY,
  username        TEXT NOT NULL REFERENCES users ON DELETE CASCADE,
  sha256          TEXT NOT NULL UNIQUE,          -- bearer lookup
  label           TEXT NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL,
  last_used_at    INTEGER,
  client_version  TEXT NOT NULL DEFAULT '',      -- the newest client this token was last used from
  client_platform TEXT NOT NULL DEFAULT '',      -- macos | windows | linux | ios | android | cli
  push_relay      TEXT,                          -- the relay this device registered with; NULL = no push; ADDITIVE at stamp 1 (additive.go)
  push_handle     TEXT,                          -- the relay's handle for this device: a capability, never listed; ADDITIVE at stamp 1 (additive.go)
  push_key        BLOB,                          -- the device's X25519 public key (HPKE); ADDITIVE at stamp 1 (additive.go)
  push_tag        TEXT,                          -- opaque to the server, echoed in each message; NULL reads as ''; ADDITIVE at stamp 1 (additive.go)
  push_muted      TEXT,                          -- comma-separated kinds this device does not want; NULL reads as ''; ADDITIVE at stamp 1 (additive.go)
  active_at       INTEGER,                       -- a computer's last reported console activity; NULL = none; ADDITIVE at stamp 1 (additive.go)
  via_token       TEXT REFERENCES tokens(id) ON DELETE SET NULL, -- the token that approved this device's sign-in; NULL = none; ADDITIVE at stamp 1 (additive.go)
  kind            TEXT,                          -- 'web' = a browser's sign-in session (websessions.go); NULL = a device token; ADDITIVE at stamp 1 (additive.go)
  idle_until      INTEGER,                       -- a web session ends at this instant unless used; NULL on a device token; ADDITIVE at stamp 1 (additive.go)
  expires_at      INTEGER,                       -- a web session ends at this instant whatever its use; NULL on a device token; ADDITIVE at stamp 1 (additive.go)
  elevated_until  INTEGER,                       -- a web session may make admin changes until this instant; NULL = never; ADDITIVE at stamp 1 (additive.go)
  keep            INTEGER,                       -- 1 = a web session kept on the signer's own computer, sliding; ADDITIVE at stamp 1 (additive.go)
  sign_in_method  TEXT,                          -- 'phone' = a computer a signed-in phone approved (desktopsignin.go); NULL = any other sign-in; ADDITIVE at stamp 1 (additive.go)
  approved_by_label TEXT                         -- the approving device's label at the approval; kept after that device goes; NULL = none; ADDITIVE at stamp 1 (additive.go)
) STRICT, WITHOUT ROWID;

CREATE INDEX tokens_push ON tokens(username) WHERE push_handle IS NOT NULL;  -- ADDITIVE at stamp 1 (additive.go)
CREATE INDEX tokens_user ON tokens(username, created_at, id);  -- an account's tokens in order, read on every authenticated request; ADDITIVE at stamp 1 (additive.go)

CREATE TABLE recovery_codes (                    -- SHA-256 of each unused code
  username TEXT NOT NULL REFERENCES users ON DELETE CASCADE,
  sha256   TEXT NOT NULL,
  PRIMARY KEY (username, sha256)
) STRICT, WITHOUT ROWID;

CREATE TABLE shares (
  id            TEXT PRIMARY KEY,                -- 10-char base58, ValidID-checked before any query
  owner         TEXT NOT NULL REFERENCES users,  -- RESTRICT: the API deletes shares before an account
  name          TEXT NOT NULL,
  name_lower    TEXT NOT NULL,                   -- ?q= search key
  folder        INTEGER NOT NULL DEFAULT 0,
  entry         TEXT NOT NULL DEFAULT '',        -- opens: page
  media         INTEGER NOT NULL DEFAULT 0,      -- opens: gallery
  listing       INTEGER NOT NULL DEFAULT 0,      -- opens: listing
  inbox         INTEGER NOT NULL DEFAULT 0,
  text          INTEGER NOT NULL DEFAULT 0,      -- a text share: one text file, opened as that file
  note          TEXT NOT NULL DEFAULT '',        -- inbox only
  closed        INTEGER NOT NULL DEFAULT 0,
  max_bytes     INTEGER NOT NULL DEFAULT 0,
  max_files     INTEGER NOT NULL DEFAULT 0,
  notify_off    INTEGER NOT NULL DEFAULT 0,
  seen_at       INTEGER,
  pinned_at     INTEGER,                         -- NULL = not pinned; the owner's own ordering, never an edit
  password_hash TEXT,                            -- NULL = no password
  password_gen  INTEGER NOT NULL DEFAULT 0,      -- bumps revoke access cookies
  created_at    INTEGER NOT NULL,
  modified_at   INTEGER,
  expires_at    INTEGER,
  bytes         INTEGER NOT NULL DEFAULT 0,      -- committed bytes, kept by the files triggers
  committed     INTEGER NOT NULL DEFAULT 0,      -- committed file count
  files         INTEGER NOT NULL DEFAULT 0,      -- including pending
  visitors      INTEGER NOT NULL DEFAULT 0,      -- distinct visitor tokens, kept by the visitors triggers
  password_sealed BLOB,                          -- the owner's readable copy (sealpw), bound to password_hash; NULL = none; ADDITIVE at stamp 1 (additive.go)
  CHECK ((entry <> '') + media + listing <= 1),  -- one View answer, enforced by the database
  CHECK (text + inbox <= 1),                     -- a text share is never an inbox
  CHECK (text = 0 OR (entry = '' AND media = 0 AND listing = 0))  -- a text share opens as its file
) STRICT, WITHOUT ROWID;

-- inbox sits beside owner because every listing filters on it: without it an
-- offset skip reads a table row per skipped index entry to test the kind.
CREATE INDEX shares_owner_created ON shares(owner, inbox, created_at DESC, id DESC);
CREATE INDEX shares_owner_name    ON shares(owner, inbox, name_lower, created_at DESC, id DESC);
CREATE INDEX shares_expiring      ON shares(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX shares_created       ON shares(inbox, created_at DESC, id DESC);
-- the empty-share sweep runs every tick and matches almost nothing; the
-- partial index holds only the shares that are still waiting for a byte.
CREATE INDEX shares_empty         ON shares(created_at) WHERE committed = 0 AND inbox = 0;

CREATE TABLE owner_stats (                       -- kept by triggers; usage and page totals in O(1)
  owner     TEXT PRIMARY KEY REFERENCES users ON DELETE CASCADE,
  shares     INTEGER NOT NULL,
  bytes     INTEGER NOT NULL,
  committed INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE files (
  share_id        TEXT NOT NULL REFERENCES shares ON DELETE CASCADE,
  path           TEXT NOT NULL,                  -- NFC relpath, the on-disk name under files/
  slug           TEXT NOT NULL,                  -- UUIDv4, the public token
  size           INTEGER NOT NULL,
  sha256         TEXT,                           -- NULL while pending
  mime           TEXT NOT NULL DEFAULT '',
  pending        INTEGER NOT NULL DEFAULT 0,
  committed_at   INTEGER,
  added_at       INTEGER,
  upload_session TEXT NOT NULL DEFAULT '',       -- the inbox's per-sender grouping
  declared_at    INTEGER,                        -- when the pending row was declared
  fold_key       TEXT,                           -- shareid.FoldPath(path), the case-folding lookup's key; ADDITIVE at stamp 1 (additive.go)
  PRIMARY KEY (share_id, path)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX files_slug ON files(share_id, slug);
CREATE INDEX files_sha ON files(sha256) WHERE sha256 IS NOT NULL;  -- the committed-file walk
CREATE INDEX files_pending ON files(declared_at) WHERE pending = 1;
CREATE INDEX files_committed ON files(share_id, committed_at) WHERE pending = 0;  -- the pusher's inbox reads; ADDITIVE at stamp 1 (additive.go)
CREATE INDEX files_fold ON files(share_id, fold_key);  -- the case-folding lookups (casefold.go); ADDITIVE at stamp 1 (additive.go)

CREATE TABLE folders (                           -- explicit empty-folder records
  share_id TEXT NOT NULL REFERENCES shares ON DELETE CASCADE,
  path    TEXT NOT NULL,
  fold_key TEXT,                                   -- shareid.FoldPath(path), as on files; ADDITIVE at stamp 1 (additive.go)
  PRIMARY KEY (share_id, path)
) STRICT, WITHOUT ROWID;

CREATE INDEX folders_fold ON folders(share_id, fold_key);  -- ADDITIVE at stamp 1 (additive.go)

CREATE TABLE scheduled (                         -- one scheduled change per field
  share_id       TEXT NOT NULL REFERENCES shares ON DELETE CASCADE,
  kind          TEXT NOT NULL,                   -- 'password' | 'expiry'
  apply_at      INTEGER NOT NULL,
  clear         INTEGER NOT NULL DEFAULT 0,
  password_hash TEXT,
  expires_at    INTEGER,
  password_sealed BLOB,                          -- the owner's readable copy (sealpw), bound to password_hash; NULL = none; ADDITIVE at stamp 1 (additive.go)
  PRIMARY KEY (share_id, kind)
) STRICT, WITHOUT ROWID;
CREATE INDEX scheduled_due ON scheduled(apply_at);

CREATE TABLE share_sources (
  share_id       TEXT NOT NULL REFERENCES shares ON DELETE CASCADE,
  source        TEXT NOT NULL,                   -- root-relative server path
  position      INTEGER NOT NULL,                -- order as added
  fixed         INTEGER NOT NULL DEFAULT 0,      -- 1 = shows only the 'fixed' source_paths rows
  revoked_at    INTEGER,                         -- set while the owner's allowlist no longer covers the source
  revoked_files INTEGER,                         -- entries the source listed when it was revoked; NULL = unreadable then
  PRIMARY KEY (share_id, source)
) STRICT, WITHOUT ROWID;

CREATE TABLE source_paths (                      -- the fixed list and the hidden list, source-relative
  share_id TEXT NOT NULL,
  source  TEXT NOT NULL,
  kind    TEXT NOT NULL,                         -- 'fixed' | 'hidden'
  rel     TEXT NOT NULL,
  PRIMARY KEY (share_id, source, kind, rel),
  FOREIGN KEY (share_id, source) REFERENCES share_sources ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE linked_slugs (                      -- a linked entry's slug survives hide and show
  share_id TEXT NOT NULL REFERENCES shares ON DELETE CASCADE,
  rel     TEXT NOT NULL,                         -- as listed (prefixed when several sources)
  slug    TEXT NOT NULL,
  PRIMARY KEY (share_id, rel)
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX linked_slugs_slug ON linked_slugs(share_id, slug);

CREATE TABLE gallery (
  share_id     TEXT NOT NULL REFERENCES shares ON DELETE CASCADE,
  slug        TEXT NOT NULL,
  width       INTEGER,
  height      INTEGER,
  duration_ms INTEGER,
  taken_at    INTEGER,
  PRIMARY KEY (share_id, slug)
) STRICT, WITHOUT ROWID;

CREATE TABLE changes (
  seq     INTEGER PRIMARY KEY AUTOINCREMENT,     -- the client cursor; never reused
  owner   TEXT NOT NULL,
  share_id TEXT NOT NULL,                         -- no FK: a deletion outlives its share
  deleted INTEGER NOT NULL,
  at      INTEGER NOT NULL
) STRICT;
CREATE INDEX changes_owner ON changes(owner, seq);
CREATE INDEX changes_share ON changes(share_id, seq);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT, WITHOUT ROWID;

CREATE TRIGGER files_ai AFTER INSERT ON files BEGIN
  UPDATE shares SET files = files + 1,
    committed = committed + (new.pending = 0),
    bytes = bytes + CASE WHEN new.pending = 0 THEN new.size ELSE 0 END
  WHERE id = new.share_id;
END;
CREATE TRIGGER files_ad AFTER DELETE ON files BEGIN
  UPDATE shares SET files = files - 1,
    committed = committed - (old.pending = 0),
    bytes = bytes - CASE WHEN old.pending = 0 THEN old.size ELSE 0 END
  WHERE id = old.share_id;
END;
CREATE TRIGGER files_au AFTER UPDATE OF size, pending ON files BEGIN
  UPDATE shares SET
    committed = committed - (old.pending = 0) + (new.pending = 0),
    bytes = bytes - CASE WHEN old.pending = 0 THEN old.size ELSE 0 END
                  + CASE WHEN new.pending = 0 THEN new.size ELSE 0 END
  WHERE id = new.share_id;
END;
CREATE TRIGGER shares_ai AFTER INSERT ON shares BEGIN
  INSERT INTO owner_stats(owner, shares, bytes, committed) VALUES (new.owner, 1, new.bytes, new.committed)
  ON CONFLICT(owner) DO UPDATE SET shares = shares + 1, bytes = bytes + excluded.bytes, committed = committed + excluded.committed;
END;
CREATE TRIGGER shares_ad AFTER DELETE ON shares BEGIN
  UPDATE owner_stats SET shares = shares - 1, bytes = bytes - old.bytes, committed = committed - old.committed WHERE owner = old.owner;
END;
CREATE TRIGGER shares_au AFTER UPDATE OF bytes, committed ON shares BEGIN
  UPDATE owner_stats SET bytes = bytes - old.bytes + new.bytes, committed = committed - old.committed + new.committed WHERE owner = new.owner;
END;

CREATE TABLE visitors (                          -- one row per distinct visitor token, per share
  share_id TEXT NOT NULL REFERENCES shares ON DELETE CASCADE,
  token   BLOB NOT NULL,                         -- HMAC of the visitor cookie or of address plus User-Agent
  PRIMARY KEY (share_id, token)
) STRICT, WITHOUT ROWID;

CREATE TRIGGER visitors_ai AFTER INSERT ON visitors BEGIN
  UPDATE shares SET visitors = visitors + 1 WHERE id = new.share_id;
END;
CREATE TRIGGER visitors_ad AFTER DELETE ON visitors BEGIN
  UPDATE shares SET visitors = visitors - 1 WHERE id = old.share_id;
END;

CREATE TABLE push_state (                        -- what the pusher has already announced; ADDITIVE at stamp 1 (additive.go)
  owner TEXT NOT NULL,                           -- '' = the server's own (the domain, the pusher's heartbeat)
  kind  TEXT NOT NULL,                           -- 'inbox' | 'revoke' | 'domain' | 'alive'
  value TEXT NOT NULL,                           -- the announcer's state
  PRIMARY KEY (owner, kind)
) STRICT, WITHOUT ROWID;

CREATE TABLE device_links (                      -- a desktop signing a phone in; one row per link; ADDITIVE at stamp 1 (additive.go)
  id              TEXT PRIMARY KEY,
  username        TEXT NOT NULL REFERENCES users ON DELETE CASCADE,
  minted_by_token TEXT NOT NULL REFERENCES tokens ON DELETE CASCADE,
  secret_hash     TEXT NOT NULL UNIQUE,
  minted_addr     TEXT NOT NULL,                 -- HMAC of the minting request's client address under the volume secret
  state           TEXT NOT NULL,                 -- minted | claimed | approved | spent | burned
  expires_at      INTEGER NOT NULL,              -- the unclaimed link's end, then the claim's
  window_ends_at  INTEGER NOT NULL,              -- renewals stop here
  created_at      INTEGER NOT NULL,
  claim_id        TEXT UNIQUE,
  claim_poll_hash TEXT,
  claim_label     TEXT,
  claim_platform  TEXT,
  claim_number    INTEGER,
  claim_same_addr INTEGER,
  claimed_at      INTEGER,
  stepped_up      INTEGER                        -- 1 when the mint proved the password (and code); NULL = not; ADDITIVE at stamp 1 (additive.go)
) STRICT, WITHOUT ROWID;
CREATE INDEX device_links_user ON device_links(username);

CREATE TABLE sign_in_events (                    -- one audit row per computer a phone signed in (desktopsignin.go); ADDITIVE at stamp 1 (additive.go)
  id                INTEGER PRIMARY KEY,
  username          TEXT NOT NULL REFERENCES users ON DELETE CASCADE,
  at                INTEGER NOT NULL,
  token_id          TEXT,                        -- the computer's token; no reference, so the row outlives it
  label             TEXT NOT NULL,
  approver_token_id TEXT,                        -- the approving device's token; no reference, so the daily count survives its revoke
  approver_label    TEXT NOT NULL,
  addr_mark         TEXT NOT NULL                -- HMAC of the computer's address under the volume secret
) STRICT;
CREATE INDEX sign_in_events_approver ON sign_in_events(approver_token_id, at);
CREATE INDEX sign_in_events_user ON sign_in_events(username, at);
`
