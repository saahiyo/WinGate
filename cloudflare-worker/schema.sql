CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    invite_code TEXT,
    external_uid INTEGER,
    status TEXT DEFAULT 'active',
    registered_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_identifier ON users(identifier);
CREATE INDEX IF NOT EXISTS idx_users_invite_code ON users(invite_code);
CREATE INDEX IF NOT EXISTS idx_users_external_uid ON users(external_uid);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    refresh_hash TEXT NOT NULL,
    refresh_family_id TEXT NOT NULL,
    refresh_token_version INTEGER DEFAULT 1,
    refresh_rotated_at TEXT,
    device_id TEXT,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_refresh ON auth_sessions(refresh_hash);

CREATE TABLE IF NOT EXISTS refresh_token_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    family_id TEXT NOT NULL,
    auth_session_id TEXT NOT NULL REFERENCES auth_sessions(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    version INTEGER DEFAULT 1,
    is_used INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_token_records(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_token_records(family_id);

CREATE TABLE IF NOT EXISTS balances (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    cash_available REAL DEFAULT 0.00,
    bonus_available REAL DEFAULT 0.00,
    locked_amount REAL DEFAULT 0.00,
    version INTEGER DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS page_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    session_id TEXT NOT NULL,
    tab_id TEXT,
    route TEXT NOT NULL,
    page_name TEXT,
    last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_page_states_user_session ON page_states(user_id, session_id);

CREATE TABLE IF NOT EXISTS game_launch_tickets (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    auth_session_id TEXT NOT NULL REFERENCES auth_sessions(id),
    game_id TEXT NOT NULL,
    ticket_hash TEXT NOT NULL UNIQUE,
    is_consumed INTEGER DEFAULT 0,
    consumed_at TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_launch_tickets_hash ON game_launch_tickets(ticket_hash);

CREATE TABLE IF NOT EXISTS game_sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    auth_session_id TEXT NOT NULL REFERENCES auth_sessions(id),
    game_id TEXT NOT NULL,
    vendor TEXT,
    state TEXT DEFAULT 'PENDING',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_heartbeat_at TEXT NOT NULL,
    closed_at TEXT,
    close_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_game_sessions_user ON game_sessions(user_id, auth_session_id, state);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    session_id TEXT,
    game_session_id TEXT,
    created_at TEXT NOT NULL,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS action_nonces (
    nonce TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS action_audit_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    game_session_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_id TEXT NOT NULL,
    idempotency_key TEXT,
    amount REAL DEFAULT 0.00,
    balance_before REAL,
    balance_after REAL,
    balance_version INTEGER,
    status TEXT DEFAULT 'SUCCESS',
    failure_reason TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency_records (
    key TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    operation TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
