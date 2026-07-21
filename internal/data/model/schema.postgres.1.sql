--
-- Keys
--
CREATE TABLE signing_key(
    id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    private_key BYTEA NOT NULL,
    create_time BIGINT NOT NULL
);
--
-- User Session Request (shared kernel for all auth flows)
--
CREATE TABLE user_session_request(
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    handler_name TEXT NOT NULL,
    session_id TEXT NOT NULL,
    strong_required BOOLEAN NOT NULL DEFAULT FALSE,
    login TEXT NOT NULL DEFAULT '',
    verification TEXT NOT NULL DEFAULT '',
    verification_challenge BYTEA,
    remember BOOLEAN NOT NULL DEFAULT FALSE,
    tainted BOOLEAN NOT NULL DEFAULT FALSE,
    verification_time BIGINT NOT NULL DEFAULT 0,
    auth_info TEXT NOT NULL DEFAULT '',
    create_time BIGINT NOT NULL
);
CREATE INDEX idx_user_session_request_session_id ON user_session_request(session_id);
--
-- User Session (active authenticated sessions)
--
CREATE TABLE session(
    id TEXT PRIMARY KEY,
    user_session_request_id TEXT NOT NULL REFERENCES user_session_request(id),
    login TEXT NOT NULL,
    verification TEXT NOT NULL,
    strong BOOLEAN NOT NULL DEFAULT FALSE,
    remember BOOLEAN NOT NULL DEFAULT FALSE,
    terminated BOOLEAN NOT NULL DEFAULT FALSE,
    verification_audit_info TEXT NOT NULL DEFAULT '',
    last_access_audit_info TEXT NOT NULL DEFAULT '',
    create_time BIGINT NOT NULL,
    last_access_time BIGINT NOT NULL
);
CREATE INDEX idx_session_login ON session(login);
--
-- OAuth2
--
CREATE TABLE oauth2_auth_request(
    id TEXT PRIMARY KEY,
    user_session_request_id TEXT NOT NULL REFERENCES user_session_request(id),
    acr TEXT,
    expiry BIGINT,
    auth_time BIGINT,
    client_id TEXT,
    nonce TEXT,
    redirect_url TEXT,
    response_type TEXT,
    response_mode TEXT,
    state TEXT,
    subject TEXT,
    challenge TEXT,
    remember BOOLEAN,
    done BOOLEAN
);
CREATE TABLE oauth2_auth_request_audience(
    audience TEXT,
    auth_request_id TEXT REFERENCES oauth2_auth_request(id)
);
CREATE TABLE oauth2_auth_request_amr(
    amr TEXT,
    auth_request_id TEXT REFERENCES oauth2_auth_request(id)
);
CREATE TABLE oauth2_auth_request_code_challenge(
    challenge TEXT,
    method TEXT,
    auth_request_id TEXT REFERENCES oauth2_auth_request(id)
);
CREATE TABLE oauth2_auth_request_scope(
    scope TEXT,
    auth_request_id TEXT REFERENCES oauth2_auth_request(id)
);
CREATE TABLE oauth2_auth_code(
    code TEXT PRIMARY KEY,
    auth_request_id TEXT REFERENCES oauth2_auth_request(id)
);
CREATE TABLE oauth2_token(
    id TEXT PRIMARY KEY,
    client_id TEXT,
    subject TEXT,
    refresh_token_id TEXT,
    expiry BIGINT
);
CREATE TABLE oauth2_token_audience(
    audience TEXT,
    token_id TEXT REFERENCES oauth2_token(id)
);
CREATE TABLE oauth2_token_scope(
    scope TEXT,
    token_id TEXT REFERENCES oauth2_token(id)
);
CREATE TABLE oauth2_refresh_token(
    id TEXT PRIMARY KEY,
    auth_time BIGINT,
    subject TEXT,
    client_id TEXT,
    expiry BIGINT,
    access_token_id TEXT REFERENCES oauth2_token(id)
);
CREATE TABLE oauth2_refresh_token_amr(
    amr TEXT,
    refresh_token_id TEXT REFERENCES oauth2_refresh_token(id)
);
CREATE TABLE oauth2_refresh_token_audience(
    audience TEXT,
    refresh_token_id TEXT REFERENCES oauth2_refresh_token(id)
);
CREATE TABLE oauth2_refresh_token_scope(
    scope TEXT,
    refresh_token_id TEXT REFERENCES oauth2_refresh_token(id)
);
--
-- EOF
--
