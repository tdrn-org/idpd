--
-- Integrity Context Key
--
CREATE TABLE integrity_context_key(
    id TEXT NOT NULL,
    secret BLOB NOT NULL,
    create_time INTEGER NOT NULL,
    PRIMARY KEY(id)
);
--
-- User Session Request (shared kernel for all auth flows)
--
CREATE TABLE user_session_request(
    id TEXT NOT NULL,
    auth_info BLOB NOT NULL,
    create_time INTEGER NOT NULL,
    expiry_time INTEGER NOT NULL,
    PRIMARY KEY(id)
);
--
-- User Session (active authenticated sessions)
--
CREATE TABLE session(
    id TEXT NOT NULL,
    user_session_request_id TEXT NOT NULL,
    login TEXT NOT NULL,
    verification TEXT NOT NULL,
    strong INTEGER NOT NULL DEFAULT 0,
    remember INTEGER NOT NULL DEFAULT 0,
    terminated INTEGER NOT NULL DEFAULT 0,
    verification_audit_info TEXT NOT NULL DEFAULT '',
    last_access_audit_info TEXT NOT NULL DEFAULT '',
    create_time INTEGER NOT NULL,
    last_access_time INTEGER NOT NULL,
    PRIMARY KEY(id),
    FOREIGN KEY(user_session_request_id) REFERENCES user_session_request(id)
);
CREATE INDEX idx_session_login ON session(login);
--
-- OAuth2
--
CREATE TABLE oauth2_signing_key(
    id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    private_key BLOB NOT NULL,
    create_time INTEGER NOT NULL,
    PRIMARY KEY(id)
);
CREATE TABLE oauth2_auth_request(
    id TEXT NOT NULL,
    oidc_auth_request BLOB NOT NULL,
    create_time INTEGER NOT NULL,
    PRIMARY KEY(id),
    FOREIGN KEY(id) REFERENCES user_session_request(id)
);
CREATE TABLE oauth2_auth_code(
    code TEXT PRIMARY KEY,
    auth_request_id TEXT,
    FOREIGN KEY(auth_request_id) REFERENCES oauth2_auth_request(id)
);
CREATE TABLE oauth2_token(
    id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    create_time INTEGER NOT NULL,
    expiry_time INTEGER NOT NULL,
    PRIMARY KEY(id)
);
CREATE TABLE oauth2_refresh_token(
    id TEXT NOT NULL,
    access_token_id TEXT NOT NULL,
    create_time INTEGER NOT NULL,
    expiry_time INTEGER NOT NULL,
    PRIMARY KEY(id),
    FOREIGN KEY(access_token_id) REFERENCES oauth2_token(id)
);
--
-- Forward
--
CREATE TABLE forward_auth_request(
    id TEXT NOT NULL,
    redirect_url TEXT NOT NULL,
    create_time INTEGER NOT NULL,
    PRIMARY KEY(id),
    FOREIGN KEY(id) REFERENCES user_session_request(id)
);
--
-- EOF
--
