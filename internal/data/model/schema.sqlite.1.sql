--
-- Keys
--
CREATE TABLE signing_key(
    id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    private_key BLOB NOT NULL,
    create_time INTEGER NOT NULL,
    PRIMARY KEY(id)
);
--
-- User
--
CREATE TABLE user_session_request(
    id TEXT NOT NULL,
    state TEXT NOT NULL,
    auth_info TEXT NOT NULL,
    create_time INTEGER NOT NULL,
    PRIMARY KEY(id)
);
--
-- OAuth2
--
CREATE TABLE oauth2_auth_request(
    id TEXT PRIMARY KEY,
	acr TEXT,
	expiry INTEGER,
	auth_time INTEGER,
	client_id TEXT,
	nonce TEXT,
	redirect_url TEXT,
	response_type TEXT,
	response_mode TEXT,
	state TEXT,
	subject TEXT,
    challenge TEXT,
	remember INTEGER,
	done INTEGER
);
CREATE TABLE oauth2_auth_request_audience(
    audience TEXT,
    auth_request_id TEXT,
    FOREIGN KEY(auth_request_id) REFERENCES oauth2_auth_request(id)
);
CREATE TABLE oauth2_auth_request_amr(
    amr TEXT,
    auth_request_id TEXT,
    FOREIGN KEY(auth_request_id) REFERENCES oauth2_auth_request(id)
);
CREATE TABLE oauth2_auth_request_code_challenge(
    challenge TEXT,
    method TEXT,
    auth_request_id TEXT,
    FOREIGN KEY(auth_request_id) REFERENCES oauth2_auth_request(id)
);
CREATE TABLE oauth2_auth_request_scope(
    scope TEXT,
    auth_request_id TEXT,
    FOREIGN KEY(auth_request_id) REFERENCES oauth2_auth_request(id)
);
CREATE TABLE oauth2_auth_code(
    code TEXT PRIMARY KEY,
    auth_request_id TEXT,
    FOREIGN KEY(auth_request_id) REFERENCES oauth2_auth_request(id)
);
CREATE TABLE oauth2_token(
    id TEXT PRIMARY KEY,
    client_id TEXT,
    subject TEXT,
    refresh_token_id TEXT,
    expiry INTEGER
);
CREATE TABLE oauth2_token_audience(
    audience TEXT,
    token_id TEXT,
    FOREIGN KEY(token_id) REFERENCES oauth2_token(id)
);
CREATE TABLE oauth2_token_scope(
    scope TEXT,
    token_id TEXT,
    FOREIGN KEY(token_id) REFERENCES oauth2_token(id)
);
CREATE TABLE oauth2_refresh_token(
    id TEXT PRIMARY KEY,
    auth_time INTEGER,
    subject TEXT,
    client_id TEXT,
    expiry INTEGER,
    access_token_id TEXT,
    FOREIGN KEY(access_token_id) REFERENCES oauth2_token(id)
);
CREATE TABLE oauth2_refresh_token_amr(
    amr TEXT,
    refresh_token_id TEXT,
    FOREIGN KEY(refresh_token_id) REFERENCES oauth2_refresh_token(id)
);
CREATE TABLE oauth2_refresh_token_audience(
    audience TEXT,
    refresh_token_id TEXT,
    FOREIGN KEY(refresh_token_id) REFERENCES oauth2_refresh_token(id)
);
CREATE TABLE oauth2_refresh_token_scope(
    scope TEXT,
    refresh_token_id TEXT,
    FOREIGN KEY(refresh_token_id) REFERENCES oauth2_refresh_token(id)
);
--
-- EOF
--
