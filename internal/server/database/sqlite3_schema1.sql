CREATE TABLE oauth2_auth_request(
    id TEXT PRIMARY KEY,
	acr TEXT,
	create_time INTEGER,
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
    expiration INTEGER
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
    expiration INTEGER,
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
CREATE TABLE signing_key(
    id TEXT PRIMARY KEY,
    algorithm TEXT,
    private_key BLOB,
    public_key BLOB,
    passivation INTEGER,
    expiration INTEGER
);
CREATE TABLE user_session_request(
    id TEXT PRIMARY KEY,
    subject TEXT,
    remember INTEGER,
    create_time INTEGER,
    state TEXT
);
CREATE TABLE user_session(
    id TEXT PRIMARY KEY,
    subject TEXT,
    remember INTEGER,
    access_token TEXT,
    token_type TEXT,
    refresh_token TEXT,
    expiration INTEGER
);
CREATE TABLE user_totp_secret(
    subject TEXT,
    secret TEXT,
    validated INTEGER,
    create_time INTEGER,
    validation_time INTEGER
);
CREATE TABLE version(
    schema TEXT
);
INSERT INTO version(
    schema
) VALUES (
    '1'
);
