CREATE TABLE oauth2_auth_request(
    id TEXT PRIMARY KEY,
	acr TEXT,
	create_time BIGINT,
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
    expiration BIGINT
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
    auth_time BIGINT,
    subject TEXT,
    client_id TEXT,
    expiration BIGINT,
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
    private_key BYTEA,
    public_key BYTEA,
    passivation BIGINT,
    expiration BIGINT
);
CREATE TABLE user_session_request(
    id TEXT PRIMARY KEY,
    subject TEXT,
    remember BOOLEAN,
    create_time BIGINT,
    state TEXT
);
CREATE TABLE user_session(
    id TEXT PRIMARY KEY,
    subject TEXT,
    remember BOOLEAN,
    access_token TEXT,
    token_type TEXT,
    refresh_token TEXT,
    expiration BIGINT
);
CREATE TABLE user_verification_log(
    subject TEXT,
    method TEXT,
    first_used BIGINT,
    last_used BIGINT,
    host TEXT,
    country TEXT,
    country_code TEXT,
    lat DOUBLE PRECISION,
    lon DOUBLE PRECISION
);
CREATE TABLE version(
    schema TEXT
);
INSERT INTO version(
    schema
) VALUES (
    '1'
);
