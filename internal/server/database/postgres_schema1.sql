CREATE TABLE auth_request(
    id TEXT PRIMARY KEY,
	acr TEXT,
	create_time BIGINT,
	auth_time BIGINT,
	client_id TEXT,
	nonce TEXT,
	redirect_uri TEXT,
	response_type TEXT,
	response_mode TEXT,
	state TEXT,
	subject TEXT,
	done BOOLEAN
);
CREATE TABLE auth_request_audience(
    audience TEXT,
    auth_request_id TEXT,
    FOREIGN KEY(auth_request_id) REFERENCES auth_request(id)
);
CREATE TABLE auth_request_amr(
    amr TEXT,
    auth_request_id TEXT,
    FOREIGN KEY(auth_request_id) REFERENCES auth_request(id)
);
CREATE TABLE auth_request_code_challenge(
    challenge TEXT,
    method TEXT,
    auth_request_id TEXT,
    FOREIGN KEY(auth_request_id) REFERENCES auth_request(id)
);
CREATE TABLE auth_request_scope(
    scope TEXT,
    auth_request_id TEXT,
    FOREIGN KEY(auth_request_id) REFERENCES auth_request(id)
);
CREATE TABLE auth_code(
    code TEXT PRIMARY KEY,
    auth_request_id TEXT,
    FOREIGN KEY(auth_request_id) REFERENCES auth_request(id)
);
CREATE TABLE token(
    id TEXT PRIMARY KEY,
    application_id TEXT,
    subject TEXT,
    refresh_token_id TEXT,
    expiration BIGINT
);
CREATE TABLE token_audience(
    audience TEXT,
    token_id TEXT,
    FOREIGN KEY(token_id) REFERENCES token(id)
);
CREATE TABLE token_scope(
    scope TEXT,
    token_id TEXT,
    FOREIGN KEY(token_id) REFERENCES token(id)
);
CREATE TABLE refresh_token(
    id TEXT PRIMARY KEY,
    auth_time BIGINT,
    user_id TEXT,
    application_id TEXT,
    expiration BIGINT,
    access_token_id TEXT,
    FOREIGN KEY(access_token_id) REFERENCES token(id)
);
CREATE TABLE refresh_token_amr(
    amr TEXT,
    refresh_token_id TEXT,
    FOREIGN KEY(refresh_token_id) REFERENCES refresh_token(id)
);
CREATE TABLE refresh_token_audience(
    audience TEXT,
    refresh_token_id TEXT,
    FOREIGN KEY(refresh_token_id) REFERENCES refresh_token(id)
);
CREATE TABLE refresh_token_scope(
    scope TEXT,
    refresh_token_id TEXT,
    FOREIGN KEY(refresh_token_id) REFERENCES refresh_token(id)
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
    state TEXT,
    create_time BIGINT,
    remember BOOLEAN
);
CREATE TABLE user_session(
    id TEXT PRIMARY KEY,
    remember BOOLEAN,
    access_token TEXT,
    token_type TEXT,
    refresh_token TEXT,
    expiration BIGINT
);
CREATE TABLE version(
    schema TEXT
);
INSERT INTO version(
    schema
) VALUES (
    '1'
);
