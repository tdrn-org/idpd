--
-- Keys
--
CREATE TABLE signing_key(
    id TEXT PRIMARY KEY,
    algorithm TEXT,
    private_key BYTEA,
    create_time BIGINT
);
--
-- EOF
--
