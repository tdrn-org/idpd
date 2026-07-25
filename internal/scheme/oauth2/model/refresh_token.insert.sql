INSERT INTO
    oauth2_refresh_token(
        id,
        access_token_id,
        create_time,
        expiry_time
    )
VALUES(
    $1,
    $2,
    $3,
    $4
)