INSERT INTO
    oauth2_token(
        id,
        client_id,
        subject,
        refresh_token_id,
        create_time,
        expiry_time
    )
VALUES(
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
)