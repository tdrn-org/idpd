INSERT INTO
    user_session_request(
        id,
        auth_info,
        create_time,
        expiry_time
    )
VALUES(
    $1,
    $2,
    $3,
    $4
)