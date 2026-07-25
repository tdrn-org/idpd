INSERT INTO
    forward_auth_request(
        id,
        user_session_request_id,
        redirect_url,
        create_time
    )
VALUES(
    $1,
    $2,
    $3,
    $4
)