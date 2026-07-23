INSERT INTO
    oauth2_auth_request(
        id,
        user_session_request_id,
        oidc_auth_request,
        create_time
    )
VALUES(
    $1,
    $2,
    $3,
    $4
)