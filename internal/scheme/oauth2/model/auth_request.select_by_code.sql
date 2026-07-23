SELECT
    a.id,
    a.user_session_request_id,
    a.oidc_auth_request,
    a.create_time
FROM
    oauth2_auth_request a,
    oauth2_auth_code b
WHERE
    a.id = b.auth_request_id AND
    b.code = $1