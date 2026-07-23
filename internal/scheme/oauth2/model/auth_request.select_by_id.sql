SELECT
    a.user_session_request_id,
    a.oidc_auth_request,
    a.create_time
FROM
    oauth2_auth_request a
WHERE
    a.id = $1