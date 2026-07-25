SELECT
    a.user_session_request_id,
    a.redirect_url,
    a.create_time
FROM
    forward_auth_request a
WHERE
    a.id = $1