SELECT
    a.auth_info,
    a.create_time
FROM
    user_session_request a
WHERE
    a.id = $1