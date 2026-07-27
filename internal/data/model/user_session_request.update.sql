UPDATE
    user_session_request
SET
    auth_info = $1
WHERE
    id = $2