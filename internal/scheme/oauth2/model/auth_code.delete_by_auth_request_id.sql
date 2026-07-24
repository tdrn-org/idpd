DELETE FROM
    oauth2_auth_code
WHERE
    auth_request_id = $1