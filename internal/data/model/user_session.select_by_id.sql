SELECT
    a.login,
    a.remember,
    a.verification,
    a.terminated,
    a.create_time,
    a.last_access_time
FROM
    user_session a
WHERE
    a.id = $1