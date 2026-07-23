SELECT
    a.secret,
    a.create_time
FROM
    integrity_context_key a
WHERE
    a.id = $1