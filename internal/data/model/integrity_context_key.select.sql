SELECT
    a.id,
    a.secret,
    a.create_time
FROM
    integrity_context_key a
ORDER BY
    a.create_time DESC