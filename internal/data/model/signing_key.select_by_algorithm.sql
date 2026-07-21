SELECT
    a.id,
    a.private_key,
    a.create_time
FROM
    signing_key a
WHERE
    a.algorithm = $1
ORDER BY
    a.create_time DESC