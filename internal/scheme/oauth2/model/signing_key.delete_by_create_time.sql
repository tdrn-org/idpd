DELETE FROM
    oauth2_signing_key
WHERE
    create_time < $1