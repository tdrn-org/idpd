SELECT
    a.address,
    a.host,
    a.lat,
    a.lng,
    a.city,
    a.country
FROM
    audit_log_entry a
WHERE
    a.id = $1