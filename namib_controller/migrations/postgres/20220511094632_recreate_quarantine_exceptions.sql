ALTER TABLE quarantine_exceptions
    RENAME TO _old_exceptions;

CREATE TABLE quarantine_exceptions
(
    id                      BIGSERIAL NOT NULL PRIMARY KEY,
    exception_target        TEXT NOT NULL,
    direction               BIGINT NOT NULL CHECK(0 <= direction AND direction <=1),
    device_id               BIGINT REFERENCES devices(id),
    mud_url                 TEXT REFERENCES mud_data (url)
);

INSERT INTO quarantine_exceptions (id, exception_target, direction, device_id)
SELECT id, exception_target, direction, device_id
FROM _old_exceptions;

DROP TABLE _old_exceptions;
