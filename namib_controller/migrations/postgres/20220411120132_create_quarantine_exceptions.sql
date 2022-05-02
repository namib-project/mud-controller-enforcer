CREATE TABLE quarantine_exceptions
(
    id                      BIGSERIAL NOT NULL PRIMARY KEY,
    exception_target        TEXT NOT NULL,
    direction               BIGINT NOT NULL CHECK(0 <= direction AND direction <=1),
    device_id               BIGINT REFERENCES devices(id) NOT NULL
)
