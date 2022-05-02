CREATE TABLE quarantine_exceptions
(
    id                      INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    exception_target        TEXT NOT NULL,
    direction               INTEGER NOT NULL CHECK(0 <= direction AND direction <=1),
    device_id               INTEGER REFERENCES devices(id) NOT NULL
)
