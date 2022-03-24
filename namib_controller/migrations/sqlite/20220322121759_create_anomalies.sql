-- Your SQL goes here
create table anomalies
(
    id                  INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    source_ip           TEXT NOT NULL,
    source_id           INTEGER REFERENCES devices (id) ON DELETE SET NULL,
    source_port         INTEGER,
    destination_ip      TEXT NOT NULL,
    destination_id      INTEGER REFERENCES devices (id) ON DELETE SET NULL,
    destination_port    INTEGER,
    protocol            TEXT NOT NULL,
    date_time_created   DATETIME NOT NULL
)
