-- Your SQL goes here
create table anomalies
(
    id                  INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    source_ip           TEXT NOT NULL,
    source_id           BIGINT REFERENCES devices (id) ON DELETE SET NULL,
    source_port         INTEGER,
    destination_ip      TEXT NOT NULL,
    destination_id      BIGINT REFERENCES devices (id) ON DELETE SET NULL,
    destination_port    INTEGER,
    l4protocol          INTEGER,
    date_time_created   DATETIME NOT NULL DEFAULT current_timestamp
)
