-- Your SQL goes here
create table anomalies
(
    id                  BIGSERIAL NOT NULL PRIMARY KEY,
    source_ip           TEXT NOT NULL,
    source_id           BIGINT REFERENCES devices (id) ON DELETE SET NULL,
    source_port         BIGINT,
    destination_ip      TEXT NOT NULL,
    destination_id      BIGINT REFERENCES devices (id) ON DELETE SET NULL,
    destination_port    BIGINT,
    l4protocol          BIGINT,
    date_time_created   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)
