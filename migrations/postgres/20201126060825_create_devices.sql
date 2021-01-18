-- Your SQL goes here
CREATE TABLE devices
(
    id                  SERIAL NOT NULL PRIMARY KEY,
    ip_addr             TEXT NOT NULL PRIMARY KEY,
    mac_addr            TEXT,
    hostname            TEXT NOT NULL DEFAULT '',
    vendor_class        TEXT NOT NULL DEFAULT '',
    mud_url             TEXT REFERENCES mud_data (url),
    last_interaction    TIMESTAMPTZ NOT NULL
)