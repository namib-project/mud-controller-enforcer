-- Your SQL goes here
CREATE TABLE devices
(
    id                  INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    ip_addr             TEXT NOT NULL,
    mac_addr            TEXT,
    hostname            TEXT NOT NULL DEFAULT '',
    vendor_class        TEXT NOT NULL DEFAULT '',
    mud_url             TEXT REFERENCES mud_data (url),
    last_interaction    DATETIME NOT NULL
)