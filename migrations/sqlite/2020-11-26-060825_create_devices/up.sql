-- Your SQL goes here
CREATE TABLE devices
(
    mac_addr            TEXT NOT NULL PRIMARY KEY,
    ip_addr             TEXT NOT NULL,
    hostname            TEXT NOT NULL DEFAULT '',
    vendor_class        TEXT NOT NULL DEFAULT '',
    mud_url             TEXT REFERENCES mud_data (url) ON UPDATE CASCADE,
    last_interaction    DATETIME NOT NULL
)