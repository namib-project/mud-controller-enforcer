-- Add migration script here
CREATE TABLE enforcers
(
    cert_id          TEXT     NOT NULL PRIMARY KEY,
    last_ip_address  TEXT     NOT NULL,
    last_interaction DATETIME NOT NULL,
    allowed          BOOLEAN  NOT NULL
)