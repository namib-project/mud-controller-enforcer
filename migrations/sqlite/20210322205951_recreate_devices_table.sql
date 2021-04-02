-- Add migration script here
ALTER TABLE devices
    RENAME TO _old_devices;

CREATE TABLE devices
(
    id               INTEGER  NOT NULL PRIMARY KEY AUTOINCREMENT,
    name             TEXT,
    ipv4_addr        TEXT UNIQUE,
    ipv6_addr        TEXT UNIQUE,
    mac_addr         TEXT,
    duid             TEXT,
    hostname         TEXT     NOT NULL DEFAULT '',
    vendor_class     TEXT     NOT NULL DEFAULT '',
    mud_url          TEXT REFERENCES mud_data (url),
    last_interaction DATETIME NOT NULL,
    clipart          TEXT,
    collect_info     BOOLEAN  NOT NULL DEFAULT FALSE,
    room_id          INTEGER REFERENCES rooms (room_id) ON DELETE SET NULL ON UPDATE NO ACTION,
    UNIQUE (mac_addr, duid)
);

INSERT INTO devices (id, ipv4_addr, mac_addr, hostname, vendor_class, mud_url, last_interaction)
SELECT id, ip_addr, mac_addr, hostname, vendor_class, mud_url, last_interaction
FROM _old_devices;

DROP TABLE _old_devices;
