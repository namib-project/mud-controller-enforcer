-- Add migration script here
CREATE TABLE floors
(
    id    INTEGER      NOT NULL PRIMARY KEY AUTOINCREMENT,
    label VARCHAR(128) NOT NULL UNIQUE
);

-- Necessary so INSERT in line 21 passes.
INSERT INTO floors (id, label) VALUES (1, '1st floor') ON CONFLICT DO NOTHING;

ALTER TABLE rooms
    RENAME TO _rooms_old;

CREATE TABLE rooms (
    room_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    number varchar(50) NOT NULL UNIQUE,
    floor_id INTEGER NOT NULL REFERENCES floors (id) ON DELETE CASCADE ON UPDATE CASCADE,
    guest VARCHAR(255) DEFAULT NULL
);

INSERT INTO rooms (room_id, number, floor_id, guest)
SELECT room_id, name, 1, null
FROM _rooms_old;

DROP TABLE _rooms_old;
