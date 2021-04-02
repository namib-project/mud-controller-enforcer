-- Add migration script here
PRAGMA foreign_keys=off;

ALTER TABLE rooms
    RENAME TO _old_rooms;

CREATE TABLE rooms
(
    room_id INTEGER     NOT NULL PRIMARY KEY AUTOINCREMENT,
    name    varchar(50) NOT NULL UNIQUE,
    color   varchar(10) NOT NULL
);

INSERT INTO rooms (room_id, name, color)
    SELECT room_id, name, color
    FROM _old_rooms;

DROP TABLE _old_rooms;

PRAGMA foreign_keys=on;
