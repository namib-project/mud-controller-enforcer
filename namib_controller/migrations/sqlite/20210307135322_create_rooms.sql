-- Add migration script here
CREATE TABLE floors
(
    id    INTEGER      NOT NULL PRIMARY KEY AUTOINCREMENT,
    label VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE rooms (
   room_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
   floor_id INTEGER NOT NULL REFERENCES floors (id) ON DELETE CASCADE ON UPDATE CASCADE,
   number varchar(50) NOT NULL UNIQUE,
   guest VARCHAR(255) DEFAULT NULL
)
