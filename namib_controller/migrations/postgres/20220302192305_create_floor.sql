-- Add migration script here
CREATE TABLE floors
(
    id    BIGSERIAL NOT NULL PRIMARY KEY,
    label VARCHAR(128) NOT NULL UNIQUE
);

-- Necessary so INSERT in line 22 passes.
INSERT INTO floors (id, label) VALUES (1, '1st floor') ON CONFLICT DO NOTHING;

ALTER TABLE rooms
    RENAME TO _rooms_old;

CREATE TABLE rooms (
    room_id BIGSERIAL NOT NULL PRIMARY KEY,
    number varchar(50) NOT NULL UNIQUE,
    floor_id BIGINT NOT NULL,
    guest VARCHAR(255) DEFAULT NULL,
    FOREIGN KEY (floor_id) REFERENCES floors (id) ON DELETE CASCADE ON UPDATE CASCADE
);

INSERT INTO rooms (room_id, number, floor_id, guest)
SELECT room_id, name, 1, null
FROM _rooms_old;

ALTER TABLE devices DROP CONSTRAINT devices_room_id_fkey;

ALTER TABLE devices ADD FOREIGN KEY (room_id)
    REFERENCES rooms (room_id)
        ON DELETE SET NULL ON UPDATE NO ACTION;

DROP TABLE _rooms_old CASCADE;
