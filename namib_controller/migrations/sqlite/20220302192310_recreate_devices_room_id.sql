-- Add migration script here
ALTER TABLE devices DROP room_id;

ALTER TABLE devices ADD room_id INTEGER
    REFERENCES rooms (room_id)
        ON DELETE SET NULL ON UPDATE NO ACTION;
