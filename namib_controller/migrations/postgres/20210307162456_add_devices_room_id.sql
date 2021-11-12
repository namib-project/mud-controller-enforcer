-- Add migration script here
ALTER TABLE devices ADD COLUMN room_id BIGINT
    REFERENCES rooms (room_id)
        ON DELETE SET NULL ON UPDATE NO ACTION;
