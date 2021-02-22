-- Add migration script here
ALTER TABLE devices ADD COLUMN collect_info BOOLEAN NOT NULL DEFAULT FALSE