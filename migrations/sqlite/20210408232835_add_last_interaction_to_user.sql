-- Add migration script here
ALTER TABLE users
ADD COLUMN last_interaction DATETIME NOT NULL DEFAULT '1970-01-01T00:00:00Z';