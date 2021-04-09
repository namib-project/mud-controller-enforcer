-- Add migration script here
ALTER TABLE users
ADD COLUMN last_interaction DATETIME NOT NULL DEFAULT now();