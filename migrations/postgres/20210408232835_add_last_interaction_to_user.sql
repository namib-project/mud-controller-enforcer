-- Add migration script here
ALTER TABLE users
ADD COLUMN last_interaction TIMESTAMP NOT NULL DEFAULT now();