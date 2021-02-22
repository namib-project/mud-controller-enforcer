-- Add migration script here
ALTER TABLE user_configs
ALTER COLUMN key TYPE varchar(64),
ALTER COLUMN value TYPE varchar(512);