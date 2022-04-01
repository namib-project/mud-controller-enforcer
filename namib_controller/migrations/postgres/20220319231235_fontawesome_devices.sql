-- Add migration script here
ALTER TABLE devices DROP clipart;

ALTER TABLE devices ADD fa_icon TEXT
    DEFAULT 'fas house-signal';
