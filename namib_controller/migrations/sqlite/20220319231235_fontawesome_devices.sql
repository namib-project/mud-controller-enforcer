-- Add migration script here
ALTER TABLE devices
    RENAME clipart TO fa_icon;
