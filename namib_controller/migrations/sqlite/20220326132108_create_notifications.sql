-- Add migration script here
create table notifications
(
    id          INTEGER         NOT NULL PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER         NOT NULL
        REFERENCES devices ON UPDATE CASCADE ON DELETE CASCADE,
    -- sources: new_device, anomaly_fw, anomaly_shai
    source      VARCHAR(255)    NOT NULL,
    timestamp   DATETIME        DEFAULT CURRENT_TIMESTAMP NOT NULL,
    read        BOOLEAN         DEFAULT 0 NOT NULL
);
