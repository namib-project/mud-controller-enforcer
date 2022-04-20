-- Add migration script here
create table notifications
(
    id          BIGSERIAL NOT NULL PRIMARY KEY,
    device_id   BIGINT  NOT NULL,
    -- sources: new_device, anomaly_fw, anomaly_shai
    source      VARCHAR(255)    NOT NULL,
    timestamp   TIMESTAMP       DEFAULT CURRENT_TIMESTAMP NOT NULL,
    read        BOOLEAN         DEFAULT false NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices ON UPDATE CASCADE ON DELETE CASCADE
);
