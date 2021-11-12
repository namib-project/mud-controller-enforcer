-- Your SQL goes here
ALTER TABLE user_configs RENAME TO _old_user_configs;

CREATE TABLE user_configs
(
    key         VARCHAR(64) NOT NULL,
    user_id     INTEGER NOT NULL,
    value       VARCHAR(512) NOT NULL DEFAULT '',
    PRIMARY KEY (key, user_id),
    FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE ON UPDATE NO ACTION
);

INSERT INTO user_configs (key, user_id, value)
    SELECT key, user_id, value
    FROM _old_user_configs;

DROP TABLE _old_user_configs;