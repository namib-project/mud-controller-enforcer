-- Your SQL goes here
DROP TABLE  user_configs;

CREATE TABLE user_configs
(
    key         VARCHAR(64) NOT NULL,
    user_id     INTEGER NOT NULL,
    value       VARCHAR(512) NOT NULL DEFAULT '',
    PRIMARY KEY (key, user_id),
    FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE ON UPDATE NO ACTION
)