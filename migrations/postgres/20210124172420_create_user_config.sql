-- Your SQL goes here
CREATE TABLE user_configs
(
    key     TEXT   NOT NULL,
    user_id BIGINT NOT NULL,
    value   TEXT   NOT NULL DEFAULT '',
    PRIMARY KEY (key, user_id),
    FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE ON UPDATE NO ACTION
)